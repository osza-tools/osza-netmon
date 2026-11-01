// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// This is the T-104 proof-of-concept CLI (task card §3.5): a boundary
// binary that prints to the standard streams by design — the TUI does
// not exist yet (Phase 3), and the task card exempts examples from the
// SR-03 print ban ("No println!/eprintln! in non-test, non-example
// code", AC-17). The allow is scoped to exactly this file, like the
// narrowly scoped allows in `src/main.rs` (T-000 §5.3); do not copy it
// anywhere else.
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! ARP discovery proof of concept, without a TUI (task T-104 §3.5).
//!
//! Usage: `poc_discover <interface-name>`
//!
//! Sequence (plan ADR-005, task card §3.5): look up the interface
//! (T-101) → open the raw socket (`EPERM` → read-only mode: neighbor
//! table only, no scan) → drop capabilities and verify the drop (fail
//! closed: a failed drop exits non-zero without scanning) → read the
//! neighbor table (T-102) → run a 2-pass ARP sweep at the default
//! 100 pps (ADR-011) → print every observation (IP, MAC, source) and a
//! summary with the counters and the outcome.
//!
//! The scope guard refuses prefixes shorter than /16 — the plan's
//! absolute host ceiling of 65,534 (FR-SC-06) — to protect against
//! accidental huge sweeps.
//!
//! Exit codes: `0` success (including read-only mode and `Partial`),
//! `1` failed scan or failed capability drop, `2` usage/interface/
//! scope errors.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use osza_netmon::discovery::arp::ArpScanner;
use osza_netmon::discovery::arp::ArpWorkerHandle;
use osza_netmon::discovery::arp::DEFAULT_LISTEN_WINDOW;
use osza_netmon::discovery::arp::DEFAULT_RATE_PPS;
use osza_netmon::discovery::arp::DiscoveryEvent;
use osza_netmon::discovery::arp::LinuxArpTransport;
use osza_netmon::discovery::arp::Observation;
use osza_netmon::discovery::arp::ScanOutcome;
use osza_netmon::discovery::arp::ScanParams;
use osza_netmon::discovery::neighbor_table::NeighborSource;
use osza_netmon::discovery::neighbor_table::ProcNeighborTable;
use osza_netmon::discovery::privilege::PrivilegeError;
use osza_netmon::discovery::privilege::drop_capabilities;
use osza_netmon::discovery::privilege::open_raw_socket;
use osza_netmon::discovery::privilege::read_thread_status;
use osza_netmon::model::ipv4::ABSOLUTE_MAX_HOSTS;
use osza_netmon::model::ipv4::Ipv4Net;
use osza_netmon::net::interfaces::derive_scope;
use osza_netmon::net::interfaces::enumerate_interfaces;

/// The PoC's scan profile: ADR-011 initial-scan defaults.
const PASSES: u8 = 2;

/// How long the event loop waits for the next worker event before
/// re-checking (bounded waits everywhere, FR-DS-09).
const EVENT_POLL: Duration = Duration::from_secs(1);

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    match classify_args(&argv) {
        Action::Usage { message } => {
            eprintln!("{message}");
            eprintln!("usage: poc_discover <interface-name>");
            ExitCode::from(2)
        }
        Action::Run { interface } => run(&interface),
    }
}

/// What the command line asks for (pure, tested below).
#[derive(Debug)]
enum Action {
    /// Scan `interface`.
    Run {
        /// The interface name argument.
        interface: String,
    },
    /// Bad invocation; print the message and the usage line.
    Usage {
        /// Why the arguments were rejected.
        message: String,
    },
}

/// Classifies the full argv (program name in position 0).
///
/// Exactly one positional argument is accepted (task card §3.5: no CLI
/// parsing — that is T-402). Non-UTF-8 arguments are errors, not
/// panics (plan §7: external input is hostile).
fn classify_args(argv: &[OsString]) -> Action {
    let mut interface: Option<String> = None;
    let mut extra: Option<String> = None;
    for (position, arg) in argv.iter().enumerate() {
        if position == 0 {
            continue; // program name
        }
        match arg.to_str() {
            Some(text) => {
                if interface.is_none() {
                    interface = Some(text.to_owned());
                } else if extra.is_none() {
                    extra = Some(text.to_owned());
                }
            }
            None => {
                return Action::Usage {
                    message: "argument is not valid UTF-8".to_owned(),
                };
            }
        }
    }
    match (interface, extra) {
        (Some(interface), None) => Action::Run { interface },
        (None, _) => Action::Usage {
            message: "an interface name is required".to_owned(),
        },
        (Some(_), Some(extra)) => Action::Usage {
            message: format!("unexpected extra argument: {extra:?}"),
        },
    }
}

/// The scan/exit-code sequence once the interface name is known.
fn run(interface_name: &str) -> ExitCode {
    println!("osza-netmon PoC discovery (no TUI)");
    // 1. Interface lookup (T-101).
    let Some(interface) = enumerate_interfaces()
        .into_iter()
        .find(|info| info.name() == interface_name)
    else {
        eprintln!("no interface named {interface_name:?} exists");
        return ExitCode::from(2);
    };
    let Some(our_mac) = interface.mac() else {
        eprintln!(
            "interface {interface_name:?} has no usable MAC address; active discovery is not possible"
        );
        return ExitCode::from(2);
    };
    let Some(our_ip) = interface.ipv4() else {
        eprintln!(
            "interface {interface_name:?} has no IPv4 address; active discovery is not possible"
        );
        return ExitCode::from(2);
    };
    let Some(scope) = derive_scope(&interface) else {
        eprintln!("interface {interface_name:?} has no derivable IPv4 scope");
        return ExitCode::from(2);
    };
    // Scope guard (task card §3.5): refuse prefixes shorter than /16 —
    // the FR-SC-06 absolute ceiling of 65,534 hosts.
    if let Err(error) = scope.host_range_capped(ABSOLUTE_MAX_HOSTS) {
        eprintln!(
            "scope {}/{} is too large for this example: {error}",
            scope.network(),
            scope.prefix_len()
        );
        return ExitCode::from(2);
    }
    println!(
        "interface: {} (mac {our_mac}, ip {our_ip}/{}, scope {}/{})",
        interface.name(),
        interface
            .prefix_len()
            .map_or_else(|| "?".to_owned(), |prefix| prefix.to_string()),
        scope.network(),
        scope.prefix_len()
    );

    // 2. Raw socket (ADR-005 step 2) — read-only fallback on EPERM.
    let socket = match open_raw_socket(interface_name) {
        Ok(socket) => Some(socket),
        Err(PrivilegeError::PermissionDenied) => {
            eprintln!(
                "no CAP_NET_RAW: starting in read-only mode (neighbor table only); \
                 grant it with: setcap cap_net_raw+ep <binary>"
            );
            None
        }
        Err(error) => {
            eprintln!("opening the raw socket failed: {error}");
            return ExitCode::from(2);
        }
    };

    // 3. Capability drop (ADR-005 step 3) — in both modes, fail closed.
    if let Err(error) = drop_capabilities() {
        eprintln!("refusing to continue: {error}");
        return ExitCode::from(1);
    }
    match read_thread_status() {
        Ok(status) => println!("privileges after drop: {status}"),
        Err(error) => {
            eprintln!("refusing to continue: the drop could not be verified: {error}");
            return ExitCode::from(1);
        }
    }

    // 4. Neighbor table (T-102) — same cycle position as FR-DS-01.
    let neighbors = read_neighbors(&scope, interface_name);

    // 5. Active sweep — or the read-only stop.
    let Some(socket) = socket else {
        println!("mode: read-only (no ARP sweep)");
        print_observations(&neighbors);
        println!(
            "summary: read-only cycle, {} neighbor-table observation(s)",
            neighbors.len()
        );
        return ExitCode::SUCCESS;
    };

    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), scope, our_mac, our_ip);
    let (worker, events) = ArpWorkerHandle::spawn(scanner);
    println!(
        "scan: {PASSES} passes at {} pps, listen window {:?}",
        DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW
    );
    print_observations(&neighbors);

    if let Err(error) = worker.start_scan(ScanParams {
        passes: PASSES,
        rate_pps: DEFAULT_RATE_PPS,
        listen_window: DEFAULT_LISTEN_WINDOW,
    }) {
        eprintln!("starting the scan failed: {error}");
        return ExitCode::from(1);
    }

    // 6. Drain events until the summary (bounded waits, FR-DS-09).
    let exit = loop {
        match events.recv_timeout(EVENT_POLL) {
            Ok(DiscoveryEvent::Observations(items)) => {
                print_observations(&items);
            }
            Ok(DiscoveryEvent::ScanFinished(summary)) => {
                println!("summary: outcome={}", summary.outcome);
                println!("summary: {}", summary.counters);
                println!("summary: replies: {}", summary.counters.replies);
                println!(
                    "summary: elapsed {:?} ({} neighbor observation(s) printed before the sweep)",
                    summary.elapsed,
                    neighbors.len()
                );
                break ExitCode::from(exit_code_for(&summary.outcome));
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("the discovery worker stopped before the scan finished");
                break ExitCode::from(1);
            }
        }
    };
    worker.shutdown();
    exit
}

/// Reads and prints the neighbor table for the scope (FR-DS-01 position:
/// before the sweep). A failed read keeps the ARP-only path alive
/// (FR-ER: "neighbor table unreadable → continue with ARP only").
fn read_neighbors(scope: &Ipv4Net, interface_name: &str) -> Vec<Observation> {
    match ProcNeighborTable::new().read_neighbors(scope, interface_name) {
        Ok(entries) => {
            println!("neighbor table: {} entrie(s)", entries.len());
            entries.iter().map(Observation::from_neighbor).collect()
        }
        Err(error) => {
            eprintln!(
                "the neighbor table could not be read ({error}); continuing with the ARP sweep only"
            );
            Vec::new()
        }
    }
}

/// Prints observations as `IP MAC (source)` lines (task card §3.5).
fn print_observations(observations: &[Observation]) {
    for observation in observations {
        println!("{observation}");
    }
}

/// The example's exit code for a scan outcome: `Failed` is a real
/// failure; everything else completed its cycle honestly.
fn exit_code_for(outcome: &ScanOutcome) -> u8 {
    match outcome {
        ScanOutcome::Failed { .. } => 1,
        ScanOutcome::Complete | ScanOutcome::Partial | ScanOutcome::Cancelled => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn argv(items: &[&str]) -> Vec<OsString> {
        std::iter::once(OsString::from("poc_discover"))
            .chain(items.iter().map(OsString::from))
            .collect()
    }

    #[test]
    fn one_positional_argument_runs() {
        match classify_args(&argv(&["eth0"])) {
            Action::Run { interface } => assert_eq!(interface, "eth0"),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_is_a_usage_error() {
        match classify_args(&argv(&[])) {
            Action::Usage { message } => assert!(message.contains("interface")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn extra_arguments_are_rejected() {
        match classify_args(&argv(&["eth0", "--rate", "200"])) {
            Action::Usage { message } => assert!(message.contains("extra")),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn flags_are_not_parsed_here() {
        // T-402 owns flags; this example takes exactly one positional
        // argument, whatever it looks like.
        assert!(matches!(
            classify_args(&argv(&["--version"])),
            Action::Run { .. }
        ));
        assert!(matches!(classify_args(&argv(&["-h"])), Action::Run { .. }));
    }

    #[test]
    fn exit_codes_follow_the_outcome() {
        assert_eq!(exit_code_for(&ScanOutcome::Complete), 0);
        assert_eq!(exit_code_for(&ScanOutcome::Partial), 0);
        assert_eq!(exit_code_for(&ScanOutcome::Cancelled), 0);
        assert_eq!(
            exit_code_for(&ScanOutcome::Failed {
                reason: "interface lost".to_owned()
            }),
            1
        );
    }

    #[test]
    fn the_scan_profile_is_the_adr_011_default() {
        assert_eq!(PASSES, 2);
        assert_eq!(DEFAULT_RATE_PPS, 100);
        assert_eq!(DEFAULT_LISTEN_WINDOW, Duration::from_millis(1500));
        assert_eq!(ABSOLUTE_MAX_HOSTS, 65_534);
    }

    #[test]
    fn scope_guard_uses_the_plan_ceiling() {
        // /16 is the largest scope the plan allows (FR-SC-06) — and /15
        // must be refused by the guard in `run`; the math is exercised
        // through Ipv4Net itself here.
        let ok = Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 16).expect("valid network");
        assert!(ok.host_range_capped(ABSOLUTE_MAX_HOSTS).is_ok());
        let too_big = Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 15).expect("valid network");
        assert!(too_big.host_range_capped(ABSOLUTE_MAX_HOSTS).is_err());
    }
}
