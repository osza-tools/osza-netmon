// SPDX-License-Identifier: GPL-3.0-only

//! The S7 privilege probes (task T-106, task card §5.9; plan SR-06,
//! ADR-005).
//!
//! Both probes re-exec this same test binary (the responder's option (a)
//! pattern) so the *test process* never drops capabilities it still
//! needs for later labs:
//!
//! * `cap-drop` — removes `CAP_NET_RAW` (via the approved `caps` crate),
//!   then verifies the typed `EPERM` path of [`open_raw_socket`] and the
//!   read-only neighbor path (S7(a)):
//!   the entries the lab taught this namespace must come back exactly.
//! * `drop-and-scan` — privileged start (open first), full
//!   [`drop_capabilities`], verification that `CapEff == CapPrm == 0`,
//!   then a complete scan on the already-open socket (S7(b)): the
//!   ADR-005 ordering, live.
//!
//! Both probes print `key=value` lines the parent parses (total,
//! size-bounded parsing on the parent side — AGENTS.md rule 4).

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::process::exit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use osza_netmon::discovery::arp::ArpScanner;
use osza_netmon::discovery::arp::LinuxArpTransport;
use osza_netmon::discovery::arp::ScanOutcome;
use osza_netmon::discovery::neighbor_table::NeighborSource;
use osza_netmon::discovery::neighbor_table::ProcNeighborTable;
use osza_netmon::discovery::privilege::PrivilegeError;
use osza_netmon::discovery::privilege::drop_capabilities;
use osza_netmon::discovery::privilege::open_raw_socket;
use osza_netmon::discovery::privilege::read_thread_status;
use osza_netmon::model::MacAddr;
use osza_netmon::model::ipv4::Ipv4Net;

/// The scan profile of the probes (ADR-011 defaults, like the example).
const PASSES: u8 = 2;

/// Entry point of the `--probe` subcommand (`args` follow `--probe`).
pub fn main(args: &[std::ffi::OsString]) -> ExitCode {
    let mut mode: Option<String> = None;
    let mut flags: Vec<String> = Vec::new();
    for arg in args {
        flags.push(arg.to_string_lossy().into_owned());
    }
    let mut iter = flags.iter();
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            // Every flag takes one value; only --mode is interpreted
            // here, the rest are read by the mode-specific helpers via
            // `value_of`.
            "--mode" => {
                mode = iter.next().cloned();
            }
            "--iface" | "--scope" | "--our-mac" | "--our-ip" => {
                let _ = iter.next();
            }
            other => {
                eprintln!("probe: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    match mode.as_deref() {
        Some("cap-drop") => cap_drop_probe(&flags),
        Some("drop-and-scan") => drop_and_scan_probe(&flags),
        other => {
            eprintln!("probe: --mode cap-drop|drop-and-scan required (got {other:?})");
            ExitCode::from(2)
        }
    }
}

/// S7(a): without `CAP_NET_RAW` — the typed `EPERM` error plus the exact
/// read-only neighbor entries.
fn cap_drop_probe(args: &[String]) -> ExitCode {
    let iface = value_of(args, "--iface").unwrap_or_else(|| "v-s7a".to_owned());
    let scope = parse_scope(args);

    // Remove CAP_NET_RAW from every set (bounding first — narrowing it
    // needs CAP_SETPCAP, which we still hold; ambient while it can still
    // be a member; then inheritable/effective/permitted).
    let cap = caps::Capability::CAP_NET_RAW;
    let steps = [
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Inheritable,
        caps::CapSet::Effective,
        caps::CapSet::Permitted,
    ];
    for step in steps {
        if let Err(err) = caps::drop(None, step, cap) {
            println!("ERROR step={step:?} {err}");
            return ExitCode::from(1);
        }
    }
    match read_thread_status() {
        Ok(status) => println!("STATUS {status}"),
        Err(err) => {
            println!("ERROR step=status {err}");
            return ExitCode::from(1);
        }
    }

    // The typed EPERM path (ADR-005 step 4: read-only mode signal).
    match open_raw_socket(&iface) {
        Err(PrivilegeError::PermissionDenied) => println!("OPEN EPERM"),
        Err(other) => {
            println!("ERROR step=open unexpected={other}");
            return ExitCode::from(1);
        }
        Ok(_) => {
            println!("ERROR step=open unexpected=success");
            return ExitCode::from(1);
        }
    }

    // The read-only path: exactly the lab-learned entries.
    match ProcNeighborTable::new().read_neighbors(&scope, &iface) {
        Ok(entries) => {
            println!("NEIGHBOR_COUNT {}", entries.len());
            for entry in &entries {
                println!("NEIGHBOR {} {} {}", entry.ip(), entry.mac(), entry.device());
            }
        }
        Err(err) => {
            println!("ERROR step=neighbors {err}");
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}

/// S7(b): privileged start → capability drop → verified zeros → the
/// scan still completes on the already-open socket.
fn drop_and_scan_probe(args: &[String]) -> ExitCode {
    let iface = value_of(args, "--iface").unwrap_or_else(|| "v-s7a".to_owned());
    let scope = parse_scope(args);
    let our_mac = parse_mac(args, "--our-mac");
    let our_ip = parse_ip(args, "--our-ip");

    // ADR-005 step 2: open BEFORE the drop.
    let socket = match open_raw_socket(&iface) {
        Ok(socket) => socket,
        Err(err) => {
            println!("ERROR step=open {err}");
            return ExitCode::from(1);
        }
    };

    // ADR-005 step 3: the drop, fail closed.
    if let Err(err) = drop_capabilities() {
        println!("ERROR step=drop {err}");
        return ExitCode::from(1);
    }

    // SR-06: verify — the parent asserts the printed CapEff/CapPrm.
    match read_thread_status() {
        Ok(status) => println!("STATUS {status}"),
        Err(err) => {
            println!("ERROR step=status {err}");
            return ExitCode::from(1);
        }
    }

    // The scan on the already-open socket (ADR-005 step 4: nothing after
    // the drop needs a capability).
    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), scope, our_mac, our_ip);
    let result = scanner.scan(
        PASSES,
        osza_netmon::discovery::arp::DEFAULT_RATE_PPS,
        osza_netmon::discovery::arp::DEFAULT_LISTEN_WINDOW,
        Arc::new(AtomicBool::new(false)),
    );
    println!("OUTCOME {}", result.outcome);
    println!("COUNTERS {}", result.counters);
    for observation in &result.observations {
        println!("OBS {} {}", observation.ip, observation.mac);
    }
    match result.outcome {
        ScanOutcome::Complete => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    }
}

/// Reads `--key value` from the flat flag list.
fn value_of(args: &[String], key: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        if flag == key {
            return iter.next().cloned();
        }
    }
    None
}

fn parse_scope(args: &[String]) -> Ipv4Net {
    let raw = value_of(args, "--scope").unwrap_or_else(|| {
        eprintln!("probe: --scope <a.b.c.d/prefix> is required");
        exit(2);
    });
    match crate::lab::parse_cidr(&raw) {
        Ok(scope) => scope,
        Err(err) => {
            eprintln!("probe: {err}");
            exit(2);
        }
    }
}

fn parse_mac(args: &[String], key: &str) -> MacAddr {
    let raw = value_of(args, key).unwrap_or_else(|| {
        eprintln!("probe: {key} is required");
        exit(2);
    });
    match raw.parse::<MacAddr>() {
        Ok(mac) => mac,
        Err(_) => {
            eprintln!("probe: bad {key} {raw:?}");
            exit(2);
        }
    }
}

fn parse_ip(args: &[String], key: &str) -> Ipv4Addr {
    let raw = value_of(args, key).unwrap_or_else(|| {
        eprintln!("probe: {key} is required");
        exit(2);
    });
    match raw.parse::<Ipv4Addr>() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("probe: bad {key} {raw:?}");
            exit(2);
        }
    }
}
