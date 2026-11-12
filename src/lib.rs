// SPDX-License-Identifier: GPL-3.0-only

//! Library crate for `osza-netmon`.
//!
//! Task T-000 (repository bootstrap) puts only the application identity
//! constants and the command-line argument classification here. Product
//! behavior arrives with the later tasks in `plan.md` §13.
//!
//! Task T-002 adds the domain model under [`model`]: the boundary-validated
//! core primitives of `plan.md` §5.2–5.3.
//!
//! Task T-101 adds the [`net`] layer: interface discovery and scope
//! derivation (`net::interfaces`, `plan.md` §6.2 FR-SC-01…05) — the first
//! piece of the Phase 1 proof of concept, still without any network I/O.
//!
//! Task T-102 adds the [`discovery`] layer: the kernel neighbor-table
//! reader (`discovery::neighbor_table`, `plan.md` §6.3 FR-DS-01/FR-DS-02,
//! SR-10) — the first discovery data source, reading `/proc/net/arp`
//! without any network I/O.
//!
//! Task T-103 adds the ARP wire format to [`discovery`]
//! (`discovery::arp`, `plan.md` §6.3 FR-DS-03/FR-DS-06, §7.2 SR-02/
//! SR-05): the 42-byte Ethernet+ARP request builder and the total,
//! solicited-only reply validator — still pure byte manipulation with
//! no socket I/O; the transport is T-104, behind the pending ADR-009.
//!
//! Task T-201 adds the [`registry`]: the in-memory device registry —
//! the single source of truth for the application state (`plan.md`
//! §6.4 FR-RG-01…07, ADR-007 aging, ADR-008 identity/shared-MAC).
//!
//! Task T-202 adds the [`enrichment`] layer: the embedded vendor database
//! (`enrichment::vendor`, `plan.md` §6.5 FR-EN-01/FR-EN-02) — an offline,
//! IEEE-OUI-derived lookup with longest-prefix match (36 → 28 → 24 bits),
//! locally-administered MACs answered before any table access, names
//! sanitized through `DisplayText` at load time (FR-EN-04), and the
//! database date exposed for the help screen. The maintainer CLI
//! `examples/gen_oui.rs` regenerates the committed image under
//! `data/oui/`.
//!
//! Task T-203 completes the enrichment layer's second half
//! (`enrichment::{hostname,dns,worker}`, `plan.md` §6.5 FR-EN-03/FR-EN-04,
//! §4 ADR-003, ADR-015): the ADR-003 resolver selection (resolv.conf and
//! the systemd-resolved fallback under the subnet rule), the hand-rolled
//! DNS PTR client behind the `NameResolver` trait (ADR-015 option (a):
//! total, bounded-response parsing, one datagram per attempt), and the
//! std-thread worker with bounded queues, per-IP deduplication, one
//! retry, 5-minute failure backoff and a 250 ms shutdown bound. The
//! application core (T-205) wires the worker's events into the registry.
//!
//! Task T-204 adds the discovery orchestration layer
//! (`discovery::{scheduler,worker}`, `plan.md` §6.3 FR-DS-08…12/FR-DS-14,
//! §8.3/§8.5): the pure FR-DS-12 scheduler state machine (finish-anchored
//! cadence, failure backoff, auto-stop after three consecutive failures,
//! manual-refresh rules, and the ADR-011 pass-policy constants — the
//! authoritative home for T-205/T-402) and the orchestrator worker thread
//! that executes whole §8.5 cycles through the T-104 arp worker
//! (neighbor read → paced ARP sweep → listen window → neighbor read →
//! outcome), stamping every event with a `model::ScanId`, one cycle at a
//! time, over bounded channels, with 250 ms end-to-end cancellation and
//! a socket-free read-only mode (FR-DS-14). The `ScanId` domain type
//! moved from `registry::observation` into [`model`] (re-exported by the
//! registry unchanged), and `discovery::arp::transport` now maps
//! pnet_datalink's opaque fatal poll error to the honest
//! interface-lost classification (T-105 follow-up 3).

//! Task T-205 adds the [`app`] layer: the headless application core
//! (plan §8.1, §8.3–8.5) — the `AppState` screen machine (Notice →
//! Scope → Dashboard ⇄ Details with the help and too-small overlays),
//! the terminal-agnostic event union feeding one bounded queue, the
//! pure `update(state, event, clock) -> effects` with the §10.3 key
//! map and the §5.9 enrichment rules, and the runtime that wires the
//! reviewed T-203/T-204 workers behind the ADR-012 single-commander
//! contract (bounded channels, flag-checked waits, a bounded shutdown
//! sequence). Phase 3 (T-301…) only attaches a terminal: scenario
//! scripts drive the whole flow headlessly, and the NFR-03 benchmark
//! proves no loop iteration blocks > 100 ms at 4,096 devices.

//! Task T-301 adds the [`ui`] layer: the terminal front end (plan
//! §8.1, §8.3, §8.4, §8.8) — the terminal lifecycle guard (raw mode,
//! alternate screen, explicit mouse capture, restore on every exit
//! path), the one dedicated input thread translating crossterm events
//! onto the app's `Key`/`AppEvent` vocabulary through the §10.3 map,
//! the SIGTERM/SIGHUP bridge quitting through the app's normal quit
//! path (ADR-018), the §8.4 loop with dirty-flag rendering and the
//! 1 Hz tick, and the binary assembly wiring the reviewed workers
//! under the ADR-005 privilege order. The screens are deliberately
//! placeholder (T-302/T-303/T-304 replace them wholesale); the
//! pty-test evidence (terminal restored after normal exit, error
//! exit, forced panic, SIGTERM, SIGHUP; resize; the end-to-end
//! smoke; idle CPU) lives in the `tests/pty` harness.

pub mod app;
pub mod discovery;
pub mod enrichment;
pub mod model;
pub mod net;
pub mod registry;
pub mod ui;

use std::ffi::OsString;

/// Machine name of the application (binary name, CLI prefix).
///
/// Per ADR-001 this constant and [`DISPLAY_NAME`] are the only places in
/// code where the application name is spelled out; every other occurrence
/// must reference one of them.
pub const APP_NAME: &str = "osza-netmon";

/// Human-readable display name used on UI surfaces.
///
/// Per ADR-001 this is the second of the two single sources for the name.
pub const DISPLAY_NAME: &str = "osza Network Monitor";

/// Application version, resolved from the package version at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Errors that can occur while classifying command-line arguments.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgError {
    /// An argument was not valid UTF-8.
    #[error("argument is not valid UTF-8")]
    InvalidUtf8,
    /// An argument was not recognized.
    #[error("unrecognized argument: {0}")]
    Unrecognized(String),
}

/// What the program should do after classifying the command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliOutcome {
    /// Print `<APP_NAME> <VERSION>` to stdout and exit with code 0.
    PrintVersion,
    /// Print the short usage text to stdout and exit with code 0.
    PrintHelp,
    /// Print a one-line error to stderr and exit with code 2.
    Error(ArgError),
}

/// Classify the process arguments.
///
/// `args` is the full argument vector as delivered by
/// [`std::env::args_os`], including the program name in the first
/// position; that first element is ignored. An argument that is not valid
/// UTF-8 classifies as an error instead of panicking (plan §7: external
/// input is hostile and must never panic the program).
///
/// T-000 interprets exactly one argument, the first one; the full flag
/// parser arrives with task T-402. With no argument at all the outcome is
/// [`CliOutcome::PrintHelp`]: T-000 adds no product behavior, and the
/// interactive default that will start the TUI arrives with a later task.
pub fn classify_args<I>(args: I) -> CliOutcome
where
    I: IntoIterator,
    I::Item: Into<OsString>,
{
    let mut args = args.into_iter();
    // argv[0] is the program name, not an argument to interpret.
    let _program_name = args.next();
    let first: Option<OsString> = args.next().map(Into::into);
    let Some(arg) = first else {
        return CliOutcome::PrintHelp;
    };
    let Some(text) = arg.to_str() else {
        return CliOutcome::Error(ArgError::InvalidUtf8);
    };
    match text {
        "--version" | "-V" => CliOutcome::PrintVersion,
        "--help" | "-h" => CliOutcome::PrintHelp,
        other => CliOutcome::Error(ArgError::Unrecognized(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flags_are_recognized() {
        assert_eq!(
            classify_args(["osza-netmon", "--version"]),
            CliOutcome::PrintVersion
        );
        assert_eq!(
            classify_args(["osza-netmon", "-V"]),
            CliOutcome::PrintVersion
        );
    }

    #[test]
    fn help_flags_are_recognized() {
        assert_eq!(
            classify_args(["osza-netmon", "--help"]),
            CliOutcome::PrintHelp
        );
        assert_eq!(classify_args(["osza-netmon", "-h"]), CliOutcome::PrintHelp);
    }

    #[test]
    fn no_arguments_prints_help() {
        assert_eq!(classify_args(["osza-netmon"]), CliOutcome::PrintHelp);
    }

    #[test]
    fn program_name_is_ignored_even_if_it_looks_like_a_flag() {
        // A single element is the program name, not an argument.
        assert_eq!(classify_args(["--version"]), CliOutcome::PrintHelp);
    }

    #[test]
    fn only_the_first_argument_is_interpreted() {
        // T-000 reads exactly one argument; the full parser is T-402.
        assert_eq!(
            classify_args(["osza-netmon", "--version", "extra"]),
            CliOutcome::PrintVersion
        );
    }

    #[test]
    fn unknown_flag_is_an_error() {
        let outcome = classify_args(["osza-netmon", "--bogus"]);
        assert_eq!(
            outcome,
            CliOutcome::Error(ArgError::Unrecognized("--bogus".to_owned()))
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_argument_is_an_error_not_a_panic() {
        use std::os::unix::ffi::OsStringExt;
        let argv = [
            OsString::from("osza-netmon"),
            OsString::from_vec(vec![0xff, 0xfe, 0xfd]),
        ];
        assert_eq!(
            classify_args(argv),
            CliOutcome::Error(ArgError::InvalidUtf8)
        );
    }
}
