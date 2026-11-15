// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// A test binary (`harness = false` — the netns target's precedent):
// compiled without `--cfg test`, so the crate-wide clippy denies fire
// on the listener's assertions; the relief is scoped to the pty
// harness files exactly as in tests/netns/main.rs.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! The netns egress listener (task T-302 §5.7.6 — the PQ-3 acceptance
//! evidence): one process per watched interface, re-exec'd from the
//! pty harness inside the scenario's network namespace.
//!
//! The listener binds one raw socket to its interface (the crate's
//! own [`open_raw_socket`] + [`LinuxArpTransport`] — the reviewed
//! T-104 path, no new code) and logs every frame it receives, one
//! line per frame, until the deadline (the harness's safety net; the
//! scenario also kills the listener by deadline expiry through the
//! same bound). It **sends nothing** — a listener that probed would
//! corrupt the egress evidence.
//!
//! # Log format
//!
//! ```text
//! ready
//! et=0x0806 op=1 tip=203.0.113.42
//! et=0x0800
//! ```
//!
//! The scenario parses `et=0x0806 op=1 tip=<address>` lines (ARP
//! requests and their targets); every other frame is logged with its
//! EtherType for diagnostics. The parser is total (bounded reads,
//! short frames logged as `short`, never a panic — P7).
//!
//! # §2.3 discipline
//!
//! The listener is passive by construction: one raw socket, `recv`
//! only. It runs inside the scenario's isolated `unshare`d namespace
//! over synthetic RFC 5737 addresses (§14.3.7) — never a real
//! network.

use std::io::Write;
use std::time::Duration;
use std::time::Instant;

use osza_netmon::discovery::LinuxArpTransport;
use osza_netmon::discovery::arp::ArpTransport;
use osza_netmon::discovery::privilege::open_raw_socket;

/// The receive slice: every wait is deadline-checked at this
/// granularity.
const SLICE: Duration = Duration::from_millis(100);

/// Runs the listener: bind, announce readiness, log frames until the
/// deadline. Errors are the harness's exit-1 signals (the log stays
/// behind for diagnostics).
///
/// # Errors
/// The socket could not be opened (the interface does not exist in
/// this namespace, or the privileges are missing), or the log file
/// could not be written.
pub fn run(interface: &str, log_path: &str, seconds: u64) -> Result<(), String> {
    let socket = open_raw_socket(interface).map_err(|error| format!("open: {error}"))?;
    let transport = LinuxArpTransport::new(socket);
    let mut log = std::fs::File::create(log_path).map_err(|error| format!("log: {error}"))?;
    // The pid file: the scenario kills the listener once its evidence
    // is collected — a killed listener closes its pty-descriptor and
    // its socket; a leaked one holds the scenario's pty open (script
    // waits for the master's EOF) until the deadline.
    std::fs::write(format!("{log_path}.pid"), std::process::id().to_string())
        .map_err(|error| format!("pid: {error}"))?;
    writeln!(log, "ready").map_err(|error| format!("log: {error}"))?;
    log.flush().ok();

    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        match transport.recv(SLICE) {
            Ok(Some(frame)) => {
                let line = describe(&frame);
                writeln!(log, "{line}").map_err(|error| format!("log: {error}"))?;
                log.flush().ok();
            }
            Ok(None) => continue,
            Err(_) => continue, // a failing stream is logged by absence
        }
    }
    Ok(())
}

/// One frame's log line (total: any byte length, any content).
fn describe(frame: &[u8]) -> String {
    if frame.len() < 14 {
        return format!("et=short len={}", frame.len());
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != 0x0806 {
        return format!("et={ether_type:#06x}");
    }
    // ARP: op at 20..22, target protocol address at 38..42 (Ethernet
    // header 14 + ARP fixed head 8 + sha 6 + spa 4 + tha 6).
    if frame.len() < 42 {
        return format!("et={ether_type:#06x} short len={}", frame.len());
    }
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    let tip = std::net::Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
    format!("et={ether_type:#06x} op={op} tip={tip}")
}
