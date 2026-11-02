// SPDX-License-Identifier: GPL-3.0-only

//! The scenario tests S1–S7 of plan §11.2 (task T-106, task card §5).
//!
//! Every scenario builds a fresh lab (a veth pair, the device-side
//! namespace and its responder), drives the **real library in-process**
//! — the scanner (and for S1 the worker) over the production
//! `LinuxArpTransport` — and asserts on the results plus the responder's
//! receive log.
//!
//! Address plan (all RFC 5737 documentation ranges, plan §14.3 rule 7):
//!
//! ```text
//! | Scenario | Subnet             | Kernel-answered   | Helper-answered        |
//! |----------|--------------------|-------------------|------------------------|
//! | S1       | 192.0.2.0/24       | 10 (.2-.11)       | 10 (.12-.21)           |
//! | S2       | 198.51.100.0/24    | 250 (.2-.251)     | none (silent logger)   |
//! | S3       | 203.0.113.0/28     | none              | none (silent)          |
//! | S4       | 203.0.113.16/28    | none              | 12 IPs -> one MAC      |
//! | S5a-e    | 203.0.113.32../28  | none              | 2-13 + hostile mode    |
//! | S6       | 203.0.113.112/28   | 2                 | 2                      |
//! | S7       | 203.0.113.128/28   | 2                 | none (silent logger)   |
//! ```
//!
//! The runner in `main.rs` executes scenarios strictly sequentially with
//! a per-scenario watchdog, and interface names carry the scenario tag,
//! so there is no cross-test interference either way (task card §5.2).

use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use std::time::Instant;

use osza_netmon::discovery::arp::ArpScanner;
use osza_netmon::discovery::arp::ArpWorkerHandle;
use osza_netmon::discovery::arp::DEFAULT_LISTEN_WINDOW;
use osza_netmon::discovery::arp::DEFAULT_RATE_PPS;
use osza_netmon::discovery::arp::DiscoveryEvent;
use osza_netmon::discovery::arp::InvalidReply;
use osza_netmon::discovery::arp::LinuxArpTransport;
use osza_netmon::discovery::arp::Observation;
use osza_netmon::discovery::arp::ScanOutcome;
use osza_netmon::discovery::arp::ScanParams;
use osza_netmon::discovery::arp::ScanResult;
use osza_netmon::discovery::neighbor_table::NeighborSource;
use osza_netmon::discovery::neighbor_table::ProcNeighborTable;
use osza_netmon::discovery::privilege::open_raw_socket;
use osza_netmon::model::MacAddr;
use osza_netmon::model::ipv4::Ipv4Net;

use crate::config::Answer;
use crate::config::Hostile;
use crate::config::Impairment;
use crate::lab::Lab;
use crate::lab::LabSpec;
use crate::lab::parse_cidr;
use crate::rng::seeds;

/// The margin over the configured rate accepted in the sliding-window
/// check (S2/S6): covers the responder's poll-scheduling stamp
/// granularity at window boundaries, nothing more (documented in the
/// execution report).
const RATE_WINDOW_MARGIN: u64 = 10;

/// The smallest acceptable stamped gap between two scanner requests —
/// the sender paces at 10 ms; poll wake-up on arrival keeps stamps
/// within a few ms of the wire time, so a stamped gap below this means
/// a real burst.
const MIN_REQUEST_GAP_MS: u64 = 5;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Parses an IPv4 literal (scenario constants — panics are fine here).
fn ip(text: &str) -> Ipv4Addr {
    text.parse()
        .unwrap_or_else(|_| panic!("bad IP literal {text:?}"))
}

fn cidr(text: &str) -> Ipv4Net {
    parse_cidr(text).unwrap_or_else(|err| panic!("bad CIDR {text:?}: {err}"))
}

/// `count` addresses starting at `start` (ascending host bytes; the
/// scenario constants never cross an octet boundary).
fn ips_from(start: &str, count: u8) -> Vec<Ipv4Addr> {
    let base = ip(start);
    let mut out = Vec::with_capacity(usize::from(count));
    for offset in 0..count {
        let octets = base.octets();
        out.push(Ipv4Addr::new(
            octets[0],
            octets[1],
            octets[2],
            octets[3] + offset,
        ));
    }
    out
}

/// The answer-table entries for `ips`, each with its own synthetic MAC
/// (`02:00:00:00:00:<host byte>`).
fn distinct_mac_answers(ips: &[Ipv4Addr]) -> Vec<Answer> {
    ips.iter()
        .map(|addr| Answer {
            ip: *addr,
            mac: MacAddr::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, addr.octets()[3]])
                .unwrap_or_else(|_| panic!("bad synthetic MAC for {addr}")),
        })
        .collect()
}

/// The target set of a lab subnet: every address except the network
/// address, the broadcast address and the scanner's own address.
fn target_set(scope: &Ipv4Net, our_ip: Ipv4Addr) -> std::collections::BTreeSet<Ipv4Addr> {
    let network = u32::from(scope.network());
    let broadcast = u32::from(scope.broadcast());
    (network + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|addr| *addr != our_ip)
        .collect()
}

/// Runs one scan on the lab through the production transport and the
/// scanner API (collecting variant).
fn scan_lab(lab: &Lab, passes: u8, rate_pps: u32, listen_window: Duration) -> ScanResult {
    let socket = open_raw_socket(&lab.host_if)
        .unwrap_or_else(|err| panic!("{}: opening the raw socket: {err}", lab.host_if));
    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), lab.scope, lab.our_mac, lab.our_ip);
    scanner.scan(
        passes,
        rate_pps,
        listen_window,
        Arc::new(AtomicBool::new(false)),
    )
}

/// The distinct `(ip, mac)` pairs of a scan's observations.
fn distinct_pairs(observations: &[Observation]) -> std::collections::BTreeSet<(Ipv4Addr, String)> {
    observations
        .iter()
        .map(|observation| (observation.ip, observation.mac.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// S1 — 20 responding addresses, all discovered, none duplicated
// ---------------------------------------------------------------------------

pub fn s1_mixed_responders() {
    let spec = LabSpec {
        tag: "s1",
        subnet: cidr("192.0.2.0/24"),
        kernel_addrs: ips_from("192.0.2.2", 10),
        answers: distinct_mac_answers(&ips_from("192.0.2.12", 10)),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::None,
    };
    let expected: std::collections::BTreeSet<Ipv4Addr> =
        ips_from("192.0.2.2", 20).into_iter().collect();
    let lab = Lab::build(&spec);

    // S1 drives the *worker* (task card §3: "scanner/worker"): the
    // event stream is the live exercise of T-104's batching path.
    let socket = open_raw_socket(&lab.host_if)
        .unwrap_or_else(|err| panic!("S1: opening the raw socket: {err}"));
    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), lab.scope, lab.our_mac, lab.our_ip);
    let (worker, events) = ArpWorkerHandle::spawn(scanner);
    worker
        .start_scan(ScanParams {
            passes: 2,
            rate_pps: DEFAULT_RATE_PPS,
            listen_window: DEFAULT_LISTEN_WINDOW,
        })
        .unwrap_or_else(|err| panic!("S1: starting the scan: {err}"));

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut observations: Vec<Observation> = Vec::new();
    let summary = loop {
        if Instant::now() > deadline {
            panic!("S1: the worker never finished the scan (60 s deadline)");
        }
        match events.recv_timeout(Duration::from_secs(1)) {
            Ok(DiscoveryEvent::Observations(items)) => observations.extend(items),
            Ok(DiscoveryEvent::ScanFinished(summary)) => break *summary,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("S1: the discovery worker stopped before the scan finished")
            }
        }
    };
    worker.shutdown();

    // All 20 discovered — the IP set matches exactly…
    let seen: std::collections::BTreeSet<Ipv4Addr> = observations.iter().map(|o| o.ip).collect();
    assert_eq!(
        seen, expected,
        "S1: discovered set must be the 20 lab devices"
    );
    // …zero duplicates…
    assert_eq!(summary.counters.duplicates, 0, "S1: duplicates");
    // …zero extras (nothing outside the 20)…
    assert_eq!(
        observations.len(),
        20,
        "S1: exactly 20 observations (none extra, none merged)"
    );
    // …every helper device with its own synthetic MAC…
    for answer in &spec.answers {
        let observation = observations
            .iter()
            .find(|o| o.ip == answer.ip)
            .unwrap_or_else(|| panic!("S1: {} missing", answer.ip));
        assert_eq!(observation.mac, answer.mac, "S1: MAC of {}", answer.ip);
    }
    // …and the 10 kernel addresses behind exactly one shared MAC (the
    // device-side veth's own), distinct from ours. The set equality
    // above already confines every observation to 192.0.2.0/24, so the
    // last octet identifies the kernel half.
    let kernel_macs: std::collections::BTreeSet<String> = observations
        .iter()
        .filter(|o| (2..=11).contains(&o.ip.octets()[3]))
        .map(|o| o.mac.to_string())
        .collect();
    assert_eq!(kernel_macs.len(), 1, "S1: kernel devices share one MAC");
    assert!(
        kernel_macs
            .iter()
            .all(|mac| mac != &lab.our_mac.to_string()),
        "S1: the shared MAC is the device side's, not ours"
    );
    // Outcome and counters.
    assert_eq!(summary.outcome, ScanOutcome::Complete, "S1: outcome");
    assert_eq!(summary.counters.replies_accepted, 20, "S1: accepted");
    assert_eq!(summary.counters.replies_rejected, 0, "S1: rejected");
    println!(
        "S1: 20/20 discovered (10 kernel + 10 helper), 0 duplicates, 0 extras, \
         outcome Complete, elapsed {:.3}s",
        summary.elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// S2 — 250 addresses on a /24 within the NFR-02 budget
// ---------------------------------------------------------------------------

pub fn s2_full_sweep_budget() {
    let spec = LabSpec {
        tag: "s2",
        subnet: cidr("198.51.100.0/24"),
        kernel_addrs: ips_from("198.51.100.2", 250),
        answers: Vec::new(), // silent helper: logs requests, answers none
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::None,
    };
    let expected: std::collections::BTreeSet<Ipv4Addr> =
        ips_from("198.51.100.2", 250).into_iter().collect();
    let lab = Lab::build(&spec);

    let started = Instant::now();
    let result = scan_lab(&lab, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    let total = started.elapsed();

    // NFR-02: full active cycle on a /24 (2 passes) ≤ 10 s.
    assert!(
        result.elapsed <= Duration::from_secs(10),
        "S2: NFR-02 violated: scan elapsed {:.3}s (total with setup {:.3}s)",
        result.elapsed.as_secs_f64(),
        total.as_secs_f64()
    );
    assert_eq!(result.outcome, ScanOutcome::Complete, "S2: outcome");
    // Counter identity: targets == sent + transient + fatal.
    assert_eq!(
        result.counters.targets,
        result.counters.requests_sent
            + result.counters.send_errors_transient
            + result.counters.send_errors_fatal,
        "S2: counter identity"
    );
    // 250 discovered, none extra, none duplicated.
    let seen: std::collections::BTreeSet<Ipv4Addr> =
        result.observations.iter().map(|o| o.ip).collect();
    assert_eq!(seen, expected, "S2: discovered set");
    assert_eq!(result.counters.replies_accepted, 250, "S2: accepted");
    assert_eq!(result.counters.duplicates, 0, "S2: duplicates");

    // Pass-2 target count == the pass-1 non-responder snapshot: 253
    // targets in pass 1, 250 answered, so pass 2 re-probes exactly the 3
    // silent ones (.252–.254) — visible in the responder's log as the
    // addresses requested exactly twice.
    let log = lab.rxlog();
    assert_eq!(log.malformed, 0, "S2: the receive log must parse cleanly");
    let counts = log.request_counts_per_target(lab.our_mac);
    let twice: Vec<Ipv4Addr> = counts
        .iter()
        .filter(|(_, count)| *count == 2)
        .map(|(ip, _)| *ip)
        .collect();
    let silent = [
        ip("198.51.100.252"),
        ip("198.51.100.253"),
        ip("198.51.100.254"),
    ];
    assert_eq!(
        twice,
        silent.to_vec(),
        "S2: pass-2 re-probes exactly the non-responders"
    );
    assert_eq!(
        result.counters.targets,
        253 + 3,
        "S2: 253 pass-1 targets + 3 pass-2 targets"
    );

    // Rate evidence: the sliding 1 s window never exceeds rate + margin,
    // and no two requests were stamped closer than the pacing interval
    // minus the documented margin.
    let window = log.max_requests_in_window(lab.our_mac, 1000);
    assert!(
        window <= u64::from(DEFAULT_RATE_PPS) + RATE_WINDOW_MARGIN,
        "S2: rate exceeded: {window} requests in a 1 s window (rate {DEFAULT_RATE_PPS} + margin {RATE_WINDOW_MARGIN})"
    );
    let gap = log.min_request_gap_ms(lab.our_mac);
    assert!(
        gap.is_none_or(|gap| gap >= MIN_REQUEST_GAP_MS),
        "S2: request burst detected: minimum stamped gap {gap:?} ms"
    );
    println!(
        "S2: 250/250 in {:.3}s (NFR-02 budget 10 s, CI margin {:.0}%); \
         targets={} sent={} window-max={window} min-gap={:?}ms",
        result.elapsed.as_secs_f64(),
        (10.0 - result.elapsed.as_secs_f64()) / 10.0 * 100.0,
        result.counters.targets,
        result.counters.requests_sent,
        gap
    );
}

// ---------------------------------------------------------------------------
// S3 — silent targets: clean completion, no hang
// ---------------------------------------------------------------------------

pub fn s3_silent_targets() {
    let spec = LabSpec {
        tag: "s3",
        subnet: cidr("203.0.113.0/28"),
        kernel_addrs: Vec::new(),
        answers: Vec::new(),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::None,
    };
    let targets = target_set(&spec.subnet, spec.host_ip());
    let target_count = targets.len() as u64;
    let lab = Lab::build(&spec);

    let started = Instant::now();
    let result = scan_lab(&lab, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    let wall = started.elapsed();

    assert_eq!(result.outcome, ScanOutcome::Complete, "S3: outcome");
    assert_eq!(result.counters.replies_accepted, 0, "S3: zero accepted");
    assert_eq!(result.counters.duplicates, 0, "S3: duplicates");
    assert_eq!(
        result.counters.targets,
        target_count * 2,
        "S3: both passes sweep everything"
    );
    // Bounded by sweep + gap + listen window (13 targets per pass):
    // 2 × 0.13 s + 1 s gap + 1.5 s listen ≈ 2.8 s — anything past the
    // documented bound is a hang.
    let bound = Duration::from_secs(6);
    assert!(
        result.elapsed <= bound,
        "S3: scan exceeded the no-hang bound: {:.3}s > {bound:?}",
        result.elapsed.as_secs_f64()
    );
    assert!(
        wall <= bound + Duration::from_secs(2),
        "S3: total wall time"
    );
    println!(
        "S3: {target_count} silent targets, complete in {:.3}s, zero accepted",
        result.elapsed.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// S4 — proxy ARP: one MAC, many IPs, none merged or dropped
// ---------------------------------------------------------------------------

pub fn s4_proxy_arp() {
    let proxy_mac: MacAddr = "02:00:00:00:00:99".parse().unwrap();
    let proxy_ips = ips_from("203.0.113.18", 12);
    let spec = LabSpec {
        tag: "s4",
        subnet: cidr("203.0.113.16/28"),
        kernel_addrs: Vec::new(),
        answers: proxy_ips
            .iter()
            .map(|ip| Answer {
                ip: *ip,
                mac: proxy_mac,
            })
            .collect(),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::None,
    };
    let lab = Lab::build(&spec);

    let result = scan_lab(&lab, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);

    assert_eq!(result.outcome, ScanOutcome::Complete, "S4: outcome");
    assert_eq!(
        result.observations.len(),
        12,
        "S4: 12 observations, none merged"
    );
    let pairs = distinct_pairs(&result.observations);
    assert_eq!(pairs.len(), 12, "S4: 12 distinct (ip, mac) pairs");
    let macs: std::collections::BTreeSet<String> = result
        .observations
        .iter()
        .map(|o| o.mac.to_string())
        .collect();
    assert_eq!(macs.len(), 1, "S4: one MAC behind all addresses");
    assert_eq!(macs.first().map(String::as_str), Some("02:00:00:00:00:99"));
    assert_eq!(result.counters.replies_accepted, 12, "S4: accepted");
    assert_eq!(result.counters.duplicates, 0, "S4: duplicates");
    println!("S4: 12 distinct IPs behind one MAC (02:00:00:00:00:99), none merged or dropped");
}

// ---------------------------------------------------------------------------
// S5 — hostile frames, each mode rejected by reason
// ---------------------------------------------------------------------------

/// The shared body of the four rejection-mode scenarios: two valid
/// devices must survive every hostile mode untouched.
fn hostile_rejection_case(
    tag: &'static str,
    subnet: &str,
    answers_from: &str,
    hostile: Hostile,
    reason: InvalidReply,
    label: &str,
) {
    let spec = LabSpec {
        tag,
        subnet: cidr(subnet),
        kernel_addrs: Vec::new(),
        answers: distinct_mac_answers(&ips_from(answers_from, 2)),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile,
    };
    let expected: std::collections::BTreeSet<Ipv4Addr> =
        ips_from(answers_from, 2).into_iter().collect();
    let lab = Lab::build(&spec);

    let result = scan_lab(&lab, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);

    assert_eq!(
        result.outcome,
        ScanOutcome::Complete,
        "{label}: the scan must complete despite hostile traffic"
    );
    let rejected = result.counters.replies.rejected_with(&reason);
    assert!(
        rejected >= 1,
        "{label}: expected at least one {reason:?} rejection, tallies: {}",
        result.counters.replies
    );
    let seen: std::collections::BTreeSet<Ipv4Addr> =
        result.observations.iter().map(|o| o.ip).collect();
    assert_eq!(
        seen, expected,
        "{label}: the accepted set must be unchanged"
    );
    assert_eq!(result.counters.duplicates, 0, "{label}: duplicates");
    let log = lab.rxlog();
    assert_eq!(log.malformed, 0, "{label}: log must parse");
    assert!(
        !log.has_guard_violation(&spec.hostile),
        "{label}: the hostile frame lost its determinism race (guard note in the log)"
    );
    println!(
        "{label}: rejected ({rejected}× {reason:?}), accepted set unchanged ({} devices)",
        expected.len()
    );
}

pub fn s5_hostile_unsolicited() {
    // The un-asked reply claims the *last* target of the scope; the
    // first request (the lowest target) triggers it, so the claim is
    // never solicited before the hostile frame is on the wire.
    hostile_rejection_case(
        "s5u",
        "203.0.113.32/28",
        "203.0.113.34",
        Hostile::Unsolicited {
            ip: ip("203.0.113.46"),
        },
        InvalidReply::NotSolicited {
            found: ip("203.0.113.46"),
        },
        "S5/unsolicited",
    );
}

pub fn s5_hostile_truncated() {
    hostile_rejection_case(
        "s5t",
        "203.0.113.48/28",
        "203.0.113.50",
        Hostile::Truncated {
            ip: ip("203.0.113.60"),
        },
        InvalidReply::Truncated {
            needed: 42,
            found: 20,
        },
        "S5/truncated",
    );
}

pub fn s5_hostile_multicast_mac() {
    // Fires on the first request (for the answered address itself): the
    // multicast-MAC variant of the reply is rejected InvalidMac, then
    // the honest reply arrives and is accepted.
    hostile_rejection_case(
        "s5m",
        "203.0.113.64/28",
        "203.0.113.66",
        Hostile::MulticastMac {
            ip: ip("203.0.113.66"),
        },
        InvalidReply::InvalidMac {
            reason: osza_netmon::model::MacAddrParseError::MulticastAddress,
        },
        "S5/multicast-mac",
    );
}

pub fn s5_hostile_out_of_scope() {
    hostile_rejection_case(
        "s5o",
        "203.0.113.80/28",
        "203.0.113.82",
        Hostile::OutOfScope {
            ip: ip("198.51.100.99"),
        },
        InvalidReply::OutOfScope {
            found: ip("198.51.100.99"),
        },
        "S5/out-of-scope",
    );
}

pub fn s5_hostile_flood() {
    // 13 answer-table devices, a 1500-frame flood of valid replies, and
    // a response cap of 8: the flood must not hang the scan and must
    // not exceed the cap (accepted ≤ 8, cap_dropped ≥ 1).
    const CAP: usize = 8;
    const FLOOD: u32 = 1500;
    let spec = LabSpec {
        tag: "s5f",
        subnet: cidr("203.0.113.96/28"),
        kernel_addrs: Vec::new(),
        answers: distinct_mac_answers(&ips_from("203.0.113.98", 13)),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::Flood { count: FLOOD },
    };
    let known: std::collections::BTreeSet<Ipv4Addr> =
        ips_from("203.0.113.98", 13).into_iter().collect();
    let lab = Lab::build(&spec);

    let socket = open_raw_socket(&lab.host_if)
        .unwrap_or_else(|err| panic!("S5/flood: opening the raw socket: {err}"));
    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), lab.scope, lab.our_mac, lab.our_ip)
        .with_response_cap(CAP);
    let started = Instant::now();
    let result = scanner.scan(
        2,
        DEFAULT_RATE_PPS,
        DEFAULT_LISTEN_WINDOW,
        Arc::new(AtomicBool::new(false)),
    );
    let wall = started.elapsed();

    assert_eq!(result.outcome, ScanOutcome::Complete, "S5/flood: outcome");
    assert!(
        (result.counters.replies_accepted as usize) <= CAP,
        "S5/flood: the response cap was exceeded: accepted {} > {CAP}",
        result.counters.replies_accepted
    );
    assert!(
        result.counters.cap_dropped >= 1,
        "S5/flood: the cap must have engaged: {}",
        result.counters
    );
    assert!(
        result.counters.duplicates >= 1,
        "S5/flood: the flood re-visits must be deduplicated: {}",
        result.counters
    );
    assert!(
        wall < Duration::from_secs(15),
        "S5/flood: no hang ({wall:.2?})"
    );
    // Nothing outside the answer table was accepted.
    for observation in &result.observations {
        assert!(
            known.contains(&observation.ip),
            "S5/flood: unexpected observation {observation}"
        );
    }
    println!(
        "S5/flood: {FLOOD} hostile replies, accepted {} ≤ cap {CAP}, cap_dropped {}, \
         duplicates {}, complete in {:.2}s",
        result.counters.replies_accepted,
        result.counters.cap_dropped,
        result.counters.duplicates,
        wall.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// S6 — egress assertion: only ARP requests to in-scope targets (SR-07)
// ---------------------------------------------------------------------------

pub fn s6_egress_only_arp_requests() {
    let spec = LabSpec {
        tag: "s6",
        subnet: cidr("203.0.113.112/28"),
        kernel_addrs: ips_from("203.0.113.114", 2),
        answers: distinct_mac_answers(&ips_from("203.0.113.116", 2)),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::None,
    };
    let lab = Lab::build(&spec);
    let targets = target_set(&lab.scope, lab.our_ip);

    let result = scan_lab(&lab, 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW);
    assert_eq!(result.outcome, ScanOutcome::Complete, "S6: outcome");

    let log = lab.rxlog();
    assert_eq!(log.malformed, 0, "S6: the receive log must parse cleanly");
    let requests = log.scanner_requests(lab.our_mac);
    let non_requests = log.scanner_non_requests(lab.our_mac);
    let environment = log.environment_frames(lab.our_mac);

    // 100% of the scanner's frames are ARP requests to in-scope targets.
    assert!(
        !requests.is_empty(),
        "S6: the log must contain the scanner's requests"
    );
    for record in &requests {
        assert_eq!(
            record.et,
            Some(0x0806),
            "S6: non-ARP EtherType from the scanner: {record:?}"
        );
        assert_eq!(
            record.op,
            Some(1),
            "S6: non-request ARP opcode from the scanner: {record:?}"
        );
        let tip = record
            .tip
            .unwrap_or_else(|| panic!("S6: request without target IP: {record:?}"));
        assert!(
            targets.contains(&tip),
            "S6: request to out-of-scope target {tip}"
        );
    }
    // Zero non-ARP egress: nothing else from our MAC ever hit the wire.
    assert!(
        non_requests.is_empty(),
        "S6: non-request frames from the scanner: {:?}",
        non_requests
            .iter()
            .map(|r| (r.et, r.op))
            .collect::<Vec<_>>()
    );
    // The helper saw every request the counters say we sent.
    assert_eq!(
        requests.len() as u64,
        result.counters.requests_sent,
        "S6: every sent request must appear in the receive log"
    );
    // NFR-06 margin: total frames ≤ rate × elapsed + margin.
    let allowance = (f64::from(DEFAULT_RATE_PPS) * result.elapsed.as_secs_f64()).ceil() as u64
        + RATE_WINDOW_MARGIN;
    assert!(
        requests.len() as u64 <= allowance,
        "S6: NFR-06 frame-count margin exceeded: {} > {allowance}",
        requests.len()
    );
    let window = log.max_requests_in_window(lab.our_mac, 1000);
    assert!(
        window <= u64::from(DEFAULT_RATE_PPS) + RATE_WINDOW_MARGIN,
        "S6: rate exceeded: {window} in a 1 s window"
    );
    println!(
        "S6: {} ARP requests out (all in-scope), 0 non-ARP frames, \
         window-max {window} ≤ {}, lab environment frames from other sources: {}",
        requests.len(),
        u64::from(DEFAULT_RATE_PPS) + RATE_WINDOW_MARGIN,
        environment.len()
    );
    // The DNS PTR half of the §2.3 assertion arrives with T-203; today
    // the honest statement is "ARP-only egress", which is what the
    // production code implements.
}

// ---------------------------------------------------------------------------
// S7 — privilege model (SR-06)
// ---------------------------------------------------------------------------

pub fn s7_privilege_model() {
    let spec = LabSpec {
        tag: "s7",
        subnet: cidr("203.0.113.128/28"),
        kernel_addrs: ips_from("203.0.113.130", 2),
        answers: Vec::new(),
        impairment: Impairment::none(seeds::SCENARIOS),
        hostile: Hostile::None,
    };
    let lab = Lab::build(&spec);

    // Teach this namespace's neighbor table the two lab devices: one
    // 1-byte UDP datagram per address makes the *kernel* resolve them
    // (harness setup traffic inside the throwaway namespace, RFC 5737
    // addresses — documented in the execution report; the product's own
    // egress is what S6 asserts).
    for target in &spec.kernel_addrs {
        udp_touch(*target);
    }
    let expected_entries = wait_for_neighbor_entries(&lab, &spec.kernel_addrs);

    // (a) Without CAP_NET_RAW: a child process drops the capability,
    //     then open_raw_socket must return the typed EPERM error and
    //     the read-only path must return exactly the lab-learned
    //     entries.
    let output = run_probe(&[
        "--mode",
        "cap-drop",
        "--iface",
        &lab.host_if,
        "--scope",
        &format!("{}/{}", lab.scope.network(), lab.scope.prefix_len()),
    ]);
    let mut open_line = None;
    let mut neighbor_lines = Vec::new();
    let mut status_line = None;
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("OPEN ") {
            open_line = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("NEIGHBOR ") {
            neighbor_lines.push(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("STATUS ") {
            status_line = Some(rest.to_owned());
        } else if line.starts_with("ERROR") {
            panic!("S7(a): probe reported {line}");
        }
    }
    assert_eq!(
        open_line.as_deref(),
        Some("EPERM"),
        "S7(a): typed EPERM expected"
    );
    assert_eq!(
        neighbor_lines.len(),
        expected_entries.len(),
        "S7(a): the read-only path must return exactly the lab-learned entries"
    );
    for line in &neighbor_lines {
        let mut fields = line.split_whitespace();
        let entry_ip = fields.next().unwrap_or_default();
        let entry_mac = fields.next().unwrap_or_default();
        let entry_dev = fields.next().unwrap_or_default();
        let addr: Ipv4Addr = entry_ip
            .parse()
            .unwrap_or_else(|_| panic!("S7(a): bad IP {entry_ip:?}"));
        assert!(
            expected_entries.contains_key(&addr),
            "S7(a): unexpected entry {addr}"
        );
        assert_eq!(entry_dev, lab.host_if, "S7(a): entry device");
        assert_eq!(
            entry_mac,
            expected_entries.get(&addr).cloned().unwrap_or_default(),
            "S7(a): entry MAC for {addr}"
        );
    }
    // The child really lost CAP_NET_RAW (bit 13) from CapEff.
    let status = status_line.unwrap_or_else(|| panic!("S7(a): no STATUS line"));
    let cap_eff = status_field(&status, "CapEff");
    assert_eq!(
        cap_eff >> 13 & 1,
        0,
        "S7(a): CapEff must not hold CAP_NET_RAW: {status}"
    );
    println!(
        "S7(a): open_raw_socket → EPERM without CAP_NET_RAW; read-only path returned \
         exactly {} lab-learned entr{}",
        neighbor_lines.len(),
        if neighbor_lines.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );

    // (b) Privileged start: open → drop → verify zeros → scan still
    //     completes on the already-open socket.
    let output = run_probe(&[
        "--mode",
        "drop-and-scan",
        "--iface",
        &lab.host_if,
        "--scope",
        &format!("{}/{}", lab.scope.network(), lab.scope.prefix_len()),
        "--our-mac",
        &lab.our_mac.to_string(),
        "--our-ip",
        &lab.our_ip.to_string(),
    ]);
    let mut status_line = None;
    let mut outcome_line = None;
    let mut counters_line = None;
    let mut obs_ips = Vec::new();
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix("STATUS ") {
            status_line = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("OUTCOME ") {
            outcome_line = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("COUNTERS ") {
            counters_line = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("OBS ") {
            obs_ips.push(
                rest.split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
            );
        } else if line.starts_with("ERROR") {
            panic!("S7(b): probe reported {line}");
        }
    }
    let status = status_line.unwrap_or_else(|| panic!("S7(b): no STATUS line"));
    assert_eq!(
        status_field(&status, "CapEff"),
        0,
        "S7(b): CapEff must be zero after the drop: {status}"
    );
    assert_eq!(
        status_field(&status, "CapPrm"),
        0,
        "S7(b): CapPrm must be zero after the drop: {status}"
    );
    assert_eq!(outcome_line.as_deref(), Some("complete"), "S7(b): outcome");
    let counters = counters_line.unwrap_or_else(|| panic!("S7(b): no COUNTERS line"));
    assert!(
        counters.contains("accepted=2"),
        "S7(b): counters: {counters}"
    );
    let observed: std::collections::BTreeSet<Ipv4Addr> =
        obs_ips.iter().filter_map(|raw| raw.parse().ok()).collect();
    let expected_obs: std::collections::BTreeSet<Ipv4Addr> =
        spec.kernel_addrs.iter().copied().collect();
    assert_eq!(observed, expected_obs, "S7(b): discovered set");
    println!(
        "S7(b): after the drop CapEff=CapPrm=0, the scan completed and discovered both devices"
    );
}

/// Sends one 1-byte UDP datagram to `target` so this namespace's kernel
/// resolves (and caches) its ARP entry (the read-only-path fixture).
fn udp_touch(target: Ipv4Addr) {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .unwrap_or_else(|err| panic!("S7: UDP socket: {err}"));
    socket
        .connect(SocketAddrV4::new(target, 9))
        .unwrap_or_else(|err| panic!("S7: UDP connect to {target}: {err}"));
    // The datagram is discarded (or answered with ICMP unreachable, both
    // fine); only the kernel's ARP resolution matters.
    let _ = socket.send(b"x");
}

/// Waits (bounded) until the neighbor table holds complete entries for
/// exactly `wanted` on the lab interface; returns the `ip → mac` map.
fn wait_for_neighbor_entries(
    lab: &Lab,
    wanted: &[Ipv4Addr],
) -> std::collections::BTreeMap<Ipv4Addr, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let entries = ProcNeighborTable::new()
            .read_neighbors(&lab.scope, &lab.host_if)
            .unwrap_or_else(|err| panic!("S7: reading the neighbor table: {err}"));
        let map: std::collections::BTreeMap<Ipv4Addr, String> = entries
            .iter()
            .map(|entry| (entry.ip(), entry.mac().to_string()))
            .collect();
        let complete: std::collections::BTreeSet<Ipv4Addr> = map.keys().copied().collect();
        let wanted_set: std::collections::BTreeSet<Ipv4Addr> = wanted.iter().copied().collect();
        if complete == wanted_set {
            return map;
        }
        if Instant::now() > deadline {
            panic!("S7: the neighbor table never learned {wanted_set:?} (has {complete:?})");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Runs a `--probe` child (this same binary) and returns its stdout.
fn run_probe(args: &[&str]) -> String {
    let exe = std::env::current_exe()
        .unwrap_or_else(|err| panic!("S7: locating this test binary: {err}"));
    let output = Command::new(exe)
        .arg("--probe")
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("S7: spawning the probe: {err}"));
    if !output.status.success() {
        panic!(
            "S7: the probe ({}) failed with {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout)
        .unwrap_or_else(|err| panic!("S7: the probe's stdout is not UTF-8: {err}"))
}

/// Reads one `Cap*=<hex>` field from a probe STATUS line.
fn status_field(status: &str, field: &str) -> u64 {
    let needle = format!("{field}=");
    for token in status.split_whitespace() {
        if let Some(hex) = token.strip_prefix(&needle) {
            return u64::from_str_radix(hex, 16).unwrap_or(u64::MAX);
        }
    }
    panic!("S7: field {field} missing from status {status:?}");
}
