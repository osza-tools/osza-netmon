// SPDX-License-Identifier: GPL-3.0-only

//! The S8/S9 measurement runs (task T-106, task card §3/§5.10; plan
//! §11.2 S8/S9 and Appendix D).
//!
//! One invocation runs the whole matrix —
//!
//! * S8: the S1, S2 and S4 scenario shapes under profiles P0–P3
//!   (helper-based impairment — the default and the CI mechanism);
//! * S9: the sleepy-host parameter variants (ignore-first, answer
//!   fraction, answer-late);
//!
//! three scan cycles per cell, recording every Appendix D per-run field
//! and emitting the report table as JSON **and** Markdown under
//! `target/netns/measure/`. No threshold assertions here: T-106
//! *produces* the tables; the G-1 comparison and the ADR-009/010/011
//! decisions are T-105.
//!
//! Invocation:
//!
//! ```text
//! OSZA_NETMON_TESTS=1 cargo test --locked --all-features --test netns -- \
//!     --measure [--run-tag run1] [--out-dir target/netns/measure]
//! ```
//!
//! Run it twice with the same seeds; the recall numbers must match
//! exactly (deterministic impairment) — the variance goes into the
//! execution report.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use osza_netmon::discovery::arp::ArpScanner;
use osza_netmon::discovery::arp::DEFAULT_LISTEN_WINDOW;
use osza_netmon::discovery::arp::DEFAULT_RATE_PPS;
use osza_netmon::discovery::arp::InvalidReply;
use osza_netmon::discovery::arp::LinuxArpTransport;
use osza_netmon::discovery::arp::Observation;
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

/// Cycles per measurement cell (G-1: "recall within 3 cycles").
const CYCLES: u32 = 3;

/// The passes and rate of every measurement scan (ADR-011 defaults).
const PASSES: u8 = 2;

// ---------------------------------------------------------------------------
// Matrix definition
// ---------------------------------------------------------------------------

/// One measurement scenario shape.
struct Shape {
    /// Artifact/lab tag (`m-s1`…).
    tag: &'static str,
    /// Display name (S1/S2/S4/S9-…).
    name: &'static str,
    /// Lab subnet (RFC 5737).
    subnet: &'static str,
    /// Kernel-answered addresses (raw count from `first_kernel`).
    kernel: Vec<Ipv4Addr>,
    /// Helper answer-table entries.
    answers: Vec<Answer>,
    /// The known-device set (recall denominator), as IPs.
    known: Vec<Ipv4Addr>,
    /// A note for the report table.
    note: &'static str,
}

/// Distinct synthetic MACs for a run of addresses (`02:00:00:00:01:xx`).
fn helper_answers_from(first: &str, count: u8) -> Vec<Answer> {
    let base: Ipv4Addr = first.parse().unwrap_or_else(|_| panic!("bad IP {first:?}"));
    (0..count)
        .map(|offset| {
            let octets = base.octets();
            let addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3] + offset);
            Answer {
                ip: addr,
                mac: MacAddr::from_octets([0x02, 0x00, 0x00, 0x00, 0x01, octets[3] + offset])
                    .unwrap_or_else(|_| panic!("bad synthetic MAC for {addr}")),
            }
        })
        .collect()
}

fn ip_range(first: &str, count: u8) -> Vec<Ipv4Addr> {
    helper_answers_from(first, count)
        .into_iter()
        .map(|a| a.ip)
        .collect()
}

/// A (label, constructor) pair of the profile table.
type Profile = (&'static str, fn(u64) -> Impairment);

/// The S8/S9 matrix: the S1, S2 and S4 shapes under profiles P0–P3
/// plus the three S9 sleepy-host variants.
fn matrix() -> Vec<(Shape, Impairment, &'static str)> {
    let shapes = [s1_shape(), s2_shape(), s4_shape()];
    let profiles: [Profile; 4] = [
        ("P0", Impairment::none),
        ("P1", Impairment::p1),
        ("P2", Impairment::p2),
        ("P3", Impairment::p3),
    ];
    let mut cells = Vec::new();
    for (index, (label, make)) in profiles.iter().enumerate() {
        let seed = seeds::MEASURE_BASE + index as u64;
        for shape in &shapes {
            cells.push((
                shape_with_tag(shape, &format!("{}-{}", shape.tag, label)),
                make(seed),
                *label,
            ));
        }
    }
    let variants: [Profile; 3] = [
        ("S9-ignore-first-2", Impairment::s9_ignore_first),
        ("S9-fraction-0.5", Impairment::s9_fraction),
        ("S9-late-400ms", Impairment::s9_late),
    ];
    let s9_shape = s9_shape();
    for (index, (label, make)) in variants.iter().enumerate() {
        let seed = seeds::MEASURE_BASE + 100 + index as u64;
        cells.push((
            shape_with_tag(&s9_shape, &format!("m-s9-{index}")),
            make(seed),
            *label,
        ));
    }
    cells
}

fn s1_shape() -> Shape {
    // S1 shape: the mixed lab — 10 kernel + 10 helper devices. Under
    // P1–P3 only the helper half can be impaired by the helper
    // mechanism (documented limitation; the kernel answers for its own
    // addresses); the table's notes column says so.
    let answers = helper_answers_from("192.0.2.12", 10);
    let kernel = ip_range("192.0.2.2", 10);
    let mut known = kernel.clone();
    known.extend(answers.iter().map(|a| a.ip));
    Shape {
        tag: "m-s1",
        name: "S1 (20 mixed)",
        subnet: "192.0.2.0/24",
        kernel,
        answers,
        known,
        note: "10 kernel-answered (unimpaired) + 10 helper-answered (impaired)",
    }
}

fn s2_shape() -> Shape {
    // S2 shape: a /24 with 250 *helper-answered* devices — unlike the
    // S2 scenario test (which times the kernel-answered sweep), the
    // measurement variant must let the impairment reach every device.
    let answers = helper_answers_from("198.51.100.2", 250);
    Shape {
        tag: "m-s2",
        name: "S2 (250 addresses)",
        subnet: "198.51.100.0/24",
        kernel: Vec::new(),
        known: answers.iter().map(|a| a.ip).collect(),
        answers,
        note: "250 helper-answered (all impaired by the profile)",
    }
}

fn s4_shape() -> Shape {
    // S4 shape: proxy ARP — 12 addresses behind one synthetic MAC.
    let proxy_mac: MacAddr = "02:00:00:00:00:99".parse().unwrap();
    let ips = ip_range("203.0.113.146", 12);
    Shape {
        tag: "m-s4",
        name: "S4 (proxy ARP)",
        subnet: "203.0.113.144/28",
        kernel: Vec::new(),
        answers: ips
            .iter()
            .map(|ip| Answer {
                ip: *ip,
                mac: proxy_mac,
            })
            .collect(),
        known: ips.clone(),
        note: "12 IPs behind one MAC (02:00:00:00:00:99)",
    }
}

fn s9_shape() -> Shape {
    // S9 shape: 12 helper-answered sleepy devices.
    let answers = helper_answers_from("203.0.113.162", 12);
    Shape {
        tag: "m-s9",
        name: "S9 (sleepy hosts)",
        subnet: "203.0.113.160/28",
        kernel: Vec::new(),
        known: answers.iter().map(|a| a.ip).collect(),
        answers,
        note: "12 helper-answered; the S9 parameter variants",
    }
}

/// Clones a shape with a different artifact tag (per-profile labs get
/// their own directory under `target/netns/`).
fn shape_with_tag(shape: &Shape, tag: &str) -> Shape {
    Shape {
        tag: Box::leak(tag.to_owned().into_boxed_str()),
        name: shape.name,
        subnet: shape.subnet,
        kernel: shape.kernel.clone(),
        answers: shape.answers.clone(),
        known: shape.known.clone(),
        note: shape.note,
    }
}

// ---------------------------------------------------------------------------
// Per-run records and output
// ---------------------------------------------------------------------------

/// One cycle's record (Appendix D per-run fields).
#[derive(Debug, Clone)]
struct CycleRecord {
    scenario: String,
    variant: String,
    cycle: u32,
    seed: u64,
    date: String,
    network_type: &'static str,
    scope_size: u32,
    mode: &'static str,
    transport: &'static str,
    rate_pps: u32,
    passes: u8,
    sender_ip_variant: &'static str,
    known_devices: usize,
    discovered_this_cycle: usize,
    discovered_cumulative: usize,
    recall_cumulative_pct: f64,
    extras: usize,
    time_to_first_ms: Option<u64>,
    sweep_duration_ms: Option<u64>,
    packets_sent: u64,
    send_errors: u64,
    replies_accepted: u64,
    duplicates: u64,
    cap_dropped: u64,
    rejected: Vec<(String, u64)>,
    outcome: String,
    scan_elapsed_ms: u128,
    cpu_ms: Option<u64>,
    responder_drops: u64,
    impairment_mechanism: &'static str,
    notes: String,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Entry point of the `--measure` subcommand.
pub fn main(args: &[std::ffi::OsString]) {
    if !crate::suite_enabled() {
        eprintln!(
            "measure: set OSZA_NETMON_TESTS=1 (and run inside the unshare wrapper) to enable"
        );
        std::process::exit(2);
    }
    crate::ensure_environment();

    let mut run_tag = "run1".to_owned();
    let mut out_dir = std::path::PathBuf::from("target/netns/measure");
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let flag = flag.to_string_lossy();
        match flag.as_ref() {
            "--run-tag" => {
                run_tag = iter
                    .next()
                    .map(|v| v.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "run1".to_owned());
            }
            "--out-dir" => {
                if let Some(value) = iter.next() {
                    out_dir = std::path::PathBuf::from(value);
                }
            }
            other => {
                eprintln!("measure: ignoring unknown argument {other:?}");
            }
        }
    }

    let started = Instant::now();
    let mut records: Vec<CycleRecord> = Vec::new();
    for (shape, impairment, label) in matrix() {
        println!(
            "measure: {} under {} (seed {}) …",
            shape.name, label, impairment.seed
        );
        let cell = run_cell(&shape, impairment, label);
        records.extend(cell);
    }

    std::fs::create_dir_all(&out_dir)
        .unwrap_or_else(|err| panic!("measure: creating {}: {err}", out_dir.display()));
    let json_path = out_dir.join(format!("netns-measure-{run_tag}.json"));
    let md_path = out_dir.join(format!("netns-measure-{run_tag}.md"));
    std::fs::write(&json_path, to_json(&records))
        .unwrap_or_else(|err| panic!("measure: writing {}: {err}", json_path.display()));
    std::fs::write(&md_path, to_markdown(&records))
        .unwrap_or_else(|err| panic!("measure: writing {}: {err}", md_path.display()));
    println!(
        "measure: {} records across {} cells in {:.1}s",
        records.len(),
        records.len() / CYCLES as usize,
        started.elapsed().as_secs_f64()
    );
    println!("measure: JSON {}", json_path.display());
    println!("measure: Markdown {}", md_path.display());
}

/// Runs one matrix cell: one lab, `CYCLES` scans, per-cycle records.
fn run_cell(shape: &Shape, impairment: Impairment, label: &str) -> Vec<CycleRecord> {
    let subnet: Ipv4Net = parse_cidr(shape.subnet)
        .unwrap_or_else(|err| panic!("measure: bad subnet {:?}: {err}", shape.subnet));
    let spec = LabSpec {
        tag: shape.tag,
        subnet,
        kernel_addrs: shape.kernel.clone(),
        answers: shape.answers.clone(),
        impairment,
        hostile: Hostile::None,
    };
    let lab = Lab::build(&spec);
    let known: std::collections::BTreeSet<Ipv4Addr> = shape.known.iter().copied().collect();
    let host_count = subnet.host_count();

    let socket = open_raw_socket(&lab.host_if)
        .unwrap_or_else(|err| panic!("measure {}: opening the raw socket: {err}", shape.tag));
    let transport = LinuxArpTransport::new(socket);
    let scanner = ArpScanner::new(Box::new(transport), lab.scope, lab.our_mac, lab.our_ip);

    let mut records = Vec::new();
    let mut cumulative: std::collections::BTreeSet<Ipv4Addr> = std::collections::BTreeSet::new();
    let mut log_rx_seen = 0usize;
    let mut log_drops_seen = 0usize;
    for cycle in 1..=CYCLES {
        let collected: Mutex<Vec<Observation>> = Mutex::new(Vec::new());
        let first_seen: Mutex<Option<Instant>> = Mutex::new(None);
        let sink = |observation: Observation| {
            let mut first = first_seen.lock().unwrap_or_else(|err| err.into_inner());
            if first.is_none() {
                *first = Some(Instant::now());
            }
            collected
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .push(observation);
        };
        let cpu_before = crate::lab::process_cpu_ms();
        let scan_start = Instant::now();
        let result = scanner.scan_with_sink(
            PASSES,
            DEFAULT_RATE_PPS,
            DEFAULT_LISTEN_WINDOW,
            Arc::new(AtomicBool::new(false)),
            &sink,
        );
        let cpu_after = crate::lab::process_cpu_ms();
        let observations = collected
            .into_inner()
            .unwrap_or_else(|err| err.into_inner());
        let first = first_seen
            .into_inner()
            .unwrap_or_else(|err| err.into_inner());

        // This cycle's slice of the responder log: requests and
        // impairment drops that arrived after the previous cycle.
        let log = lab.rxlog();
        let cycle_requests: Vec<&crate::rxlog::RxRecord> = log
            .rx
            .iter()
            .skip(log_rx_seen)
            .filter(|record| {
                record.et == Some(0x0806) && record.op == Some(1) && record.src == Some(lab.our_mac)
            })
            .collect();
        let drops_this_cycle = log.drops.len().saturating_sub(log_drops_seen) as u64;
        log_rx_seen = log.rx.len();
        log_drops_seen = log.drops.len();
        let sweep_ms = cycle_span_ms(&cycle_requests);

        // Cumulative recall over known devices; extras outside the
        // known set.
        let this_cycle: std::collections::BTreeSet<Ipv4Addr> =
            observations.iter().map(|o| o.ip).collect();
        let before = cumulative.len();
        for ip in &this_cycle {
            cumulative.insert(*ip);
        }
        let hits: usize = cumulative.intersection(&known).count();
        let extras: usize = cumulative.difference(&known).count();
        let recall = hits as f64 / known.len() as f64 * 100.0;

        records.push(CycleRecord {
            scenario: shape.name.to_owned(),
            variant: label.to_owned(),
            cycle,
            seed: impairment.seed,
            date: chrono_like_now(),
            network_type: "netns synthetic (veth pair, user namespaces)",
            scope_size: host_count,
            mode: "active",
            transport: "LinuxArpTransport (pnet_datalink 0.35.0, interim per ADR-009 Pending)",
            rate_pps: DEFAULT_RATE_PPS,
            passes: PASSES,
            sender_ip_variant: "interface IP",
            known_devices: known.len(),
            discovered_this_cycle: cumulative.len() - before,
            discovered_cumulative: cumulative.len(),
            recall_cumulative_pct: (recall * 100.0).round() / 100.0,
            extras,
            time_to_first_ms: first
                .map(|instant| instant.duration_since(scan_start).as_millis() as u64),
            sweep_duration_ms: sweep_ms,
            packets_sent: result.counters.requests_sent,
            send_errors: result.counters.send_errors_transient + result.counters.send_errors_fatal,
            replies_accepted: result.counters.replies_accepted,
            duplicates: result.counters.duplicates,
            cap_dropped: result.counters.cap_dropped,
            rejected: rejection_tallies(&result),
            outcome: result.outcome.to_string(),
            scan_elapsed_ms: result.elapsed.as_millis(),
            cpu_ms: match (cpu_before, cpu_after) {
                (Some(a), Some(b)) if b >= a => Some(b - a),
                _ => None,
            },
            responder_drops: drops_this_cycle,
            impairment_mechanism: "helper responder",
            notes: shape.note.to_owned(),
        });
        println!(
            "  cycle {cycle}: recall {recall:.1}% (cumulative {}/{}), \
             packets {}, accepted {}, duplicates {}",
            hits,
            known.len(),
            result.counters.requests_sent,
            result.counters.replies_accepted,
            result.counters.duplicates
        );
    }
    records
}

/// The sweep span of one cycle: last request − first request + one
/// pacing interval (10 ms), as observed at the responder.
fn cycle_span_ms(requests: &[&crate::rxlog::RxRecord]) -> Option<u64> {
    let first = requests.first().map(|r| r.t)?;
    let last = requests.last().map(|r| r.t)?;
    Some(last - first + 10)
}

/// The 14 rejection tallies, name → count (T-103's reason set).
fn rejection_tallies(result: &osza_netmon::discovery::arp::ScanResult) -> Vec<(String, u64)> {
    let sample = ip("203.0.113.200");
    let reasons: [(&str, InvalidReply); 14] = [
        (
            "truncated",
            InvalidReply::Truncated {
                needed: 42,
                found: 0,
            },
        ),
        (
            "wrong_ether_type",
            InvalidReply::WrongEtherType { found: 0 },
        ),
        (
            "wrong_hardware_type",
            InvalidReply::WrongHardwareType { found: 0 },
        ),
        (
            "wrong_protocol_type",
            InvalidReply::WrongProtocolType { found: 0 },
        ),
        (
            "wrong_hardware_length",
            InvalidReply::WrongHardwareLength { found: 0 },
        ),
        (
            "wrong_protocol_length",
            InvalidReply::WrongProtocolLength { found: 0 },
        ),
        ("wrong_opcode", InvalidReply::WrongOpcode { found: 1 }),
        ("mac_mismatch", InvalidReply::MacMismatch),
        (
            "invalid_mac",
            InvalidReply::InvalidMac {
                reason: osza_netmon::model::MacAddrParseError::MulticastAddress,
            },
        ),
        ("out_of_scope", InvalidReply::OutOfScope { found: sample }),
        (
            "network_address",
            InvalidReply::NetworkAddress { found: sample },
        ),
        (
            "broadcast_address",
            InvalidReply::BroadcastAddress { found: sample },
        ),
        ("own_address", InvalidReply::OwnAddress),
        (
            "not_solicited",
            InvalidReply::NotSolicited { found: sample },
        ),
    ];
    reasons
        .iter()
        .map(|(name, reason)| {
            (
                (*name).to_owned(),
                result.counters.replies.rejected_with(reason),
            )
        })
        .collect()
}

fn ip(text: &str) -> Ipv4Addr {
    text.parse()
        .unwrap_or_else(|_| panic!("bad IP literal {text:?}"))
}

/// A UTC timestamp without pulling a dependency (`YYYY-MM-DDTHH:MM:SSZ`
/// from `SystemTime`).
fn chrono_like_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Days since epoch → civil date (Howard Hinnant's algorithm).
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

// ---------------------------------------------------------------------------
// Output: JSON and Markdown
// ---------------------------------------------------------------------------

/// Minimal, dependency-free JSON emitter for the records array.
fn to_json(records: &[CycleRecord]) -> String {
    let mut out = String::from("{\n  \"run\": {\n");
    out.push_str("    \"harness\": \"osza-netmon T-106 netns measurement\",\n");
    out.push_str(&format!("    \"date\": \"{}\",\n", chrono_like_now()));
    out.push_str("    \"cycles_per_cell\": 3,\n");
    out.push_str("    \"impairment_mechanism\": \"helper responder (default and CI path)\",\n");
    out.push_str("    \"seeds\": \"per cell, recorded in each record's seed field (deterministic SplitMix64)\"\n");
    out.push_str("  },\n  \"records\": [\n");
    for (index, record) in records.iter().enumerate() {
        out.push_str("    {\n");
        let mut fields: Vec<(String, String)> = vec![
            ("scenario".into(), json_string(&record.scenario)),
            ("variant".into(), json_string(&record.variant)),
            ("cycle".into(), record.cycle.to_string()),
            ("seed".into(), record.seed.to_string()),
            ("date".into(), json_string(&record.date)),
            ("network_type".into(), json_string(record.network_type)),
            ("scope_size".into(), record.scope_size.to_string()),
            ("mode".into(), json_string(record.mode)),
            ("transport".into(), json_string(record.transport)),
            ("rate_pps".into(), record.rate_pps.to_string()),
            ("passes".into(), record.passes.to_string()),
            (
                "sender_ip_variant".into(),
                json_string(record.sender_ip_variant),
            ),
            ("known_devices".into(), record.known_devices.to_string()),
            (
                "discovered_this_cycle".into(),
                record.discovered_this_cycle.to_string(),
            ),
            (
                "discovered_cumulative".into(),
                record.discovered_cumulative.to_string(),
            ),
            (
                "recall_cumulative_pct".into(),
                format!("{:.2}", record.recall_cumulative_pct),
            ),
            ("extras".into(), record.extras.to_string()),
            (
                "time_to_first_ms".into(),
                record
                    .time_to_first_ms
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".into()),
            ),
            ("sweep_duration_ms".into(), record.sweep_ms_or_null()),
            ("packets_sent".into(), record.packets_sent.to_string()),
            ("send_errors".into(), record.send_errors.to_string()),
            (
                "replies_accepted".into(),
                record.replies_accepted.to_string(),
            ),
            ("duplicates".into(), record.duplicates.to_string()),
            ("cap_dropped".into(), record.cap_dropped.to_string()),
            ("outcome".into(), json_string(&record.outcome)),
            ("scan_elapsed_ms".into(), record.scan_elapsed_ms.to_string()),
            (
                "cpu_ms".into(),
                record
                    .cpu_ms
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "null".into()),
            ),
            ("responder_drops".into(), record.responder_drops.to_string()),
            (
                "impairment_mechanism".into(),
                json_string(record.impairment_mechanism),
            ),
            ("notes".into(), json_string(&record.notes)),
        ];
        if record.rejected.iter().any(|(_, count)| *count > 0) {
            let entries: Vec<String> = record
                .rejected
                .iter()
                .filter(|(_, count)| *count > 0)
                .map(|(name, count)| {
                    format!(
                        "          {{\"reason\": {}, \"count\": {}}}",
                        json_string(name),
                        count
                    )
                })
                .collect();
            fields.push((
                "rejected_by_reason".into(),
                format!("[\n{}\n      ]", entries.join(",\n")),
            ));
        } else {
            fields.push(("rejected_by_reason".into(), "[]".into()));
        }
        for (position, (key, value)) in fields.iter().enumerate() {
            out.push_str(&format!("      \"{key}\": {value}"));
            if position + 1 < fields.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("    }");
        if index + 1 < records.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  ]\n}\n");
    out
}

impl CycleRecord {
    fn sweep_ms_or_null(&self) -> String {
        self.sweep_duration_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "null".into())
    }
}

/// JSON string escaping for the few free-form fields.
fn json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The Appendix D report table (per scenario/network), one Markdown
/// table per scenario with the profile variants as rows.
fn to_markdown(records: &[CycleRecord]) -> String {
    let mut scenarios: Vec<&str> = Vec::new();
    for record in records {
        if !scenarios.contains(&record.scenario.as_str()) {
            scenarios.push(record.scenario.as_str());
        }
    }
    let mut out = String::from(
        "# osza-netmon T-106 netns measurement (S8/S9)\n\n\
         Generated by the `--measure` entry point; three cycles per cell; helper-based\n\
         impairment (the default and CI mechanism); seeds in the JSON records.\n\n",
    );
    for scenario in scenarios {
        let mine: Vec<&CycleRecord> = records
            .iter()
            .filter(|record| record.scenario == scenario)
            .collect();
        let Some(first) = mine.first() else {
            continue;
        };
        out.push_str(&format!(
            "## {} — known devices: {}, scope size: {}\n\n",
            scenario, first.known_devices, first.scope_size
        ));
        out.push_str(&format!("{}\n\n", first.notes));
        out.push_str("| Variant | Recall cycle 1 | Recall cycle 3 | Extras | Time to first | Sweep time | Packets | Notes |\n");
        out.push_str("|---|---|---|---|---|---|---|---|\n");
        let mut variants: Vec<&str> = Vec::new();
        for record in &mine {
            if !variants.contains(&record.variant.as_str()) {
                variants.push(record.variant.as_str());
            }
        }
        for variant in variants {
            let cycle = |n: u32| mine.iter().find(|r| r.variant == variant && r.cycle == n);
            let c1 = cycle(1);
            let c3 = cycle(3);
            let recall = |record: Option<&&CycleRecord>| {
                record
                    .map(|r| format!("{:.1}%", r.recall_cumulative_pct))
                    .unwrap_or_else(|| "—".to_owned())
            };
            let first_ms = c1
                .and_then(|r| r.time_to_first_ms)
                .map(|v| format!("{v} ms"))
                .unwrap_or_else(|| "—".to_owned());
            let sweep = c1
                .and_then(|r| r.sweep_duration_ms)
                .map(|v| format!("{v} ms"))
                .unwrap_or_else(|| "—".to_owned());
            let packets = c1
                .map(|r| r.packets_sent.to_string())
                .unwrap_or_else(|| "—".to_owned());
            let extras = c3
                .map(|r| r.extras.to_string())
                .unwrap_or_else(|| "—".to_owned());
            let note = match c1.map(|r| r.seed) {
                Some(seed) => format!("seed {seed}"),
                None => "—".to_owned(),
            };
            out.push_str(&format!(
                "| {variant} | {} | {} | {extras} | {first_ms} | {sweep} | {packets} | {note} |\n",
                recall(c1),
                recall(c3),
            ));
        }
        out.push('\n');
    }
    out.push_str(
        "Recall is cumulative over the cell's three cycles against the known-device count.\n\
         `Time to first` and `Sweep time` are the cycle-1 values (per-cycle values in the JSON).\n",
    );
    out
}
