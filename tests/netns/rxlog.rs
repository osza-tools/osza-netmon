// SPDX-License-Identifier: GPL-3.0-only

//! The responder receive log (task T-106).
//!
//! The dev-only responder appends one line per received frame (plus its
//! own sends, drops and lifecycle markers) and flushes per line, so the
//! driving test can poll the file while the lab is live and read the
//! full evidence afterwards (task card §3: "receive log retrievable by
//! the test").
//!
//! Format v1 (one record per line, `key=value` fields):
//!
//! ```text
//! # osza-netmon netns responder log v1
//! READY iface=v-s1b pid=1234 seed=99 drop=0.050
//! RX t=123 et=0x0806 src=32:5e:.. dst=ff:ff:ff:ff:ff:ff op=1 sip=192.0.2.1 tip=192.0.2.12 len=42
//! TX t=125 kind=answer src=02:00:00:00:00:0c dst=32:5e:.. sip=192.0.2.12 tip=192.0.2.1
//! DROP t=124 ip=192.0.2.13 idx=2 reason=probability
//! ```
//!
//! `t` is milliseconds since responder start. `RX` records carry the
//! frame's Ethernet and ARP facts (when present); `TX` records carry the
//! reply the responder sent (`kind` = `answer`, `answer-delayed` —
//! scheduled on a per-answer thread, the send itself best-effort — or
//! `hostile-<mode>`).
//!
//! Parsing is total and size-bounded (AGENTS.md rule 4): the parser
//! never panics, skips nothing silently (malformed lines are counted and
//! surfaced), and the writer caps itself at [`LOG_MAX_LINES`] records.

use std::fmt::Write as _;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read as _;
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::Path;

use osza_netmon::model::MacAddr;

use crate::config::Hostile;

/// The log writer stops after this many records (and notes it once).
pub const LOG_MAX_LINES: usize = 200_000;

/// The parser refuses to read more than this (a size-bounded read of a
/// file we still treat as untrusted input).
pub const LOG_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The loggable facts of one received frame (what [`LogWriter::rx`]
/// takes; the responder's frame parser extracts them).
#[derive(Debug, Clone, Copy, Default)]
pub struct RxFields {
    /// Ethernet EtherType, when the header was complete.
    pub et: Option<u16>,
    /// Ethernet source MAC, when present.
    pub src: Option<MacAddr>,
    /// Ethernet destination MAC, when present.
    pub dst: Option<MacAddr>,
    /// ARP opcode, when the frame carried a parseable ARP body.
    pub op: Option<u16>,
    /// ARP sender IP, when present.
    pub sip: Option<Ipv4Addr>,
    /// ARP target IP, when present.
    pub tip: Option<Ipv4Addr>,
    /// Frame length in bytes.
    pub len: usize,
}

/// The marker line written once at responder start (after the socket is
/// bound — the lab's readiness signal).
pub const READY_MARK: &str = "READY";

// ---------------------------------------------------------------------------
// Writer (responder side)
// ---------------------------------------------------------------------------

/// Appending, line-flushing log writer.
pub struct LogWriter {
    file: File,
    /// Records written so far (including non-frame records).
    lines: usize,
    /// Set once the cap was hit (the note is written once).
    capped: bool,
    /// Responder start, for `t=` millisecond timestamps.
    start: std::time::Instant,
}

impl LogWriter {
    /// Opens (truncating) the log at `path` and writes the header.
    pub fn create(path: &Path, header: &str) -> std::io::Result<Self> {
        let mut file = File::create(path)?;
        writeln!(file, "# osza-netmon netns responder log v1")?;
        if !header.is_empty() {
            writeln!(file, "{header}")?;
        }
        file.flush()?;
        Ok(Self {
            file,
            lines: 2,
            capped: false,
            start: std::time::Instant::now(),
        })
    }

    /// Milliseconds since responder start.
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Writes one record unless the cap was reached.
    pub fn record(&mut self, line: &str) {
        if self.capped {
            return;
        }
        if self.lines >= LOG_MAX_LINES {
            self.capped = true;
            let _ = writeln!(self.file, "LOG_FULL lines={}", self.lines);
            let _ = self.file.flush();
            return;
        }
        let _ = writeln!(self.file, "{line}");
        let _ = self.file.flush();
        self.lines += 1;
    }

    /// The `READY` marker (readiness signal — written after the socket
    /// is bound and the answer table is loaded).
    pub fn ready(&mut self, iface: &str, pid: u32, config_line: &str) {
        self.record(&format!(
            "{READY_MARK} iface={iface} pid={pid} {config_line}"
        ));
    }
    /// One received frame, as pre-extracted fields (see
    /// [`RxFields`] — the responder's parser picks them out).
    pub fn rx(&mut self, fields: RxFields) {
        let mut line = format!("RX t={}", self.now_ms());
        write_line_field(
            &mut line,
            "et",
            fields.et.map(|value| format!("0x{value:04x}")),
        );
        write_line_field(&mut line, "src", fields.src.map(|value| value.to_string()));
        write_line_field(&mut line, "dst", fields.dst.map(|value| value.to_string()));
        write_line_field(&mut line, "op", fields.op.map(|value| value.to_string()));
        write_line_field(&mut line, "sip", fields.sip.map(|value| value.to_string()));
        write_line_field(&mut line, "tip", fields.tip.map(|value| value.to_string()));
        let _ = write!(line, " len={}", fields.len);
        self.record(&line);
    }

    /// One sent frame (`kind` = `answer` or `hostile-…`).
    pub fn tx(&mut self, kind: &str, src: MacAddr, dst: MacAddr, sip: Ipv4Addr, tip: Ipv4Addr) {
        self.tx_raw(kind, &src.to_string(), dst, sip, tip);
    }

    /// [`tx`](Self::tx) with a pre-formatted source-MAC string — for
    /// hostile frames whose "MAC" cannot be a `MacAddr` (multicast).
    pub fn tx_raw(&mut self, kind: &str, src: &str, dst: MacAddr, sip: Ipv4Addr, tip: Ipv4Addr) {
        let t = self.now_ms();
        let line = format!("TX t={t} kind={kind} src={src} dst={dst} sip={sip} tip={tip}");
        self.record(&line);
    }

    /// One impairment decision to stay silent, with the per-address
    /// request index and the reason.
    pub fn drop_decision(&mut self, ip: Ipv4Addr, idx: u32, reason: &str) {
        let line = format!("DROP t={} ip={ip} idx={idx} reason={reason}", self.now_ms());
        self.record(&line);
    }

    /// An arbitrary marker (guard violations, send errors, shutdown).
    pub fn note(&mut self, key: &str, value: &str) {
        let line = format!("NOTE t={} {key}={value}", self.now_ms());
        self.record(&line);
    }
}

/// Appends ` key=value` when the field is present.
fn write_line_field(line: &mut String, key: &str, value: Option<String>) {
    if let Some(value) = value {
        let _ = write!(line, " {key}={value}");
    }
}

// ---------------------------------------------------------------------------
// Parser (test side)
// ---------------------------------------------------------------------------

/// One received-frame record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxRecord {
    /// Milliseconds since responder start.
    pub t: u64,
    /// Ethernet EtherType, when the Ethernet header was complete.
    pub et: Option<u16>,
    /// Ethernet source MAC, when present.
    pub src: Option<MacAddr>,
    /// Ethernet destination MAC, when present.
    pub dst: Option<MacAddr>,
    /// ARP opcode, when the frame carried a parseable ARP body.
    pub op: Option<u16>,
    /// ARP sender IP, when present.
    pub sip: Option<Ipv4Addr>,
    /// ARP target IP, when present.
    pub tip: Option<Ipv4Addr>,
    /// Frame length in bytes.
    pub len: usize,
}

/// One sent-frame record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxRecord {
    /// Milliseconds since responder start.
    pub t: u64,
    /// `answer` or `hostile-<mode>`.
    pub kind: String,
    /// The reply's sender MAC, as written (a plain string: hostile
    /// frames can carry multicast sources that no `MacAddr` can
    /// represent — T-002's constructor rejects them by design).
    pub src: String,
    /// The reply's target (the scanner side).
    pub dst: MacAddr,
    /// The reply's claimed IP.
    pub sip: Ipv4Addr,
    /// The reply's target IP.
    pub tip: Ipv4Addr,
}

/// One impairment drop decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropRecord {
    /// Milliseconds since responder start.
    pub t: u64,
    /// The address that stayed silent.
    pub ip: Ipv4Addr,
    /// The per-address request index at the decision.
    pub idx: u32,
    /// `ignore-first` | `probability` | `fraction`.
    pub reason: String,
}

/// A parsed receive log.
#[derive(Debug, Default)]
pub struct RxLog {
    /// `RX` records in arrival order.
    pub rx: Vec<RxRecord>,
    /// `TX` records in arrival order.
    pub tx: Vec<TxRecord>,
    /// `DROP` records in arrival order.
    pub drops: Vec<DropRecord>,
    /// The `READY` line, if seen.
    pub ready: Option<String>,
    /// `NOTE key=value` records (guard violations, send errors, …).
    pub notes: Vec<String>,
    /// Lines that failed to parse (must stay zero for our own logs).
    pub malformed: usize,
}

impl RxLog {
    /// Reads and parses the log at `path` (bounded by [`LOG_MAX_BYTES`]).
    pub fn read(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file.take(LOG_MAX_BYTES));
        let mut log = Self::default();
        for line in reader.lines() {
            let line = line?;
            let line = line.trim_end_matches('\r');
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix("READY ") {
                log.ready = Some(rest.to_owned());
                continue;
            }
            let mut fields = line.split_whitespace();
            let tag = fields.next().unwrap_or_default();
            let kv = FieldMap::new(fields);
            match tag {
                "RX" => log.rx.push(RxRecord {
                    t: kv.u64_field("t"),
                    et: kv.hex_u16_field("et"),
                    src: kv.mac_field("src"),
                    dst: kv.mac_field("dst"),
                    op: kv.u16_field("op"),
                    sip: kv.ip_field("sip"),
                    tip: kv.ip_field("tip"),
                    len: kv.u64_field("len") as usize,
                }),
                "TX" => {
                    // `src` is kept as written (hostile frames may carry
                    // non-unicast sources); the structural fields must
                    // parse.
                    let src = kv.str_field("src").unwrap_or_default().to_owned();
                    let (Some(dst), Some(sip), Some(tip)) =
                        (kv.mac_field("dst"), kv.ip_field("sip"), kv.ip_field("tip"))
                    else {
                        log.malformed += 1;
                        continue;
                    };
                    if src.is_empty() {
                        log.malformed += 1;
                        continue;
                    }
                    log.tx.push(TxRecord {
                        t: kv.u64_field("t"),
                        kind: kv.str_field("kind").unwrap_or_default().to_owned(),
                        src,
                        dst,
                        sip,
                        tip,
                    });
                }
                "DROP" => log.drops.push(DropRecord {
                    t: kv.u64_field("t"),
                    ip: match kv.ip_field("ip") {
                        Some(ip) => ip,
                        None => {
                            log.malformed += 1;
                            continue;
                        }
                    },
                    idx: kv.u64_field("idx") as u32,
                    reason: kv.str_field("reason").unwrap_or_default().to_owned(),
                }),
                "NOTE" => log.notes.push(line.to_owned()),
                "LOG_FULL" => log.notes.push(line.to_owned()),
                _ => log.malformed += 1,
            }
        }
        Ok(log)
    }

    /// All `RX` records that are ARP requests (`et=0x0806`, `op=1`) with
    /// the given Ethernet source — i.e. the frames the scanner sent.
    pub fn scanner_requests(&self, scanner_mac: MacAddr) -> Vec<&RxRecord> {
        self.rx
            .iter()
            .filter(|record| {
                record.et == Some(0x0806) && record.op == Some(1) && record.src == Some(scanner_mac)
            })
            .collect()
    }

    /// Frames whose Ethernet source is `scanner_mac` but which are *not*
    /// ARP requests — any such frame is non-conforming egress (S6).
    pub fn scanner_non_requests(&self, scanner_mac: MacAddr) -> Vec<&RxRecord> {
        self.rx
            .iter()
            .filter(|record| {
                record.src == Some(scanner_mac)
                    && !(record.et == Some(0x0806) && record.op == Some(1))
            })
            .collect()
    }

    /// Frames received from any other source (the lab's own kernel
    /// traffic: ARP replies, IPv6 if any) — recorded for honest S6 notes.
    pub fn environment_frames(&self, scanner_mac: MacAddr) -> Vec<&RxRecord> {
        self.rx
            .iter()
            .filter(|record| record.src != Some(scanner_mac))
            .collect()
    }

    /// How many times each address was requested by the scanner
    /// (`ARP request → target IP` counts; S2's per-target evidence).
    pub fn request_counts_per_target(&self, scanner_mac: MacAddr) -> Vec<(Ipv4Addr, u64)> {
        let mut counts: std::collections::BTreeMap<Ipv4Addr, u64> =
            std::collections::BTreeMap::new();
        for record in self.scanner_requests(scanner_mac) {
            if let Some(tip) = record.tip {
                *counts.entry(tip).or_default() += 1;
            }
        }
        counts.into_iter().collect()
    }

    /// The largest number of scanner requests inside any sliding
    /// `window_ms` window (the rate-bound evidence for S2/S6).
    pub fn max_requests_in_window(&self, scanner_mac: MacAddr, window_ms: u64) -> u64 {
        let times: Vec<u64> = self
            .scanner_requests(scanner_mac)
            .iter()
            .filter_map(|record| record.tip.map(|_| record.t))
            .collect();
        if times.is_empty() {
            return 0;
        }
        // Two-pointer over the sorted-by-arrival timestamps.
        let mut best = 0u64;
        let mut left = 0usize;
        for right in 0..times.len() {
            while times[right] - times[left] > window_ms {
                left += 1;
            }
            let count = (right - left + 1) as u64;
            if count > best {
                best = count;
            }
        }
        best
    }

    /// The smallest gap in milliseconds between consecutive scanner
    /// requests (pacing evidence: the deadline-based sender never
    /// bursts).
    pub fn min_request_gap_ms(&self, scanner_mac: MacAddr) -> Option<u64> {
        let times: Vec<u64> = self
            .scanner_requests(scanner_mac)
            .iter()
            .filter_map(|record| record.tip.map(|_| record.t))
            .collect();
        if times.len() < 2 {
            return None;
        }
        times.windows(2).map(|pair| pair[1] - pair[0]).min()
    }

    /// `true` when the responder recorded a guard violation for the
    /// given hostile mode (e.g. the unsolicited reply lost its race
    /// against the scanner's solicitation).
    pub fn has_guard_violation(&self, mode: &Hostile) -> bool {
        let needle = match mode {
            Hostile::Unsolicited { .. } => "guard=unsolicited-late",
            Hostile::Truncated { .. } => "guard=truncated-late",
            Hostile::MulticastMac { .. } => "guard=multicast-late",
            Hostile::OutOfScope { .. } => "guard=out-of-scope-late",
            Hostile::Flood { .. } => "guard=flood-late",
            Hostile::None => return false,
        };
        self.notes
            .iter()
            .any(|note| note.contains("guard=") && note.contains(needle))
    }
}

/// A tiny `key=value` field map over the remainder of a line.
struct FieldMap<'a> {
    map: std::collections::HashMap<&'a str, &'a str>,
}

impl<'a> FieldMap<'a> {
    fn new(fields: impl Iterator<Item = &'a str>) -> Self {
        let mut map = std::collections::HashMap::new();
        for field in fields {
            if let Some((key, value)) = field.split_once('=') {
                map.insert(key, value);
            }
        }
        Self { map }
    }

    fn str_field(&self, key: &str) -> Option<&'a str> {
        self.map.get(key).copied()
    }

    fn u64_field(&self, key: &str) -> u64 {
        self.str_field(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    fn u16_field(&self, key: &str) -> Option<u16> {
        self.str_field(key).and_then(|v| v.parse().ok())
    }

    fn hex_u16_field(&self, key: &str) -> Option<u16> {
        self.str_field(key).and_then(|v| {
            let digits = v.strip_prefix("0x").unwrap_or(v);
            u16::from_str_radix(digits, 16).ok()
        })
    }

    fn mac_field(&self, key: &str) -> Option<MacAddr> {
        self.str_field(key).and_then(|v| v.parse().ok())
    }

    fn ip_field(&self, key: &str) -> Option<Ipv4Addr> {
        self.str_field(key).and_then(|v| v.parse().ok())
    }
}

/// Self-tests of this module (the harness target has no libtest runner;
/// these run as part of the suite's self-check scenario).
pub mod selftests {
    use super::*;

    fn write_log(lines: &[&str]) -> RxLog {
        let dir = std::env::temp_dir().join(format!("ozs-rxlog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.txt");
        let mut file = File::create(&path).unwrap();
        writeln!(file, "# header").unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
        RxLog::read(&path).unwrap()
    }

    pub fn parses_ready_rx_tx_drop_and_notes() {
        let log = write_log(&[
            "READY iface=v pid=7 seed=1 drop=0.000",
            "RX t=10 et=0x0806 src=32:5e:d9:91:36:68 dst=ff:ff:ff:ff:ff:ff op=1 sip=192.0.2.1 tip=192.0.2.12 len=42",
            "TX t=11 kind=answer src=02:00:00:00:00:0c dst=32:5e:d9:91:36:68 sip=192.0.2.12 tip=192.0.2.1",
            "DROP t=12 ip=192.0.2.13 idx=1 reason=ignore-first",
            "NOTE t=13 guard=unsolicited-late",
            "RX t=20 et=0x86dd src=32:5e:d9:91:36:68 dst=33:33:00:00:00:01 len=86",
        ]);
        assert_eq!(
            log.ready.as_deref(),
            Some("iface=v pid=7 seed=1 drop=0.000")
        );
        assert_eq!(log.rx.len(), 2);
        assert_eq!(log.tx.len(), 1);
        assert_eq!(log.drops.len(), 1);
        assert_eq!(log.notes.len(), 1);
        assert_eq!(log.malformed, 0);

        let scanner: MacAddr = "32:5e:d9:91:36:68".parse().unwrap();
        // One request, one non-request (the IPv6 frame) from the scanner.
        assert_eq!(log.scanner_requests(scanner).len(), 1);
        assert_eq!(log.scanner_non_requests(scanner).len(), 1);
        // The non-ARP frame's source is still the scanner, so it is not
        // an environment frame.
        assert_eq!(log.environment_frames(scanner).len(), 0);
        assert_eq!(
            log.request_counts_per_target(scanner),
            vec![("192.0.2.12".parse().unwrap(), 1u64)]
        );
        assert!(log.has_guard_violation(&Hostile::Unsolicited {
            ip: "192.0.2.9".parse().unwrap()
        }));
    }

    pub fn window_and_gap_math() {
        let scanner: MacAddr = "32:5e:d9:91:36:68".parse().unwrap();
        let mk = |t: u64, tip: u8| {
            format!(
                "RX t={t} et=0x0806 src=32:5e:d9:91:36:68 dst=ff:ff:ff:ff:ff:ff \
                 op=1 sip=192.0.2.1 tip=192.0.2.{tip} len=42"
            )
        };
        let log = write_log(&[
            &mk(0, 10),
            &mk(10, 11),
            &mk(20, 12),
            &mk(30, 13),
            &mk(1000, 14),
        ]);
        assert_eq!(log.max_requests_in_window(scanner, 1000), 5); // t=0 and t=1000 span exactly the inclusive window
        assert_eq!(log.max_requests_in_window(scanner, 25), 3);
        assert_eq!(log.min_request_gap_ms(scanner), Some(10));
        assert_eq!(log.malformed, 0);
    }

    pub fn malformed_lines_are_counted_never_panicked() {
        let log = write_log(&[
            "RX t=1 et=0xZZZZ src=not-a-mac op=1 len=abc",
            "GIBBERISH x y z",
            "TX t=2 kind=answer",
        ]);
        // `RX` parses (fields default to None/0 on garbage); the unknown
        // tag and the keyless TX are counted malformed.
        assert!(log.malformed >= 1);
        assert_eq!(log.rx.len(), 1);
    }
}
