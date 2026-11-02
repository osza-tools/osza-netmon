// SPDX-License-Identifier: GPL-3.0-only

//! The dev-only responder (task T-106, task card §3 — implementation
//! option (a): self-reexec of the test binary via `--responder`, no new
//! artifact).
//!
//! Runs inside the device-side nested `unshare --net` namespace of a
//! lab. Binds one `AF_PACKET` channel on the configured veth end (via
//! the production [`open_raw_socket`] — user-namespace root supplies
//! `CAP_NET_RAW`, ADR-005), then:
//!
//! 1. logs every received frame ([`LogWriter`]);
//! 2. answers ARP requests for the configured address table with
//!    synthetic MACs (`02:…`, plan §14.3 rule 8);
//! 3. applies the seeded impairment (P0–P3, S9 — one decision chain per
//!    request: ignore-first → drop draw → fraction draw → delay draw,
//!    all from one [`Rng`] stream, never wall-clock);
//! 4. fires the configured hostile mode once, on the first request
//!    (plan §11.2 S5).
//!
//! All output goes to the log file — the responder never writes to the
//! parent's stdio and exits `0` only on a clean lifetime end; a startup
//! failure is logged and exits non-zero (the lab's readiness wait turns
//! that into a test failure with the log as evidence).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use osza_netmon::discovery::arp::ArpTransport;
use osza_netmon::discovery::arp::LinuxArpTransport;
use osza_netmon::discovery::privilege::open_raw_socket;
use osza_netmon::model::MacAddr;

use crate::config::Answer;
use crate::config::Hostile;
use crate::config::ResponderConfig;
use crate::frames;
use crate::frames::ArpRequestView;
use crate::rng::Rng;
use crate::rxlog::LogWriter;

/// The receive poll interval — short enough that request timestamps
/// track arrivals closely (the rate evidence of S2/S6), long enough to
/// idle cheaply.
const RECV_POLL: Duration = Duration::from_millis(20);

/// Safety lifetime: the responder never outlives this even if its parent
/// dies without killing it (hang-proofing, task card §8).
const MAX_LIFETIME: Duration = Duration::from_secs(900);

/// Entry point of the `--responder` subcommand (`args` are the flags
/// after `--responder`).
pub fn main(args: &[std::ffi::OsString]) {
    let mut config_path: Option<PathBuf> = None;
    let mut log_path: Option<PathBuf> = None;
    let mut pairs = args.iter();
    while let Some(flag) = pairs.next() {
        let flag = flag.to_string_lossy();
        match flag.as_ref() {
            "--config" => {
                config_path = pairs.next().map(PathBuf::from);
            }
            "--log" => {
                log_path = pairs.next().map(PathBuf::from);
            }
            other => {
                eprintln!("responder: unknown argument {other:?}");
                exit(2);
            }
        }
    }
    let (Some(config_path), Some(log_path)) = (config_path, log_path) else {
        eprintln!("responder: --config <path> and --log <path> are required");
        exit(2);
    };

    if let Err(error) = run(&config_path, &log_path) {
        eprintln!("responder: {error}");
        // The log is the evidence channel; the parent's readiness wait
        // reports it.
        if let Ok(mut writer) = LogWriter::create(&log_path, "") {
            writer.note("fatal", &error);
        }
        exit(1);
    }
}

/// The responder body; `Err` = startup failure (logged by the caller).
fn run(config_path: &Path, log_path: &Path) -> Result<(), String> {
    let raw = std::fs::read(config_path)
        .map_err(|error| format!("reading config {}: {error}", config_path.display()))?;
    if raw.len() as u64 > crate::config::CONFIG_MAX_BYTES {
        return Err("the config file exceeds the size bound".to_owned());
    }
    let text = String::from_utf8(raw).map_err(|_| "the config file is not UTF-8".to_owned())?;
    let config = ResponderConfig::parse(&text)?;

    let socket = open_raw_socket(&config.iface)
        .map_err(|error| format!("opening the raw socket on {}: {error}", config.iface))?;
    // Arc-shared: delayed answers are sent from per-answer threads so
    // the delay of one device never queues behind another's (the
    // impairment models per-*device* latency — a serial sleeper would
    // add a phantom shared bottleneck and understate recall).
    let transport = Arc::new(LinuxArpTransport::new(socket));

    let mut writer =
        LogWriter::create(log_path, "").map_err(|error| format!("creating the log: {error}"))?;
    writer.ready(
        &config.iface,
        std::process::id(),
        &config.impairment.to_string(),
    );

    let mut responder = Responder {
        config: &config,
        transport,
        log: &mut writer,
        rng: Rng::new(config.impairment.seed),
        request_index: HashMap::new(),
        hostile_fired: false,
        started: Instant::now(),
    };
    responder.serve();
    writer.note("shutdown", "lifetime-end");
    Ok(())
}

/// The serving state (one lab, one responder).
struct Responder<'a> {
    config: &'a ResponderConfig,
    transport: Arc<LinuxArpTransport>,
    log: &'a mut LogWriter,
    rng: Rng,
    /// Per-address request counters (span scan cycles — the sleepy-host
    /// semantics of S9/P3).
    request_index: HashMap<Ipv4Addr, u32>,
    hostile_fired: bool,
    started: Instant,
}

impl Responder<'_> {
    /// The main loop: receive, log, decide, answer.
    fn serve(&mut self) {
        while self.started.elapsed() < MAX_LIFETIME {
            match self.transport.recv(RECV_POLL) {
                Ok(Some(frame)) => self.handle_frame(&frame),
                Ok(None) => {}
                Err(err) if err.is_fatal() => {
                    self.log.note("fatal-recv", &err.to_string());
                    return;
                }
                Err(_) => {}
            }
        }
    }

    /// Logs one frame and reacts to it if it is an ARP request.
    fn handle_frame(&mut self, frame: &[u8]) {
        let view = frames::parse_arp_request(frame);
        let (op, sip, tip) = arp_body_fields(frame, view);
        self.log.rx(crate::rxlog::RxFields {
            et: frames::ethertype(frame),
            src: frames::eth_src(frame),
            dst: frames::eth_dst(frame),
            op,
            sip,
            tip,
            len: frame.len(),
        });

        let Some(request) = view else {
            return;
        };
        if !self.hostile_fired {
            self.hostile_fired = true;
            self.fire_hostile(&request);
        }
        self.maybe_answer(&request);
    }

    /// The impairment decision chain for one answer-table request.
    fn maybe_answer(&mut self, request: &ArpRequestView) {
        let Some(answer) = self.lookup(request.target_ip) else {
            return; // not ours: the kernel or nobody answers.
        };
        let idx = self.bump_index(request.target_ip);
        let impairment = &self.config.impairment;

        if idx <= impairment.ignore_first {
            self.log
                .drop_decision(request.target_ip, idx, "ignore-first");
            return;
        }
        if self.rng.chance(impairment.drop_prob) {
            self.log
                .drop_decision(request.target_ip, idx, "probability");
            return;
        }
        if !self.rng.chance(impairment.answer_fraction) {
            self.log.drop_decision(request.target_ip, idx, "fraction");
            return;
        }
        let delay_ms = if impairment.delay_max_ms == 0 {
            0
        } else {
            self.rng
                .range(impairment.delay_min_ms, impairment.delay_max_ms)
        };
        self.send_reply_delayed(
            request.requester_mac,
            answer,
            request.requester_ip,
            delay_ms,
        );
    }

    /// Sends one answer for `answer`, after `delay_ms` — concurrently
    /// with the receive loop when the delay is nonzero (per-answer
    /// thread; see the `Arc` note in [`run`]). The TX record is written
    /// at *scheduling* time; the delayed send itself is best-effort
    /// (a socket that died with the lab drops the frame silently).
    fn send_reply_delayed(&mut self, dst: MacAddr, answer: Answer, tpa: Ipv4Addr, delay_ms: u64) {
        let frame = frames::build_arp_reply(dst, answer.mac.octets(), answer.ip, dst, tpa);
        if delay_ms == 0 {
            match self.transport.send(&frame) {
                Ok(()) => self.log.tx("answer", answer.mac, dst, answer.ip, tpa),
                Err(err) => self.log.note("send-error", &err.to_string()),
            }
            return;
        }
        // Delayed: schedule now (log included), send from a thread.
        self.log
            .tx("answer-delayed", answer.mac, dst, answer.ip, tpa);
        let transport = Arc::clone(&self.transport);
        let thread_frame = frame.clone();
        let spawn = std::thread::Builder::new()
            .name("ozs-delayed-answer".to_owned())
            .spawn(move || {
                std::thread::sleep(Duration::from_millis(delay_ms));
                // Best-effort: errors are invisible here by design (the
                // receive loop's own channel is the evidence path).
                let _ = transport.send(&thread_frame);
            });
        if spawn.is_err() {
            // Thread exhaustion: fall back to the honest inline path.
            std::thread::sleep(Duration::from_millis(delay_ms));
            let _ = self.transport.send(&frame);
        }
    }

    /// Sends one reply frame and logs it under `kind` (`sha` is raw
    /// octets — see [`frames::build_arp_reply`]).
    fn send_reply(&mut self, dst: MacAddr, sha: [u8; 6], spa: Ipv4Addr, tpa: Ipv4Addr, kind: &str) {
        let frame = frames::build_arp_reply(dst, sha, spa, dst, tpa);
        match self.transport.send(&frame) {
            Ok(()) => {
                let src = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]
                );
                self.log.tx_raw(kind, &src, dst, spa, tpa)
            }
            Err(err) => self.log.note("send-error", &err.to_string()),
        }
    }

    /// The answer-table entry for `ip`, if any.
    fn lookup(&self, ip: Ipv4Addr) -> Option<Answer> {
        self.config
            .answers
            .iter()
            .copied()
            .find(|entry| entry.ip == ip)
    }

    /// Increments (from 1) and returns the per-address request index.
    fn bump_index(&mut self, ip: Ipv4Addr) -> u32 {
        let counter = self.request_index.entry(ip).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Emits the configured hostile traffic once, on the first request.
    ///
    /// Every mode races against the scanner's solicitation by
    /// construction, so each one is guarded: if this responder has
    /// already seen a request for the address the hostile frame claims
    /// (visible in the request-index map), a `guard=<mode>-late` note is
    /// logged — the driving test turns that into a failure instead of a
    /// silently wrong tally (deterministic behavior, never a wall-clock
    /// race — T-104 review F-6).
    fn fire_hostile(&mut self, request: &ArpRequestView) {
        match self.config.hostile {
            Hostile::None => {}
            Hostile::Unsolicited { ip } => {
                if self.request_index.contains_key(&ip) {
                    self.log.note("guard", "unsolicited-late");
                    return;
                }
                // A valid reply for an address the scanner has not asked
                // for yet (the test picks one that sorts after the first
                // target, so it cannot have been solicited at this point).
                self.send_reply(
                    request.requester_mac,
                    synthetic_hostile_mac(ip).octets(),
                    ip,
                    request.requester_ip,
                    "hostile-unsolicited",
                );
            }
            Hostile::Truncated { ip } => {
                if self.request_index.contains_key(&ip) {
                    self.log.note("guard", "truncated-late");
                    return;
                }
                let full = frames::build_arp_reply(
                    request.requester_mac,
                    synthetic_hostile_mac(ip).octets(),
                    ip,
                    request.requester_mac,
                    request.requester_ip,
                );
                let cut = full.get(..20).unwrap_or(&full);
                match self.transport.send(cut) {
                    Ok(()) => {
                        self.log.tx(
                            "hostile-truncated",
                            synthetic_hostile_mac(ip),
                            request.requester_mac,
                            ip,
                            request.requester_ip,
                        );
                    }
                    Err(err) => self.log.note("send-error", &err.to_string()),
                }
            }
            Hostile::MulticastMac { ip } => {
                if self.request_index.contains_key(&ip) {
                    self.log.note("guard", "multicast-late");
                    return;
                }
                // Structurally consistent reply whose sender MAC is
                // multicast → InvalidMac at the scanner.
                self.send_reply(
                    request.requester_mac,
                    hostile_multicast_mac_octets(),
                    ip,
                    request.requester_ip,
                    "hostile-multicast-mac",
                );
            }
            Hostile::OutOfScope { ip } => {
                if self.request_index.contains_key(&ip) {
                    self.log.note("guard", "out-of-scope-late");
                    return;
                }
                // Valid unicast MAC, consistent Ethernet, but the claimed
                // IP is outside the scan scope → OutOfScope.
                self.send_reply(
                    request.requester_mac,
                    synthetic_hostile_mac(ip).octets(),
                    ip,
                    request.requester_ip,
                    "hostile-out-of-scope",
                );
            }
            Hostile::Flood { count } => {
                if self.config.answers.is_empty() {
                    self.log.note("guard", "flood-empty-table");
                    return;
                }
                let mut sent = 0u32;
                for i in 0..count {
                    let answer = self.config.answers[(i as usize) % self.config.answers.len()];
                    let frame = frames::build_arp_reply(
                        request.requester_mac,
                        answer.mac.octets(),
                        answer.ip,
                        request.requester_mac,
                        request.requester_ip,
                    );
                    if let Err(err) = self.transport.send(&frame) {
                        self.log.note("send-error", &err.to_string());
                    } else {
                        sent += 1;
                    }
                }
                // One summary line; per-frame TX records would only
                // bloat the log (the flood count is what matters).
                self.log.note("flood-sent", &sent.to_string());
            }
        }
    }
}

/// Log fields for the ARP body of a frame: for a request view the
/// requester/target pair; otherwise whatever a full-size ARP body
/// carries (replies), `None` for anything shorter.
fn arp_body_fields(
    frame: &[u8],
    view: Option<ArpRequestView>,
) -> (Option<u16>, Option<Ipv4Addr>, Option<Ipv4Addr>) {
    if let Some(view) = view {
        return (Some(1), Some(view.requester_ip), Some(view.target_ip));
    }
    if frame.len() < frames::ETH_ARP_LEN || frames::ethertype(frame) != Some(0x0806) {
        return (None, None, None);
    }
    let op = Some(u16::from_be_bytes([frame[20], frame[21]]));
    let sip = Some(Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]));
    let tip = Some(Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]));
    (op, sip, tip)
}

/// The multicast sender MAC octets of the hostile `multicast_mac`
/// mode (`01:00:5e:…` — the IPv4 multicast OUI; never a valid unicast
/// source, plan Appendix E MAC bits). Raw bytes by necessity: the
/// `MacAddr` constructor rejects multicast addresses by design
/// (T-002), and the hostile frame must carry one anyway — the
/// scanner's parser is the authority that rejects it.
fn hostile_multicast_mac_octets() -> [u8; 6] {
    [0x01, 0x00, 0x5E, 0xAA, 0x00, 0x01]
}

/// A locally-administered synthetic MAC for the hostile frames
/// (`02:00:00:00:ff:xx`, `xx` = the claimed IP's host byte).
fn synthetic_hostile_mac(ip: Ipv4Addr) -> MacAddr {
    MacAddr::from_octets([0x02, 0x00, 0x00, 0x00, 0xFF, ip.octets()[3]])
        .unwrap_or_else(|_| unreachable!("02:… is always a valid unicast MAC"))
}
