// SPDX-License-Identifier: GPL-3.0-only

//! The ARP sweep engine (plan §6.3 FR-DS-03…11, §4 ADR-011/ADR-012;
//! task T-104).
//!
//! [`ArpScanner`] drives one scan over one scope through any
//! [`ArpTransport`] (ADR-009 stays Pending; the production transport is
//! provisional and swappable). One scan:
//!
//! 1. **Target generation** (FR-SC-05, via the private `targets`
//!    iterator): every host of
//!    the scope except the network address, the broadcast address and
//!    the interface's own address; `/31` keeps both addresses (RFC
//!    3021); `/32` (or any empty scope) completes immediately with zero
//!    counters. Targets are generated lazily — never materialized.
//! 2. **Pacing** (FR-DS-04): sends are scheduled on deadlines —
//!    `max(previous_deadline, now) + interval` — so a late wake-up is
//!    never compensated with a burst; waiting happens in cancel-checked
//!    slices.
//! 3. **Multi-pass** (ADR-011): pass 1 reaches every target; pass 2+
//!    re-probes only the non-responders as of the pass start, after a
//!    pass gap measured from the previous pass's last send; with no
//!    non-responders left, the remaining passes and the gap are skipped.
//! 4. **Concurrent listen** (ADR-012: `std::thread`, no async): the
//!    calling thread sends while a receive thread polls
//!    [`ArpTransport::recv`] and validates every frame with T-103's
//!    [`parse_arp_reply`] against this scan's **solicited set** — the
//!    address is inserted *before* its request is sent, so a fast reply
//!    is never misjudged unsolicited.
//! 5. **Listen window**: after the last send, replies keep flowing for
//!    `listen_window` before the scan returns.
//! 6. **Cancellation** (FR-DS-09): every wait — pacing, pass gap, listen
//!    window, receive poll — is sliced at ≤ 50 ms with a flag check, so
//!    the scan returns within 250 ms of the cancel flag in every phase.
//!
//! The outcome classification (FR-DS-11) is first-terminal-event-wins:
//! `Cancelled`, then `Failed` (fatal transport error, or every attempted
//! send failed), then end-of-scan `Partial` (a transient send error
//! occurred) or `Complete`.

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::discovery::arp::codec::ArpReply;
use crate::discovery::arp::codec::ArpReplyContext;
use crate::discovery::arp::codec::ArpReplyCounters;
use crate::discovery::arp::codec::build_arp_request;
use crate::discovery::arp::codec::parse_arp_reply;
use crate::discovery::arp::transport::ArpTransport;
use crate::discovery::arp::transport::TransportError;
use crate::discovery::neighbor_table::NeighborEntry;
use crate::discovery::privilege::lock_or_recover;
use crate::model::field::Source;
use crate::model::ipv4::Ipv4Net;
use crate::model::mac::MacAddr;

// ---------------------------------------------------------------------------
// Tunables and defaults (ADR-011 unless noted)
// ---------------------------------------------------------------------------

/// Default send rate, 100 packets/s (FR-DS-04).
pub const DEFAULT_RATE_PPS: u32 = 100;

/// Maximum send rate, 500 packets/s (FR-DS-04).
pub const MAX_RATE_PPS: u32 = 500;

/// Default per-scan response cap: **1,024** distinct accepted
/// observations (plan §7.1 mitigation; task card §3.2).
pub const DEFAULT_RESPONSE_CAP: usize = 1_024;

/// Default pass gap: **1 s** between the last send of one pass and the
/// first send of the next (ADR-011).
pub const DEFAULT_PASS_GAP: Duration = Duration::from_secs(1);

/// Default listen window: **1.5 s** after the last send of the last pass
/// (ADR-011).
pub const DEFAULT_LISTEN_WINDOW: Duration = Duration::from_millis(1_500);

/// Upper bound for `passes`: the plan's probe-strategy experiment space
/// is "passes 1/2/3" (Appendix D), and ADR-011's defaults are 2 (initial
/// scan) and 1 (periodic rediscovery) — no larger value is meaningful
/// until T-105 says otherwise (Plan Question PQ-2 in the T-104 execution
/// report).
pub const MAX_PASSES: u8 = 3;

/// Every interruptible wait sleeps in slices of at most this long, so a
/// cancel flag is observed well inside FR-DS-09's 250 ms budget.
const CANCEL_SLICE: Duration = Duration::from_millis(50);

/// The receive thread's poll interval: at most 50 ms per task card
/// §3.2; 20 ms leaves margin for the join on top of a final poll.
const RECV_POLL: Duration = Duration::from_millis(20);

/// Ethernet EtherType ARP (`0x0806`) at frame offsets 12..14 — the
/// software filter the production transport needs because it opens the
/// socket with `ETH_P_ALL` (task card §2.1; the frame still passes
/// through [`parse_arp_reply`], which re-checks condition 1).
const ETHERTYPE_ARP_BE: [u8; 2] = [0x08, 0x06];

// ---------------------------------------------------------------------------
// Scan outputs
// ---------------------------------------------------------------------------

/// One piece of discovery evidence (plan §5.1: an `(MAC, IPv4)` sighting
/// with its source).
///
/// The scanner emits these with [`Source::ArpReply`]; the neighbor-table
/// read converts its entries with [`Observation::from_neighbor`]. This
/// is the shared observation type of the discovery layer — see the T-104
/// execution report (Plan Question PQ-3) for why it lives here and not
/// as a duplicate in each source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Observation {
    /// The observed IPv4 address.
    pub ip: Ipv4Addr,
    /// The observed (validated, unicast) hardware address.
    pub mac: MacAddr,
    /// Where the evidence came from.
    pub source: Source,
}

impl Observation {
    /// An observation from one accepted ARP reply (source `ArpReply`).
    pub fn from_arp_reply(reply: &ArpReply) -> Self {
        Self {
            ip: reply.sender_ip,
            mac: reply.sender_mac,
            source: Source::ArpReply,
        }
    }

    /// An observation from one neighbor-table row (source
    /// `NeighborTable`).
    pub fn from_neighbor(entry: &NeighborEntry) -> Self {
        Self {
            ip: entry.ip(),
            mac: entry.mac(),
            source: Source::NeighborTable,
        }
    }

    /// The source label used by the example's summary lines (factual,
    /// plan §5.4 vocabulary; not a verdict).
    pub fn source_label(&self) -> &'static str {
        match self.source {
            Source::ArpReply => "arp reply",
            Source::NeighborTable => "neighbor table",
            Source::LocalInterface => "local interface",
            Source::ReverseDns => "reverse dns",
            Source::VendorDb => "vendor db",
        }
    }
}

impl fmt::Display for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ({})", self.ip, self.mac, self.source_label())
    }
}

/// Why a scan ended the way it did (FR-DS-11; task card §3.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanOutcome {
    /// All targets of all executed passes were sent without error and
    /// the listen window elapsed.
    #[error("complete")]
    Complete,
    /// The scan ran to the end but at least one transient send error
    /// occurred.
    #[error("partial")]
    Partial,
    /// A fatal transport error occurred, or every attempted send failed.
    /// Observations gathered before the failure are kept.
    #[error("failed: {reason}")]
    Failed {
        /// The fatal reason, as one line.
        reason: String,
    },
    /// The cancel flag was observed (FR-DS-09).
    #[error("cancelled")]
    Cancelled,
}

/// What one scan did, in numbers (task card §3.2).
///
/// `targets` counts probe target *attempts* started (one per target loop
/// iteration that reached the send call, summed over passes — for a full
/// pass 1 that is the whole target set), so
/// `targets == requests_sent + send_errors_transient + send_errors_fatal`
/// always holds. `replies` carries T-103's by-reason rejection tallies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanCounters {
    /// Probe target attempts started across all executed passes.
    pub targets: u64,
    /// Requests actually handed to the transport.
    pub requests_sent: u64,
    /// Transient send failures (counted; the scan continues → `Partial`).
    pub send_errors_transient: u64,
    /// Fatal send failures (the scan stops → `Failed`).
    pub send_errors_fatal: u64,
    /// Distinct accepted observations (after dedup, under the cap).
    pub replies_accepted: u64,
    /// Replies rejected by [`parse_arp_reply`], all reasons combined.
    pub replies_rejected: u64,
    /// Accepted replies re-seeing a known `(ip, mac)` pair.
    pub duplicates: u64,
    /// Valid replies dropped because the response cap was reached.
    pub cap_dropped: u64,
    /// Passes whose sending began (a pass interrupted mid-flight still
    /// ran).
    pub passes_run: u8,
    /// T-103's reply tallies, including every rejection reason.
    pub replies: ArpReplyCounters,
}

impl fmt::Display for ScanCounters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "targets={} sent={} send_errors={} (transient={} fatal={}) \
             accepted={} rejected={} duplicates={} cap_dropped={} passes={}",
            self.targets,
            self.requests_sent,
            self.send_errors_transient + self.send_errors_fatal,
            self.send_errors_transient,
            self.send_errors_fatal,
            self.replies_accepted,
            self.replies_rejected,
            self.duplicates,
            self.cap_dropped,
            self.passes_run
        )
    }
}

/// The result of one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// FR-DS-11 classification; first terminal event wins.
    pub outcome: ScanOutcome,
    /// Accepted observations. Empty after
    /// [`scan_with_sink`](ArpScanner::scan_with_sink) — there the
    /// sink stream is the delivery (task card §3.2);
    /// [`scan`](ArpScanner::scan) collects.
    pub observations: Vec<Observation>,
    /// What the scan did.
    pub counters: ScanCounters,
    /// Wall time from scan start to return.
    pub elapsed: Duration,
}

// ---------------------------------------------------------------------------
// The scanner
// ---------------------------------------------------------------------------

/// The ARP sweep engine over one scope (task card §3.2).
///
/// Cheap to construct and reuseable for many scans: it owns only the
/// transport and the scope facts. All per-scan state (solicited set,
/// responders, counters) lives inside the scan call, so nothing carries
/// over between scans.
pub struct ArpScanner {
    transport: Box<dyn ArpTransport>,
    scope: Ipv4Net,
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    pass_gap: Duration,
    response_cap: usize,
}

impl ArpScanner {
    /// A scanner for `scope`, announcing `our_mac`/`our_ip` in every
    /// request (FR-DS-03) and sweeping through `transport`.
    pub fn new(
        transport: Box<dyn ArpTransport>,
        scope: Ipv4Net,
        our_mac: MacAddr,
        our_ip: Ipv4Addr,
    ) -> Self {
        Self {
            transport,
            scope,
            our_mac,
            our_ip,
            pass_gap: DEFAULT_PASS_GAP,
            response_cap: DEFAULT_RESPONSE_CAP,
        }
    }

    /// Overrides the inter-pass gap (default 1 s, ADR-011). Test/tuning
    /// hook.
    pub fn with_pass_gap(mut self, gap: Duration) -> Self {
        self.pass_gap = gap;
        self
    }

    /// Overrides the per-scan response cap (default 1,024). Test/tuning
    /// hook.
    pub fn with_response_cap(mut self, cap: usize) -> Self {
        self.response_cap = cap;
        self
    }

    /// Runs one scan and collects the accepted observations into the
    /// result (the convenience wrapper of task card §3.2).
    pub fn scan(
        &self,
        passes: u8,
        rate_pps: u32,
        listen_window: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ScanResult {
        let collected: Mutex<Vec<Observation>> = Mutex::new(Vec::new());
        let sink = |observation: Observation| {
            lock_or_recover(&collected).push(observation);
        };
        let mut result = self.scan_with_sink(passes, rate_pps, listen_window, cancel, &sink);
        let observations = std::mem::take(&mut *lock_or_recover(&collected));
        result.observations = observations;
        result
    }

    /// Runs one scan, streaming every accepted observation to `sink` as
    /// it arrives (FR-DS-10; the worker builds its batches on this).
    ///
    /// [`ScanResult::observations`] is empty on return — the sink stream
    /// is the delivery; a cancelled scan's "observations so far" are the
    /// ones already sunk.
    pub fn scan_with_sink(
        &self,
        passes: u8,
        rate_pps: u32,
        listen_window: Duration,
        cancel: Arc<AtomicBool>,
        sink: &(dyn Fn(Observation) + Sync),
    ) -> ScanResult {
        let started = Instant::now();
        let rate = clamp_rate(rate_pps);
        let interval = send_interval(rate);
        let passes = clamp_passes(passes);

        // FR-SC-05 degenerate scope: /32 (or empty) → nothing to probe;
        // Complete immediately, zero counters, no listen window.
        if targets(self.scope, self.our_ip).next().is_none() {
            return ScanResult {
                outcome: ScanOutcome::Complete,
                observations: Vec::new(),
                counters: ScanCounters::default(),
                elapsed: started.elapsed(),
            };
        }

        // Per-scan shared state (nothing carries over between scans).
        let shared = ScanShared {
            solicited: RwLock::new(HashSet::new()),
            responded: RwLock::new(HashSet::new()),
            terminal: Mutex::new(None),
            done: AtomicBool::new(false),
            cancel,
        };

        thread::scope(|scope| {
            let receiver = thread::Builder::new()
                .name("arp-receive".to_owned())
                .spawn_scoped(scope, || self.receive_loop(&shared, sink));
            let send_report = self.send_passes(passes, interval, listen_window, &shared);
            // The listen window is inside send_passes; stop the receiver.
            shared.done.store(true, Ordering::Release);
            let rx_report = match receiver {
                Ok(handle) => handle.join().unwrap_or_else(|_| {
                    // Defensive (receive code is total): a panicked
                    // receiver is a fatal, classified event.
                    shared.record_terminal(Terminal::Failed(TransportError::FatalIo {
                        message: "the receive thread terminated unexpectedly".to_owned(),
                    }));
                    RxReport::default()
                }),
                Err(_) => {
                    // Thread creation failed (resource exhaustion): the
                    // scan cannot observe anything — fatal, no panic
                    // (SR-02).
                    shared.record_terminal(Terminal::Failed(TransportError::FatalIo {
                        message: "the receive thread could not be spawned".to_owned(),
                    }));
                    RxReport::default()
                }
            };
            // A cancel that landed during the final join is still a
            // cancelled scan (the flag was observed before return).
            shared.observe_cancel();
            let outcome = shared.classify(&send_report);
            ScanResult {
                outcome,
                observations: Vec::new(),
                counters: merge_counters(&send_report, &rx_report),
                elapsed: started.elapsed(),
            }
        })
    }

    /// The sending side: passes, pacing, pass gaps and the listen window.
    fn send_passes(
        &self,
        passes: u8,
        interval: Duration,
        listen_window: Duration,
        shared: &ScanShared,
    ) -> SendReport {
        let mut report = SendReport::default();
        let mut pass1_attempts: u64 = 0;
        'passes: for pass in 1..=passes {
            report.passes_run += 1;
            // Pass 2+ probes only the non-responders as of this moment
            // (ADR-011): snapshot the responder set at pass start.
            let non_responders: Option<HashSet<Ipv4Addr>> = if pass == 1 {
                None
            } else {
                Some(lock_or_recover_responded_read(&shared.responded))
            };
            let mut next_deadline: Option<Instant> = None;
            for target in targets(self.scope, self.our_ip) {
                if let Some(skip) = &non_responders
                    && skip.contains(&target)
                {
                    continue;
                }
                // Pacing: wait for the deadline (or interruption).
                if let Some(deadline) = next_deadline
                    && shared.wait_until(deadline)
                {
                    break 'passes;
                }
                // The receiver may have recorded a fatal error.
                if shared.terminal_set() || shared.observe_cancel() {
                    break 'passes;
                }
                // Solicited-before-send (FR-DS-06 condition 12): the
                // address is askable before the frame leaves, so a fast
                // reply validates.
                lock_or_recover_write(&shared.solicited).insert(target);
                report.targets += 1;
                if pass == 1 {
                    pass1_attempts += 1;
                }
                let frame = build_arp_request(self.our_mac, self.our_ip, target);
                match self.transport.send(&frame) {
                    Ok(()) => report.requests_sent += 1,
                    Err(err) if err.is_fatal() => {
                        report.send_errors_fatal += 1;
                        shared.record_terminal(Terminal::Failed(err));
                        break 'passes;
                    }
                    Err(_) => report.send_errors_transient += 1,
                }
                // Next deadline: max(previous, now) + interval — a late
                // wake-up is never compensated with a burst (FR-DS-04).
                let now = Instant::now();
                let base = next_deadline
                    .filter(|previous| *previous > now)
                    .unwrap_or(now);
                next_deadline = Some(base.checked_add(interval).unwrap_or(now));
            }
            // Gap before the next pass — but only if a next pass exists
            // and non-responders remain (otherwise: skip the remaining
            // passes and the gap, straight to the listen window).
            if pass < passes {
                let responded_count =
                    lock_or_recover_responded_read(&shared.responded).len() as u64;
                if responded_count < pass1_attempts {
                    if shared.wait_for(self.pass_gap) {
                        break;
                    }
                } else {
                    break;
                }
            }
        }
        // Listen window: replies keep flowing for `listen_window` after
        // the last send (FR-DS-05) — unless the scan already ended
        // (cancelled or failed: first terminal event wins).
        if !shared.terminal_set() && !shared.observe_cancel() {
            shared.wait_for(listen_window);
        }
        report
    }

    /// The receiving side: polls the transport, validates every frame
    /// with T-103's parser against this scan's solicited set, dedups,
    /// caps, counts and streams observations to `sink`.
    fn receive_loop(&self, shared: &ScanShared, sink: &(dyn Fn(Observation) + Sync)) -> RxReport {
        let mut report = RxReport::default();
        loop {
            if shared.observe_cancel() || shared.done.load(Ordering::Acquire) {
                break;
            }
            if shared.terminal_set() {
                break;
            }
            match self.transport.recv(RECV_POLL) {
                Ok(Some(frame)) => {
                    // Software EtherType filter (task card §2.1): the
                    // production transport's socket hears every frame on
                    // the interface; non-ARP frames are dropped here and
                    // never counted as rejected *replies* — collecting
                    // them would contradict FR-DS-07.
                    if !has_arp_ethertype(&frame) {
                        continue;
                    }
                    let outcome = {
                        let solicited = shared
                            .solicited
                            .read()
                            .unwrap_or_else(PoisonError::into_inner);
                        let ctx =
                            ArpReplyContext::new(self.our_mac, self.our_ip, self.scope, &solicited);
                        parse_arp_reply(&frame, &ctx)
                    };
                    report.replies.record(&outcome);
                    if let Ok(reply) = outcome {
                        let key = (reply.sender_ip, reply.sender_mac);
                        if report.seen.contains(&key) {
                            report.duplicates += 1;
                        } else if report.accepted >= self.response_cap as u64 {
                            // The cap drops the observation, never the
                            // scan (task card §3.2).
                            report.cap_dropped += 1;
                        } else {
                            report.seen.insert(key);
                            report.accepted += 1;
                            lock_or_recover_write(&shared.responded).insert(reply.sender_ip);
                            sink(Observation::from_arp_reply(&reply));
                        }
                    }
                }
                Ok(None) => {}
                Err(err) if err.is_fatal() => {
                    shared.record_terminal(Terminal::Failed(err));
                    break;
                }
                // Transient receive error: keep polling.
                Err(_) => {}
            }
        }
        report
    }
}

impl fmt::Debug for ArpScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArpScanner")
            .field("scope", &self.scope)
            .field("our_mac", &self.our_mac)
            .field("our_ip", &self.our_ip)
            .field("pass_gap", &self.pass_gap)
            .field("response_cap", &self.response_cap)
            .field("transport", &"dyn ArpTransport")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Per-scan shared state
// ---------------------------------------------------------------------------

/// The per-scan state shared by the sending and receiving threads.
struct ScanShared {
    /// Addresses this scan has asked (FR-DS-06 condition 12); written by
    /// the sender before each send, read by the receiver per frame.
    solicited: RwLock<HashSet<Ipv4Addr>>,
    /// Addresses with an accepted reply (ADR-011 pass-2 filter);
    /// written by the receiver, snapshotted by the sender at pass start.
    responded: RwLock<HashSet<Ipv4Addr>>,
    /// The first terminal event (cancel or fatal) — wins the outcome.
    terminal: Mutex<Option<Terminal>>,
    /// Set when the sending side is finished (the receiver stops).
    done: AtomicBool,
    /// The caller's cancel flag (FR-DS-09).
    cancel: Arc<AtomicBool>,
}

/// Terminal events, in arrival order.
enum Terminal {
    /// A fatal transport error.
    Failed(TransportError),
    /// The cancel flag was observed.
    Cancelled,
}

/// The sending side's numbers.
#[derive(Default)]
struct SendReport {
    targets: u64,
    requests_sent: u64,
    send_errors_transient: u64,
    send_errors_fatal: u64,
    passes_run: u8,
}

/// The receiving side's numbers.
#[derive(Default)]
struct RxReport {
    replies: ArpReplyCounters,
    accepted: u64,
    duplicates: u64,
    cap_dropped: u64,
    seen: HashSet<(Ipv4Addr, MacAddr)>,
}

impl ScanShared {
    /// Records the first terminal event; later events do not overwrite
    /// it (first-terminal-event-wins, FR-DS-11).
    fn record_terminal(&self, event: Terminal) {
        let mut slot = lock_or_recover(&self.terminal);
        if slot.is_none() {
            *slot = Some(event);
        }
    }

    /// `true` once a terminal event was recorded.
    fn terminal_set(&self) -> bool {
        lock_or_recover(&self.terminal).is_some()
    }

    /// Observes the cancel flag; records `Cancelled` if this is the
    /// first terminal event. `true` when cancelled.
    fn observe_cancel(&self) -> bool {
        if self.cancel.load(Ordering::Acquire) {
            self.record_terminal(Terminal::Cancelled);
            true
        } else {
            false
        }
    }

    /// Sleeps until `deadline` in cancel-checked slices
    /// ([`CANCEL_SLICE`]); `true` if interrupted.
    fn wait_until(&self, deadline: Instant) -> bool {
        loop {
            if self.observe_cancel() || self.terminal_set() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            thread::sleep((deadline - now).min(CANCEL_SLICE));
        }
    }

    /// Sleeps for `duration` in cancel-checked slices; `true` if
    /// interrupted.
    fn wait_for(&self, duration: Duration) -> bool {
        let start = Instant::now();
        loop {
            if self.observe_cancel() || self.terminal_set() {
                return true;
            }
            let elapsed = start.elapsed();
            if elapsed >= duration {
                return false;
            }
            let remaining = duration - elapsed;
            thread::sleep(remaining.min(CANCEL_SLICE));
        }
    }

    /// The FR-DS-11 classification from the terminal slot and the send
    /// report.
    fn classify(&self, report: &SendReport) -> ScanOutcome {
        match lock_or_recover(&self.terminal).take() {
            Some(Terminal::Cancelled) => ScanOutcome::Cancelled,
            Some(Terminal::Failed(err)) => ScanOutcome::Failed {
                reason: err.to_string(),
            },
            None => {
                if report.requests_sent == 0
                    && (report.send_errors_transient + report.send_errors_fatal) > 0
                {
                    ScanOutcome::Failed {
                        reason: "every attempted send failed".to_owned(),
                    }
                } else if report.send_errors_transient > 0 {
                    ScanOutcome::Partial
                } else {
                    ScanOutcome::Complete
                }
            }
        }
    }
}

/// Locks `responded` for reading without panicking on poisoning.
fn lock_or_recover_responded_read(responded: &RwLock<HashSet<Ipv4Addr>>) -> HashSet<Ipv4Addr> {
    responded
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Locks an `RwLock` for writing without panicking on poisoning.
fn lock_or_recover_write<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}

/// Merges the two threads' numbers into the public counters.
fn merge_counters(send: &SendReport, rx: &RxReport) -> ScanCounters {
    ScanCounters {
        targets: send.targets,
        requests_sent: send.requests_sent,
        send_errors_transient: send.send_errors_transient,
        send_errors_fatal: send.send_errors_fatal,
        replies_accepted: rx.accepted,
        replies_rejected: rx.replies.rejected(),
        duplicates: rx.duplicates,
        cap_dropped: rx.cap_dropped,
        passes_run: send.passes_run,
        replies: rx.replies.clone(),
    }
}

// ---------------------------------------------------------------------------
// Target generation and pacing math (pure functions)
// ---------------------------------------------------------------------------

/// The probe targets of `scope` (FR-SC-05): all host addresses except
/// the network address, the broadcast address and `our_ip`.
///
/// * prefix ≤ 30: `network+1 ..= broadcast-1`;
/// * `/31`: both addresses (RFC 3021), minus `our_ip`;
/// * `/32`: nothing (the single address is both network and broadcast).
///
/// Lazy: a plain iterator, never a materialized collection — a `/16`
/// scope costs no allocation here.
fn targets(scope: Ipv4Net, our_ip: Ipv4Addr) -> impl Iterator<Item = Ipv4Addr> {
    let network = u32::from(scope.network());
    let (first, last) = match scope.prefix_len() {
        32 => (1, 0), // empty range: /32 has no probe targets
        31 => (network, network + 1),
        _ => (network + 1, u32::from(scope.broadcast()) - 1),
    };
    (first..=last)
        .map(Ipv4Addr::from)
        .filter(move |ip| *ip != our_ip)
}

/// Clamps `rate_pps` into `1..=MAX_RATE_PPS` (FR-DS-04; 0 must never
/// reach the interval division).
fn clamp_rate(rate_pps: u32) -> u32 {
    rate_pps.clamp(1, MAX_RATE_PPS)
}

/// Clamps `passes` into `1..=MAX_PASSES`.
fn clamp_passes(passes: u8) -> u8 {
    passes.clamp(1, MAX_PASSES)
}

/// The send interval for a clamped rate (`rate ≥ 1`, so no division by
/// zero).
fn send_interval(rate_pps: u32) -> Duration {
    Duration::from_nanos(1_000_000_000 / u64::from(rate_pps))
}

/// `true` if the frame's Ethernet EtherType is ARP (offsets 12..14) —
/// the software filter for `ETH_P_ALL` transports (task card §2.1).
/// Total: short frames simply are not ARP frames.
fn has_arp_ethertype(frame: &[u8]) -> bool {
    frame.get(12..14) == Some(&ETHERTYPE_ARP_BE)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::arp::codec::InvalidReply;
    use crate::discovery::arp::test_support::FakeTransport;

    /// A fresh cancel flag, never set.
    fn never_cancel() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    /// Sets the flag after `delay`, from a helper thread.
    fn cancel_after(delay: Duration) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&flag);
        thread::spawn(move || {
            thread::sleep(delay);
            setter.store(true, Ordering::Release);
        });
        flag
    }

    fn our_mac() -> MacAddr {
        crate::discovery::arp::test_support::test_our_mac()
    }

    fn net(addr: [u8; 4], prefix: u8) -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), prefix)
            .expect("valid test network")
    }

    fn addr(o: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::new(o[0], o[1], o[2], o[3])
    }

    // ---- target generation (AC-2) ----------------------------------------

    #[test]
    fn targets_of_a_24_exclude_network_broadcast_and_own_ip() {
        let scope = net([192, 0, 2, 0], 24);
        let list: Vec<Ipv4Addr> = targets(scope, addr([192, 0, 2, 1])).collect();
        assert_eq!(list.len(), 253); // 254 hosts minus our own address
        assert_eq!(list.first(), Some(&addr([192, 0, 2, 2])));
        assert_eq!(list.last(), Some(&addr([192, 0, 2, 254])));
        assert!(!list.contains(&addr([192, 0, 2, 0])));
        assert!(!list.contains(&addr([192, 0, 2, 255])));
        assert!(!list.contains(&addr([192, 0, 2, 1])));
    }

    #[test]
    fn targets_of_a_30_are_the_two_hosts_minus_our_ip() {
        let scope = net([192, 0, 2, 0], 30);
        let list: Vec<Ipv4Addr> = targets(scope, addr([192, 0, 2, 1])).collect();
        assert_eq!(list, vec![addr([192, 0, 2, 2])]);
        // Own IP outside the network changes nothing about the hosts.
        let outside: Vec<Ipv4Addr> = targets(scope, addr([198, 51, 100, 9])).collect();
        assert_eq!(outside, vec![addr([192, 0, 2, 1]), addr([192, 0, 2, 2])]);
    }

    #[test]
    fn targets_of_a_31_use_both_addresses_rfc3021() {
        let scope = net([192, 0, 2, 0], 31);
        let list: Vec<Ipv4Addr> = targets(scope, addr([192, 0, 2, 0])).collect();
        assert_eq!(list, vec![addr([192, 0, 2, 1])]);
        let both: Vec<Ipv4Addr> = targets(scope, addr([198, 51, 100, 9])).collect();
        assert_eq!(both, vec![addr([192, 0, 2, 0]), addr([192, 0, 2, 1])]);
    }

    #[test]
    fn targets_of_a_32_are_empty() {
        let scope = net([192, 0, 2, 7], 32);
        assert_eq!(targets(scope, addr([198, 51, 100, 9])).count(), 0);
        // Even when the single address is not our own: it is the network
        // *and* the broadcast address — no probe targets (FR-SC-05).
    }

    #[test]
    fn targets_are_lazy_a_huge_scope_costs_nothing() {
        // A /8 has 16,777,214 hosts; materializing it would allocate
        // ~64 MiB. Taking three must be instant.
        let scope = net([10, 0, 0, 0], 8);
        let started = Instant::now();
        let first: Vec<Ipv4Addr> = targets(scope, addr([192, 0, 2, 1])).take(3).collect();
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "lazy generation took {:?}",
            started.elapsed()
        );
        assert_eq!(
            first,
            vec![
                addr([10, 0, 0, 1]),
                addr([10, 0, 0, 2]),
                addr([10, 0, 0, 3])
            ]
        );
    }

    // ---- parameter clamping and pacing math (AC-3) -----------------------

    #[test]
    fn rate_is_clamped_to_one_pps_minimum_and_500_maximum() {
        for (given, expected) in [
            (0u32, 1u32),
            (1, 1),
            (2, 2),
            (100, 100),
            (499, 499),
            (500, 500),
            (501, 500),
            (u32::MAX, 500),
        ] {
            assert_eq!(clamp_rate(given), expected, "rate {given}");
        }
    }

    #[test]
    fn send_intervals_match_the_reference_rates() {
        assert_eq!(send_interval(1), Duration::from_secs(1));
        assert_eq!(send_interval(100), Duration::from_millis(10));
        assert_eq!(send_interval(500), Duration::from_millis(2));
    }

    #[test]
    fn passes_are_clamped_to_one_minimum_and_plan_maximum() {
        assert_eq!(clamp_passes(0), 1);
        assert_eq!(clamp_passes(1), 1);
        assert_eq!(clamp_passes(3), 3);
        assert_eq!(clamp_passes(255), MAX_PASSES);
    }

    #[test]
    fn deadline_math_never_compensates_a_late_wakeup_with_a_burst() {
        // A deadline in the future: the next one is interval later.
        let now = Instant::now();
        let future = now + Duration::from_millis(100);
        let base = Some(future)
            .filter(|previous| *previous > now)
            .unwrap_or(now);
        let next = base
            .checked_add(Duration::from_millis(10))
            .expect("no overflow");
        assert!(next >= future + Duration::from_millis(10) - Duration::from_millis(2));
        // A late wake-up (previous deadline already in the past): the
        // next deadline is computed from *now*, never from the missed
        // one — no catch-up burst (FR-DS-04).
        let late = now
            .checked_sub(Duration::from_millis(50))
            .expect("in range");
        let base = Some(late).filter(|previous| *previous > now).unwrap_or(now);
        let next = base
            .checked_add(Duration::from_millis(10))
            .expect("no overflow");
        assert!(next >= now);
        assert!(next <= now + Duration::from_millis(15));
    }

    // ---- zero-target scans -------------------------------------------------

    #[test]
    fn a_32_scope_completes_immediately_with_zero_counters() {
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 7], 32),
            our_mac(),
            addr([192, 0, 2, 7]),
        );
        let started = Instant::now();
        let result = scanner.scan(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW, never_cancel());
        assert_eq!(result.outcome, ScanOutcome::Complete);
        assert_eq!(result.counters, ScanCounters::default());
        assert_eq!(result.observations, Vec::new());
        // No listen window: far below the 1.5 s default.
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(fake.sent_log().len(), 0, "nothing was sent");
    }

    // ---- a full happy-path scan -------------------------------------------

    #[test]
    fn a_full_scan_discovers_every_responder() {
        // 192.0.2.0/29: hosts .1–.6, our IP .1 → 5 targets .2–.6.
        let fake = FakeTransport::new();
        for host in 2u8..=6 {
            fake.responder(
                addr([192, 0, 2, host]),
                format!("02:00:00:00:00:{:02x}", host)
                    .parse()
                    .expect("valid MAC"),
            );
        }
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_pass_gap(Duration::from_millis(20));
        let result = scanner.scan(
            2,
            DEFAULT_RATE_PPS,
            Duration::from_millis(60),
            never_cancel(),
        );
        assert_eq!(result.outcome, ScanOutcome::Complete);
        assert_eq!(result.observations.len(), 5);
        // Every target answered, so no request is ever repeated: pass 2
        // finds an empty non-responder set (whether the pre-gap
        // skip-check caught the last in-flight reply or the pass-start
        // snapshot did, the send count is the same).
        assert_eq!(result.counters.requests_sent, 5);
        assert_eq!(result.counters.targets, 5);
        assert_eq!(result.counters.replies_accepted, 5);
        assert_eq!(result.counters.replies_rejected, 0);
        assert_eq!(result.counters.send_errors_transient, 0);
        // Pacing lower bound: 5 sends at ≥ ~10 ms spacing plus the
        // 60 ms listen window.
        assert!(
            result.elapsed >= Duration::from_millis(95),
            "elapsed {:?} breaks pacing/window lower bounds",
            result.elapsed
        );
        assert_eq!(fake.sent_log().len(), 5);
    }

    // ---- pacing (AC-3) ------------------------------------------------------

    #[test]
    fn pacing_enforces_the_configured_interval_lower_bound() {
        // 13 targets (192.0.2.0/28 minus our .1), 1 pass, 100 pps →
        // consecutive sends ≥ ~10 ms apart.
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 28),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(20),
            never_cancel(),
        );
        assert_eq!(result.outcome, ScanOutcome::Complete);
        let log = fake.sent_log();
        assert_eq!(log.len(), 13);
        let mut previous: Option<Instant> = None;
        for (at, _) in &log {
            if let Some(prev) = previous {
                let gap = *at - prev;
                assert!(
                    gap >= Duration::from_millis(9),
                    "burst detected: gap {:?} < 9 ms",
                    gap
                );
            }
            previous = Some(*at);
        }
        let span = log.last().expect("nonempty").0 - log.first().expect("nonempty").0;
        assert!(span >= Duration::from_millis(108), "span {span:?}");
    }

    #[test]
    fn rate_zero_is_clamped_to_one_packet_per_second() {
        // Two targets (own IP outside the /30), rate 0 → 1 pps: the
        // second send must wait a full second.
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 30),
            our_mac(),
            addr([198, 51, 100, 9]),
        );
        let result = scanner.scan(1, 0, Duration::from_millis(10), never_cancel());
        assert_eq!(result.outcome, ScanOutcome::Complete);
        let log = fake.sent_log();
        assert_eq!(log.len(), 2);
        let gap = log[1].0 - log[0].0;
        assert!(
            gap >= Duration::from_millis(950),
            "rate 0 must clamp to 1 pps, gap was {gap:?}"
        );
    }

    // ---- multi-pass (AC-4) --------------------------------------------------

    #[test]
    fn pass_two_probes_only_non_responders_after_the_gap() {
        // 5 targets; only .2 answers. Pass 1: 5 requests; pass 2 (after
        // the gap): the 4 non-responders only.
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_pass_gap(Duration::from_millis(80));
        let result = scanner.scan(
            2,
            DEFAULT_RATE_PPS,
            Duration::from_millis(30),
            never_cancel(),
        );
        assert_eq!(result.outcome, ScanOutcome::Complete);
        assert_eq!(result.counters.passes_run, 2);
        assert_eq!(result.counters.requests_sent, 9); // 5 + 4
        assert_eq!(result.counters.targets, 9); // attempts across passes
        assert_eq!(result.counters.replies_accepted, 1);
        // The pass-2 frames: targets .3–.6 only, .2 never re-asked.
        let log = fake.sent_log();
        assert_eq!(log.len(), 9);
        let pass2: Vec<Ipv4Addr> = log[5..]
            .iter()
            .map(|(_, frame)| target_ip_of(frame))
            .collect();
        assert_eq!(
            pass2,
            vec![
                addr([192, 0, 2, 3]),
                addr([192, 0, 2, 4]),
                addr([192, 0, 2, 5]),
                addr([192, 0, 2, 6]),
            ]
        );
        // The gap is really waited: 9 sends (≥ ~80 ms of pacing) + 80 ms
        // gap + 30 ms window — comfortably above 150 ms.
        assert!(
            result.elapsed >= Duration::from_millis(150),
            "{:?}",
            result.elapsed
        );
    }

    #[test]
    fn all_responded_skips_remaining_passes_and_the_gap() {
        // 3 passes requested, everything answers in pass 1: the gap
        // (300 ms) must not be waited. `send_lag` parks each send
        // briefly *after* the reply is queued, so the receive thread has
        // processed every reply — including the last one — before the
        // sender reaches the skip-check: deterministic, no race with
        // in-flight replies.
        let fake = FakeTransport::new();
        fake.send_lag(Duration::from_millis(5));
        for host in 2u8..=6 {
            fake.responder(
                addr([192, 0, 2, host]),
                format!("02:00:00:00:00:{:02x}", host)
                    .parse()
                    .expect("valid MAC"),
            );
        }
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_pass_gap(Duration::from_millis(300));
        let result = scanner.scan(
            3,
            DEFAULT_RATE_PPS,
            Duration::from_millis(30),
            never_cancel(),
        );
        assert_eq!(result.outcome, ScanOutcome::Complete);
        assert_eq!(result.counters.passes_run, 1);
        assert_eq!(result.counters.requests_sent, 5);
        assert!(
            result.elapsed < Duration::from_millis(300),
            "{:?}",
            result.elapsed
        );
    }

    // ---- solicited-only (AC-5) ----------------------------------------------

    #[test]
    fn replies_for_addresses_nobody_asked_are_rejected() {
        // A well-formed reply for .5 — in scope, usable, not our own —
        // arrives *before* .5 is probed: at 4 pps the sweep reaches .5
        // only after ~750 ms, so the receive thread processes the frame
        // while .5 is still unsolicited (deterministic).
        let fake = FakeTransport::new();
        fake.inject_reply(
            our_mac(),
            addr([192, 0, 2, 1]),
            "02:00:00:00:00:05".parse().expect("valid MAC"),
            addr([192, 0, 2, 5]),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(1, 4, Duration::from_millis(40), never_cancel());
        assert_eq!(result.observations, Vec::new());
        assert_eq!(
            result
                .counters
                .replies
                .rejected_with(&InvalidReply::NotSolicited {
                    found: addr([192, 0, 2, 5])
                }),
            1
        );
        assert_eq!(result.counters.replies_rejected, 1);
        assert_eq!(result.counters.replies_accepted, 0);
    }

    #[test]
    fn replies_from_outside_the_scope_are_rejected_as_out_of_scope() {
        // Same shape, but the sender IP lies outside the /29 — the
        // out-of-scope condition (10) fires before solicited-only (12).
        let fake = FakeTransport::new();
        fake.inject_reply(
            our_mac(),
            addr([192, 0, 2, 1]),
            "02:00:00:00:00:99".parse().expect("valid MAC"),
            addr([192, 0, 2, 99]),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(40),
            never_cancel(),
        );
        assert_eq!(
            result
                .counters
                .replies
                .rejected_with(&InvalidReply::OutOfScope {
                    found: addr([192, 0, 2, 99])
                }),
            1
        );
        assert_eq!(result.observations, Vec::new());
    }

    #[test]
    fn a_fast_reply_to_a_just_sent_request_is_accepted() {
        // The solicited set is written *before* the request leaves, so
        // the reply queued during send() validates (FR-DS-06 condition
        // 12 must not misjudge prompt responders).
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(40),
            never_cancel(),
        );
        assert_eq!(result.counters.replies_accepted, 1);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].source, Source::ArpReply);
    }

    // ---- response cap (AC-6) --------------------------------------------------

    #[test]
    fn the_response_cap_drops_excess_replies_without_failing_the_scan() {
        // 13 targets, all answer, cap 3: accepted 3, cap_dropped 10, the
        // scan still runs both passes and ends Complete.
        let fake = FakeTransport::new();
        for host in 2u8..=14 {
            fake.responder(
                addr([192, 0, 2, host]),
                format!("02:00:00:00:00:{:02x}", host)
                    .parse()
                    .expect("valid MAC"),
            );
        }
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 28),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_response_cap(3)
        .with_pass_gap(Duration::from_millis(20));
        let result = scanner.scan(
            2,
            DEFAULT_RATE_PPS,
            Duration::from_millis(30),
            never_cancel(),
        );
        assert_eq!(
            result.outcome,
            ScanOutcome::Complete,
            "cap never fails a scan"
        );
        assert_eq!(result.counters.replies_accepted, 3);
        // Pass 1: 13 valid replies → 3 accepted, 10 cap-dropped. Pass 2
        // re-probes the 10 non-responders (only 3 ever responded) → 10
        // more valid replies, all cap-dropped: 20 in total.
        assert_eq!(result.counters.cap_dropped, 20);
        assert_eq!(result.observations.len(), 3);
        // 3 of 13 responded → pass 2 probes the other 10 → 23 requests.
        assert_eq!(result.counters.requests_sent, 23);
    }

    // ---- dedup ---------------------------------------------------------------

    #[test]
    fn duplicate_replies_are_counted_not_re_emitted() {
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        // Two extra copies of the same reply.
        fake.inject_reply(
            our_mac(),
            addr([192, 0, 2, 1]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
            addr([192, 0, 2, 2]),
        );
        fake.inject_reply(
            our_mac(),
            addr([192, 0, 2, 1]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
            addr([192, 0, 2, 2]),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(40),
            never_cancel(),
        );
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.counters.replies_accepted, 1);
        assert_eq!(result.counters.duplicates, 2);
    }

    #[test]
    fn one_ip_under_two_macs_is_two_observations() {
        // ADR-008: never hide the conflict by merging.
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        fake.inject_reply(
            our_mac(),
            addr([192, 0, 2, 1]),
            "02:00:00:00:aa:02".parse().expect("valid MAC"),
            addr([192, 0, 2, 2]),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(40),
            never_cancel(),
        );
        assert_eq!(result.observations.len(), 2);
        assert_eq!(result.counters.replies_accepted, 2);
        assert_eq!(result.counters.duplicates, 0);
    }

    // ---- EtherType software filter ------------------------------------------

    #[test]
    fn non_arp_frames_are_dropped_before_validation_and_not_counted() {
        let fake = FakeTransport::new();
        // An IPv4 EtherType frame (and a short runt): neither is an ARP
        // reply, neither may pollute the reply counters.
        let mut ipv4_frame = vec![0u8; 60];
        ipv4_frame[12] = 0x08;
        ipv4_frame[13] = 0x00;
        fake.inject_frame(ipv4_frame);
        fake.inject_frame(vec![0u8; 10]);
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(40),
            never_cancel(),
        );
        assert_eq!(result.counters.replies.total(), 0);
        assert_eq!(result.counters.replies_rejected, 0);
        assert_eq!(result.observations, Vec::new());
    }

    // ---- listen window (AC-7) --------------------------------------------------

    #[test]
    fn a_late_reply_inside_the_listen_window_is_accepted() {
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        fake.reply_delay(Duration::from_millis(150));
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        // Window 400 ms ≫ reply at 150 ms after the (single-pass, fast)
        // sweep: the reply lands inside the window.
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(400),
            never_cancel(),
        );
        assert_eq!(result.counters.replies_accepted, 1);
        assert_eq!(result.observations.len(), 1);
    }

    #[test]
    fn a_reply_after_the_listen_window_is_not_received() {
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        fake.reply_delay(Duration::from_millis(150));
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        // Window 30 ms ≪ reply at 150 ms: the receiver has stopped.
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(30),
            never_cancel(),
        );
        assert_eq!(result.outcome, ScanOutcome::Complete);
        assert_eq!(result.counters.replies_accepted, 0);
        assert_eq!(result.observations, Vec::new());
    }

    // ---- outcomes (AC-9) -------------------------------------------------------

    #[test]
    fn a_transient_send_error_makes_the_outcome_partial() {
        let fake = FakeTransport::new();
        fake.fail_send_at(2, TransportError::SendBufferFull); // third send
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_pass_gap(Duration::from_millis(10));
        let result = scanner.scan(
            2,
            DEFAULT_RATE_PPS,
            Duration::from_millis(20),
            never_cancel(),
        );
        assert_eq!(result.outcome, ScanOutcome::Partial);
        assert_eq!(result.counters.send_errors_transient, 1);
        assert_eq!(result.counters.requests_sent, 9); // 10 attempts, 1 failed
        assert_eq!(result.counters.targets, 10);
    }

    #[test]
    fn a_fatal_send_error_fails_the_scan_with_the_reason() {
        let fake = FakeTransport::new();
        fake.fail_send_at(0, TransportError::InterfaceLost);
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW, never_cancel());
        assert_eq!(
            result.outcome,
            ScanOutcome::Failed {
                reason: TransportError::InterfaceLost.to_string()
            }
        );
        assert_eq!(result.counters.send_errors_fatal, 1);
        assert_eq!(result.counters.requests_sent, 0);
        // Failed scans do not wait the listen window.
        assert!(
            result.elapsed < Duration::from_millis(250),
            "{:?}",
            result.elapsed
        );
    }

    #[test]
    fn a_fatal_receive_error_fails_the_scan() {
        let fake = FakeTransport::new();
        fake.fail_recv_with(TransportError::SocketClosed);
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let result = scanner.scan(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(30),
            never_cancel(),
        );
        assert_eq!(
            result.outcome,
            ScanOutcome::Failed {
                reason: TransportError::SocketClosed.to_string()
            }
        );
    }

    #[test]
    fn every_send_failing_transiently_fails_the_scan() {
        let fake = FakeTransport::new();
        fake.fail_all_sends(TransportError::WouldBlock);
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 30),
            our_mac(),
            addr([198, 51, 100, 9]), // 2 targets
        )
        .with_pass_gap(Duration::from_millis(10));
        let result = scanner.scan(
            2,
            DEFAULT_RATE_PPS,
            Duration::from_millis(10),
            never_cancel(),
        );
        assert_eq!(
            result.outcome,
            ScanOutcome::Failed {
                reason: "every attempted send failed".to_owned()
            }
        );
        assert_eq!(result.counters.requests_sent, 0);
        assert!(result.counters.send_errors_transient >= 2);
    }

    // ---- cancellation (AC-8, FR-DS-09: ≤ 250 ms in every phase) --------------

    #[test]
    fn cancelling_while_sending_returns_promptly() {
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 22), // 1022 targets
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        // 1 pps + 1022 targets: uncancellable this would run ~17 min.
        let cancel = cancel_after(Duration::from_millis(15));
        let started = Instant::now();
        let result = scanner.scan(1, 1, DEFAULT_LISTEN_WINDOW, cancel);
        let elapsed = started.elapsed();
        assert_eq!(result.outcome, ScanOutcome::Cancelled);
        assert!(
            elapsed < Duration::from_millis(280),
            "cancellation took {elapsed:?} (flag set at ~15 ms)"
        );
        assert!(result.counters.requests_sent < 10);
    }

    #[test]
    fn cancelling_in_the_pass_gap_returns_promptly() {
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_pass_gap(Duration::from_millis(600));
        // Pass 1 takes ~40 ms; the flag lands inside the 600 ms gap.
        let cancel = cancel_after(Duration::from_millis(120));
        let started = Instant::now();
        let result = scanner.scan(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW, cancel);
        let elapsed = started.elapsed();
        assert_eq!(result.outcome, ScanOutcome::Cancelled);
        assert!(
            elapsed < Duration::from_millis(400),
            "cancellation took {elapsed:?} (flag set at ~120 ms, gap 600 ms)"
        );
    }

    #[test]
    fn cancelling_in_the_listen_window_returns_promptly() {
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let cancel = cancel_after(Duration::from_millis(80));
        let started = Instant::now();
        let result = scanner.scan(1, DEFAULT_RATE_PPS, Duration::from_millis(800), cancel);
        let elapsed = started.elapsed();
        assert_eq!(result.outcome, ScanOutcome::Cancelled);
        assert!(
            elapsed < Duration::from_millis(330),
            "cancellation took {elapsed:?} (flag set at ~80 ms, window 800 ms)"
        );
    }

    #[test]
    fn cancelling_while_blocked_in_recv_returns_promptly() {
        let fake = FakeTransport::new();
        fake.recv_sleeps(true); // recv parks the full 20 ms poll
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let cancel = cancel_after(Duration::from_millis(50));
        let started = Instant::now();
        let result = scanner.scan(1, DEFAULT_RATE_PPS, Duration::from_millis(800), cancel);
        let elapsed = started.elapsed();
        assert_eq!(result.outcome, ScanOutcome::Cancelled);
        assert!(
            elapsed < Duration::from_millis(300),
            "cancellation took {elapsed:?} (flag set at ~50 ms, window 800 ms)"
        );
    }

    #[test]
    fn a_cancelled_scan_reports_the_work_done_so_far() {
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let cancel = cancel_after(Duration::from_millis(60));
        let result = scanner.scan(1, DEFAULT_RATE_PPS, Duration::from_millis(800), cancel);
        assert_eq!(result.outcome, ScanOutcome::Cancelled);
        // Whatever completed before the flag is visible in the counters.
        assert!(result.counters.targets > 0);
        assert!(result.counters.requests_sent > 0);
    }

    // ---- streaming ------------------------------------------------------------

    #[test]
    fn scan_with_sink_streams_and_leaves_the_result_observations_empty() {
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        fake.responder(
            addr([192, 0, 2, 3]),
            "02:00:00:00:00:03".parse().expect("valid MAC"),
        );
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            net([192, 0, 2, 0], 29),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let seen: Mutex<Vec<Observation>> = Mutex::new(Vec::new());
        let result = scanner.scan_with_sink(
            1,
            DEFAULT_RATE_PPS,
            Duration::from_millis(40),
            never_cancel(),
            &|observation: Observation| lock_or_recover(&seen).push(observation),
        );
        assert_eq!(result.observations, Vec::new(), "streaming leaves it empty");
        let streamed = lock_or_recover(&seen).clone();
        assert_eq!(streamed.len(), 2);
        assert_eq!(result.counters.replies_accepted, 2);
        // The streamed items are the same facts the result counted.
        assert!(
            streamed
                .iter()
                .all(|observation| observation.source == Source::ArpReply)
        );
    }

    // ---- helper ------------------------------------------------------------

    /// The probed IPv4 of a 42-byte request frame (offsets 38..42).
    fn target_ip_of(frame: &[u8]) -> Ipv4Addr {
        let bytes: [u8; 4] = frame
            .get(38..42)
            .expect("42-byte request frame")
            .try_into()
            .expect("four bytes");
        Ipv4Addr::from(u32::from_be_bytes(bytes))
    }
}
