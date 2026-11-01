// SPDX-License-Identifier: GPL-3.0-only

//! The discovery worker thread (plan §8.3, §4 ADR-012; task card §3.4).
//!
//! [`ArpWorkerHandle`] wraps an [`ArpScanner`] in one background thread
//! ("osza-arp-worker") behind **bounded** channels: a small command
//! channel in, a bounded event channel out. The worker is a thin
//! wrapper — no scheduling, no registry work (those are T-204/T-201):
//! it runs scans when told, streams observations in batches (FR-DS-10),
//! and reports one summary per scan.
//!
//! Events are [`DiscoveryEvent`]s, defined here because `AppEvent` does
//! not exist yet (it arrives with T-205, which will map
//! [`DiscoveryEvent::Observations`] and [`DiscoveryEvent::ScanFinished`]
//! onto its own event type — Plan Question PQ-3 in the T-104 execution
//! report). Per plan §8.2 the worker imports nothing from `registry`,
//! `app` or `ui`.
//!
//! Concurrency contract (task card §3.4):
//!
//! * **Cancel while scanning:** the worker thread is busy inside
//!   [`ArpScanner::scan_with_sink`], so cancellation cannot wait for it
//!   to read commands — [`ArpWorkerHandle::cancel`] sets the scan's
//!   shared flag directly. Every scan gets a **fresh**
//!   `Arc<AtomicBool>`, so a stale cancel cannot abort the next scan.
//! * **Batching (FR-DS-10):** a pending batch is flushed at the latest
//!   [`FLUSH_MAX_DELAY`] (50 ms) after its first observation — by a
//!   dedicated flusher thread whose timer does not depend on new
//!   arrivals — and immediately when it reaches [`MAX_BATCH_SIZE`].
//! * **No uninterruptible blocking:** nothing blocks on a full channel.
//!   Deliveries loop on `try_send`, checking the shutdown (and, for
//!   mid-scan batches, cancel) flags, waiting at most
//!   [`SEND_RETRY_WAIT`] per attempt; a disconnected receiver stops the
//!   running scan and ends the worker.
//! * **Delivery policy:** mid-scan batches may be dropped when the
//!   consumer stalls *and* the scan is cancelled; the final flush and
//!   the [`DiscoveryEvent::ScanFinished`] summary are delivered unless
//!   the receiver disconnected or shutdown was requested.
//! * **Shutdown** (and handle drop) stops the thread and joins it.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use crate::discovery::arp::scanner::ArpScanner;
use crate::discovery::arp::scanner::Observation;
use crate::discovery::arp::scanner::ScanCounters;
use crate::discovery::arp::scanner::ScanOutcome;
use crate::discovery::privilege::lock_or_recover;

/// Command-channel capacity (bounded, small: commands are rare — one
/// per scan plus shutdown).
pub const COMMAND_CAPACITY: usize = 8;

/// Event-channel capacity (bounded): with batches of at most
/// [`MAX_BATCH_SIZE`] observations, a full queue already holds an order
/// of magnitude more observations than a /24 scan produces per second.
pub const EVENT_CAPACITY: usize = 64;

/// A pending batch is flushed when it reaches this many observations.
pub const MAX_BATCH_SIZE: usize = 32;

/// A pending batch is flushed at the latest this long after its first
/// observation (FR-DS-10: "batched ≤ every 50 ms").
pub const FLUSH_MAX_DELAY: Duration = Duration::from_millis(50);

/// The flusher thread's wakeup period: it checks batch ages this often;
/// the flush deadline is honored within one tick.
pub const FLUSH_TICK: Duration = Duration::from_millis(10);

/// Wait between two `try_send` attempts on a full channel (task card
/// §3.4: "wait ≤ 10 ms, retry").
pub const SEND_RETRY_WAIT: Duration = Duration::from_millis(10);

/// How long the idle worker waits on the command channel before
/// re-checking the shutdown flag (bounded waits everywhere, FR-DS-09).
pub const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The worker thread's name (pthread names are truncated to 15 bytes).
const WORKER_THREAD_NAME: &str = "osza-arp-worker";

// ---------------------------------------------------------------------------
// Protocol types
// ---------------------------------------------------------------------------

/// The parameters of one scan (task card §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanParams {
    /// Pass count (clamped by the scanner, ADR-011).
    pub passes: u8,
    /// Send rate in packets/s (FR-DS-04).
    pub rate_pps: u32,
    /// Post-sweep listen window (ADR-011).
    pub listen_window: Duration,
}

/// What the worker has been told to do. Commands arrive on a bounded
/// channel of capacity [`COMMAND_CAPACITY`]; users drive it through
/// [`ArpWorkerHandle`] rather than by sending commands directly (the
/// handle owns the per-scan cancel flags).
#[derive(Debug)]
pub enum ScanCommand {
    /// Run one scan; `cancel` is the fresh, scan-scoped flag created by
    /// [`ArpWorkerHandle::start_scan`].
    StartScan {
        /// Scan tuning.
        params: ScanParams,
        /// The scan's cancel flag (FR-DS-09).
        cancel: Arc<AtomicBool>,
    },
    /// Stop the worker thread (idempotent with handle drop).
    Shutdown,
}

/// What the worker reports (T-205 will map these onto `AppEvent`;
/// Plan Question PQ-3 in the T-104 execution report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryEvent {
    /// A batch of observations, flushed per FR-DS-10.
    Observations(Vec<Observation>),
    /// One scan ended; sent after the final flush, with the counters.
    /// Boxed: the summary outweighs a batch by an order of magnitude
    /// (clippy::large_enum_variant) and appears once per scan.
    ScanFinished(Box<ScanSummary>),
}

/// The end-of-scan summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanSummary {
    /// FR-DS-11 outcome.
    pub outcome: ScanOutcome,
    /// What the scan did.
    pub counters: ScanCounters,
    /// Wall time of the scan.
    pub elapsed: Duration,
}

/// Why a command could not be handed to the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkerError {
    /// The bounded command channel is full (a scan is typically already
    /// queued; FR-DS-08 owns the "one scan at a time" rule).
    #[error("the worker command queue is full")]
    CommandQueueFull,
    /// The worker thread is gone.
    #[error("the discovery worker has stopped")]
    WorkerStopped,
}

// ---------------------------------------------------------------------------
// Pending batch (shared between the scan sink and the flusher)
// ---------------------------------------------------------------------------

/// Observations waiting to be flushed, plus the instant the first one
/// arrived (the flush deadline anchor).
#[derive(Default)]
struct PendingBatch {
    items: Vec<Observation>,
    first: Option<Instant>,
}

// ---------------------------------------------------------------------------
// Worker handle
// ---------------------------------------------------------------------------

/// The caller's side of the discovery worker (task card §3.4).
///
/// [`spawn`](ArpWorkerHandle::spawn) returns the handle together with
/// the event [`Receiver`]; dropping the handle requests shutdown and
/// joins the worker thread.
pub struct ArpWorkerHandle {
    commands: SyncSender<ScanCommand>,
    /// The cancel flag of the most recently *requested* scan (created
    /// fresh by `start_scan`, so stale cancels cannot abort the next
    /// scan).
    current_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    /// Set by [`shutdown`](ArpWorkerHandle::shutdown)/drop; checked by
    /// every retry loop inside the worker.
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ArpWorkerHandle {
    /// Spawns the worker thread around `scanner` and returns the handle
    /// plus the bounded event channel's receiving end.
    pub fn spawn(scanner: ArpScanner) -> (Self, Receiver<DiscoveryEvent>) {
        let (command_tx, command_rx) = mpsc::sync_channel::<ScanCommand>(COMMAND_CAPACITY);
        let (event_tx, event_rx) = mpsc::sync_channel::<DiscoveryEvent>(EVENT_CAPACITY);
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let mut worker = Worker {
            scanner,
            commands: command_rx,
            events: event_tx,
            shutdown: Arc::clone(&shutdown_flag),
        };
        let thread = thread::Builder::new()
            .name(WORKER_THREAD_NAME.to_owned())
            .spawn(move || worker.main_loop())
            .ok();
        let handle = Self {
            commands: command_tx,
            current_cancel: Arc::new(Mutex::new(None)),
            shutdown: Arc::clone(&shutdown_flag),
            thread,
        };
        if handle.thread.is_none() {
            // Thread creation failed (resource exhaustion): mark
            // shutdown so the handle's drop does not wait on a thread
            // that never existed (no panic, SR-02).
            handle.shutdown.store(true, Ordering::Release);
        }
        (handle, event_rx)
    }

    /// Requests one scan. The command travels with a **fresh** cancel
    /// flag, which [`cancel`](Self::cancel) can set while the scan runs.
    pub fn start_scan(&self, params: ScanParams) -> Result<(), WorkerError> {
        let cancel = Arc::new(AtomicBool::new(false));
        match self.commands.try_send(ScanCommand::StartScan {
            params,
            cancel: Arc::clone(&cancel),
        }) {
            Ok(()) => {
                *lock_or_recover(&self.current_cancel) = Some(cancel);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err(WorkerError::CommandQueueFull),
            Err(TrySendError::Disconnected(_)) => Err(WorkerError::WorkerStopped),
        }
    }

    /// Cancels the most recently requested scan (works while the worker
    /// thread is busy inside the scan; FR-DS-09).
    pub fn cancel(&self) {
        if let Some(flag) = lock_or_recover(&self.current_cancel).as_ref() {
            flag.store(true, Ordering::Release);
        }
    }

    /// Requests shutdown and joins the worker thread (also performed by
    /// [`Drop`]). Consuming: an explicit, synchronous stop.
    pub fn shutdown(mut self) {
        self.shutdown_internal();
    }

    /// The shared shutdown flag (the flusher and retry loops check it).
    fn shutdown_internal(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        // Wake the idle loop; a busy scan is stopped by cancelling it.
        if let Some(flag) = lock_or_recover(&self.current_cancel).as_ref() {
            flag.store(true, Ordering::Release);
        }
        let _ = self.commands.try_send(ScanCommand::Shutdown);
        if let Some(thread) = self.thread.take() {
            // Join without panic on a poisoned worker thread: the
            // handle's contract is "stop and join", not "unwrap".
            let _ = thread.join();
        }
    }
}

impl Drop for ArpWorkerHandle {
    fn drop(&mut self) {
        self.shutdown_internal();
    }
}

// ---------------------------------------------------------------------------
// Worker thread body
// ---------------------------------------------------------------------------

/// The worker thread's own state.
struct Worker {
    scanner: ArpScanner,
    commands: Receiver<ScanCommand>,
    events: SyncSender<DiscoveryEvent>,
    shutdown: Arc<AtomicBool>,
}

impl Worker {
    /// The idle loop: bounded waits on the command channel, one scan at
    /// a time.
    fn main_loop(&mut self) {
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            match self.commands.recv_timeout(COMMAND_POLL_INTERVAL) {
                Ok(ScanCommand::StartScan { params, cancel }) => {
                    self.run_scan(params, cancel);
                }
                Ok(ScanCommand::Shutdown) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                // No command sender left (handle dropped): the flag is
                // set by drop, so the loop head ends us next iteration;
                // break here too for the direct-send case.
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    }

    /// Runs one scan: streams observations into a pending batch that a
    /// flusher thread delivers under the FR-DS-10 deadline, then sends
    /// the final flush and the summary.
    fn run_scan(&mut self, params: ScanParams, cancel: Arc<AtomicBool>) {
        let pending: Arc<Mutex<PendingBatch>> = Arc::new(Mutex::new(PendingBatch::default()));
        let scan_done = Arc::new(AtomicBool::new(false));

        thread::scope(|scope| {
            let flusher = thread::Builder::new()
                .name("arp-flush".to_owned())
                .spawn_scoped(scope, {
                    // Clones for the flusher thread; the loop reads the
                    // shared batch and the flags.
                    let pending = Arc::clone(&pending);
                    let events = self.events.clone();
                    let cancel = Arc::clone(&cancel);
                    let scan_done = Arc::clone(&scan_done);
                    let shutdown = Arc::clone(&self.shutdown);
                    move || flush_loop(&pending, &events, &cancel, &scan_done, &shutdown)
                });
            let sink = |observation: Observation| {
                let mut batch = lock_or_recover(&pending);
                if batch.first.is_none() {
                    batch.first = Some(Instant::now());
                }
                batch.items.push(observation);
                if batch.items.len() >= MAX_BATCH_SIZE {
                    let items = std::mem::take(&mut batch.items);
                    batch.first = None;
                    drop(batch);
                    if deliver(&self.events, &self.shutdown, Some(&cancel), items)
                        == Delivery::Disconnected
                    {
                        // The consumer is gone: stop the scan (task card
                        // §3.4).
                        cancel.store(true, Ordering::Release);
                    }
                }
            };
            let result = self.scanner.scan_with_sink(
                params.passes,
                params.rate_pps,
                params.listen_window,
                Arc::clone(&cancel),
                &sink,
            );
            // Final flush (before ScanFinished; cancel does not drop
            // the final batch — only shutdown/disconnect do).
            scan_done.store(true, Ordering::Release);
            let items = std::mem::take(&mut lock_or_recover(&pending).items);
            let _ = deliver(&self.events, &self.shutdown, None, items);
            if let Ok(handle) = flusher {
                // The flusher saw scan_done and exited; join it.
                let _ = handle.join();
            }
            // ScanFinished: delivered unless disconnected or shutdown.
            let summary = Box::new(ScanSummary {
                outcome: result.outcome,
                counters: result.counters,
                elapsed: result.elapsed,
            });
            if deliver_summary(
                &self.events,
                &self.shutdown,
                DiscoveryEvent::ScanFinished(summary),
            ) == Delivery::Disconnected
            {
                // Nothing left to report to; end the worker.
                self.shutdown.store(true, Ordering::Release);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Flushing and delivery
// ---------------------------------------------------------------------------

/// The periodic flusher: age-based flushing independent of arrivals
/// (FR-DS-10).
fn flush_loop(
    pending: &Arc<Mutex<PendingBatch>>,
    events: &SyncSender<DiscoveryEvent>,
    cancel: &AtomicBool,
    scan_done: &AtomicBool,
    shutdown: &AtomicBool,
) {
    loop {
        if scan_done.load(Ordering::Acquire) || shutdown.load(Ordering::Acquire) {
            break;
        }
        thread::sleep(FLUSH_TICK);
        let mut batch = lock_or_recover(pending);
        if let Some(first) = batch.first
            && first.elapsed() >= FLUSH_MAX_DELAY
            && !batch.items.is_empty()
        {
            let items = std::mem::take(&mut batch.items);
            batch.first = None;
            drop(batch);
            if deliver(events, shutdown, Some(cancel), items) == Delivery::Disconnected {
                cancel.store(true, Ordering::Release);
            }
        }
    }
}

/// How a delivery attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Delivery {
    /// The event is in the channel.
    Delivered,
    /// The event was dropped (flagged interrupt or channel gone).
    Dropped,
    /// The receiving end is gone.
    Disconnected,
}

/// Delivers one batch of observations without uninterruptible blocking
/// (task card §3.4): loop on `try_send`; on `Full`, check the flags and
/// wait at most [`SEND_RETRY_WAIT`]; on `Disconnected`, stop.
///
/// `interrupt` (the scan's cancel flag for mid-scan batches) makes a
/// stalled consumer drop the batch once the scan itself is being
/// cancelled; the final flush and the summary pass `None` — they are
/// only dropped on shutdown or disconnect.
fn deliver(
    events: &SyncSender<DiscoveryEvent>,
    shutdown: &AtomicBool,
    interrupt: Option<&AtomicBool>,
    items: Vec<Observation>,
) -> Delivery {
    if items.is_empty() {
        return Delivery::Delivered;
    }
    let mut event = DiscoveryEvent::Observations(items);
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Delivery::Dropped;
        }
        match events.try_send(event) {
            Ok(()) => return Delivery::Delivered,
            Err(TrySendError::Full(back)) => {
                if let Some(flag) = interrupt
                    && flag.load(Ordering::Acquire)
                {
                    return Delivery::Dropped;
                }
                event = back;
                thread::sleep(SEND_RETRY_WAIT);
            }
            Err(TrySendError::Disconnected(_)) => return Delivery::Disconnected,
        }
    }
}

/// Delivers the final summary — same non-blocking discipline, interrupt
/// only on shutdown (task card §3.4: `ScanFinished` must be delivered
/// unless the receiver disconnected or shutdown was requested).
fn deliver_summary(
    events: &SyncSender<DiscoveryEvent>,
    shutdown: &AtomicBool,
    event: DiscoveryEvent,
) -> Delivery {
    let mut event = event;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Delivery::Dropped;
        }
        match events.try_send(event) {
            Ok(()) => return Delivery::Delivered,
            Err(TrySendError::Full(back)) => {
                event = back;
                thread::sleep(SEND_RETRY_WAIT);
            }
            Err(TrySendError::Disconnected(_)) => return Delivery::Disconnected,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::arp::scanner::DEFAULT_RATE_PPS;
    use crate::discovery::arp::test_support::FakeTransport;

    fn our_mac() -> crate::model::mac::MacAddr {
        crate::discovery::arp::test_support::test_our_mac()
    }

    fn addr(o: [u8; 4]) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3])
    }

    fn scanner_for(fake: &FakeTransport) -> ArpScanner {
        ArpScanner::new(
            Box::new(fake.clone()),
            crate::model::ipv4::Ipv4Net::new(addr([192, 0, 2, 0]), 29).expect("valid network"),
            our_mac(),
            addr([192, 0, 2, 1]),
        )
        .with_pass_gap(Duration::from_millis(10))
    }

    /// Collects all events until `ScanFinished`.
    fn drain_until_finished(
        events: &Receiver<DiscoveryEvent>,
    ) -> (Vec<Vec<Observation>>, ScanSummary) {
        let mut batches = Vec::new();
        loop {
            match events.recv_timeout(Duration::from_secs(5)) {
                Ok(DiscoveryEvent::Observations(items)) => batches.push(items),
                Ok(DiscoveryEvent::ScanFinished(summary)) => return (batches, *summary),
                Err(err) => panic!("no event arrived: {err}"),
            }
        }
    }

    #[test]
    fn channel_capacities_are_the_documented_constants() {
        assert_eq!(COMMAND_CAPACITY, 8);
        assert_eq!(EVENT_CAPACITY, 64);
        assert_eq!(MAX_BATCH_SIZE, 32);
        assert_eq!(FLUSH_MAX_DELAY, Duration::from_millis(50));
        assert_eq!(SEND_RETRY_WAIT, Duration::from_millis(10));
    }

    #[test]
    fn a_scan_streams_batches_and_finishes_with_a_summary() {
        let fake = FakeTransport::new();
        for host in 2u8..=6 {
            fake.responder(
                addr([192, 0, 2, host]),
                format!("02:00:00:00:00:{:02x}", host)
                    .parse()
                    .expect("valid MAC"),
            );
        }
        let (worker, events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        worker
            .start_scan(ScanParams {
                passes: 1,
                rate_pps: DEFAULT_RATE_PPS,
                listen_window: Duration::from_millis(80),
            })
            .expect("start ok");
        let (batches, summary) = drain_until_finished(&events);
        let observations: Vec<Observation> = batches.concat();
        assert_eq!(observations.len(), 5);
        assert_eq!(summary.outcome, ScanOutcome::Complete);
        assert_eq!(summary.counters.replies_accepted, 5);
        worker.shutdown();
    }

    #[test]
    fn a_single_observation_is_flushed_within_the_50ms_deadline() {
        // One responder only; the scan's listen window (600 ms) is far
        // longer than the flush deadline, so receiving the batch early
        // proves the flush timer — not scan end — delivered it.
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let (worker, events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        worker
            .start_scan(ScanParams {
                passes: 1,
                rate_pps: DEFAULT_RATE_PPS,
                listen_window: Duration::from_millis(600),
            })
            .expect("start ok");
        let started = Instant::now();
        let first = events
            .recv_timeout(Duration::from_secs(5))
            .expect("flush arrives");
        let waited = started.elapsed();
        match first {
            DiscoveryEvent::Observations(items) => assert_eq!(items.len(), 1),
            other => panic!("expected observations, got {other:?}"),
        }
        // 50 ms deadline + one 10 ms tick + generous CI slop ≪ 200 ms,
        // and far below the 600 ms scan end.
        assert!(waited < Duration::from_millis(200), "flush took {waited:?}");
        // Drain to the finish so the worker can shut down cleanly.
        let _ = drain_until_finished(&events);
        worker.shutdown();
    }

    #[test]
    fn batches_never_exceed_the_documented_maximum_size() {
        // A /24: 254 targets all answering → far more than one batch.
        let fake = FakeTransport::new();
        for host in 1u16..=254 {
            fake.responder(
                std::net::Ipv4Addr::new(192, 0, 2, (host % 256) as u8),
                crate::model::mac::MacAddr::from_octets([
                    0x02,
                    0x00,
                    0x00,
                    0x00,
                    (host >> 8) as u8,
                    (host % 256) as u8,
                ])
                .expect("valid unicast MAC"),
            );
        }
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            crate::model::ipv4::Ipv4Net::new(addr([192, 0, 2, 0]), 24).expect("valid network"),
            our_mac(),
            addr([198, 51, 100, 9]),
        )
        .with_pass_gap(Duration::from_millis(10));
        let (worker, events) = ArpWorkerHandle::spawn(scanner);
        worker
            .start_scan(ScanParams {
                passes: 1,
                rate_pps: 500, // fastest allowed: batches fill quickly
                listen_window: Duration::from_millis(60),
            })
            .expect("start ok");
        let (batches, summary) = drain_until_finished(&events);
        assert_eq!(summary.counters.replies_accepted, 254);
        assert!(
            batches
                .iter()
                .all(|batch| !batch.is_empty() && batch.len() <= MAX_BATCH_SIZE),
            "a batch exceeded {MAX_BATCH_SIZE}: {:?}",
            batches.iter().map(Vec::len).collect::<Vec<_>>()
        );
        assert!(batches.len() >= 8, "expected several batches");
        worker.shutdown();
    }

    #[test]
    fn cancel_takes_effect_while_the_event_channel_is_full() {
        // A /21 with every target answering at 500 pps produces 2,046
        // observations → 64 batches of ≤ 32 — exactly the event channel's
        // capacity. The consumer drains nothing until after the cancel,
        // so the worker hits real `try_send::Full` backpressure while the
        // scan runs, and cancel must still end the scan (FR-DS-09).
        let fake = FakeTransport::new();
        for host in 1u16..=2046 {
            let quad = 0xc000_0200u32 + u32::from(host); // 192.0.2.0/21
            fake.responder(
                std::net::Ipv4Addr::from(quad),
                crate::model::mac::MacAddr::from_octets([
                    0x02,
                    0x00,
                    0x00,
                    (host >> 8) as u8,
                    (host & 0xff) as u8,
                    0x7f,
                ])
                .expect("valid unicast MAC"),
            );
        }
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            crate::model::ipv4::Ipv4Net::new(addr([192, 0, 2, 0]), 21).expect("valid network"),
            our_mac(),
            addr([198, 51, 100, 9]), // outside the scope: all 2,046 hosts are targets
        );
        let (worker, events) = ArpWorkerHandle::spawn(scanner);
        worker
            .start_scan(ScanParams {
                passes: 1,
                rate_pps: 500,
                listen_window: Duration::from_secs(2),
            })
            .expect("start ok");
        // Let the sweep run (≈ 4.1 s at 500 pps) and the queue fill.
        thread::sleep(Duration::from_millis(5_000));
        let started = Instant::now();
        worker.cancel();
        // The scan ends promptly; the (blocked) summary delivery
        // completes once the consumer drains.
        let mut finished = None;
        while finished.is_none() {
            match events.recv_timeout(Duration::from_secs(10)) {
                Ok(DiscoveryEvent::ScanFinished(summary)) => finished = Some(summary),
                Ok(DiscoveryEvent::Observations(_)) => continue,
                Err(err) => panic!("event expected while draining: {err}"),
            }
        }
        let summary = finished.expect("set above");
        assert_eq!(summary.outcome, ScanOutcome::Cancelled);
        assert!(summary.counters.requests_sent > 0);
        let cancel_to_finish = started.elapsed();
        assert!(
            cancel_to_finish < Duration::from_secs(5),
            "worker stalled after cancel under backpressure: {cancel_to_finish:?}"
        );
        worker.shutdown();
    }

    #[test]
    fn a_stale_cancel_does_not_abort_the_next_scan() {
        let fake = FakeTransport::new();
        fake.responder(
            addr([192, 0, 2, 2]),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let (worker, events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        // Scan 1: cancelled almost immediately.
        worker
            .start_scan(ScanParams {
                passes: 2,
                rate_pps: DEFAULT_RATE_PPS,
                listen_window: Duration::from_millis(800),
            })
            .expect("start ok");
        thread::sleep(Duration::from_millis(20));
        worker.cancel();
        let (_, first) = drain_until_finished(&events);
        assert_eq!(first.outcome, ScanOutcome::Cancelled);
        // Scan 2: a fresh flag — must complete.
        worker
            .start_scan(ScanParams {
                passes: 1,
                rate_pps: DEFAULT_RATE_PPS,
                listen_window: Duration::from_millis(50),
            })
            .expect("start ok");
        let (_, second) = drain_until_finished(&events);
        assert_eq!(second.outcome, ScanOutcome::Complete);
        assert_eq!(second.counters.replies_accepted, 1);
        worker.shutdown();
    }

    #[test]
    fn shutdown_joins_cleanly_while_a_scan_is_running() {
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            crate::model::ipv4::Ipv4Net::new(addr([192, 0, 2, 0]), 22).expect("valid network"),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let (worker, events) = ArpWorkerHandle::spawn(scanner);
        worker
            .start_scan(ScanParams {
                passes: 3,
                rate_pps: 1, // would run for ~half an hour uncancellable
                listen_window: Duration::from_secs(5),
            })
            .expect("start ok");
        thread::sleep(Duration::from_millis(50));
        // Shutdown from a helper thread so a wedged join cannot hang the
        // test forever without evidence.
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle_worker = worker;
        let joiner = thread::spawn(move || {
            handle_worker.shutdown();
            done_tx.send(()).expect("channel open");
        });
        let joined = done_rx.recv_timeout(Duration::from_secs(5));
        assert!(joined.is_ok(), "shutdown did not join within 5 s");
        joiner.join().expect("joiner must not panic");
        // The receiver may or may not hold a final event; drain it.
        while events.try_recv().is_ok() {}
    }

    #[test]
    fn the_command_queue_is_bounded() {
        let fake = FakeTransport::new();
        let scanner = ArpScanner::new(
            Box::new(fake.clone()),
            crate::model::ipv4::Ipv4Net::new(addr([192, 0, 2, 0]), 22).expect("valid network"),
            our_mac(),
            addr([192, 0, 2, 1]),
        );
        let (worker, events) = ArpWorkerHandle::spawn(scanner);
        worker
            .start_scan(ScanParams {
                passes: 3,
                rate_pps: 1, // would run for ~17 min uncancelled
                listen_window: Duration::from_secs(1),
            })
            .expect("first scan running");
        // The worker is busy inside the scan; the bounded command queue
        // must report Full after COMMAND_CAPACITY buffered commands.
        let mut full_seen = false;
        for _ in 0..(COMMAND_CAPACITY + 2) {
            if worker
                .start_scan(ScanParams {
                    passes: 1,
                    rate_pps: DEFAULT_RATE_PPS,
                    listen_window: Duration::from_millis(10),
                })
                .is_err()
            {
                full_seen = true;
                break;
            }
        }
        assert!(full_seen, "the command channel never reported full");
        // Dropping the handle cancels the running scan, joins the
        // worker, and the queued commands are never executed (the
        // shutdown flag outranks them in the idle loop).
        let started = Instant::now();
        drop(worker);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "drop did not join within 5 s"
        );
        drop(events);
    }
}
