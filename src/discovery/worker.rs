// SPDX-License-Identifier: GPL-3.0-only

//! The discovery orchestrator: one worker thread that executes whole
//! discovery cycles per plan §8.5 (neighbor read → paced ARP sweep →
//! listen window → neighbor read → outcome), stamps every event with a
//! [`ScanId`], and enforces one-cycle-at-a-time, bounded channels and
//! cancellation (plan §6.3 FR-DS-08…11/FR-DS-14, §8.3, §4 ADR-012;
//! task T-204).
//!
//! # Shape (ADR-012, plan §8.3)
//!
//! [`DiscoveryWorker`] owns the T-104 [`ArpWorkerHandle`] plus its
//! event receiver (active mode), a [`NeighborSource`], the scope and
//! interface name, and the per-session [`ScanId`] counter, and talks
//! to the application through two **bounded** channels:
//!
//! * commands — [`OrchestratorCommand`] ([`StartCycle`], [`CancelCycle`],
//!   [`Shutdown`]) on a channel of [`CYCLE_COMMAND_CAPACITY`] slots;
//! * events — [`CycleEvent`] (`Started` / `Observations` / `Finished`)
//!   on a channel of [`CYCLE_EVENT_CAPACITY`] slots. **Every**
//!   observation batch and summary carries the [`ScanId`] of its
//!   cycle; T-205 maps these onto its own `AppEvent` (plan §8.2 — this
//!   module never imports `registry`).
//!
//! # One cycle at a time (FR-DS-08)
//!
//! [`start_cycle`](DiscoveryWorker::start_cycle) checks the shared
//! cycle-running flag first: a start while a cycle runs returns the
//! typed [`OrchestratorError::AlreadyInProgress`] and **queues
//! nothing** (defense in depth under the scheduler's own ruling, task
//! card §3.3). The flag is set by the worker thread for the whole
//! `run_cycle` span, so the check covers the entire cycle. The
//! contract is single-commander (plan §8.3/§8.4: one main loop drives
//! the workers); the microsecond window between a successful
//! `try_send` and the worker's flag store is therefore not reachable
//! in the intended wiring, and the worker still only ever runs one
//! cycle per popped command.
//!
//! # Cancellation (FR-DS-09)
//!
//! Every wait is poll-sliced at [`WAIT_SLICE`] (≤ 50 ms) against the
//! cycle's cancel flag and the shutdown flag;
//! [`cancel_cycle`](DiscoveryWorker::cancel_cycle) propagates to [`ArpWorkerHandle::cancel`] within one slice, and the
//! ARP scan's own 50 ms cancel slices carry the abort the rest of the
//! way — the end-to-end design bound is 250 ms. Each cycle gets a
//! **fresh** cancel flag (the T-104 guarantee is preserved). A
//! cancelled cycle skips the post-sweep neighbor read (the user asked
//! to stop; the already-delivered evidence stays valid and is simply
//! not aged — ADR-007) and, when the sweep itself was success-class,
//! emits `Finished` with [`ScanOutcome::Cancelled`]. A sweep that
//! itself **failed** stays [`ScanOutcome::Failed`] — the worse
//! outcome wins (execution report §6, Decision 5): a late cancel
//! never masks a real failure, so it still counts toward the
//! FR-DS-12 streak and the failure backoff.
//!
//! # Delivery policy (mirrors T-104, task card §3.3)
//!
//! Mid-cycle observation batches are forwarded with `try_send` plus a
//! small retry budget ([`FORWARD_RETRY_BUDGET`] × [`SEND_RETRY_WAIT`])
//! and are **dropped and counted** when the event channel stays
//! saturated (or the consumer disconnected, or shutdown was requested,
//! or the cycle is being cancelled — dropping is what keeps cancel
//! inside its bound under saturation). `cycle started` and
//! `cycle finished` are delivered by retrying until the consumer makes
//! space, and are dropped only when the receiver disconnected or
//! shutdown was requested. Nothing ever blocks on a channel without a
//! flag-checked bound.
//!
//! # ScanId discipline (task card §3.3)
//!
//! A late arp-worker batch belonging to a cancelled/finished cycle
//! must never be emitted under a new cycle's id: the orchestrator
//! drains the arp channel while idle and right before starting a new
//! scan, dropping and counting anything found there
//! ([`OrchestratorStats::stale_arp_events`]); batches are only
//! forwarded while the current cycle's own scan is in flight. (The
//! real T-104 worker orders its final flush and `ScanFinished` — it
//! joins the flusher thread first — so stragglers cannot occur with a
//! correct worker; the drains are the defense in depth the card
//! asks for, and the AC-8 test drives a gated fake session that
//! replays exactly such a straggler.)
//!
//! # Read-only mode (FR-DS-14)
//!
//! [`DiscoveryWorker::spawn_read_only`] is constructed with **no**
//! [`ArpWorkerHandle`] and no scanner — its signature offers no way to
//! hand one in, so no socket exists at all. The cycle is:
//! `cycle started (read-only)` → one neighbor read → `cycle finished`.
//! A successful read-only cycle's outcome is [`ScanOutcome::Complete`]
//! (aging semantics identical, ADR-007); a failed neighbor read fails
//! the cycle (the scheduler's failure rules apply through the
//! outcome).
//!
//! # Neighbor-read failures in active mode (Manager ruling, §3.3)
//!
//! The ARP sweep is the primary source, so a failed neighbor read
//! does **not** stop an active cycle: the cycle still runs, the
//! outcome is downgraded to [`ScanOutcome::Partial`] and the typed
//! reason is recorded in [`CycleSummary::degraded`] (for T-205/T-401
//! messages). Never age on a degraded view — `Partial` does not age
//! (ADR-007), which is the honest result.
//!
//! # Dead arp worker (task card §3.3)
//!
//! The T-104 worker thread cannot die mid-cycle by construction (no
//! panic path, channels kept alive by its handle). If it nonetheless
//! goes away (join failure, command channel disconnected), the cycle
//! is classified [`ScanOutcome::Failed`] with the reason and the
//! orchestrator marks itself arp-gone: later starts return the typed
//! [`OrchestratorError::ArpWorkerGone`]. It never silently respawns.
//!
//! # Intended T-205 wiring (who constructs what, in what order)
//!
//! ```text
//! // active mode:
//! let socket   = open_raw_socket(&iface)?;            // privilege.rs (before the drop)
//! let scanner  = ArpScanner::new(Box::new(LinuxArpTransport::new(socket)),
//!                                scope, our_mac, our_ip);
//! let (arp, arp_events) = ArpWorkerHandle::spawn(scanner);
//! let (worker, events)  = DiscoveryWorker::spawn_active(arp, arp_events,
//!                                 Box::new(ProcNeighborTable::new()), scope, iface_name);
//! // read-only mode (FR-DS-14, no socket is ever opened):
//! let (worker, events)  = DiscoveryWorker::spawn_read_only(
//!                                 Box::new(ProcNeighborTable::new()), scope, iface_name);
//! // driving: scheduler decisions -> worker.start_cycle(trigger, ScanParams {
//! //     passes, rate_pps: DEFAULT_RATE_PPS, listen_window: DEFAULT_LISTEN_WINDOW })
//! // events -> AppEvent (T-205) -> registry.observe / begin_cycle / end_cycle
//! ```
//!
//! [`StartCycle`]: OrchestratorCommand::StartCycle
//! [`CancelCycle`]: OrchestratorCommand::CancelCycle
//! [`Shutdown`]: OrchestratorCommand::Shutdown

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TrySendError;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use crate::discovery::arp::scanner::Observation;
use crate::discovery::arp::scanner::ScanCounters;
use crate::discovery::arp::scanner::ScanOutcome;
use crate::discovery::arp::worker::ArpWorkerHandle;
use crate::discovery::arp::worker::DiscoveryEvent;
use crate::discovery::arp::worker::MAX_BATCH_SIZE;
use crate::discovery::arp::worker::ScanParams;
use crate::discovery::arp::worker::ScanSummary;
use crate::discovery::arp::worker::WorkerError;
use crate::discovery::neighbor_table::NeighborEntry;
use crate::discovery::neighbor_table::NeighborSource;
use crate::discovery::privilege::lock_or_recover;
use crate::discovery::scheduler::Trigger;
use crate::model::Ipv4Net;
use crate::model::ScanId;

/// Command-channel capacity (bounded, small; commands are rare).
pub const CYCLE_COMMAND_CAPACITY: usize = 8;

/// Event-channel capacity (bounded; the same order of magnitude as the
/// arp worker's event channel, whose batches are the dominant traffic).
pub const CYCLE_EVENT_CAPACITY: usize = 64;

/// Every interruptible wait of the orchestrator is sliced at most this
/// long (FR-DS-09; the card's "poll-sliced (≤ 50 ms)").
pub const WAIT_SLICE: Duration = Duration::from_millis(50);

/// How long the idle orchestrator waits on its command channel before
/// re-checking the shutdown flag (bounded waits everywhere).
pub const COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Mid-cycle batches are retried at most this many times when the
/// event channel is saturated, then dropped and counted (T-203's
/// event-budget pattern at T-104's retry pace).
pub const FORWARD_RETRY_BUDGET: u32 = 8;

/// The pause between two forwarding attempts on a full channel
/// (T-104's `SEND_RETRY_WAIT`).
pub const SEND_RETRY_WAIT: Duration = Duration::from_millis(10);

/// The first [`ScanId`] a session issues. Counting starts at 1 (the
/// counter is monotonic per session, task card §3.3): 0 is then never
/// a live cycle id, which keeps any future "no cycle yet" sentinel
/// unambiguous.
pub const FIRST_SCAN_ID: u64 = 1;

/// The orchestrator thread's name (pthread names are truncated to 15
/// bytes; the trailing characters are cosmetic only).
const THREAD_NAME: &str = "osza-orchestrator";

// ---------------------------------------------------------------------------
// Commands, events, errors
// ---------------------------------------------------------------------------

/// What the orchestrator has been told to do (bounded channel of
/// [`CYCLE_COMMAND_CAPACITY`]); callers drive it through
/// [`DiscoveryWorker`] rather than sending commands directly (the
/// handle owns the per-cycle cancel flags).
#[derive(Debug)]
pub enum OrchestratorCommand {
    /// Run one cycle (FR-DS-08: one at a time — the handle rejects
    /// starts while a cycle runs). `cancel` is the fresh, cycle-scoped
    /// flag created by [`DiscoveryWorker::start_cycle`].
    StartCycle {
        /// Why the cycle starts (scheduler trigger).
        trigger: Trigger,
        /// The scan tuning for the cycle's ARP sweep (ignored in
        /// read-only mode, which sends nothing).
        params: ScanParams,
        /// The cycle's cancel flag (FR-DS-09).
        cancel: Arc<AtomicBool>,
    },
    /// Cancel the running cycle (FR-DS-09). The flag set by
    /// [`DiscoveryWorker::cancel_cycle`] is the mechanism that works
    /// while the thread is busy inside a cycle; this command is the
    /// protocol's name for the same intent and is a no-op when the
    /// thread finds it while idle.
    CancelCycle,
    /// Stop the orchestrator thread (idempotent with handle drop).
    Shutdown,
}

/// The mode a cycle ran in (FR-DS-14; read-only constructs no socket).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CycleMode {
    /// Neighbor reads plus the paced ARP sweep (the T-104 worker).
    Active,
    /// Neighbor reads only — no socket exists in this mode.
    ReadOnly,
}

impl std::fmt::Display for CycleMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let word = match self {
            CycleMode::Active => "active",
            CycleMode::ReadOnly => "read-only",
        };
        f.write_str(word)
    }
}

/// Why an active cycle's outcome was degraded to
/// [`ScanOutcome::Partial`] — typed so T-205/T-401 can word the
/// messages (task card §3.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Degradation {
    /// The pre-sweep neighbor read failed; the sweep still ran.
    #[error("the pre-sweep neighbor-table read failed: {reason}")]
    PreReadFailed {
        /// The neighbor source's failure, as one line.
        reason: String,
    },
    /// The post-sweep neighbor read failed.
    #[error("the post-sweep neighbor-table read failed: {reason}")]
    PostReadFailed {
        /// The neighbor source's failure, as one line.
        reason: String,
    },
}

/// The end-of-cycle summary (task card §3.3: outcome, counters,
/// elapsed — plus the typed degradation reason when one applies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleSummary {
    /// FR-DS-11 outcome of the cycle (downgraded to `Partial` when a
    /// neighbor read failed in active mode).
    pub outcome: ScanOutcome,
    /// What the cycle's ARP sweep did (all-zero in read-only mode).
    pub counters: ScanCounters,
    /// Wall time of the whole cycle (pre-read through post-read).
    pub elapsed: Duration,
    /// The typed reason the outcome was degraded, if it was.
    pub degraded: Option<Degradation>,
}

/// What the orchestrator reports. Every batch and summary carries the
/// [`ScanId`] of its cycle (task card §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleEvent {
    /// A cycle began.
    Started {
        /// The cycle's identity.
        scan_id: ScanId,
        /// Why the cycle started.
        trigger: Trigger,
        /// Which machinery the cycle runs.
        mode: CycleMode,
    },
    /// A batch of observations of the cycle named by `scan_id`
    /// (FR-DS-10: batches of at most [`MAX_BATCH_SIZE`]).
    Observations {
        /// The cycle's identity.
        scan_id: ScanId,
        /// The observations.
        batch: Vec<Observation>,
    },
    /// A cycle ended (delivered even under event-channel saturation;
    /// dropped only on disconnect or shutdown).
    Finished {
        /// The cycle's identity.
        scan_id: ScanId,
        /// Why the cycle had started.
        trigger: Trigger,
        /// Which machinery the cycle ran.
        mode: CycleMode,
        /// How the cycle ended.
        summary: Box<CycleSummary>,
    },
}

/// Why a call on the orchestrator handle failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrchestratorError {
    /// A cycle is already running: typed already-in-progress, nothing
    /// queued (FR-DS-08).
    #[error("a discovery cycle is already in progress")]
    AlreadyInProgress,
    /// The bounded command channel is full (defense: unreachable for
    /// starts under the single-commander contract because the
    /// FR-DS-08 guard precedes the send; reachable for cancels when
    /// the queue is saturated — the cancel flag is set regardless).
    #[error("the orchestrator command queue is full")]
    CommandQueueFull,
    /// The orchestrator thread is gone.
    #[error("the orchestrator thread has stopped")]
    WorkerStopped,
    /// The arp worker died mid-cycle earlier (typed worker-gone,
    /// task card §3.3); active discovery needs an application
    /// restart — the orchestrator never silently respawns it.
    #[error("the arp worker has stopped; active discovery is unavailable")]
    ArpWorkerGone,
}

impl OrchestratorError {
    /// Maps a failed `try_send` on the command channel (kept total;
    /// used by the handle and unit-tested directly).
    pub fn from_send(error: TrySendError<OrchestratorCommand>) -> Self {
        match error {
            TrySendError::Full(_) => OrchestratorError::CommandQueueFull,
            TrySendError::Disconnected(_) => OrchestratorError::WorkerStopped,
        }
    }
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

/// Lock-free orchestrator counters (the T-203 `HostnameStats` pattern):
/// what happened, observable without draining the event channel.
#[derive(Debug, Default)]
pub struct OrchestratorStats {
    /// Cycles begun (`cycle started` emitted).
    pub cycles_started: AtomicU64,
    /// Cycles ended (`cycle finished` emitted or dropped under
    /// shutdown/disconnect).
    pub cycles_finished: AtomicU64,
    /// Starts rejected by the FR-DS-08 guard.
    pub starts_rejected: AtomicU64,
    /// Observation batches forwarded to the event channel.
    pub batches_forwarded: AtomicU64,
    /// Mid-cycle batches dropped and counted (event-channel
    /// saturation, cancellation, disconnect or shutdown).
    pub batches_dropped: AtomicU64,
    /// Arp events consumed outside an attributable window and dropped
    /// (ScanId discipline — a correct arp worker never produces
    /// these).
    pub stale_arp_events: AtomicU64,
}

/// A consistent snapshot of [`OrchestratorStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrchestratorStatsSnapshot {
    /// Cycles begun.
    pub cycles_started: u64,
    /// Cycles ended.
    pub cycles_finished: u64,
    /// Starts rejected by the FR-DS-08 guard.
    pub starts_rejected: u64,
    /// Batches forwarded.
    pub batches_forwarded: u64,
    /// Batches dropped and counted.
    pub batches_dropped: u64,
    /// Stale arp events dropped and counted.
    pub stale_arp_events: u64,
}

impl OrchestratorStats {
    /// Takes the snapshot.
    pub fn snapshot(&self) -> OrchestratorStatsSnapshot {
        OrchestratorStatsSnapshot {
            cycles_started: self.cycles_started.load(Ordering::Relaxed),
            cycles_finished: self.cycles_finished.load(Ordering::Relaxed),
            starts_rejected: self.starts_rejected.load(Ordering::Relaxed),
            batches_forwarded: self.batches_forwarded.load(Ordering::Relaxed),
            batches_dropped: self.batches_dropped.load(Ordering::Relaxed),
            stale_arp_events: self.stale_arp_events.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// The arp-worker session (production pair + the AC-8 test seam)
// ---------------------------------------------------------------------------

/// The active-mode arp machinery the orchestrator drives: the real
/// T-104 pair ([`ArpWorkerHandle`] plus its event receiver) in
/// production.
///
/// The trait is `pub(crate)` and exists for exactly one reason: the
/// ScanId-discipline test (task card AC-8) must inject a **gated
/// fake** that replays an event no correct worker can produce — a
/// batch arriving after its scan's `ScanFinished` — which is
/// impossible through the real handle (it joins its flusher thread
/// before sending the summary, so the final flush always precedes
/// `ScanFinished`). The orchestrator must still defend against such a
/// straggler (the card says so), and this seam is how the defense is
/// proven.
pub(crate) trait ArpWorkerSession: Send {
    /// Requests one ARP scan (the real handle's `start_scan`).
    fn start_scan(&self, params: &ScanParams) -> Result<(), WorkerError>;
    /// Cancels the most recently requested scan (the real handle's
    /// `cancel`).
    fn cancel(&self);
    /// Receives the next arp-worker event, waiting at most `timeout`.
    fn recv_timeout(&self, timeout: Duration) -> Result<DiscoveryEvent, RecvTimeoutError>;
    /// Stops and joins the arp worker (the real handle's consuming
    /// `shutdown`).
    fn shutdown(self: Box<Self>);
}

/// The production [`ArpWorkerSession`]: the T-104 handle and receiver
/// pair, exactly as [`ArpWorkerHandle::spawn`] produced them.
struct RealArpSession {
    handle: ArpWorkerHandle,
    events: Receiver<DiscoveryEvent>,
}

impl ArpWorkerSession for RealArpSession {
    fn start_scan(&self, params: &ScanParams) -> Result<(), WorkerError> {
        self.handle.start_scan(*params)
    }

    fn cancel(&self) {
        self.handle.cancel();
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<DiscoveryEvent, RecvTimeoutError> {
        self.events.recv_timeout(timeout)
    }

    fn shutdown(self: Box<Self>) {
        self.handle.shutdown();
    }
}

// ---------------------------------------------------------------------------
// The handle
// ---------------------------------------------------------------------------

/// The caller's side of the discovery orchestrator (task card §3.3).
///
/// [`spawn_active`](Self::spawn_active) takes the T-104
/// [`ArpWorkerHandle`] and its event receiver (T-205 constructs them
/// around the privileged socket); [`spawn_read_only`](Self::spawn_read_only)
/// takes neither — no socket exists in that mode (FR-DS-14). Dropping
/// the handle requests shutdown and joins the orchestrator thread
/// (which in turn cancels, drains and joins the arp worker).
pub struct DiscoveryWorker {
    commands: SyncSender<OrchestratorCommand>,
    /// The cancel flag of the most recently *requested* cycle (fresh
    /// per cycle, so a stale cancel cannot abort the next one).
    current_cancel: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    /// Set by [`shutdown`](DiscoveryWorker::shutdown)/drop; checked by
    /// every wait inside the worker.
    stop: Arc<AtomicBool>,
    /// Set by the worker thread for the whole span of a cycle — the
    /// handle's FR-DS-08 guard.
    cycle_running: Arc<AtomicBool>,
    /// Set when the arp worker died (task card §3.3); read by the
    /// handle for the typed worker-gone error.
    arp_gone: Arc<AtomicBool>,
    stats: Arc<OrchestratorStats>,
    thread: Option<JoinHandle<()>>,
}

impl DiscoveryWorker {
    /// Spawns the orchestrator in **active** mode around the T-104
    /// pair (T-205 wiring: the socket is opened and the scanner
    /// constructed *before* this call; the orchestrator owns the pair
    /// from here on).
    pub fn spawn_active(
        arp: ArpWorkerHandle,
        arp_events: Receiver<DiscoveryEvent>,
        neighbors: Box<dyn NeighborSource + Send>,
        scope: Ipv4Net,
        interface_name: impl Into<String>,
    ) -> (Self, Receiver<CycleEvent>) {
        Self::spawn_with_mode(
            Mode::Active(Box::new(RealArpSession {
                handle: arp,
                events: arp_events,
            })),
            neighbors,
            scope,
            interface_name,
        )
    }

    /// Spawns the orchestrator in **read-only** mode (FR-DS-14): no
    /// `ArpWorkerHandle`, no scanner, no socket — the signature offers
    /// no way to hand any of them in. Cycles are one neighbor read.
    pub fn spawn_read_only(
        neighbors: Box<dyn NeighborSource + Send>,
        scope: Ipv4Net,
        interface_name: impl Into<String>,
    ) -> (Self, Receiver<CycleEvent>) {
        Self::spawn_with_mode(Mode::ReadOnly, neighbors, scope, interface_name)
    }

    /// The common spawn (both public constructors and the AC-8 test
    /// seam funnel here).
    fn spawn_with_mode(
        mode: Mode,
        neighbors: Box<dyn NeighborSource + Send>,
        scope: Ipv4Net,
        interface_name: impl Into<String>,
    ) -> (Self, Receiver<CycleEvent>) {
        let (command_tx, command_rx) =
            mpsc::sync_channel::<OrchestratorCommand>(CYCLE_COMMAND_CAPACITY);
        let (event_tx, event_rx) = mpsc::sync_channel::<CycleEvent>(CYCLE_EVENT_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let cycle_running = Arc::new(AtomicBool::new(false));
        let arp_gone = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(OrchestratorStats::default());
        let worker = WorkerThread {
            mode,
            neighbors,
            scope,
            iface: interface_name.into(),
            next_scan_id: FIRST_SCAN_ID,
            commands: command_rx,
            events: event_tx,
            stop: Arc::clone(&stop),
            cycle_running: Arc::clone(&cycle_running),
            arp_gone: Arc::clone(&arp_gone),
            stats: Arc::clone(&stats),
        };
        let thread = thread::Builder::new()
            .name(THREAD_NAME.to_owned())
            .spawn(move || worker.run())
            .ok();
        let handle = Self {
            commands: command_tx,
            current_cancel: Arc::new(Mutex::new(None)),
            stop: Arc::clone(&stop),
            cycle_running: Arc::clone(&cycle_running),
            arp_gone: Arc::clone(&arp_gone),
            stats: Arc::clone(&stats),
            thread,
        };
        if handle.thread.is_none() {
            // Thread creation failed (resource exhaustion): mark
            // shutdown so the handle's drop does not wait on a thread
            // that never existed (no panic, SR-02).
            handle.stop.store(true, Ordering::Release);
        }
        (handle, event_rx)
    }

    /// Requests one cycle (FR-DS-08 at the orchestrator layer).
    ///
    /// While a cycle runs: the typed
    /// [`OrchestratorError::AlreadyInProgress`], nothing queued. After
    /// the arp worker died: [`OrchestratorError::ArpWorkerGone`]. A
    /// full command channel (unreachable for starts under the
    /// single-commander contract — see the module docs) yields
    /// [`OrchestratorError::CommandQueueFull`]; the call never blocks.
    pub fn start_cycle(
        &self,
        trigger: Trigger,
        params: ScanParams,
    ) -> Result<(), OrchestratorError> {
        if self.cycle_running.load(Ordering::Acquire) {
            self.stats.starts_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(OrchestratorError::AlreadyInProgress);
        }
        if self.arp_gone.load(Ordering::Acquire) {
            return Err(OrchestratorError::ArpWorkerGone);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        match self.commands.try_send(OrchestratorCommand::StartCycle {
            trigger,
            params,
            cancel: Arc::clone(&cancel),
        }) {
            Ok(()) => {
                *lock_or_recover(&self.current_cancel) = Some(cancel);
                Ok(())
            }
            Err(err) => Err(OrchestratorError::from_send(err)),
        }
    }

    /// Cancels the running cycle (FR-DS-09).
    ///
    /// The shared flag of the most recently requested cycle is set
    /// **first** — that is the mechanism that works while the worker
    /// thread is busy inside the cycle — and the [`OrchestratorCommand::CancelCycle`]
    /// command is sent as the protocol's name for the same intent
    /// (best effort). A full command channel returns
    /// [`OrchestratorError::CommandQueueFull`] *after* the flag was
    /// set: the cancellation itself still takes effect; the call never
    /// blocks.
    pub fn cancel_cycle(&self) -> Result<(), OrchestratorError> {
        if let Some(flag) = lock_or_recover(&self.current_cancel).as_ref() {
            flag.store(true, Ordering::Release);
        }
        match self.commands.try_send(OrchestratorCommand::CancelCycle) {
            Ok(()) => Ok(()),
            Err(err) => Err(OrchestratorError::from_send(err)),
        }
    }

    /// A snapshot of the shared counters.
    pub fn stats(&self) -> OrchestratorStatsSnapshot {
        self.stats.snapshot()
    }

    /// Requests shutdown and joins the orchestrator thread (also
    /// performed by [`Drop`]). The worker cancels any running cycle,
    /// waits for its end (bounded by the cancel discipline), then
    /// stops and joins the arp worker (whose own shutdown bound
    /// applies). Design bound ≈ 500 ms (cancel 250 ms + joins);
    /// the tests assert a justified CI-jitter margin.
    pub fn shutdown(mut self) {
        self.shutdown_internal();
    }

    fn shutdown_internal(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Cancel whatever cycle is running so the joins stay bounded.
        if let Some(flag) = lock_or_recover(&self.current_cancel).as_ref() {
            flag.store(true, Ordering::Release);
        }
        let _ = self.commands.try_send(OrchestratorCommand::Shutdown);
        if let Some(thread) = self.thread.take() {
            // Join without panicking on a poisoned worker thread: the
            // handle's contract is "stop and join", not "unwrap" (the
            // same choice as the T-104 handle; a join failure is
            // impossible by construction — no panic path exists).
            let _ = thread.join();
        }
    }
}

impl Drop for DiscoveryWorker {
    fn drop(&mut self) {
        self.shutdown_internal();
    }
}

// ---------------------------------------------------------------------------
// The worker thread
// ---------------------------------------------------------------------------

/// Which machinery a worker owns (the read-only variant deliberately
/// carries nothing — there is no way to reach a socket from it).
enum Mode {
    /// The T-104 pair behind [`ArpWorkerSession`].
    Active(Box<dyn ArpWorkerSession>),
    /// Neighbor reads only (FR-DS-14).
    ReadOnly,
}

/// The orchestrator thread's owned world.
struct WorkerThread {
    mode: Mode,
    neighbors: Box<dyn NeighborSource + Send>,
    scope: Ipv4Net,
    iface: String,
    next_scan_id: u64,
    commands: Receiver<OrchestratorCommand>,
    events: SyncSender<CycleEvent>,
    stop: Arc<AtomicBool>,
    cycle_running: Arc<AtomicBool>,
    arp_gone: Arc<AtomicBool>,
    stats: Arc<OrchestratorStats>,
}

/// The identity of the cycle currently running: bundled so the cycle
/// helpers stay under the argument-count lint (all parts are `Copy`).
#[derive(Debug, Clone, Copy)]
struct CycleCtx {
    /// The cycle's identity.
    scan_id: ScanId,
    /// Why the cycle started.
    trigger: Trigger,
    /// Which machinery the cycle runs.
    mode: CycleMode,
    /// When the cycle began (wall clock of the whole cycle).
    started: Instant,
}

impl WorkerThread {
    /// The run loop: bounded command waits, one cycle at a time.
    fn run(mut self) {
        loop {
            if self.stop.load(Ordering::Acquire) {
                break;
            }
            // ScanId discipline: anything the arp side delivered while
            // no cycle runs cannot be attributed — drop and count it.
            // (A correct arp worker never emits between scans; this is
            // the card's defense in depth.)
            self.drain_stale_arp_events();
            match self.commands.recv_timeout(COMMAND_POLL_INTERVAL) {
                Ok(OrchestratorCommand::StartCycle {
                    trigger,
                    params,
                    cancel,
                }) => self.run_cycle(trigger, params, cancel),
                // The cancel flag (set by the handle) is the mechanism
                // that works mid-cycle; found while idle it is a no-op.
                Ok(OrchestratorCommand::CancelCycle) => {}
                Ok(OrchestratorCommand::Shutdown) => break,
                Err(RecvTimeoutError::Timeout) => continue, // re-check stop
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        // Stop the active machinery: cancels any residual scan and
        // joins the arp worker thread (its own bounded shutdown).
        if let Mode::Active(session) = std::mem::replace(&mut self.mode, Mode::ReadOnly) {
            session.shutdown();
        }
    }

    /// Runs one whole discovery cycle (§8.5, task card §3.3).
    fn run_cycle(&mut self, trigger: Trigger, params: ScanParams, cancel: Arc<AtomicBool>) {
        let scan_id = ScanId::new(self.next_scan_id);
        self.next_scan_id = self.next_scan_id.saturating_add(1);
        let ctx = CycleCtx {
            scan_id,
            trigger,
            mode: if matches!(self.mode, Mode::Active(_)) {
                CycleMode::Active
            } else {
                CycleMode::ReadOnly
            },
            started: Instant::now(),
        };
        self.cycle_running.store(true, Ordering::Release);
        self.stats.cycles_started.fetch_add(1, Ordering::Relaxed);
        if matches!(self.mode, Mode::Active(_)) {
            self.run_active_cycle(ctx, params, &cancel);
        } else {
            self.run_read_only_cycle(ctx, &cancel);
        }
    }

    /// The read-only cycle (FR-DS-14): started → one neighbor read →
    /// finished. `Complete` on a successful read (aging semantics
    /// identical, ADR-007); `Failed` when the read fails (the
    /// scheduler's failure rules apply through the outcome).
    fn run_read_only_cycle(&mut self, ctx: CycleCtx, cancel: &AtomicBool) {
        let CycleCtx {
            scan_id,
            trigger,
            mode,
            ..
        } = ctx;
        self.deliver_lifecycle(CycleEvent::Started {
            scan_id,
            trigger,
            mode,
        });
        match self.read_neighbors() {
            Ok(entries) => {
                self.forward_neighbor_entries(scan_id, &entries, cancel);
                let outcome = if self.tearing_down(cancel) {
                    ScanOutcome::Cancelled
                } else {
                    ScanOutcome::Complete
                };
                self.finish_cycle(ctx, outcome, ScanCounters::default(), None);
            }
            Err(reason) => {
                let outcome = ScanOutcome::Failed {
                    reason: format!("reading the neighbor table failed: {reason}"),
                };
                self.finish_cycle(ctx, outcome, ScanCounters::default(), None);
            }
        }
    }

    /// The active cycle (§8.5): started → pre-read → ARP sweep (with
    /// the listen window inside the scanner) → post-read → finished.
    fn run_active_cycle(&mut self, ctx: CycleCtx, params: ScanParams, cancel: &AtomicBool) {
        let CycleCtx {
            scan_id,
            trigger,
            mode,
            ..
        } = ctx;
        self.deliver_lifecycle(CycleEvent::Started {
            scan_id,
            trigger,
            mode,
        });
        // §8.5 step 1: the pre-sweep neighbor read — instant first
        // rows (FR-DS-01). A failure degrades but does not stop the
        // cycle (the sweep is the primary source, task card §3.3).
        let mut degraded: Option<Degradation> = None;
        match self.read_neighbors() {
            Ok(entries) => self.forward_neighbor_entries(scan_id, &entries, cancel),
            Err(reason) => degraded = Some(Degradation::PreReadFailed { reason }),
        }
        if self.tearing_down(cancel) {
            // Cancelled during the pre-read: no sweep, no post-read.
            self.finish_cycle(
                ctx,
                ScanOutcome::Cancelled,
                ScanCounters::default(),
                degraded,
            );
            return;
        }
        // Take the session out so `self` stays usable around it; the
        // placeholder is replaced back before returning.
        let session = match std::mem::replace(&mut self.mode, Mode::ReadOnly) {
            Mode::Active(session) => session,
            // Defensive: run_active_cycle is entered only for active
            // mode (checked in run_cycle); if a future refactor broke
            // that, fail the cycle honestly instead of panicking.
            Mode::ReadOnly => {
                self.finish_cycle(
                    ctx,
                    ScanOutcome::Failed {
                        reason: "internal mode mismatch: no arp session for an active cycle"
                            .to_owned(),
                    },
                    ScanCounters::default(),
                    None,
                );
                return;
            }
        };
        // §8.5 steps 2–3: the paced ARP sweep and its listen window,
        // run by the T-104 worker; the orchestrator forwards the
        // worker's batches tagged with this cycle's ScanId.
        let ended = self.drive_arp_scan(session.as_ref(), ctx, &params, cancel);
        if let Some(summary) = ended {
            // §8.5 step 4: the post-sweep neighbor read — skipped when
            // the cycle is being cancelled (the user asked to stop;
            // the already-delivered evidence stays valid and is not
            // aged, ADR-007). A cancel observed at this stage cancels
            // only a success-class sweep: a sweep that itself failed
            // keeps its outcome — the worse outcome wins (execution
            // report §6, Decision 5) — so the failure still feeds the
            // FR-DS-12 streak and the failure backoff instead of
            // masquerading as a user cancellation.
            let mut outcome = summary.outcome.clone();
            let counters = summary.counters.clone();
            let sweep_failed = matches!(outcome, ScanOutcome::Failed { .. });
            if self.tearing_down(cancel) {
                if !sweep_failed {
                    outcome = ScanOutcome::Cancelled;
                }
            } else if !matches!(outcome, ScanOutcome::Cancelled) {
                match self.read_neighbors() {
                    Ok(entries) => self.forward_neighbor_entries(scan_id, &entries, cancel),
                    Err(reason) => degraded = Some(Degradation::PostReadFailed { reason }),
                }
            }
            // Never age on a degraded view (ADR-007): a failed
            // neighbor read downgrades Complete (or Partial) to
            // Partial with the typed reason. A Failed sweep stays
            // Failed — the worse outcome is the honest one.
            if degraded.is_some() && matches!(outcome, ScanOutcome::Complete | ScanOutcome::Partial)
            {
                outcome = ScanOutcome::Partial;
            }
            self.finish_cycle(ctx, outcome, counters, degraded);
        }
        // Give the session back (the ReadOnly above was a placeholder).
        self.mode = Mode::Active(session);
    }

    /// Drives the ARP half of an active cycle: starts the scan,
    /// forwards its batches tagged with `scan_id`, and waits for its
    /// `ScanFinished` (all waits sliced at [`WAIT_SLICE`]).
    ///
    /// Returns the arp scan's summary, or `None` when the cycle was
    /// already finished inside (arp worker gone before or during the
    /// scan — the failed fast paths below; the caller then only
    /// restores its session).
    fn drive_arp_scan(
        &mut self,
        session: &dyn ArpWorkerSession,
        ctx: CycleCtx,
        params: &ScanParams,
        cancel: &AtomicBool,
    ) -> Option<Box<ScanSummary>> {
        // A dead arp worker cannot be revived: fail the cycle fast
        // (task card §3.3) — later starts see the typed error.
        if self.arp_gone.load(Ordering::Acquire) {
            self.finish_cycle(
                ctx,
                ScanOutcome::Failed {
                    reason: "the arp worker is gone".to_owned(),
                },
                ScanCounters::default(),
                None,
            );
            return None;
        }
        // ScanId discipline: anything pending on the arp channel
        // before this cycle's scan starts belongs to an earlier
        // cycle — drop and count it, never forward it.
        self.drain_stale_from(session);
        if let Err(err) = session.start_scan(params) {
            // The arp worker refused the scan (queue full is
            // unreachable for the single commander; a stopped worker
            // is the real case): the cycle fails, typed and counted.
            self.arp_gone.store(true, Ordering::Release);
            self.finish_cycle(
                ctx,
                ScanOutcome::Failed {
                    reason: format!("starting the arp scan failed: {err}"),
                },
                ScanCounters::default(),
                None,
            );
            return None;
        }
        loop {
            if self.tearing_down(cancel) {
                session.cancel();
            }
            match session.recv_timeout(WAIT_SLICE) {
                Ok(DiscoveryEvent::Observations(batch)) => {
                    self.forward_batch(ctx.scan_id, batch, cancel);
                }
                Ok(DiscoveryEvent::ScanFinished(summary)) => return Some(summary),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    // The arp worker died mid-cycle — impossible by
                    // construction (task card §3.3); classified Failed,
                    // marked gone, never respawned.
                    self.arp_gone.store(true, Ordering::Release);
                    self.finish_cycle(
                        ctx,
                        ScanOutcome::Failed {
                            reason: "the arp worker stopped during the cycle".to_owned(),
                        },
                        ScanCounters::default(),
                        None,
                    );
                    return None;
                }
            }
        }
    }

    /// `true` when the cycle must wind down as cancelled (its own
    /// cancel flag, or the orchestrator's shutdown).
    fn tearing_down(&self, cancel: &AtomicBool) -> bool {
        self.stop.load(Ordering::Acquire) || cancel.load(Ordering::Acquire)
    }

    /// Reads the neighbor source, mapping a failure to its one-line
    /// reason (the typed [`Degradation`] wraps it for the summary).
    fn read_neighbors(&self) -> Result<Vec<NeighborEntry>, String> {
        self.neighbors
            .read_neighbors(&self.scope, &self.iface)
            .map_err(|err| err.to_string())
    }

    /// Forwards neighbor entries as tagged observation batches,
    /// chunked at the arp worker's documented batch size so each event
    /// is independently droppable under saturation (FR-DS-10 shape).
    fn forward_neighbor_entries(
        &self,
        scan_id: ScanId,
        entries: &[NeighborEntry],
        cancel: &AtomicBool,
    ) {
        for chunk in entries.chunks(MAX_BATCH_SIZE) {
            let batch: Vec<Observation> = chunk.iter().map(Observation::from_neighbor).collect();
            self.forward_batch(scan_id, batch, cancel);
        }
    }

    /// Forwards one mid-cycle batch under the T-104 delivery policy:
    /// `try_send` with a small retry budget; dropped and counted on
    /// saturation, cancellation, disconnect or shutdown. On
    /// disconnect the cycle is cancelled too — nobody is listening
    /// (the T-104 "consumer is gone" rule).
    fn forward_batch(&self, scan_id: ScanId, batch: Vec<Observation>, cancel: &AtomicBool) {
        if batch.is_empty() {
            return;
        }
        let mut event = CycleEvent::Observations { scan_id, batch };
        for _ in 0..FORWARD_RETRY_BUDGET {
            if self.stop.load(Ordering::Acquire) {
                self.stats.batches_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            match self.events.try_send(event) {
                Ok(()) => {
                    self.stats.batches_forwarded.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(TrySendError::Full(back)) => {
                    if cancel.load(Ordering::Acquire) {
                        // Dropping is what keeps cancel inside its
                        // bound under saturation (task card §3.3).
                        self.stats.batches_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    event = back;
                    thread::sleep(SEND_RETRY_WAIT);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.stats.batches_dropped.fetch_add(1, Ordering::Relaxed);
                    cancel.store(true, Ordering::Release);
                    return;
                }
            }
        }
        self.stats.batches_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Delivers a lifecycle event (`cycle started` / `cycle
    /// finished`): retried until the consumer makes space; dropped
    /// only on shutdown (documented policy) or when the receiver is
    /// gone — which also ends the orchestrator after the cycle (the
    /// T-104 pattern).
    fn deliver_lifecycle(&self, event: CycleEvent) {
        let mut event = event;
        loop {
            if self.stop.load(Ordering::Acquire) {
                return;
            }
            match self.events.try_send(event) {
                Ok(()) => return,
                Err(TrySendError::Full(back)) => {
                    event = back;
                    thread::sleep(SEND_RETRY_WAIT);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.stop.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }

    /// Emits `cycle finished` and clears the FR-DS-08 guard.
    ///
    /// The guard is cleared **before** the event is delivered: the
    /// application reacts to `Finished` (e.g. by issuing the next
    /// cycle), and it must never observe a cycle that already ended as
    /// still running. (The other direction is safe: a start accepted
    /// during the finish delivery merely queues for the worker's next
    /// command pick-up — the thread is single-cycle by construction.)
    fn finish_cycle(
        &mut self,
        ctx: CycleCtx,
        outcome: ScanOutcome,
        counters: ScanCounters,
        degraded: Option<Degradation>,
    ) {
        let summary = Box::new(CycleSummary {
            outcome,
            counters,
            elapsed: ctx.started.elapsed(),
            degraded,
        });
        self.stats.cycles_finished.fetch_add(1, Ordering::Relaxed);
        self.cycle_running.store(false, Ordering::Release);
        self.deliver_lifecycle(CycleEvent::Finished {
            scan_id: ctx.scan_id,
            trigger: ctx.trigger,
            mode: ctx.mode,
            summary,
        });
    }

    /// Drains unattributable arp events (ScanId discipline) from the
    /// owned session while idle. See [`Self::drain_stale_from`].
    fn drain_stale_arp_events(&mut self) {
        let session = match std::mem::replace(&mut self.mode, Mode::ReadOnly) {
            Mode::Active(session) => session,
            Mode::ReadOnly => return, // nothing to drain in read-only mode
        };
        self.drain_stale_from(session.as_ref());
        self.mode = Mode::Active(session);
    }

    /// Consumes everything currently pending on the arp channel and
    /// counts it as stale: no cycle is running (or the next scan has
    /// not started yet), so nothing there can be attributed — a
    /// correct arp worker never delivers here (its final flush always
    /// precedes its `ScanFinished`), which is exactly why these are
    /// dropped rather than forwarded (task card §3.3).
    fn drain_stale_from(&self, session: &dyn ArpWorkerSession) {
        while let Ok(_event) = session.recv_timeout(Duration::ZERO) {
            self.stats.stale_arp_events.fetch_add(1, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::arp::scanner::ArpScanner;
    use crate::discovery::arp::scanner::{DEFAULT_LISTEN_WINDOW, DEFAULT_RATE_PPS};
    use crate::discovery::arp::test_support::FakeTransport;
    use crate::discovery::neighbor_table::parse_arp_table;
    use crate::model::field::Source;

    /// A synthetic documentation scope (RFC 5737): 192.0.2.0/29 — five
    /// probe targets (.2…​.6) beside our own .1.
    fn scope() -> Ipv4Net {
        Ipv4Net::new(std::net::Ipv4Addr::new(192, 0, 2, 0), 29).expect("valid network")
    }

    fn our_mac() -> crate::model::mac::MacAddr {
        crate::discovery::arp::test_support::test_our_mac()
    }

    fn our_ip() -> std::net::Ipv4Addr {
        crate::discovery::arp::test_support::TEST_OUR_IP
    }

    /// A /29 scanner over the fake transport with a 10 ms pass gap
    /// (the T-104 test-suite trick; the default 1 s gap exists to let
    /// real targets update their caches, which a fake does not need).
    fn scanner_for(fake: &FakeTransport) -> ArpScanner {
        ArpScanner::new(Box::new(fake.clone()), scope(), our_mac(), our_ip())
            .with_pass_gap(Duration::from_millis(10))
    }

    fn params(passes: u8, rate_pps: u32, listen_window: Duration) -> ScanParams {
        ScanParams {
            passes,
            rate_pps,
            listen_window,
        }
    }

    // -----------------------------------------------------------------------
    // Fake neighbor source (scripted, optionally gated)
    // -----------------------------------------------------------------------

    /// An arp-table text with `n` complete eth0 rows inside the /29
    /// (only .2…​.6 are real scope members; the fake source applies no
    /// filtering itself, mirroring the `NeighborSource` contract that
    /// rows arrive already reduced — a few out-of-scope rows are
    /// harmless because the orchestrator forwards what it is given).
    fn table_text(rows: usize) -> String {
        let mut text = String::from("IP address HW type Flags HW address Mask Device\n");
        for i in 0..rows {
            let host = 2 + (i % 5);
            text.push_str(&format!(
                "192.0.2.{host} 0x1 0x2 02:00:00:00:00:{host:02x} * eth0\n"
            ));
        }
        text
    }

    #[derive(Clone, Default)]
    struct FakeNeighbors {
        state: Arc<Mutex<NeighborScript>>,
    }

    #[derive(Default)]
    struct NeighborScript {
        /// One entry per read: `Ok` carries an arp-table text, `Err`
        /// an io-error message. Exhausted → empty read.
        reads: std::collections::VecDeque<Result<String, String>>,
        /// When set, the next read parks on this latch first (bounded;
        /// the command-queue test holds the worker inside a read).
        gate: Option<mpsc::Receiver<()>>,
        calls: usize,
    }

    impl FakeNeighbors {
        fn new(reads: Vec<Result<String, String>>) -> Self {
            let mut script = NeighborScript::default();
            script.reads.extend(reads);
            Self {
                state: Arc::new(Mutex::new(script)),
            }
        }

        /// A gate that parks the next read until `release` fires.
        fn gated(&self) -> mpsc::Sender<()> {
            let (tx, rx) = mpsc::channel();
            lock_or_recover(&self.state).gate = Some(rx);
            tx
        }

        fn calls(&self) -> usize {
            lock_or_recover(&self.state).calls
        }
    }

    impl NeighborSource for FakeNeighbors {
        fn read_neighbors(
            &self,
            _scope: &Ipv4Net,
            _interface_name: &str,
        ) -> Result<Vec<NeighborEntry>, crate::discovery::neighbor_table::NeighborError> {
            let mut state = lock_or_recover(&self.state);
            state.calls += 1;
            if let Some(rx) = state.gate.take() {
                drop(state);
                // Bounded park: a wedged test fails rather than hangs.
                let _ = rx.recv_timeout(Duration::from_secs(5));
                state = lock_or_recover(&self.state);
            }
            match state.reads.pop_front() {
                None => Ok(Vec::new()),
                Some(Ok(text)) => Ok(parse_arp_table(&text)),
                Some(Err(message)) => Err(crate::discovery::neighbor_table::NeighborError::Io {
                    path: std::path::PathBuf::from("/proc/net/arp"),
                    source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, message),
                }),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Gated arp session (AC-8's delayed-batch fake; also the dead-worker
    // and disconnect fakes)
    // -----------------------------------------------------------------------

    /// A scripted [`ArpWorkerSession`]: each `start_scan` activates the
    /// next script; events replay from the active script while a scan
    /// runs; the **straggler** is delivered only while no scan is
    /// active and its gate is open (the defective late batch of an
    /// earlier scan — impossible through the real worker, which is why
    /// the trait seam exists). `gone` turns `recv` into a disconnect.
    #[derive(Clone, Default)]
    struct GatedArpSession {
        state: Arc<Mutex<GatedState>>,
    }

    #[derive(Default)]
    struct GatedState {
        starts: Vec<ScanParams>,
        cancels: usize,
        scripts: std::collections::VecDeque<std::collections::VecDeque<DiscoveryEvent>>,
        /// The script of the scan currently in flight (`None` while
        /// idle — only then can the straggler or a drain apply).
        active: Option<std::collections::VecDeque<DiscoveryEvent>>,
        straggler: Option<DiscoveryEvent>,
        gate_open: bool,
        /// While set, the active script's terminal `ScanFinished` is
        /// withheld — `recv_timeout` reports `Timeout` (the orchestrator
        /// keeps poll-slicing at `WAIT_SLICE` inside `drive_arp_scan`)
        /// until the latch fires (T-204-RW1 R-3.3).
        finish_hold: Option<mpsc::Receiver<()>>,
        gone: bool,
    }

    impl GatedArpSession {
        fn scan(&self, events: Vec<DiscoveryEvent>) {
            lock_or_recover(&self.state)
                .scripts
                .push_back(events.into());
        }

        fn straggler_batch(&self, observation: Observation) {
            lock_or_recover(&self.state).straggler =
                Some(DiscoveryEvent::Observations(vec![observation]));
        }

        fn open_gate(&self) {
            lock_or_recover(&self.state).gate_open = true;
        }

        /// Engages the finish hold-gate (mirrors
        /// [`FakeNeighbors::gated`]): while engaged, the active
        /// script's terminal `ScanFinished` is withheld — the
        /// orchestrator keeps poll-slicing at `WAIT_SLICE` inside
        /// `drive_arp_scan` — until the returned latch fires. That
        /// makes "the cancel flag is latched before the post-sweep
        /// outcome branch runs" a property of the script, not of
        /// timing.
        fn hold_finish(&self) -> mpsc::Sender<()> {
            let (tx, rx) = mpsc::channel();
            lock_or_recover(&self.state).finish_hold = Some(rx);
            tx
        }

        fn go_dead(&self) {
            // Only the receive side dies (the channel disconnects): the
            // test drives the mid-cycle death path, with `start_scan`
            // still accepting (the start-refusal branch of the
            // orchestrator is the same arp-gone handling, covered by
            // the typed-error assertion below).
            lock_or_recover(&self.state).gone = true;
        }

        fn start_count(&self) -> usize {
            lock_or_recover(&self.state).starts.len()
        }

        fn recorded_params(&self) -> ScanParams {
            lock_or_recover(&self.state).starts[0]
        }
    }

    impl ArpWorkerSession for GatedArpSession {
        fn start_scan(&self, params: &ScanParams) -> Result<(), WorkerError> {
            let mut state = lock_or_recover(&self.state);
            state.starts.push(*params);
            state.active = state.scripts.pop_front();
            Ok(())
        }

        fn cancel(&self) {
            lock_or_recover(&self.state).cancels += 1;
        }

        fn recv_timeout(&self, _timeout: Duration) -> Result<DiscoveryEvent, RecvTimeoutError> {
            let mut state = lock_or_recover(&self.state);
            if state.gone {
                return Err(RecvTimeoutError::Disconnected);
            }
            // The finish hold-gate (T-204-RW1): while engaged, the
            // active script's terminal `ScanFinished` is withheld —
            // `Timeout`, so the caller keeps poll-slicing — until the
            // latch fires; only then does the finish pass through.
            let holding_finish = state.finish_hold.is_some()
                && matches!(
                    state
                        .active
                        .as_ref()
                        .map(|script| (script.len(), script.front())),
                    Some((1, Some(DiscoveryEvent::ScanFinished(_))))
                );
            if holding_finish {
                let released = match state.finish_hold.as_ref() {
                    Some(hold) => matches!(
                        hold.try_recv(),
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
                    ),
                    None => true,
                };
                if !released {
                    return Err(RecvTimeoutError::Timeout);
                }
                state.finish_hold = None;
            }
            if let Some(script) = state.active.as_mut()
                && let Some(event) = script.pop_front()
            {
                if script.is_empty() {
                    // The scan's script (ending in its `ScanFinished`)
                    // is fully delivered: back to idle semantics.
                    state.active = None;
                }
                return Ok(event);
            }
            if state.gate_open
                && let Some(straggler) = state.straggler.take()
            {
                // Delivered outside any scan — only the idle/cycle-start
                // drains ever see this.
                return Ok(straggler);
            }
            Err(RecvTimeoutError::Timeout)
        }

        fn shutdown(self: Box<Self>) {
            // Nothing to join in the fake.
        }
    }

    /// Spawns the orchestrator around a scripted session (the private
    /// seam the AC-8 / dead-worker tests use; production goes through
    /// [`DiscoveryWorker::spawn_active`]).
    fn spawn_with_session(
        session: GatedArpSession,
        neighbors: FakeNeighbors,
    ) -> (DiscoveryWorker, Receiver<CycleEvent>) {
        DiscoveryWorker::spawn_with_mode(
            Mode::Active(Box::new(session)),
            Box::new(neighbors),
            scope(),
            "eth0",
        )
    }

    // -----------------------------------------------------------------------
    // Event helpers
    // -----------------------------------------------------------------------

    /// Collects events until `Finished` (each individual wait bounded).
    fn drain_until_finished(events: &Receiver<CycleEvent>) -> Vec<CycleEvent> {
        let mut collected = Vec::new();
        loop {
            match events.recv_timeout(Duration::from_secs(5)) {
                Ok(event @ CycleEvent::Finished { .. }) => {
                    collected.push(event);
                    return collected;
                }
                Ok(event) => collected.push(event),
                Err(err) => panic!("no event arrived: {err} (collected {collected:?})"),
            }
        }
    }

    /// Waits for the next event, bounded.
    fn next_event(events: &Receiver<CycleEvent>) -> CycleEvent {
        events
            .recv_timeout(Duration::from_secs(5))
            .expect("an event arrives")
    }

    fn started_of(event: &CycleEvent) -> (ScanId, Trigger, CycleMode) {
        match event {
            CycleEvent::Started {
                scan_id,
                trigger,
                mode,
            } => (*scan_id, *trigger, *mode),
            other => panic!("expected Started, got {other:?}"),
        }
    }

    fn finished_of(event: &CycleEvent) -> (ScanId, Trigger, CycleMode, CycleSummary) {
        match event {
            CycleEvent::Finished {
                scan_id,
                trigger,
                mode,
                summary,
            } => (*scan_id, *trigger, *mode, (**summary).clone()),
            other => panic!("expected Finished, got {other:?}"),
        }
    }

    /// The observations of an `Observations` event.
    fn observations_of(event: &CycleEvent) -> (ScanId, Vec<Observation>) {
        match event {
            CycleEvent::Observations { scan_id, batch } => (*scan_id, batch.clone()),
            other => panic!("expected Observations, got {other:?}"),
        }
    }

    /// Polls the shared stats until `pred` holds (bounded, no blind
    /// sleeps beyond the poll tick).
    fn wait_stats(
        worker: &DiscoveryWorker,
        pred: impl Fn(&OrchestratorStatsSnapshot) -> bool,
    ) -> OrchestratorStatsSnapshot {
        let start = Instant::now();
        loop {
            let snap = worker.stats();
            if pred(&snap) {
                return snap;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "stats condition not reached within 5 s: {snap:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    // -----------------------------------------------------------------------
    // AC-3: the full-cycle event sequence through the REAL arp worker
    // -----------------------------------------------------------------------

    #[test]
    fn full_cycle_event_sequence_through_the_real_arp_worker() {
        let fake = FakeTransport::new();
        // Two responders (.2, .3) and three silent targets (.4…​.6):
        // pass 1 reaches all five, pass 2 re-probes the three silent
        // ones — 8 sends prove the 2-pass command reached the scanner.
        for host in [2u8, 3] {
            fake.responder(
                std::net::Ipv4Addr::new(192, 0, 2, host),
                crate::model::mac::MacAddr::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, host])
                    .expect("valid unicast MAC"),
            );
        }
        let neighbors = FakeNeighbors::new(vec![
            Ok(table_text(2)), // pre-read
            Ok(table_text(2)), // post-read
        ]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) = DiscoveryWorker::spawn_active(
            arp,
            arp_events,
            Box::new(neighbors.clone()),
            scope(),
            "eth0",
        );

        // Cycle 1 (initial, 2 passes, 500 pps, 200 ms window).
        worker
            .start_cycle(Trigger::Initial, params(2, 500, Duration::from_millis(200)))
            .expect("start ok");
        let collected = drain_until_finished(&events);

        // The exact §8.5 sequence: started → pre-read → arp batches →
        // post-read → finished, one Started and one Finished.
        let (id, trigger, mode) = started_of(&collected[0]);
        assert_eq!(
            (id, trigger, mode),
            (ScanId::new(1), Trigger::Initial, CycleMode::Active)
        );
        let (fid, ftrigger, fmode, summary) =
            finished_of(collected.last().expect("at least the finish"));
        assert_eq!(
            (fid, ftrigger, fmode),
            (ScanId::new(1), Trigger::Initial, CycleMode::Active)
        );
        assert_eq!(summary.outcome, ScanOutcome::Complete);
        assert_eq!(summary.degraded, None);
        assert_eq!(summary.counters.replies_accepted, 2);
        assert_eq!(summary.counters.requests_sent, 8); // 5 + 3 re-probed
        assert_eq!(
            summary.counters.passes_run, 2,
            "the 2-pass command reached the scanner"
        );
        assert!(
            summary.elapsed >= Duration::from_millis(200),
            "the 200 ms listen window is inside the cycle: {:?}",
            summary.elapsed
        );

        // Observation events between started and finished: neighbor
        // pre-read, arp replies, neighbor post-read — every batch
        // tagged with the same ScanId.
        let mut sources: Vec<Source> = Vec::new();
        let mut arp_seen = 0;
        for event in &collected[1..collected.len() - 1] {
            let (bid, batch) = observations_of(event);
            assert_eq!(bid, ScanId::new(1), "every batch carries the cycle id");
            assert!(!batch.is_empty());
            for observation in &batch {
                sources.push(observation.source);
                if observation.source == Source::ArpReply {
                    arp_seen += 1;
                }
            }
        }
        assert_eq!(arp_seen, 2, "two responders observed");
        // The source pattern is pre-read, arp, post-read.
        let neighbor_table = sources
            .iter()
            .filter(|s| **s == Source::NeighborTable)
            .count();
        assert_eq!(neighbor_table, 4, "pre-read 2 + post-read 2 rows");
        assert_eq!(sources.len(), 6);
        assert_eq!(
            sources.first(),
            Some(&Source::NeighborTable),
            "pre-read first"
        );
        assert_eq!(
            sources.last(),
            Some(&Source::NeighborTable),
            "post-read last"
        );
        assert!(
            sources.contains(&Source::ArpReply),
            "arp evidence between the reads"
        );
        assert_eq!(neighbors.calls(), 2, "pre- and post-read");

        // Rate as commanded: consecutive sends of pass 1 keep the
        // 2 ms (500 pps) minimum spacing.
        let sent = fake.sent_log();
        assert_eq!(sent.len(), 8, "5 targets + 3 re-probed");
        let first_pass = &sent[..5];
        for pair in first_pass.windows(2) {
            let gap = pair[1].0.duration_since(pair[0].0);
            assert!(
                gap >= Duration::from_millis(1),
                "pacing violated: {gap:?} (CI scheduling may add, never remove, spacing)"
            );
        }

        // Cycle 2 (manual): ids increase monotonically.
        worker
            .start_cycle(
                Trigger::Manual,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(80)),
            )
            .expect("second start ok");
        let second = drain_until_finished(&events);
        let (id2, trigger2, _) = started_of(&second[0]);
        assert_eq!((id2, trigger2), (ScanId::new(2), Trigger::Manual));
        assert!(id2.as_u64() > id.as_u64());
        let (_, _, _, summary2) = finished_of(second.last().expect("finish present"));
        assert_eq!(summary2.outcome, ScanOutcome::Complete);
        // 1 pass over 5 targets, no re-probe pass: 5 sends more.
        assert_eq!(fake.sent_log().len(), 13);
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // AC-4: one cycle at a time
    // -----------------------------------------------------------------------

    #[test]
    fn a_start_during_a_running_cycle_is_rejected_and_queues_nothing() {
        let fake = FakeTransport::new();
        fake.responder(
            std::net::Ipv4Addr::new(192, 0, 2, 2),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1)), Ok(table_text(1))]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) =
            DiscoveryWorker::spawn_active(arp, arp_events, Box::new(neighbors), scope(), "eth0");
        // A long cycle (3 passes, 1 s window): plenty of time to hit
        // the guard mid-cycle.
        worker
            .start_cycle(
                Trigger::Initial,
                params(3, DEFAULT_RATE_PPS, Duration::from_secs(1)),
            )
            .expect("start ok");
        assert_eq!(
            started_of(&next_event(&events)).0,
            ScanId::new(1),
            "the cycle began"
        );
        // The rejected start: typed already-in-progress, nothing queued.
        assert_eq!(
            worker.start_cycle(
                Trigger::Manual,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(50))
            ),
            Err(OrchestratorError::AlreadyInProgress)
        );
        let rejected_at = fake.sent_log().len();
        // The running cycle finishes: exactly one Started was ever
        // seen (the first one, consumed above), and the send count is
        // exactly one cycle's (5 targets in pass 1 + 4 non-responders
        // re-probed in each of passes 2 and 3 = 13).
        let collected = drain_until_finished(&events);
        let started_count = collected
            .iter()
            .filter(|event| matches!(event, CycleEvent::Started { .. }))
            .count();
        assert_eq!(started_count, 0, "no second cycle ever started");
        let (_, _, _, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(summary.counters.requests_sent, 13);
        assert_eq!(fake.sent_log().len(), 13);
        assert!(
            fake.sent_log().len() >= rejected_at,
            "sends only grew from cycle 1"
        );
        // Proof that nothing was queued: a fresh start is accepted
        // (a queued command would be running now and the guard would
        // reject this).
        assert_eq!(
            worker.start_cycle(
                Trigger::Manual,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(50))
            ),
            Ok(())
        );
        let second = drain_until_finished(&events);
        assert_eq!(started_of(&second[0]).0, ScanId::new(2));
        assert_eq!(fake.sent_log().len(), 18, "13 + one 1-pass sweep of 5");
        let snap = wait_stats(&worker, |snap| snap.starts_rejected >= 1);
        assert_eq!(snap.starts_rejected, 1);
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // AC-5: cancellation
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_completes_within_the_bound_and_the_next_cycle_runs() {
        let fake = FakeTransport::new();
        fake.responder(
            std::net::Ipv4Addr::new(192, 0, 2, 2),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1)), Ok(table_text(1))]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) =
            DiscoveryWorker::spawn_active(arp, arp_events, Box::new(neighbors), scope(), "eth0");
        // A cycle whose listen window (3 s) would run far past the
        // cancel bound.
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_secs(3)),
            )
            .expect("start ok");
        assert_eq!(started_of(&next_event(&events)).0, ScanId::new(1));
        // Wait for the pre-read batch (the cycle is mid-flight).
        assert_eq!(observations_of(&next_event(&events)).0, ScanId::new(1));
        let cancelled_at = Instant::now();
        worker.cancel_cycle().expect("cancel accepted");
        // The finish arrives well inside the bound (design 250 ms;
        // 1 s = the 4× CI headroom T-203 used for its shutdown bound).
        let mut collected = Vec::new();
        loop {
            let event = next_event(&events);
            let is_finish = matches!(event, CycleEvent::Finished { .. });
            collected.push(event);
            if is_finish {
                break;
            }
        }
        let elapsed = cancelled_at.elapsed();
        let (fid, _, mode, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(fid, ScanId::new(1));
        assert_eq!(mode, CycleMode::Active);
        assert_eq!(summary.outcome, ScanOutcome::Cancelled);
        assert_eq!(summary.degraded, None);
        assert!(
            elapsed < Duration::from_secs(1),
            "cancel to finish took {elapsed:?}"
        );
        // The post-read was skipped: the pre-read batch was consumed
        // above, and arp evidence the sweep gathered *before* the
        // cancel propagated is still valid and delivered (T-104's
        // policy — the registry takes it; the Cancelled outcome simply
        // never ages). What must not appear is any *neighbor-table*
        // row after the cancel: zero.
        let neighbor_rows = collected
            .iter()
            .filter_map(|event| match event {
                CycleEvent::Observations { batch, .. } => Some(
                    batch
                        .iter()
                        .filter(|observation| observation.source == Source::NeighborTable)
                        .count(),
                ),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(neighbor_rows, 0, "no post-read after cancel");
        // The next cycle runs normally: fresh cancel flag (the T-104
        // guarantee preserved end to end).
        worker
            .start_cycle(
                Trigger::Periodic,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(80)),
            )
            .expect("next start ok");
        let second = drain_until_finished(&events);
        let (_, _, _, summary2) = finished_of(second.last().expect("finish present"));
        assert_eq!(summary2.outcome, ScanOutcome::Complete);
        assert_eq!(summary2.counters.replies_accepted, 1);
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // AC-6: backpressure
    // -----------------------------------------------------------------------

    /// The saturation fixture: a pre-read of 2,200 rows (69 batches of
    /// 32 — more than the 64-slot event channel) with a small sweep.
    fn saturation_fixture() -> (
        DiscoveryWorker,
        Receiver<CycleEvent>,
        FakeTransport,
        FakeNeighbors,
    ) {
        let fake = FakeTransport::new();
        fake.responder(
            std::net::Ipv4Addr::new(192, 0, 2, 2),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let neighbors = FakeNeighbors::new(vec![
            Ok(table_text(2_200)), // pre-read floods the event channel
            Ok(table_text(2)),     // post-read (tiny)
        ]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) = DiscoveryWorker::spawn_active(
            arp,
            arp_events,
            Box::new(neighbors.clone()),
            scope(),
            "eth0",
        );
        (worker, events, fake, neighbors)
    }

    #[test]
    fn saturated_events_drop_and_count_mid_cycle_batches_but_deliver_the_finish() {
        let (worker, events, fake, _neighbors) = saturation_fixture();
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(80)),
            )
            .expect("start ok");
        // The consumer does not drain. The pre-read (69 batches of 32 —
        // five more than the 64-slot channel) resolves fully before
        // the sweep's first send, so waiting for the sweep to be
        // underway means the drops have already happened.
        let sweep_started = Instant::now();
        while fake.sent_log().is_empty() {
            assert!(
                sweep_started.elapsed() < Duration::from_secs(5),
                "the sweep never started; stats {:?}",
                worker.stats()
            );
            thread::sleep(Duration::from_millis(10));
        }
        let before_drain = worker.stats();
        assert!(
            before_drain.batches_dropped >= 5,
            "the saturated pre-read dropped and counted: {before_drain:?}"
        );
        // Now drain: the finish is still delivered once space appears.
        let collected = drain_until_finished(&events);
        let (fid, _, _, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(fid, ScanId::new(1));
        assert_eq!(
            summary.outcome,
            ScanOutcome::Complete,
            "the cycle itself stayed healthy"
        );
        let snap = wait_stats(&worker, |snap| snap.cycles_finished >= 1);
        assert!(
            snap.batches_dropped >= 5,
            "mid-cycle batches dropped and counted: {snap:?}"
        );
        assert!(snap.batches_forwarded >= 1);
        worker.shutdown();
    }

    #[test]
    fn cancel_under_event_saturation_still_meets_the_bound() {
        let (worker, events, _fake, _neighbors) = saturation_fixture();
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(80)),
            )
            .expect("start ok");
        let _snap = wait_stats(&worker, |snap| snap.batches_dropped >= 1);
        let cancelled_at = Instant::now();
        worker.cancel_cycle().expect("cancel accepted");
        let collected = drain_until_finished(&events);
        let elapsed = cancelled_at.elapsed();
        let (_, _, _, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(summary.outcome, ScanOutcome::Cancelled);
        assert!(
            elapsed < Duration::from_secs(1),
            "cancel under saturation took {elapsed:?}"
        );
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // T-204-RW1 (F-1): post-sweep outcome precedence — a late cancel
    // never downgrades a Failed sweep (§6 Decision 5)
    // -----------------------------------------------------------------------

    /// The shared prologue of the two late-cancel regressions: a
    /// scripted sweep that gathers one reply and then ends in the given
    /// outcome, its terminal `ScanFinished` held back by the finish
    /// hold-gate; the pre-read and ARP batches are consumed mid-sweep,
    /// the cancel is latched, and only then is the finish released —
    /// so the post-sweep outcome branch provably runs with
    /// `tearing_down == true` and the sweep's own outcome already
    /// fixed, with no timing dependence (the flag store happens-before
    /// the latch send, which happens-before the withheld finish is
    /// delivered).
    fn late_cancel_fixture(
        sweep_outcome: ScanOutcome,
    ) -> (
        DiscoveryWorker,
        Receiver<CycleEvent>,
        FakeNeighbors,
        mpsc::Sender<()>,
    ) {
        let session = GatedArpSession::default();
        session.scan(vec![
            DiscoveryEvent::Observations(vec![obs(2)]),
            finished_event(sweep_outcome, 3),
        ]);
        // Only the pre-read is scripted on the neighbor side: a second
        // read call would be exactly the post-sweep read the skip must
        // prevent.
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1))]);
        let release = session.hold_finish();
        let (worker, events) = spawn_with_session(session, neighbors.clone());
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("start ok");
        assert_eq!(started_of(&next_event(&events)).0, ScanId::new(1));
        // The pre-read batch, then the sweep's own batch — both
        // consumed while the finish is held, i.e. mid-sweep.
        let (pre_id, pre_batch) = observations_of(&next_event(&events));
        assert_eq!(pre_id, ScanId::new(1));
        assert!(
            pre_batch
                .iter()
                .all(|observation| observation.source == Source::NeighborTable)
        );
        let (arp_id, arp_batch) = observations_of(&next_event(&events));
        assert_eq!(arp_id, ScanId::new(1));
        assert_eq!(arp_batch, vec![obs(2)]);
        // The cancel is latched *before* the finish is released: this
        // is the F-1 race, determinized.
        worker.cancel_cycle().expect("cancel accepted");
        release.send(()).expect("finish released");
        (worker, events, neighbors, release)
    }

    #[test]
    fn a_late_cancel_does_not_downgrade_a_failed_sweep() {
        let (worker, events, neighbors, _release) = late_cancel_fixture(ScanOutcome::Failed {
            reason: "the scripted sweep failed fatally (socket gone)".to_owned(),
        });
        // Post-cancel drain: nothing but the finish may appear — no
        // observation of any kind (the post-sweep read was skipped).
        let collected = drain_until_finished(&events);
        assert!(
            collected[..collected.len() - 1]
                .iter()
                .all(|event| !matches!(event, CycleEvent::Observations { .. })),
            "no observations at all after the cancel"
        );
        let neighbor_rows = collected
            .iter()
            .filter_map(|event| match event {
                CycleEvent::Observations { batch, .. } => Some(
                    batch
                        .iter()
                        .filter(|observation| observation.source == Source::NeighborTable)
                        .count(),
                ),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(neighbor_rows, 0, "no post-read after the cancel");
        let (fid, _, mode, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(fid, ScanId::new(1));
        assert_eq!(mode, CycleMode::Active);
        // The F-1 pin: the sweep's own Failed survives the late cancel
        // — reason byte-identical, no cancel suffix. Never Cancelled:
        // this match arm is the proof.
        match &summary.outcome {
            ScanOutcome::Failed { reason } => assert_eq!(
                reason, "the scripted sweep failed fatally (socket gone)",
                "the sweep's own reason, byte-identical, no cancel suffix"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(summary.degraded, None, "the pre-read succeeded");
        assert_eq!(
            summary.counters.replies_accepted, 3,
            "the sweep's counters pass through"
        );
        assert_eq!(
            neighbors.calls(),
            1,
            "pre-read only — the post-sweep read was skipped"
        );
        worker.shutdown();
    }

    #[test]
    fn a_late_cancel_still_cancels_a_completed_sweep() {
        let (worker, events, neighbors, _release) = late_cancel_fixture(ScanOutcome::Complete);
        let collected = drain_until_finished(&events);
        let neighbor_rows = collected
            .iter()
            .filter_map(|event| match event {
                CycleEvent::Observations { batch, .. } => Some(
                    batch
                        .iter()
                        .filter(|observation| observation.source == Source::NeighborTable)
                        .count(),
                ),
                _ => None,
            })
            .sum::<usize>();
        assert_eq!(neighbor_rows, 0, "no post-read after the cancel");
        let (fid, _, mode, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(fid, ScanId::new(1));
        assert_eq!(mode, CycleMode::Active);
        // The preserved half, pinned: a success-class sweep under the
        // same late flag still finishes Cancelled (the R-1 table's
        // Complete/Partial rows) — an implementation that removed the
        // downgrade entirely would fail here.
        assert_eq!(summary.outcome, ScanOutcome::Cancelled);
        assert_eq!(summary.degraded, None);
        assert_eq!(
            neighbors.calls(),
            1,
            "pre-read only — the post-sweep read was skipped"
        );
        worker.shutdown();
    }

    #[test]
    fn a_full_command_channel_returns_the_typed_error_without_blocking() {
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1))]);
        // The first read parks on the gate: the worker sits inside
        // run_cycle with the StartCycle already popped, so the command
        // channel is free to fill with cancels.
        let release = neighbors.gated();
        let fake = FakeTransport::new();
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) = DiscoveryWorker::spawn_active(
            arp,
            arp_events,
            Box::new(neighbors.clone()),
            scope(),
            "eth0",
        );
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(50)),
            )
            .expect("start ok");
        assert_eq!(started_of(&next_event(&events)).0, ScanId::new(1));
        // Spam cancels: the first CYCLE_COMMAND_CAPACITY fill the
        // queue, the rest report the typed error — every call returns
        // immediately (never blocks), and the flag of call 1 is set
        // regardless, so the cancellation still takes effect.
        let started = Instant::now();
        let mut full_seen = 0;
        let mut accepted = 0;
        for _ in 0..(CYCLE_COMMAND_CAPACITY + 4) {
            match worker.cancel_cycle() {
                Ok(()) => accepted += 1,
                Err(OrchestratorError::CommandQueueFull) => full_seen += 1,
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        let took = started.elapsed();
        assert_eq!(accepted, CYCLE_COMMAND_CAPACITY);
        assert_eq!(full_seen, 4, "the typed error once the queue is full");
        assert!(took < Duration::from_secs(1), "12 calls took {took:?}");
        // A start during the (still running, gated) cycle is the FR-DS-08
        // answer, not a queue error — the guard precedes the send.
        assert_eq!(
            worker.start_cycle(
                Trigger::Manual,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(50))
            ),
            Err(OrchestratorError::AlreadyInProgress)
        );
        // Release the gate: the cycle finishes Cancelled (the flag was
        // set by the very first cancel).
        release.send(()).expect("gate open");
        let collected = drain_until_finished(&events);
        let (_, _, _, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(summary.outcome, ScanOutcome::Cancelled);
        worker.shutdown();
    }

    #[test]
    fn command_send_errors_map_to_the_typed_variants() {
        // A full channel (receiver alive) maps to CommandQueueFull.
        let (tx, rx) = mpsc::sync_channel::<OrchestratorCommand>(1);
        tx.try_send(OrchestratorCommand::CancelCycle)
            .expect("first fills the queue");
        let full = tx
            .try_send(OrchestratorCommand::CancelCycle)
            .expect_err("the queue is full");
        assert_eq!(
            OrchestratorError::from_send(full),
            OrchestratorError::CommandQueueFull
        );
        // A disconnected channel maps to WorkerStopped.
        drop(rx);
        let gone = tx
            .try_send(OrchestratorCommand::CancelCycle)
            .expect_err("the receiver is gone");
        assert_eq!(
            OrchestratorError::from_send(gone),
            OrchestratorError::WorkerStopped
        );
        assert_eq!(
            OrchestratorError::CommandQueueFull.to_string(),
            "the orchestrator command queue is full"
        );
    }

    // -----------------------------------------------------------------------
    // AC-7: read-only mode
    // -----------------------------------------------------------------------

    #[test]
    fn read_only_cycles_complete_without_any_socket_machinery() {
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(3))]);
        // FR-DS-14: the read-only constructor takes no arp handle and
        // no scanner — nothing socket-touching can even be handed in
        // (the signature is the proof; this test proves the behavior:
        // one neighbor read, Complete, zero sweep counters, and no
        // ArpReply evidence can ever appear).
        let (worker, events) =
            DiscoveryWorker::spawn_read_only(Box::new(neighbors.clone()), scope(), "eth0");
        worker
            .start_cycle(
                Trigger::Manual,
                params(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("start ok");
        let collected = drain_until_finished(&events);
        assert_eq!(collected.len(), 3, "started, one batch, finished");
        let (id, trigger, mode) = started_of(&collected[0]);
        assert_eq!(
            (id, trigger, mode),
            (ScanId::new(1), Trigger::Manual, CycleMode::ReadOnly)
        );
        let (bid, batch) = observations_of(&collected[1]);
        assert_eq!(bid, ScanId::new(1));
        assert_eq!(batch.len(), 3);
        assert!(
            batch
                .iter()
                .all(|observation| observation.source == Source::NeighborTable)
        );
        let (fid, _, fmode, summary) = finished_of(&collected[2]);
        assert_eq!((fid, fmode), (ScanId::new(1), CycleMode::ReadOnly));
        assert_eq!(
            summary.outcome,
            ScanOutcome::Complete,
            "aging semantics identical"
        );
        assert_eq!(summary.counters, ScanCounters::default(), "no sweep ran");
        assert_eq!(summary.degraded, None);
        assert_eq!(neighbors.calls(), 1, "exactly one neighbor read");
        worker.shutdown();
    }

    #[test]
    fn read_only_neighbor_failure_fails_the_cycle() {
        let neighbors = FakeNeighbors::new(vec![Err("permission denied".to_owned())]);
        let (worker, events) =
            DiscoveryWorker::spawn_read_only(Box::new(neighbors), scope(), "eth0");
        worker
            .start_cycle(
                Trigger::Initial,
                params(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("start ok");
        let collected = drain_until_finished(&events);
        assert_eq!(
            collected.len(),
            2,
            "started then finished (no observations)"
        );
        let (_, _, _, summary) = finished_of(collected.last().expect("finish present"));
        match &summary.outcome {
            ScanOutcome::Failed { reason } => {
                assert!(reason.contains("reading the neighbor table failed"));
                assert!(reason.contains("permission denied"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // AC-8: ScanId discipline (the gated fake that delays a batch)
    // -----------------------------------------------------------------------

    fn obs(host: u8) -> Observation {
        Observation {
            ip: std::net::Ipv4Addr::new(192, 0, 2, host),
            mac: crate::model::mac::MacAddr::from_octets([0x02, 0x00, 0x00, 0x00, 0x00, host])
                .expect("valid unicast MAC"),
            source: Source::ArpReply,
        }
    }

    fn finished_event(outcome: ScanOutcome, replies: u64) -> DiscoveryEvent {
        DiscoveryEvent::ScanFinished(Box::new(ScanSummary {
            outcome,
            counters: ScanCounters {
                replies_accepted: replies,
                requests_sent: replies,
                ..ScanCounters::default()
            },
            elapsed: Duration::from_millis(10),
        }))
    }

    #[test]
    fn a_stale_arp_batch_is_dropped_and_counted_never_misattributed() {
        let session = GatedArpSession::default();
        // Scan 1 runs normally: one batch, then the summary.
        session.scan(vec![
            DiscoveryEvent::Observations(vec![obs(2)]),
            finished_event(ScanOutcome::Complete, 1),
        ]);
        // …​but a batch of scan 1 arrives LATE — after its ScanFinished
        // (a defect the real worker cannot exhibit: it joins its
        // flusher before the summary; the orchestrator still defends).
        session.straggler_batch(obs(9));
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1)), Ok(table_text(1))]);
        let (worker, events) = spawn_with_session(session.clone(), neighbors);
        worker
            .start_cycle(
                Trigger::Initial,
                params(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("start ok");
        let first = drain_until_finished(&events);
        assert_eq!(started_of(&first[0]).0, ScanId::new(1));
        let (_, _, _, summary) = finished_of(first.last().expect("finish present"));
        assert_eq!(summary.outcome, ScanOutcome::Complete);
        // The straggler is released now — while no cycle runs. The
        // idle drain must catch it: dropped and counted.
        session.open_gate();
        let snap = wait_stats(&worker, |snap| snap.stale_arp_events >= 1);
        assert_eq!(snap.stale_arp_events, 1);
        assert!(
            !first.iter().any(|event| match event {
                CycleEvent::Observations { batch, .. } => batch.contains(&obs(9)),
                _ => false,
            }),
            "the straggler was never emitted under cycle 1"
        );
        // Scan 2 is scripted cleanly; its events are all attributed to
        // cycle 2 and the straggler never reappears.
        session.scan(vec![
            DiscoveryEvent::Observations(vec![obs(3)]),
            finished_event(ScanOutcome::Complete, 1),
        ]);
        worker
            .start_cycle(
                Trigger::Periodic,
                params(1, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("second start ok");
        let second = drain_until_finished(&events);
        assert_eq!(started_of(&second[0]).0, ScanId::new(2));
        for event in &second[1..second.len() - 1] {
            let (bid, batch) = observations_of(event);
            assert_eq!(bid, ScanId::new(2), "cycle 2 events only");
            assert!(!batch.contains(&obs(9)), "the stale batch never leaked");
        }
        assert_eq!(session.start_count(), 2);
        assert_eq!(
            session.recorded_params().passes,
            2,
            "cycle 1 carried its passes"
        );
        let snap = worker.stats();
        assert_eq!(snap.stale_arp_events, 1, "still exactly one stale drop");
        assert_eq!(snap.cycles_finished, 2);
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // The dead-arp-worker ruling (§3.3)
    // -----------------------------------------------------------------------

    #[test]
    fn a_dead_arp_worker_fails_the_cycle_and_later_starts_see_the_typed_error() {
        let session = GatedArpSession::default();
        session.scan(vec![
            DiscoveryEvent::Observations(vec![obs(2)]),
            finished_event(ScanOutcome::Complete, 1),
        ]);
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1)), Ok(table_text(1))]);
        let (worker, events) = spawn_with_session(session.clone(), neighbors);
        worker
            .start_cycle(
                Trigger::Initial,
                params(2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("start ok");
        // Cycle 1 completes; then the session dies.
        let first = drain_until_finished(&events);
        assert_eq!(
            finished_of(first.last().expect("finish present")).3.outcome,
            ScanOutcome::Complete
        );
        session.go_dead();
        // Cycle 2: the scan starts, then the channel disconnects —
        // classified Failed, and the orchestrator marks itself gone.
        session.scan(Vec::new());
        worker
            .start_cycle(
                Trigger::Periodic,
                params(1, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW),
            )
            .expect("start ok");
        let second = drain_until_finished(&events);
        let (fid, _, _, summary) = finished_of(second.last().expect("finish present"));
        assert_eq!(fid, ScanId::new(2));
        match &summary.outcome {
            ScanOutcome::Failed { reason } => {
                assert!(reason.contains("the arp worker stopped during the cycle"))
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Later starts surface the typed worker-gone error — no
        // silent respawn.
        assert_eq!(
            worker.start_cycle(
                Trigger::Manual,
                params(1, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW)
            ),
            Err(OrchestratorError::ArpWorkerGone)
        );
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // The neighbor-read degradation ruling (§3.3)
    // -----------------------------------------------------------------------

    #[test]
    fn neighbor_read_failures_in_active_mode_degrade_to_partial_with_the_typed_reason() {
        let fake = FakeTransport::new();
        fake.responder(
            std::net::Ipv4Addr::new(192, 0, 2, 2),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let neighbors = FakeNeighbors::new(vec![
            Err("permission denied".to_owned()), // pre-read fails
            Ok(table_text(1)),                   // post-read succeeds
        ]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) =
            DiscoveryWorker::spawn_active(arp, arp_events, Box::new(neighbors), scope(), "eth0");
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(80)),
            )
            .expect("start ok");
        let collected = drain_until_finished(&events);
        let (_, _, _, summary) = finished_of(collected.last().expect("finish present"));
        // The sweep itself completed (the primary source), but the
        // failed pre-read degrades the cycle: Partial, never aged
        // (ADR-007), with the typed reason for T-205/T-401.
        assert_eq!(summary.outcome, ScanOutcome::Partial);
        assert_eq!(
            summary.degraded,
            Some(Degradation::PreReadFailed {
                reason: "reading the neighbor table at /proc/net/arp failed: permission denied"
                    .to_owned()
            })
        );
        assert_eq!(summary.counters.replies_accepted, 1, "the sweep still ran");
        // The post-read batch was still delivered.
        let last_batch = collected
            .iter()
            .rev()
            .find_map(|event| match event {
                CycleEvent::Observations { batch, .. } if !batch.is_empty() => Some(batch.clone()),
                _ => None,
            })
            .expect("a post-read batch");
        assert!(last_batch.iter().all(|o| o.source == Source::NeighborTable));
        worker.shutdown();
    }

    #[test]
    fn a_post_read_failure_degrades_too() {
        let fake = FakeTransport::new();
        fake.responder(
            std::net::Ipv4Addr::new(192, 0, 2, 2),
            "02:00:00:00:00:02".parse().expect("valid MAC"),
        );
        let neighbors = FakeNeighbors::new(vec![
            Ok(table_text(1)),              // pre-read fine
            Err("no such file".to_owned()), // post-read fails
        ]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) =
            DiscoveryWorker::spawn_active(arp, arp_events, Box::new(neighbors), scope(), "eth0");
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_millis(80)),
            )
            .expect("start ok");
        let collected = drain_until_finished(&events);
        let (_, _, _, summary) = finished_of(collected.last().expect("finish present"));
        assert_eq!(summary.outcome, ScanOutcome::Partial);
        assert_eq!(
            summary.degraded,
            Some(Degradation::PostReadFailed {
                reason: "reading the neighbor table at /proc/net/arp failed: no such file"
                    .to_owned()
            })
        );
        worker.shutdown();
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_cancels_a_running_cycle_and_joins_within_the_bound() {
        let fake = FakeTransport::new();
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1)), Ok(table_text(1))]);
        let (arp, arp_events) = ArpWorkerHandle::spawn(scanner_for(&fake));
        let (worker, events) =
            DiscoveryWorker::spawn_active(arp, arp_events, Box::new(neighbors), scope(), "eth0");
        // A cycle that would run for seconds if not cancelled.
        worker
            .start_cycle(
                Trigger::Initial,
                params(1, DEFAULT_RATE_PPS, Duration::from_secs(5)),
            )
            .expect("start ok");
        assert_eq!(started_of(&next_event(&events)).0, ScanId::new(1));
        // Shutdown from a helper thread so a wedged join cannot hang
        // the test without evidence (the T-104 pattern).
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = worker;
        let joiner = thread::spawn(move || {
            handle.shutdown();
            done_tx.send(()).expect("channel open");
        });
        let joined = done_rx.recv_timeout(Duration::from_secs(2));
        assert!(joined.is_ok(), "shutdown did not join within 2 s");
        joiner.join().expect("joiner must not panic");
        // Design bound 500 ms (cancel 250 ms + arp join 250 ms); the
        // 2 s assertion is the 4× CI headroom (justified in the
        // T-204 execution report §6 like T-203's AC-9 margin).
        // Drain whatever the policy may have dropped or delivered.
        while events.try_recv().is_ok() {}
    }

    #[test]
    fn shutdown_of_an_idle_worker_is_immediate() {
        let neighbors = FakeNeighbors::new(vec![]);
        let (worker, _events) =
            DiscoveryWorker::spawn_read_only(Box::new(neighbors), scope(), "eth0");
        let started = Instant::now();
        worker.shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "idle shutdown took {:?}",
            started.elapsed()
        );
    }

    // -----------------------------------------------------------------------
    // Constants and plumbing
    // -----------------------------------------------------------------------

    #[test]
    fn channel_capacities_and_pacing_constants_are_the_documented_values() {
        assert_eq!(CYCLE_COMMAND_CAPACITY, 8);
        assert_eq!(CYCLE_EVENT_CAPACITY, 64);
        assert_eq!(WAIT_SLICE, Duration::from_millis(50));
        assert_eq!(COMMAND_POLL_INTERVAL, Duration::from_millis(100));
        assert_eq!(FORWARD_RETRY_BUDGET, 8);
        assert_eq!(SEND_RETRY_WAIT, Duration::from_millis(10));
        assert_eq!(FIRST_SCAN_ID, 1);
    }

    #[test]
    fn scan_ids_start_at_one_and_increase_every_cycle() {
        // Read-only cycles are the cheapest way to mint ids.
        let neighbors = FakeNeighbors::new(vec![Ok(table_text(1)); 3]);
        let (worker, events) =
            DiscoveryWorker::spawn_read_only(Box::new(neighbors), scope(), "eth0");
        let mut last_id = 0;
        for trigger in [Trigger::Initial, Trigger::Manual, Trigger::Periodic] {
            worker
                .start_cycle(trigger, params(1, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW))
                .expect("start ok");
            let collected = drain_until_finished(&events);
            let (id, ..) = started_of(&collected[0]);
            assert!(id.as_u64() > last_id, "ids increase monotonically");
            last_id = id.as_u64();
        }
        assert_eq!(last_id, 3);
        worker.shutdown();
    }
}
