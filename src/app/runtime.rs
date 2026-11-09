// SPDX-License-Identifier: GPL-3.0-only

//! The runtime: the wiring layer that owns the event queue, the
//! discovery forwarder thread, the effects executor and the clock, and
//! drives the pure [`update`](super::update::update) loop (plan §8.3/§8.4;
//! task T-205 §5.8).
//!
//! # The loop (§8.4; one iteration = [`Runtime::step`])
//!
//! 1. `wait = min(next_auto_in(now) [when armed], tick deadline, the
//!    given wait, MAX_WAIT)`; block on the queue with `recv_timeout`.
//!    The auto deadline only shapes the wait while discovery is armed
//!    (the poll it wakes for is gated by arming — FR-ST-02); the tick
//!    deadline is 1 s since the last handled tick (FR-UI-07).
//! 2. Handle the event — or, on timeout with the tick deadline
//!    reached, a synthesized [`AppEvent::Tick`]: `effects =
//!    update(&mut state, event, clock)`.
//! 3. Drain up to [`DRAIN_MAX`] further immediately-available events
//!    the same way, then drain the hostname worker's events (below).
//!    The drain bound keeps one iteration's work small enough that
//!    rendering is never starved: at the ADR-008 registry cap a full
//!    cycle's worst case (≈ 32 neighbor batches of 32 + lifecycle +
//!    input) needs only a handful of iterations, each far inside the
//!    NFR-03 budget.
//! 4. If `discovery_armed && !quit`: `scheduler.poll(now)` — a
//!    `StartCycle` becomes one executed
//!    [`Effect::StartScan`] per the
//!    binding §2 recipe; `poll` returns only `StartCycle` or `None` in
//!    this position (the other decisions come from
//!    `manual_refresh`/`cycle_finished`), and the impossible arms are
//!    handled honestly (nothing, never silenced).
//! 5. Execute the effects `update` produced, refresh
//!    [`CountersSnapshot`](super::state::CountersSnapshot), return.
//!    [`Runtime::run_until_quit`] wraps `step` until the authoritative
//!    `quit` flag.
//!
//! # Event sources (ADR-012)
//!
//! * The **input side**: [`AppEventSender`] — the bounded
//!   `sync_channel`'s sending end, held by T-301's input thread
//!   (`try_send` plus a bounded retry against its stop flag — T-301
//!   implements that; the sender is [`Clone`] for exactly that
//!   shape). A full queue answers `Full` immediately: senders never
//!   block unboundedly (§8.3).
//! * The **discovery forwarder**: one owned thread moving
//!   [`CycleEvent`]s from the orchestrator's channel into the queue
//!   as [`AppEvent::Discovery`]. Delivery policy mirrors the
//!   orchestrator's own (T-204 `worker.rs` "Delivery policy"): data
//!   events (observation batches) get a bounded retry budget
//!   ([`FORWARD_RETRY_BUDGET`] × [`FORWARD_RETRY_WAIT`]) and are
//!   dropped and counted on saturation; lifecycle events (`Started`,
//!   `Finished`) retry until delivered or the stop flag is set (the
//!   main loop drains, so this terminates). Every wait is
//!   flag-checked; the thread is joined on shutdown. A spawn failure
//!   (an OOM-class event) degrades the same way T-204's worker
//!   treats it: the handle is absent, events stop flowing, shutdown
//!   joins what exists — never a panic.
//! * The **hostname side is drained inline** (deviation D-2, report
//!   §5): T-203's `HostnameWorker::events()` returns a *borrowed*
//!   receiver — the handle keeps it, by design ("drained by the
//!   application's main loop") — so no `'static` forwarder thread can
//!   own it, and the card's second forwarder thread cannot exist as
//!   specified against the reviewed handle shape. The runtime instead
//!   drains the receiver (through the executor's
//!   [`hostname_events`](EffectsExecutor::hostname_events) accessor)
//!   at every step boundary, up to [`DRAIN_MAX`] events, running each
//!   through `update` directly — no extra bounded hop, hence no
//!   forwarder-side drop policy to mirror: T-203's own bounded `emit`
//!   already counts its drops (`events_dropped`). Worst-case latency
//!   is one wait slice (≤ [`MAX_WAIT`]); lookups take seconds anyway.
//!   The counters snapshot keeps the (now structurally zero)
//!   hostname-forwarder drop field, honestly documented.
//!
//! # Shutdown (on `state.quit`)
//!
//! [`Runtime::shutdown`] (also run by [`Runtime::step`] on quit and by
//! [`Drop`]; double shutdown is a no-op, never a panic):
//!
//! 1. `executor.shutdown()` — the orchestrator cancels and joins any
//!    running cycle inside the T-204 bound (≈ 500 ms), then the
//!    hostname worker joins inside the T-203 bound (250 ms);
//! 2. the forwarder stop flag is set, then the thread is joined —
//!    bounded by one poll slice plus any in-flight retry budget
//!    (≈ 200 ms); the executor's shutdown has already disconnected the
//!    orchestrator's channel, so the thread exits even without the
//!    flag.
//!
//! Whole-sequence design bound ≈ 1 s. There is no in-session cancel
//! control: user quit is the only cancel path, and this sequence is
//! it (§5.3; a `CancelScan` effect deliberately does not exist).
//!
//! # Deterministic test driving
//!
//! `step(Duration::ZERO)` processes whatever is queued plus one
//! scheduler poll and one hostname drain — no waiting. Scenario tests
//! push events via [`AppEventSender`], step, and assert on
//! [`Runtime::state`].

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::TryRecvError;
use std::sync::mpsc::TrySendError;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use crate::discovery::scheduler::SchedulerDecision;
use crate::discovery::worker::CycleEvent;
use crate::model::Clock;

use super::action::Effect;
use super::action::EffectError;
use super::action::EffectsExecutor;
use super::event::AppEvent;
use super::state::AppState;

/// The bounded application event queue's capacity (§8.3: "no
/// unbounded channels anywhere").
///
/// Justification: the worst per-cycle burst is ≈ 32 neighbor batches
/// (1,022 hosts / 32 per batch) + ≤ 32 arp batches + lifecycle +
/// input + tick — far below 256; the bound exists so a wedged consumer
/// back-pressures the forwarder into its drop policy instead of
/// growing without limit.
pub const APP_EVENT_CAPACITY: usize = 256;

/// The upper bound of one loop iteration's blocking wait (§5.8): the
/// tick deadline is 1 s, so a longer wait could never be useful.
pub const MAX_WAIT: Duration = Duration::from_secs(1);

/// The 1 Hz redraw tick (FR-UI-07).
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// How many immediately-available events one iteration drains after
/// the first (§5.8 step 3): bounds per-iteration work so rendering is
/// never starved (see the module docs for the arithmetic).
pub const DRAIN_MAX: usize = 16;

/// The discovery forwarder's retry budget for data events (mirrors
/// T-204's `FORWARD_RETRY_BUDGET`).
pub const FORWARD_RETRY_BUDGET: u32 = 8;

/// The wait between two forwarder retry attempts (mirrors T-204's
/// `SEND_RETRY_WAIT`).
pub const FORWARD_RETRY_WAIT: Duration = Duration::from_millis(10);

/// The forwarder's poll slice while waiting for worker events: every
/// wait is flag-checked at this granularity (bounded waits everywhere,
/// §8.3).
pub const FORWARD_POLL_SLICE: Duration = Duration::from_millis(100);

/// The discovery forwarder thread's name (pthread names are truncated
/// to 15 bytes).
const FORWARDER_THREAD_NAME: &str = "osza-disco-fwd";

// ---------------------------------------------------------------------------
// The sender
// ---------------------------------------------------------------------------

/// The sending end of the bounded application event queue (§5.8).
///
/// This is what T-301's input thread will hold: `try_send` plus a
/// bounded retry against the input thread's own stop flag (T-301
/// implements the retry; the sender is [`Clone`] so the input thread,
/// any resize watcher and the tests can share it). A full queue
/// answers [`TrySendError::Full`] immediately — senders never block
/// unboundedly (§8.3).
#[derive(Debug, Clone)]
pub struct AppEventSender {
    queue: SyncSender<AppEvent>,
}

impl AppEventSender {
    /// Attempts to enqueue one event without blocking.
    ///
    /// # Errors
    /// [`TrySendError::Full`] when the bounded queue is saturated
    /// (retry with a bound, then drop the event — the input side is
    /// lossy by design); [`TrySendError::Disconnected`] when the
    /// runtime is gone.
    pub fn try_send(&self, event: AppEvent) -> Result<(), TrySendError<AppEvent>> {
        self.queue.try_send(event)
    }
}

// ---------------------------------------------------------------------------
// The forwarder
// ---------------------------------------------------------------------------

/// The shared state of the discovery forwarder (stop flag + counter).
#[derive(Debug, Default)]
struct ForwarderState {
    stop: AtomicBool,
    dropped_batches: AtomicU64,
}

/// The discovery forwarder thread body (module docs for the policy).
fn forward_discovery(
    events: Receiver<CycleEvent>,
    queue: AppEventSender,
    state: Arc<ForwarderState>,
) {
    loop {
        if state.stop.load(Ordering::Acquire) {
            return;
        }
        match events.recv_timeout(FORWARD_POLL_SLICE) {
            Ok(event) => {
                let lifecycle = !matches!(event, CycleEvent::Observations { .. });
                deliver(
                    AppEvent::Discovery(event),
                    &queue,
                    &state.stop,
                    lifecycle,
                    &state.dropped_batches,
                );
            }
            Err(RecvTimeoutError::Timeout) => continue,
            // The orchestrator is gone (shutdown): nothing more to
            // forward.
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Delivers one wrapped event under the §5.8 policy: data events are
/// dropped and counted once the retry budget is spent; lifecycle
/// events retry until delivered or the stop flag is set.
fn deliver(
    mut event: AppEvent,
    queue: &AppEventSender,
    stop: &AtomicBool,
    lifecycle: bool,
    drops: &AtomicU64,
) {
    let mut tries = 0u32;
    loop {
        if stop.load(Ordering::Acquire) {
            // Stopped mid-delivery: count the data loss honestly;
            // lifecycle loss is not a counter (the app is shutting
            // down; the queue's remaining content is abandoned).
            if !lifecycle {
                drops.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        match queue.try_send(event) {
            Ok(()) => return,
            // The event comes back on `Full`; retry within the budget.
            Err(TrySendError::Full(returned)) => {
                tries += 1;
                if !lifecycle && tries >= FORWARD_RETRY_BUDGET {
                    drops.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                event = returned;
            }
            // The runtime is gone: nothing to deliver to.
            Err(TrySendError::Disconnected(_)) => return,
        }
        thread::sleep(FORWARD_RETRY_WAIT);
    }
}

// ---------------------------------------------------------------------------
// The runtime
// ---------------------------------------------------------------------------

/// The wiring layer (module docs above). Generic over the
/// [`EffectsExecutor`] so tests drive with [`RecordingExecutor`] and
/// production with [`WorkerExecutor`](super::action::WorkerExecutor).
pub struct Runtime<E: EffectsExecutor> {
    state: AppState,
    executor: E,
    events: Receiver<AppEvent>,
    clock: Arc<dyn Clock + Send + Sync>,
    /// Effects `update` produced this iteration, awaiting step 5.
    pending: Vec<Effect>,
    /// The mono anchor of the last handled tick.
    tick_anchor: Instant,
    /// The discovery forwarder's shared state.
    forwarder: Arc<ForwarderState>,
    /// The discovery forwarder's join handle (`None` once joined or if
    /// the spawn failed — see the module docs).
    forwarder_thread: Option<JoinHandle<()>>,
    /// Set when the queue's last sender is gone (documented in
    /// `run_until_quit`).
    queue_disconnected: bool,
    /// Idempotent-shutdown guard.
    shut_down: bool,
}

impl<E: EffectsExecutor> Runtime<E> {
    /// Wires the runtime around an [`AppState`], an executor, the
    /// orchestrator's event receiver (owned — the T-204 spawn hands it
    /// over) and the shared clock.
    ///
    /// Returns the runtime and the queue's sending end (what T-301's
    /// input thread will hold).
    pub fn new(
        state: AppState,
        executor: E,
        discovery_events: Receiver<CycleEvent>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> (Self, AppEventSender) {
        let (queue_tx, queue_rx) = sync_channel::<AppEvent>(APP_EVENT_CAPACITY);
        let sender = AppEventSender { queue: queue_tx };
        let forwarder = Arc::new(ForwarderState::default());
        let forwarder_thread = thread::Builder::new()
            .name(FORWARDER_THREAD_NAME.to_owned())
            .spawn({
                let forwarder = Arc::clone(&forwarder);
                let sender = sender.clone();
                move || forward_discovery(discovery_events, sender, forwarder)
            })
            .ok();
        let runtime = Runtime {
            state,
            executor,
            events: queue_rx,
            clock,
            pending: Vec::new(),
            tick_anchor: Instant::now(),
            forwarder,
            forwarder_thread,
            queue_disconnected: false,
            shut_down: false,
        };
        (runtime, sender)
    }

    /// The application state (assert on it in tests; render read-only
    /// views of it in T-301).
    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// Consumes the state's dirty flag — [`AppState::take_dirty`](super::AppState::take_dirty)
    /// (task T-301's pre-authorized accessor E-1) exposed through the
    /// runtime, because the runtime owns the state and the render loop
    /// holds the runtime: `true` when a render is due for changes
    /// accumulated since the last call.
    ///
    /// The delegation is T-301 deviation D-1 (its report §5): the
    /// card authorizes the accessor on the state but no existing API
    /// lends a `&mut AppState` out of the runtime, so the one-line
    /// forward is the minimal reach path — nothing else in this
    /// module changed.
    pub fn take_dirty(&mut self) -> bool {
        self.state.take_dirty()
    }

    /// One loop iteration (§5.8; module docs). Deterministic under
    /// `Duration::ZERO`: whatever is queued is processed, plus one
    /// scheduler poll and one hostname drain.
    pub fn step(&mut self, wait: Duration) {
        // 1. The effective wait (module docs; the auto deadline only
        //    counts while armed — the poll it feeds is gated).
        let now = self.clock.now();
        let mut effective = wait.min(MAX_WAIT);
        if self.state.discovery_armed
            && let Some(next_auto) = self.state.scheduler.next_auto_in(now)
        {
            effective = effective.min(next_auto);
        }
        let since_tick = now.mono().saturating_duration_since(self.tick_anchor);
        effective = effective.min(TICK_INTERVAL.saturating_sub(since_tick));

        // 2. Block (or not) and handle.
        match self.events.recv_timeout(effective) {
            Ok(event) => self.handle(event),
            Err(RecvTimeoutError::Timeout) => {
                // A synthesized tick when the deadline was reached.
                let now = self.clock.now();
                if now.mono().saturating_duration_since(self.tick_anchor) >= TICK_INTERVAL {
                    self.handle(AppEvent::Tick);
                }
            }
            Err(RecvTimeoutError::Disconnected) => self.queue_disconnected = true,
        }

        // 3. Drain up to DRAIN_MAX immediately-available events.
        for _ in 0..DRAIN_MAX {
            match self.events.try_recv() {
                Ok(event) => self.handle(event),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.queue_disconnected = true;
                    break;
                }
            }
        }

        // 3b. Drain the hostname worker's events inline (deviation
        //     D-2; module docs): collect first so the executor borrow
        //     ends before `update` runs.
        if let Some(receiver) = self.executor.hostname_events() {
            let mut drained = Vec::new();
            for _ in 0..DRAIN_MAX {
                match receiver.try_recv() {
                    Ok(event) => drained.push(event),
                    Err(TryRecvError::Empty) | Err(TryRecvError::Disconnected) => break,
                }
            }
            for event in drained {
                self.handle(AppEvent::Hostname(event));
            }
        }

        // 4. The scheduler poll (only when armed and alive; the
        //    single-commander contract makes AlreadyInProgress
        //    impossible here, and AutoScansStopped arrives via
        //    cycle_finished — §5.8).
        if self.state.discovery_armed && !self.state.quit {
            match self.state.scheduler.poll(self.clock.now()) {
                SchedulerDecision::StartCycle { trigger, .. } => {
                    self.execute_effect(Effect::StartScan {
                        trigger,
                        params: super::update::scan_params_for(trigger),
                    });
                }
                // Nothing due — and the arms that cannot appear in
                // this position are handled honestly (nothing), never
                // silenced.
                SchedulerDecision::None
                | SchedulerDecision::AlreadyInProgress
                | SchedulerDecision::AutoScansStopped => {}
            }
        }

        // 5. The effects `update` produced, then the counters refresh.
        let pending = std::mem::take(&mut self.pending);
        for effect in pending {
            self.execute_effect(effect);
        }
        self.refresh_counters();

        // Quit is the only cancel path: shut the workers down here.
        if self.state.quit {
            self.shutdown();
        }
    }

    /// Runs `step` until the authoritative quit flag (or a fully
    /// disconnected queue — with every sender gone no input can ever
    /// arrive, so spinning would be dishonest; the caller inspects
    /// [`state`](Self::state) and decides).
    pub fn run_until_quit(&mut self) {
        while !self.state.quit && !self.queue_disconnected {
            self.step(MAX_WAIT);
        }
        if self.state.quit {
            self.shutdown();
        }
    }

    /// Handles one event through the pure `update`, collecting its
    /// effects (the tick anchor tracks handled ticks).
    fn handle(&mut self, event: AppEvent) {
        if matches!(event, AppEvent::Tick) {
            self.tick_anchor = self.clock.now().mono();
        }
        let effects = super::update::update(&mut self.state, event, self.clock.as_ref());
        self.pending.extend(effects);
    }

    /// Executes one effect through the executor; a failed start
    /// surfaces as one honest `ScanFailed` message (§5.8; the
    /// `AlreadyInProgress` "should be impossible" case is surfaced the
    /// same way, never silenced). A rejected hostname lookup needs no
    /// message: the field honestly stays `Pending`, the worker counts
    /// the rejection, and the next cycle's re-queue heals it (§5.9).
    ///
    /// A start that the orchestrator refused leaves the scheduler
    /// holding *running*: no cycle will ever finish, so no further
    /// start is issued — the honest reflection of T-204's "the
    /// orchestrator never silently respawns it" (an application
    /// restart is the remedy; the message says so via T-401's
    /// wording).
    fn execute_effect(&mut self, effect: Effect) {
        match self.executor.execute(effect) {
            Ok(()) => {}
            Err(EffectError::StartScan(error)) => {
                let appended = self.state.messages.append(
                    super::message::MessageKind::ScanFailed {
                        reason: error.to_string(),
                    },
                    self.clock.now(),
                );
                self.state.dirty |= appended;
            }
            Err(EffectError::ResolveHostname(_)) => {
                // Counted in the worker's `enqueue_rejected`; the
                // field stays `Pending` (honest); the re-queue on the
                // next cycle heals a transient `QueueFull`.
            }
        }
    }

    /// Refreshes the counters snapshot (§5.4: the runtime's job,
    /// never `update`'s).
    fn refresh_counters(&mut self) {
        let worker = self.executor.worker_stats();
        self.state.counters = super::state::CountersSnapshot {
            orchestrator: worker.orchestrator,
            hostname: worker.hostname,
            forwarder_dropped_batches: self.forwarder.dropped_batches.load(Ordering::Relaxed),
            // Deviation D-2: no hostname forwarder exists, so this
            // counter is structurally zero; the worker's own
            // `events_dropped` is the authoritative hostname-drop
            // counter (visible as `counters.hostname.events_dropped`).
            forwarder_dropped_hostnames: 0,
        };
    }

    /// The bounded shutdown sequence (module docs): executor first
    /// (cancel + joins, the T-204/T-203 bounds), then the forwarder
    /// flag and join. Idempotent — a second call is a no-op, never a
    /// panic (§5.8).
    pub fn shutdown(&mut self) {
        if self.shut_down {
            return;
        }
        self.shut_down = true;
        // 1. The workers.
        self.executor.shutdown();
        // 2. The forwarder: flag, then join (bounded by one poll slice
        //    plus an in-flight retry budget; the executor's shutdown
        //    has already disconnected the orchestrator's channel).
        self.forwarder.stop.store(true, Ordering::Release);
        if let Some(thread) = self.forwarder_thread.take() {
            let _ = thread.join();
        }
    }
}

impl<E: EffectsExecutor> Drop for Runtime<E> {
    fn drop(&mut self) {
        // The final safety net: an un-shutdown runtime (a test that
        // forgot `q`, a panicked caller) still joins its threads.
        self.shutdown();
    }
}

// ---------------------------------------------------------------------------
// The test executor (pub for T-301 reuse — §5.8's "your choice",
// documented)
// ---------------------------------------------------------------------------

/// An [`EffectsExecutor`] that records every effect and answers
/// scripted results — the assert-on-effects seam of the scenario
/// suites, reusable by T-301's input-thread tests.
///
/// By default every effect succeeds; [`RecordingExecutor::failing`]
/// scripts a start failure (to drive the honest `ScanFailed` path).
#[derive(Debug, Default)]
pub struct RecordingExecutor {
    recorded: Mutex<Vec<Effect>>,
    fail_starts: Option<EffectError>,
}

impl RecordingExecutor {
    /// Records everything and fails nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records everything; every `StartScan` answers `error`.
    pub fn failing(error: EffectError) -> Self {
        RecordingExecutor {
            recorded: Mutex::new(Vec::new()),
            fail_starts: Some(error),
        }
    }

    /// The effects seen so far, in order.
    pub fn recorded(&self) -> Vec<Effect> {
        self.recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// How many effects were seen.
    pub fn count(&self) -> usize {
        self.recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

impl EffectsExecutor for RecordingExecutor {
    fn execute(&mut self, effect: Effect) -> Result<(), EffectError> {
        self.recorded
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(effect.clone());
        match (&effect, &self.fail_starts) {
            (Effect::StartScan { .. }, Some(error)) => Err(error.clone()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::action::EffectError;
    use crate::app::action::WorkerExecutor;
    use crate::app::config::AppMode;
    use crate::app::config::SessionParams;
    use crate::app::event::InputEvent;
    use crate::app::event::Key;
    use crate::app::state::ScopeEntry;
    use crate::app::state::Screen;
    use crate::app::update::update;
    use crate::discovery::DEFAULT_LISTEN_WINDOW;
    use crate::discovery::DEFAULT_RATE_PPS;
    use crate::discovery::DiscoveryWorker;
    use crate::discovery::Observation as ScannerObservation;
    use crate::discovery::ScanOutcome as DiscoveryOutcome;
    use crate::discovery::ScanParams;
    use crate::discovery::scheduler::Trigger;
    use crate::discovery::worker::CycleMode;
    use crate::discovery::worker::CycleSummary;
    use crate::discovery::worker::OrchestratorError;
    use crate::model::FakeClock;
    use crate::model::Field;
    use crate::model::Hostname;
    use crate::model::Ipv4Net;
    use crate::model::ScanId;
    use crate::model::Source;
    use crate::net::Eligibility;
    use crate::net::InterfaceClass;
    use crate::registry::DeviceKey;
    use crate::registry::SortMode;
    use crate::registry::Tag;
    use std::net::Ipv4Addr;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::AtomicBool;

    // ---- shared fixtures ------------------------------------------------------

    fn db() -> Arc<crate::enrichment::vendor::VendorDb> {
        Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        )
    }

    /// A synthetic eligible interface: `eth9`, index 2, MAC
    /// `aa:bb:cc:dd:ee:01` (locally administered — no collision with
    /// the benchmark's `02:00:…:01` synthetic MACs), 192.0.2.1/29,
    /// gateway .6 — matching the synthetic scope of the fixtures.
    fn eth_entry() -> ScopeEntry {
        ScopeEntry {
            name: "eth9".to_owned(),
            index: 2,
            mac: Some("aa:bb:cc:dd:ee:01".parse().expect("valid MAC")),
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 29)),
            is_up: true,
            is_running: true,
            is_loopback: false,
            class: InterfaceClass::Physical,
            eligibility: Eligibility::Eligible,
            default_gateway: Some(Ipv4Addr::new(192, 0, 2, 6)),
        }
    }

    /// A synthetic eligible interface without a MAC (the documented
    /// no-identity confirm path): confirmation arms discovery without
    /// inserting a local device — the benchmark fixture, so the
    /// registry holds exactly 4,096 synthetic devices at the cap.
    fn macless_entry() -> ScopeEntry {
        ScopeEntry {
            mac: None,
            ..eth_entry()
        }
    }

    /// A clock shared with the workers (the T-203 `SharedFakeClock`
    /// pattern, inlined here so the trait implementation stays local).
    struct SharedFakeClock(Arc<StdMutex<FakeClock>>);

    impl Clock for SharedFakeClock {
        fn now(&self) -> crate::model::Timestamp {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .now()
        }
    }

    /// A dummy (disconnected) orchestrator receiver for runtimes
    /// without a discovery worker: the forwarder exits immediately and
    /// honestly.
    fn dummy_discovery_receiver() -> Receiver<CycleEvent> {
        let (sender, receiver) = sync_channel::<CycleEvent>(1);
        drop(sender);
        receiver
    }

    fn send(sender: &AppEventSender, event: AppEvent) {
        sender
            .try_send(event)
            .expect("the 256-slot queue has room for test traffic");
    }

    /// A state confirmed through the pure core (the realistic T-301
    /// assembly order: build, confirm, then wire the runtime).
    fn confirmed_state(clock: &dyn Clock) -> AppState {
        let mut state =
            AppState::with_scope_entries(SessionParams::default(), vec![eth_entry()], db(), clock)
                .expect("valid");
        let pure_clock = FakeClock::new();
        let effects = update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('y'))),
            &pure_clock,
        );
        assert!(effects.is_empty());
        let effects = update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &pure_clock,
        );
        assert_eq!(
            effects,
            vec![Effect::ResolveHostname {
                ip: Ipv4Addr::new(192, 0, 2, 1)
            }]
        );
        state
    }

    // ---- AC-3 (runtime half): pre-confirmation, nothing discovery-shaped ----

    #[test]
    fn ac3_runtime_never_polls_or_starts_discovery_before_confirmation() {
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::new(SharedFakeClock(Arc::new(StdMutex::new(FakeClock::new()))));
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![eth_entry()],
            db(),
            clock.as_ref(),
        )
        .expect("valid");
        let (mut runtime, sender) = Runtime::new(
            state,
            RecordingExecutor::new(),
            dummy_discovery_receiver(),
            Arc::clone(&clock),
        );
        // A key mash through the real queue: notice screen, navigation
        // keys, refresh, sort — no StartScan effect is ever emitted
        // and the scheduler is never polled.
        for key in [
            Key::Down,
            Key::Up,
            Key::Char('j'),
            Key::Char('k'),
            Key::Char('r'),
            Key::Char('s'),
            Key::Char('?'),
            Key::Enter,
            Key::Esc,
        ] {
            send(&sender, AppEvent::Input(InputEvent::Key(key)));
            runtime.step(Duration::ZERO);
        }
        assert_eq!(runtime.state().screen(), Screen::Notice);
        assert!(!runtime.state().discovery_armed());
        assert_eq!(runtime.executor.recorded(), Vec::<Effect>::new());
        // The scheduler was never polled: the fresh Immediately slot
        // is intact and no start decision was ever made.
        assert!(!runtime.state().scheduler.is_running());
        assert_eq!(
            runtime.state().scheduler.next_auto_in(clock.now()),
            Some(Duration::ZERO)
        );
        drop(runtime);
    }

    #[test]
    fn take_dirty_surfaces_and_clears_the_render_due_flag() {
        // T-301's render loop consumes the flag through the runtime
        // (the E-1 accessor's reach path, deviation D-1): one `true`
        // per step that changed something, `false` on a step that
        // processed only ignored input.
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::new(SharedFakeClock(Arc::new(StdMutex::new(FakeClock::new()))));
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![eth_entry()],
            db(),
            clock.as_ref(),
        )
        .expect("valid");
        let (mut runtime, sender) = Runtime::new(
            state,
            RecordingExecutor::new(),
            dummy_discovery_receiver(),
            clock,
        );
        // The construction-time dirty flag survives to the first
        // consume even when the first step processes nothing.
        assert!(runtime.take_dirty(), "the first frame is due");
        assert!(!runtime.take_dirty());
        // A state-changing event (resize) re-marks it…
        send(
            &sender,
            AppEvent::Resize {
                width: 100,
                height: 30,
            },
        );
        runtime.step(Duration::ZERO);
        assert!(runtime.take_dirty(), "a resize is a change");
        // …an ignored key does not (update leaves the flag clear).
        send(&sender, AppEvent::Input(InputEvent::Key(Key::Char('x'))));
        runtime.step(Duration::ZERO);
        assert!(!runtime.take_dirty(), "an unknown key changes nothing");
        drop(runtime);
    }

    // ---- AC-4: the first scan after confirmation ------------------------------

    #[test]
    fn ac4_first_loop_iteration_starts_exactly_the_initial_two_pass_scan() {
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::new(SharedFakeClock(Arc::new(StdMutex::new(FakeClock::new()))));
        let state = confirmed_state(clock.as_ref());
        let (mut runtime, _sender) = Runtime::new(
            state,
            RecordingExecutor::new(),
            dummy_discovery_receiver(),
            Arc::clone(&clock),
        );
        // The next loop iteration: exactly the Initial start with the
        // §2 recipe.
        runtime.step(Duration::ZERO);
        assert_eq!(
            runtime.executor.recorded(),
            vec![Effect::StartScan {
                trigger: Trigger::Initial,
                params: ScanParams {
                    passes: 2,
                    rate_pps: DEFAULT_RATE_PPS,
                    listen_window: DEFAULT_LISTEN_WINDOW,
                },
            }],
            "exactly one Initial start with the binding recipe"
        );
        // And the scheduler holds the one running cycle.
        assert!(runtime.state().scheduler.is_running());
        drop(runtime);
    }

    // ---- The honest failed-start path -----------------------------------------

    #[test]
    fn a_failed_start_appends_one_scan_failed_message_and_never_resilences() {
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::new(SharedFakeClock(Arc::new(StdMutex::new(FakeClock::new()))));
        let state = confirmed_state(clock.as_ref());
        let (mut runtime, sender) = Runtime::new(
            state,
            RecordingExecutor::failing(EffectError::StartScan(OrchestratorError::ArpWorkerGone)),
            dummy_discovery_receiver(),
            Arc::clone(&clock),
        );
        runtime.step(Duration::ZERO);
        // The honest message, exactly once; the reason carries the
        // typed error verbatim. (The construction-time
        // NoEligibleResolver is also in the log — default params,
        // hostnames enabled — so assert by kind, not by position.)
        assert_eq!(
            runtime
                .state()
                .messages
                .count_of(&crate::app::message::MessageKind::ScanFailed {
                    reason: String::new()
                }),
            1
        );
        let latest = runtime
            .state()
            .messages()
            .last()
            .map(|message| message.kind.clone());
        assert_eq!(
            latest,
            // §5.7: the reason is the *worker's* verbatim one-liner
            // (the inner OrchestratorError Display), not this layer's
            // wrapping sentence — T-401 words the message.
            Some(crate::app::message::MessageKind::ScanFailed {
                reason: "the arp worker has stopped; active discovery is unavailable".to_owned()
            })
        );
        assert!(runtime.state().dirty());
        // The refused start leaves the scheduler holding *running*:
        // no further start is issued (the orchestrator never silently
        // respawns; a restart is the remedy) and a manual refresh is
        // answered honestly.
        send(&sender, AppEvent::Input(InputEvent::Key(Key::Char('r'))));
        runtime.step(Duration::ZERO);
        assert_eq!(
            runtime
                .state()
                .messages
                .count_of(&crate::app::message::MessageKind::ScanFailed {
                    reason: String::new()
                }),
            1,
            "no second start attempt, no duplicate failure message"
        );
        assert!(
            runtime
                .state()
                .messages
                .contains_kind(&crate::app::message::MessageKind::ScanAlreadyInProgress)
        );
        assert!(
            runtime
                .state()
                .messages
                .contains_kind(&crate::app::message::MessageKind::ScanAlreadyInProgress)
        );
        assert_eq!(runtime.executor.count(), 1, "no second start attempt");
        drop(runtime);
    }

    // ---- AC-5: the runtime integration over real workers ----------------------

    /// A scripted fake neighbor source (the T-204 pattern): one
    /// arp-table row, built with the reviewed public parser.
    struct FakeNeighbors {
        table: String,
    }

    impl FakeNeighbors {
        fn with_host(host: u8) -> Self {
            FakeNeighbors {
                table: format!(
                    "IP address HW type Flags HW address Mask Device\n\
                     192.0.2.{host} 0x1 0x2 02:00:00:00:00:{host:02x} * eth9\n"
                ),
            }
        }
    }

    impl crate::discovery::NeighborSource for FakeNeighbors {
        fn read_neighbors(
            &self,
            _scope: &Ipv4Net,
            _interface_name: &str,
        ) -> Result<Vec<crate::discovery::NeighborEntry>, crate::discovery::NeighborError> {
            Ok(crate::discovery::parse_arp_table(&self.table))
        }
    }

    /// A fake resolver answering every query with one fixed name (the
    /// T-203 `ScriptedResolver` shape, minimal form). The trait is
    /// implemented here in test code only — never in production code
    /// (the §2 ruling; the paths are fully qualified to keep the §8.2
    /// import grep honest).
    struct FakeResolver {
        name: &'static str,
    }

    impl crate::enrichment::dns::NameResolver for FakeResolver {
        fn reverse(
            &mut self,
            _ip: Ipv4Addr,
            _timeout: Duration,
        ) -> Result<Option<Hostname>, crate::enrichment::dns::ResolveError> {
            Ok(Some(Hostname::try_from(self.name).expect("valid name")))
        }
    }

    #[test]
    fn ac5_runtime_integration_read_only_cycle_with_real_workers() {
        // Shared clock: the runtime and the hostname worker read the
        // same (frozen) time.
        let shared = Arc::new(StdMutex::new(FakeClock::new()));
        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedFakeClock(Arc::clone(&shared)));

        // The synthetic scope the worker and the state agree on.
        let scope = Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 29).expect("valid network");

        // Real read-only orchestrator over the fake neighbor source.
        let (discovery, discovery_events) =
            DiscoveryWorker::spawn_read_only(Box::new(FakeNeighbors::with_host(5)), scope, "eth9");

        // Real hostname worker over the fake resolver.
        let hostname = crate::enrichment::worker::HostnameWorker::spawn(
            crate::enrichment::hostname::HostnameConfig::default(),
            Some(Box::new(FakeResolver {
                name: "host-five.lan",
            })),
            Arc::clone(&clock),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("spawn succeeds");

        // The state: read-only mode, notice pre-acknowledged, one
        // synthetic eligible entry matching the worker's scope.
        let params = SessionParams {
            mode: AppMode::ReadOnly {
                reason: "no raw socket".to_owned(),
            },
            notice_acknowledged: true,
            ..SessionParams::default()
        };
        let state = AppState::with_scope_entries(params, vec![eth_entry()], db(), clock.as_ref())
            .expect("valid");

        let executor = WorkerExecutor::new(discovery, hostname);
        let (mut runtime, sender) = Runtime::new(state, executor, discovery_events, clock);

        // Confirm the scope through the real queue; the confirm's own
        // ResolveHostname effect reaches the real hostname worker.
        send(&sender, AppEvent::Input(InputEvent::Key(Key::Enter)));
        runtime.step(Duration::ZERO);
        assert!(runtime.state().discovery_armed());
        assert_eq!(runtime.state().screen(), Screen::Dashboard);

        // The observed neighbor's identity (needed by the wait
        // condition below — the local device's own lookup resolving
        // first must not end the wait early).
        let observed_key = DeviceKey {
            iface_index: 2,
            mac: "02:00:00:00:00:05".parse().expect("valid MAC"),
        };

        // Bounded-poll the loop until the whole cycle AND the observed
        // device's hostname answer have flowed through (no blind
        // sleeps — the deadline bounds the wait; 10 s dwarfs a
        // read-only cycle plus one fake lookup).
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            runtime.step(Duration::from_millis(20));
            let state = runtime.state();
            let hostname_known = state
                .registry
                .get(&observed_key)
                .is_some_and(|device| device.hostname.is_known());
            let cycle_done = state.last_scan().is_some();
            if hostname_known && cycle_done {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the cycle and the hostname answer must flow within the bound"
            );
        }

        let state = runtime.state();
        // Cycle events flowed through the forwarder into the registry:
        // the local device plus the observed .5 neighbor.
        assert_eq!(state.registry.device_count(), 2);
        let observed = state.registry.get(&observed_key).expect("the .5 device");
        assert_eq!(observed.primary_ip(), Ipv4Addr::new(192, 0, 2, 5));
        assert!(observed.sources.contains(Source::NeighborTable));
        // The local device is present and tagged.
        let local = state
            .registry
            .iter()
            .find(|device| device.tags.contains(Tag::ThisDevice))
            .expect("the local device");
        assert_eq!(local.primary_ip(), Ipv4Addr::new(192, 0, 2, 1));
        // Hostname fields became Known (the fake resolver answered;
        // the inline drain fed `update`).
        assert_eq!(
            observed.hostname,
            Field::Known {
                value: Hostname::try_from("host-five.lan").expect("valid"),
                source: Source::ReverseDns,
            }
        );
        // last_scan recorded the outcome.
        let scan = state.last_scan().expect("recorded");
        assert_eq!(scan.mode, CycleMode::ReadOnly);
        assert_eq!(scan.outcome, DiscoveryOutcome::Complete);
        assert_eq!(scan.trigger, Trigger::Initial);
        // next_auto_in equals the interval from the finish (the
        // finish-anchored cadence, ruling (a)).
        assert_eq!(
            state
                .scheduler
                .next_auto_in(state.last_scan().expect("recorded").finished_at),
            Some(Duration::from_secs(60))
        );
        // The counters snapshot was refreshed from the real workers.
        assert_eq!(state.counters().orchestrator.cycles_started, 1);
        assert_eq!(state.counters().orchestrator.cycles_finished, 1);
        assert!(state.counters().hostname.queries_issued >= 1);
        // The read-only message from construction is still present.
        assert!(
            state
                .messages
                .contains_kind(&crate::app::message::MessageKind::ReadOnlyMode {
                    reason: String::new()
                })
        );

        // Quit through the queue: the shutdown sequence joins all
        // threads cleanly (a failure would panic or hang; the drop
        // guard below joins whatever a missed shutdown left).
        send(&sender, AppEvent::Input(InputEvent::Key(Key::Char('q'))));
        runtime.step(Duration::ZERO);
        assert!(runtime.state().quit());
        // A second step after shutdown: no panic (idempotent).
        runtime.step(Duration::ZERO);
        drop(runtime);
    }

    // ---- AC-11: the NFR-03 benchmark ------------------------------------------

    /// One synthetic observation: a unique, locally-administered,
    /// unicast MAC and a unique private address.
    fn bench_obs(index: u64) -> ScannerObservation {
        ScannerObservation {
            ip: Ipv4Addr::new(10, (index / 254) as u8, (index % 254) as u8 + 1, 7),
            mac: format!(
                "02:00:{:02x}:{:02x}:{:02x}:01",
                (index >> 16) as u8,
                (index >> 8) as u8,
                (index & 0xff) as u8
            )
            .parse()
            .expect("valid synthetic MAC"),
            source: Source::NeighborTable,
        }
    }

    fn finished_event(scan_id: u64, trigger: Trigger, mode: CycleMode) -> AppEvent {
        AppEvent::Discovery(CycleEvent::Finished {
            scan_id: ScanId::new(scan_id),
            trigger,
            mode,
            summary: Box::new(CycleSummary {
                outcome: DiscoveryOutcome::Complete,
                counters: Default::default(),
                elapsed: Duration::from_secs(1),
                degraded: None,
            }),
        })
    }

    #[test]
    fn ac11_nfr03_no_iteration_blocks_at_4096_devices() {
        let clock: Arc<dyn Clock + Send + Sync> =
            Arc::new(SharedFakeClock(Arc::new(StdMutex::new(FakeClock::new()))));
        let mut state = AppState::with_scope_entries(
            SessionParams {
                notice_acknowledged: true,
                ..SessionParams::default()
            },
            vec![macless_entry()],
            db(),
            clock.as_ref(),
        )
        .expect("valid");
        let pure_clock = FakeClock::new();
        // Confirm (no local device: the entry has no MAC — the
        // documented no-identity path — so the registry below holds
        // exactly the 4,096 synthetic devices, at the ADR-008 cap).
        let _ = update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &pure_clock,
        );

        // Pre-fill: 4,096 synthetic devices through the real update
        // path, inside one cycle (128 batches × 32), then finish it.
        update(
            &mut state,
            AppEvent::Discovery(CycleEvent::Started {
                scan_id: ScanId::new(1),
                trigger: Trigger::Initial,
                mode: CycleMode::ReadOnly,
            }),
            &pure_clock,
        );
        for chunk_index in 0..128u64 {
            let batch: Vec<_> = (0..32u64)
                .map(|offset| bench_obs(chunk_index * 32 + offset))
                .collect();
            let _ = update(
                &mut state,
                AppEvent::Discovery(CycleEvent::Observations {
                    scan_id: ScanId::new(1),
                    batch,
                }),
                &pure_clock,
            );
        }
        let _ = update(
            &mut state,
            finished_event(1, Trigger::Initial, CycleMode::ReadOnly),
            &pure_clock,
        );
        assert_eq!(
            state.registry.device_count(),
            4096,
            "exactly the ADR-008 cap"
        );

        let (mut runtime, sender) = Runtime::new(
            state,
            RecordingExecutor::new(),
            dummy_discovery_receiver(),
            clock,
        );

        // The burst: Started + 128 × Observations(32) + Finished +
        // Tick + 5 Input events (the card's exact list; 136 events fit
        // the 256-slot queue).
        send(
            &sender,
            AppEvent::Discovery(CycleEvent::Started {
                scan_id: ScanId::new(2),
                trigger: Trigger::Periodic,
                mode: CycleMode::ReadOnly,
            }),
        );
        for chunk_index in 0..128u64 {
            let batch: Vec<_> = (0..32u64)
                .map(|offset| bench_obs(chunk_index * 32 + offset))
                .collect();
            send(
                &sender,
                AppEvent::Discovery(CycleEvent::Observations {
                    scan_id: ScanId::new(2),
                    batch,
                }),
            );
        }
        send(
            &sender,
            finished_event(2, Trigger::Periodic, CycleMode::ReadOnly),
        );
        send(&sender, AppEvent::Tick);
        for key in [
            Key::Char('j'),
            Key::Down,
            Key::Char('k'),
            Key::Up,
            Key::Char('r'),
        ] {
            send(&sender, AppEvent::Input(InputEvent::Key(key)));
        }

        // Drive the burst through loop iterations; measure each. The
        // drain bound (16 + 1 events per iteration) needs at most
        // ceil(136 / 17) = 8 iterations; 16 cover it with margin.
        let mut iterations: Vec<Duration> = Vec::new();
        while iterations.len() < 16 {
            let began = Instant::now();
            runtime.step(Duration::ZERO);
            iterations.push(began.elapsed());
        }
        let max = iterations.iter().max().copied().unwrap_or_default();
        let mean: Duration = {
            let total: Duration = iterations.iter().sum();
            total / u32::try_from(iterations.len()).unwrap_or(1)
        };
        for (index, spent) in iterations.iter().enumerate() {
            assert!(
                spent < &Duration::from_millis(100),
                "iteration {index} took {spent:?} (NFR-03: < 100 ms at 4,096 devices)"
            );
        }
        println!(
            "NFR-03 burst: {} iterations, mean {mean:?}, max {max:?}",
            iterations.len()
        );

        // The sort-toggle iteration at 4,096 devices.
        send(&sender, AppEvent::Input(InputEvent::Key(Key::Char('s'))));
        let began = Instant::now();
        runtime.step(Duration::ZERO);
        let sort_spent = began.elapsed();
        assert!(
            sort_spent < Duration::from_millis(100),
            "the sort-toggle iteration took {sort_spent:?}"
        );
        println!("NFR-03 sort toggle: {sort_spent:?}");
        assert_eq!(runtime.state().registry.sort_mode(), SortMode::Hostname);
        // The whole burst was processed (the finish landed; the 4,096
        // re-observations kept every record alive — still exactly at
        // the cap, nothing dropped).
        let scan = runtime.state().last_scan().expect("the burst's finish");
        assert_eq!(scan.trigger, Trigger::Periodic);
        assert_eq!(
            runtime.state().registry.device_count(),
            4096,
            "the re-observations merged; no cap drop occurred"
        );
        assert!(!runtime.state().registry.cap_warning());
        drop(runtime);
    }
}
