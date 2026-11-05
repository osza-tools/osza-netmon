// SPDX-License-Identifier: GPL-3.0-only

//! The hostname worker thread: bounded queues, per-IP state,
//! retry/backoff, and shutdown (plan §6.5 FR-EN-03, §4 ADR-003
//! item 4, ADR-012, §8.3; task T-203, policies D-3/D-4).
//!
//! # Shape (ADR-012, plan §8.3)
//!
//! One [`std::thread`] owns a boxed [`super::dns::NameResolver`]
//! and an injected clock, and talks to the application through **two
//! bounded channels** (`std::sync::mpsc::sync_channel`, capacities from
//! [`HostnameConfig`], default 256
//! each):
//!
//! * commands — [`HostnameCommand::Resolve`] and
//!   [`HostnameCommand::Shutdown`];
//! * events — [`HostnameEvent::Resolved`] and
//!   [`HostnameEvent::ShutdownAck`]; these are the enrichment
//!   event/command types the application core consumes in T-205
//!   (plan §8.2), kept UI-agnostic.
//!
//! **Serial** lookups are intentional (bounded effort, plan §1.3
//! principle P4): no parallel queries, ever.
//!
//! # The one-event invariant
//!
//! Every accepted `Resolve` command yields **exactly one** `Resolved`
//! event — from a fresh query or from cached state — with exactly two
//! documented exceptions: after shutdown is requested, in-flight work
//! is abandoned without an event (task-card R-5), and an event whose
//! channel stays saturated through the retry budget is dropped and
//! counted rather than blocking forever (P6, NFR-03).
//!
//! # Per-IP state (policy D-4)
//!
//! * *Known* / *Unknown* — terminal
//!   for the session: never re-queried, answered from the cache.
//! * [`TrackedState::Failed { not_before }`] — the IP is not
//!   re-queried until `failure_backoff` (default 5 min, ADR-003
//!   item 4) has elapsed; commands during the backoff are answered
//!   `Unavailable(Failed)` without a query.
//! * *In-flight* dedup — commands for one IP that arrive in the same
//!   processed batch trigger exactly one query (the batch memo), each
//!   command still gets its event. Because lookups are serial and
//!   synchronous, a query always completes before the next command is
//!   processed, so the memo never spans batches.
//!
//! The state map is capped at `max_tracked_ips` (default 4,096,
//! matching the registry cap of plan NFR-05). Beyond the cap the
//! honest option chosen here: **new IPs are answered
//! `Unavailable(Failed)` immediately, counted as
//! `capped_rejected`, and existing entries are kept.** The
//! alternative — emitting no event — would break the one-event
//! invariant the application relies on; the counter keeps the answer
//! honest.
//!
//! # Outcome mapping (policy D-3, plan §5.1)
//!
//! | Situation | Event outcome |
//! |---|---|
//! | Valid PTR name | `Field::Known { value, source: Source::ReverseDns }` |
//! | NOERROR or NXDOMAIN, no usable PTR | `Field::Unknown` |
//! | Attempt failures (timeout, transport, malformed, failure RCODE) after the retry policy | `Field::Unavailable(Reason::Failed)` (and backoff) |
//! | No eligible resolver | `Field::Unavailable(Reason::NoResolver)` |
//! | Feature disabled via config | `Field::Unavailable(Reason::Disabled)` |
//!
//! # Enqueue contract (P6, NFR-03)
//!
//! The application enqueues via [`HostnameWorker::try_resolve`]
//! (`try_send`): a full command channel returns
//! [`EnqueueError::QueueFull`] — counted — and never blocks. The
//! worker emits events with `try_send` plus a small shutdown-aware
//! retry budget (`EVENT_RETRY_BUDGET` attempts with
//! `EVENT_RETRY_PAUSE` pauses, ≤ 8 ms total); a saturated event
//! channel then drops and counts the event.
//!
//! # Retry policy (policy D-4)
//!
//! On `Err(..)` from one resolver attempt, the worker retries up to
//! `attempts` total (default 2 = one retry), then classifies per
//! D-3. Total worst case per lookup: 2 datagrams, 2 ×
//! `query_timeout`. Each attempt is one [`NameResolver::reverse`]
//! call, which builds its own query with its own LCG ID (policy D-2's
//! per-attempt ID rule); the retry is the same lookup with a fresh
//! datagram — the adaptation is recorded in the T-203 report.
//!
//! # Shutdown (task-card R-5)
//!
//! [`HostnameWorker::shutdown`] sets the shared stop flag and then
//! best-effort enqueues the `Shutdown` command. The worker thread
//! exits within **250 ms** regardless of in-flight lookups or channel
//! state: command waits are sliced at `COMMAND_POLL_SLICE` (100 ms)
//! with a stop check per slice, and the production resolver polls its
//! socket in 50 ms slices against the same flag (mirroring the T-104
//! cancel discipline). In-flight work is abandoned (no event) or
//! completed only if already answered; the worker sends its
//! `ShutdownAck` (subject to the same drop-and-count rule) and exits.
//! The worker never panics on any input; every failure maps to an
//! outcome or a counted rejection. Dropping the handle without
//! `shutdown` also ends the thread: both channel ends close and the
//! run loop observes the disconnect.
//!
//! # Clock ownership
//!
//! The worker holds its clock as `Arc<dyn Clock + Send + Sync>`
//! rather than the card's `&dyn Clock` / `Box<dyn Clock>` sketch, for
//! one reason the card itself requires: the AC-6 tests must advance a
//! `FakeClock` **while the worker owns it**, across the thread
//! boundary — which demands shared ownership. Production passes
//! `Arc::new(SystemClock)`; the choice is recorded in the T-203
//! report.
//!
//! # Intended T-205 wiring
//!
//! `main` selects the resolver once per session
//! ([`super::hostname::select_from_system`]), spawns this worker (or
//! none, when disabled), enqueues `Resolve` commands for observed
//! IPs, and feeds each `Resolved` event to
//! `registry.set_hostname(key, outcome)` — this module never imports
//! `registry` (plan §8.2).

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::model::{Clock, Field, Hostname, Reason, Source};

use super::dns::NameResolver;
use super::hostname::HostnameConfig;

/// How long one command-channel wait may block before re-checking the
/// stop flag (task-card R-5: the thread must exit within 250 ms; two
/// of these slices fit inside that budget with margin).
const COMMAND_POLL_SLICE: Duration = Duration::from_millis(100);

/// How many times a saturated event channel is retried before the
/// event is dropped and counted.
const EVENT_RETRY_BUDGET: u32 = 8;

/// The pause between event-channel retries; the whole retry loop is
/// bounded at 8 × 1 ms = 8 ms.
const EVENT_RETRY_PAUSE: Duration = Duration::from_millis(1);

/// A command to the hostname worker (consumed by the worker thread;
/// produced by the application, plan §8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameCommand {
    /// Resolve this address into a hostname (one `Resolved` event).
    Resolve {
        /// The address to look up.
        ip: Ipv4Addr,
    },
    /// Stop the worker (acknowledged by [`HostnameEvent::ShutdownAck`]).
    Shutdown,
}

/// An event from the hostname worker (produced by the worker thread;
/// consumed by the application, plan §8.2). UI-agnostic data only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameEvent {
    /// The outcome of one accepted `Resolve` command.
    Resolved {
        /// The address that was looked up.
        ip: Ipv4Addr,
        /// The mapped field state (policy D-3).
        outcome: Field<Hostname>,
    },
    /// The worker thread is exiting (sent after shutdown is observed).
    ShutdownAck,
}

/// Rejections of an enqueue attempt (the command channel is bounded;
/// the enqueuer is never blocked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnqueueError {
    /// The command queue is full (counted as `enqueue_rejected`).
    #[error("hostname command queue is full")]
    QueueFull,
    /// The worker is no longer running.
    #[error("the hostname worker is no longer running")]
    WorkerGone,
}

/// Shared, lock-free counters of the hostname worker (both the handle
/// and the thread see them; snapshots are for tests and diagnostics).
#[derive(Debug, Default)]
pub struct HostnameStats {
    commands_accepted: AtomicU64,
    enqueue_rejected: AtomicU64,
    queries_issued: AtomicU64,
    events_sent: AtomicU64,
    events_dropped: AtomicU64,
    capped_rejected: AtomicU64,
}

impl HostnameStats {
    /// A consistent-enough snapshot (each counter read once, relaxed).
    pub fn snapshot(&self) -> HostnameStatsSnapshot {
        HostnameStatsSnapshot {
            commands_accepted: self.commands_accepted.load(Ordering::Relaxed),
            enqueue_rejected: self.enqueue_rejected.load(Ordering::Relaxed),
            queries_issued: self.queries_issued.load(Ordering::Relaxed),
            events_sent: self.events_sent.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
            capped_rejected: self.capped_rejected.load(Ordering::Relaxed),
        }
    }
}

/// One read of [`HostnameStats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostnameStatsSnapshot {
    /// `Resolve` commands taken from the queue.
    pub commands_accepted: u64,
    /// Enqueue attempts rejected because the queue was full.
    pub enqueue_rejected: u64,
    /// Resolver attempts started (per attempt, not per lookup).
    pub queries_issued: u64,
    /// Events delivered to the queue (acks included).
    pub events_sent: u64,
    /// Events dropped after the retry budget (acks included).
    pub events_dropped: u64,
    /// IPs answered `Unavailable(Failed)` because the tracked-IP cap
    /// was reached (existing entries are kept).
    pub capped_rejected: u64,
}

impl fmt::Display for HostnameStatsSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "commands {}, enqueue rejected {}, queries {}, events sent {}, events dropped {}, capped rejected {}",
            self.commands_accepted,
            self.enqueue_rejected,
            self.queries_issued,
            self.events_sent,
            self.events_dropped,
            self.capped_rejected
        )
    }
}

/// The handle side of the hostname worker: enqueue commands, drain
/// events, read counters, shut down.
#[derive(Debug)]
pub struct HostnameWorker {
    commands: SyncSender<HostnameCommand>,
    events: Receiver<HostnameEvent>,
    stop: Arc<AtomicBool>,
    stats: Arc<HostnameStats>,
    join: Option<JoinHandle<()>>,
}

impl HostnameWorker {
    /// Spawns the worker thread.
    ///
    /// * `config` — the validated [`HostnameConfig`].
    /// * `resolver` — `None` means every lookup answers
    ///   `Unavailable(NoResolver)` without any socket use; `Some`
    ///   wraps the production [`super::dns::UdpResolver`] or a test
    ///   fake.
    /// * `clock` — injected time (production: `Arc::new(SystemClock)`;
    ///   tests: a shared `FakeClock`).
    /// * `stop` — the shared stop flag; the same `Arc` must be given
    ///   to [`crate::enrichment::dns::UdpResolver::new`] so a pending socket wait
    ///   is interrupted on shutdown.
    ///
    /// Fails only when the OS refuses to spawn the thread.
    pub fn spawn(
        config: HostnameConfig,
        resolver: Option<Box<dyn NameResolver>>,
        clock: Arc<dyn Clock + Send + Sync>,
        stop: Arc<AtomicBool>,
    ) -> std::io::Result<Self> {
        let (command_tx, command_rx) = sync_channel(config.command_capacity);
        let (event_tx, event_rx) = sync_channel(config.event_capacity);
        let stats = Arc::new(HostnameStats::default());
        let worker = WorkerThread {
            config,
            resolver,
            clock,
            stop: Arc::clone(&stop),
            commands: command_rx,
            events: event_tx,
            stats: Arc::clone(&stats),
            tracked: HashMap::new(),
        };
        let join = thread::Builder::new()
            .name("osza-hostname-worker".to_owned())
            .spawn(move || worker.run())?;
        Ok(HostnameWorker {
            commands: command_tx,
            events: event_rx,
            stop,
            stats,
            join: Some(join),
        })
    }

    /// Enqueues one lookup without ever blocking (P6, NFR-03).
    ///
    /// `Err(QueueFull)` is counted; `Err(WorkerGone)` means the
    /// worker thread has exited (it cannot happen while this handle
    /// keeps the command sender alive and the thread is healthy).
    pub fn try_resolve(&self, ip: Ipv4Addr) -> Result<(), EnqueueError> {
        match self.commands.try_send(HostnameCommand::Resolve { ip }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.stats.enqueue_rejected.fetch_add(1, Ordering::Relaxed);
                Err(EnqueueError::QueueFull)
            }
            Err(TrySendError::Disconnected(_)) => Err(EnqueueError::WorkerGone),
        }
    }

    /// The event queue (drained by the application's main loop).
    pub fn events(&self) -> &Receiver<HostnameEvent> {
        &self.events
    }

    /// A snapshot of the shared counters.
    pub fn stats(&self) -> HostnameStatsSnapshot {
        self.stats.snapshot()
    }

    /// Requests shutdown and joins the thread.
    ///
    /// The stop flag alone guarantees the exit; the `Shutdown`
    /// command is a best-effort fast path (a full command channel
    /// cannot delay the exit). A join error would mean the worker
    /// panicked — impossible by construction (task-card R-5) — and is
    /// propagated loudly rather than swallowed.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Best effort: an ok/error result is equally fine — the flag
        // is the guarantee, this only speeds the common case up.
        let _ = self.commands.try_send(HostnameCommand::Shutdown);
        if let Some(join) = self.join.take()
            && let Err(payload) = join.join()
        {
            std::panic::resume_unwind(payload);
        }
    }
}

/// Per-IP session state inside the worker (policy D-4).
#[derive(Debug, Clone)]
enum TrackedState {
    /// A resolved name; terminal for the session.
    Known(Hostname),
    /// A definitive no-name answer; terminal for the session.
    Unknown,
    /// All attempts failed; not re-queried before `not_before`.
    Failed {
        /// The monotonic instant after which the IP may be re-queried.
        not_before: std::time::Instant,
    },
}

/// The worker thread's owned world.
struct WorkerThread {
    config: HostnameConfig,
    resolver: Option<Box<dyn NameResolver>>,
    clock: Arc<dyn Clock + Send + Sync>,
    stop: Arc<AtomicBool>,
    commands: Receiver<HostnameCommand>,
    events: SyncSender<HostnameEvent>,
    stats: Arc<HostnameStats>,
    tracked: HashMap<Ipv4Addr, TrackedState>,
}

impl WorkerThread {
    /// The run loop: blocking discipline — one command wait at a time,
    /// sliced at [`COMMAND_POLL_SLICE`] with a stop check per slice;
    /// lookups run serially inside batch handling.
    fn run(mut self) {
        loop {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            match self.commands.recv_timeout(COMMAND_POLL_SLICE) {
                Ok(command) => {
                    // Batch everything that is already queued (plan
                    // §8.3's worker batching); the channel capacity
                    // bounds the batch.
                    let mut batch = vec![command];
                    while let Ok(next) = self.commands.try_recv() {
                        batch.push(next);
                    }
                    if self.handle_batch(&batch) {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue, // re-check stop
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
        self.ack();
    }

    /// Processes one batch; `true` when shutdown was requested. On
    /// stop, remaining commands are abandoned without events
    /// (task-card R-5).
    fn handle_batch(&mut self, batch: &[HostnameCommand]) -> bool {
        // The in-flight memo: outcomes computed in this batch are
        // reused for every further command of the same IP (one query,
        // one event per command).
        let mut memo: HashMap<Ipv4Addr, Field<Hostname>> = HashMap::new();
        for command in batch {
            if self.stop.load(Ordering::Relaxed) {
                return true;
            }
            match command {
                HostnameCommand::Shutdown => return true,
                HostnameCommand::Resolve { ip } => self.handle_resolve(*ip, &mut memo),
            }
        }
        false
    }

    /// Answers one `Resolve` command (the D-3/D-4 state machine).
    fn handle_resolve(&mut self, ip: Ipv4Addr, memo: &mut HashMap<Ipv4Addr, Field<Hostname>>) {
        self.stats.commands_accepted.fetch_add(1, Ordering::Relaxed);

        // In-flight dedup: this batch already queried the IP.
        if let Some(outcome) = memo.get(&ip) {
            self.emit(ip, outcome.clone());
            return;
        }

        // Config gate: the feature is disabled (--no-hostnames, T-402).
        if !self.config.enabled {
            self.emit(ip, Field::Unavailable(Reason::Disabled));
            return;
        }

        // Resolver gate: no eligible resolver (ADR-003 item 3) — no
        // query is ever sent.
        if self.resolver.is_none() {
            self.emit(ip, Field::Unavailable(Reason::NoResolver));
            return;
        }

        match self.tracked.get(&ip) {
            Some(TrackedState::Known(hostname)) => {
                let outcome = Field::Known {
                    value: hostname.clone(),
                    source: Source::ReverseDns,
                };
                self.emit(ip, outcome);
            }
            Some(TrackedState::Unknown) => self.emit(ip, Field::Unknown),
            Some(TrackedState::Failed { not_before }) if self.clock.now().mono() < *not_before => {
                // Still inside the failure backoff: answer from state.
                self.emit(ip, Field::Unavailable(Reason::Failed));
            }
            _ => {
                // Unknown IP, or a backoff that expired: the cap may
                // reject the new IP (existing entries are kept).
                if !self.tracked.contains_key(&ip)
                    && self.tracked.len() >= self.config.max_tracked_ips
                {
                    self.stats.capped_rejected.fetch_add(1, Ordering::Relaxed);
                    self.emit(ip, Field::Unavailable(Reason::Failed));
                    return;
                }
                // `None` means abandoned by shutdown: no event, no state.
                if let Some(outcome) = self.run_lookup(ip) {
                    memo.insert(ip, outcome.clone());
                    self.remember(ip, &outcome);
                    self.emit(ip, outcome);
                }
            }
        }
    }

    /// Runs one lookup with the retry policy (policy D-4): `attempts`
    /// total attempts, each one `NameResolver::reverse` call (its own
    /// query, its own ID, one datagram each). `None` = abandoned by
    /// shutdown.
    fn run_lookup(&mut self, ip: Ipv4Addr) -> Option<Field<Hostname>> {
        let Some(resolver) = self.resolver.as_mut() else {
            // Unreachable (the resolver gate ran); kept total.
            return Some(Field::Unavailable(Reason::NoResolver));
        };
        for _ in 0..self.config.attempts {
            if self.stop.load(Ordering::Relaxed) {
                return None;
            }
            self.stats.queries_issued.fetch_add(1, Ordering::Relaxed);
            match resolver.reverse(ip, self.config.query_timeout) {
                Ok(Some(hostname)) => {
                    return Some(Field::Known {
                        value: hostname,
                        source: Source::ReverseDns,
                    });
                }
                Ok(None) => return Some(Field::Unknown),
                Err(_) => continue, // retry until the attempt budget is spent
            }
        }
        Some(Field::Unavailable(Reason::Failed))
    }

    /// Records a lookup outcome in the session state.
    fn remember(&mut self, ip: Ipv4Addr, outcome: &Field<Hostname>) {
        match outcome {
            Field::Known { value, .. } => {
                self.tracked.insert(ip, TrackedState::Known(value.clone()));
            }
            Field::Unknown => {
                self.tracked.insert(ip, TrackedState::Unknown);
            }
            Field::Unavailable(Reason::Failed) => {
                let now = self.clock.now();
                // Saturating: at the end of the Instant range the
                // backoff degrades to "not before now" (unreachable in
                // practice; kept panic-free, plan SR-02).
                let not_before = now
                    .mono()
                    .checked_add(self.config.failure_backoff)
                    .unwrap_or(now.mono());
                self.tracked.insert(ip, TrackedState::Failed { not_before });
            }
            // Disabled/NoResolver are answered by the gates before any
            // state exists; Pending is never an outcome.
            Field::Unavailable(_) | Field::Pending => {}
        }
    }

    /// Delivers one event: `try_send` with a small shutdown-aware
    /// retry budget; a saturated queue drops and counts (P6, NFR-03).
    fn emit(&mut self, ip: Ipv4Addr, outcome: Field<Hostname>) {
        let mut pending = HostnameEvent::Resolved { ip, outcome };
        let mut tries = 0u32;
        loop {
            match self.events.try_send(pending) {
                Ok(()) => {
                    self.stats.events_sent.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(TrySendError::Full(back)) => {
                    if self.stop.load(Ordering::Relaxed) || tries >= EVENT_RETRY_BUDGET {
                        self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    tries += 1;
                    pending = back;
                    thread::sleep(EVENT_RETRY_PAUSE);
                }
                Err(TrySendError::Disconnected(_)) => {
                    // The handle is gone: nothing to count for.
                    self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }

    /// The final shutdown acknowledgement, under the same bounded
    /// delivery rule as every event.
    fn ack(&mut self) {
        let mut pending = HostnameEvent::ShutdownAck;
        let mut tries = 0u32;
        loop {
            match self.events.try_send(pending) {
                Ok(()) => {
                    self.stats.events_sent.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                Err(TrySendError::Full(back)) => {
                    if tries >= EVENT_RETRY_BUDGET {
                        self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    tries += 1;
                    pending = back;
                    thread::sleep(EVENT_RETRY_PAUSE);
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.stats.events_dropped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::dns::ResolveError;
    use crate::enrichment::hostname::HostnameConfig;
    use crate::model::{FakeClock, SystemClock, Timestamp};
    use std::collections::VecDeque;
    use std::net::UdpSocket;
    use std::sync::PoisonError;
    use std::sync::atomic::AtomicU64;
    use std::sync::mpsc;
    use std::time::Instant;

    // ---- fakes ---------------------------------------------------------------

    /// A shared fake clock: the worker reads it through the trait, the
    /// test advances it between commands (AC-6, zero sleeps).
    struct SharedFakeClock(Arc<std::sync::Mutex<FakeClock>>);

    impl Clock for SharedFakeClock {
        fn now(&self) -> Timestamp {
            self.0.lock().unwrap_or_else(PoisonError::into_inner).now()
        }
    }

    type Step = Result<Option<Hostname>, ResolveError>;

    fn host(name: &str) -> Step {
        Ok(Some(Hostname::try_from(name).expect("valid name")))
    }

    /// A scripted resolver: pops one scripted step per call, counts
    /// calls, can gate its first call until the test releases it
    /// (making batches deterministic), and can signal the test after a
    /// chosen number of calls.
    struct ScriptedResolver {
        calls: Arc<AtomicU64>,
        script: std::sync::Mutex<VecDeque<Step>>,
        gate: Option<mpsc::Receiver<()>>,
        entered: Option<mpsc::Sender<()>>,
        notify_at: Option<(u64, mpsc::Sender<()>)>,
    }

    impl ScriptedResolver {
        fn new(calls: Arc<AtomicU64>, script: Vec<Step>) -> Self {
            ScriptedResolver {
                calls,
                script: std::sync::Mutex::new(script.into()),
                gate: None,
                entered: None,
                notify_at: None,
            }
        }

        /// Signals `notify` once the call count reaches `at`.
        fn notifying(
            calls: Arc<AtomicU64>,
            script: Vec<Step>,
            at: u64,
        ) -> (Self, mpsc::Receiver<()>) {
            let (tx, rx) = mpsc::channel();
            (
                ScriptedResolver {
                    calls,
                    script: std::sync::Mutex::new(script.into()),
                    gate: None,
                    entered: None,
                    notify_at: Some((at, tx)),
                },
                rx,
            )
        }

        /// Gates the first call: signals `entered`, then blocks until
        /// released.
        fn gated(
            calls: Arc<AtomicU64>,
            script: Vec<Step>,
        ) -> (Self, mpsc::Receiver<()>, mpsc::Sender<()>) {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let resolver = ScriptedResolver {
                calls,
                script: std::sync::Mutex::new(script.into()),
                gate: Some(release_rx),
                entered: Some(entered_tx),
                notify_at: None,
            };
            (resolver, entered_rx, release_tx)
        }
    }

    impl NameResolver for ScriptedResolver {
        fn reverse(&mut self, _ip: Ipv4Addr, _timeout: Duration) -> Step {
            if let Some(gate) = self.gate.take() {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                }
                // Block until the test releases; a dropped sender
                // (worker shutdown path) also unblocks us.
                let _ = gate.recv();
            }
            let call = self.calls.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some((at, notify)) = self.notify_at.as_ref()
                && call == *at
            {
                let _ = notify.send(());
            }
            let mut script = self.script.lock().unwrap_or_else(PoisonError::into_inner);
            script.pop_front().unwrap_or(Err(ResolveError::Timeout))
        }
    }

    /// A resolver that must never be called: the disabled and
    /// no-resolver paths prove they touch no socket by failing loudly
    /// if this runs (AC-7).
    struct TouchingResolver {
        calls: Arc<AtomicU64>,
    }

    impl NameResolver for TouchingResolver {
        fn reverse(&mut self, _ip: Ipv4Addr, _timeout: Duration) -> Step {
            self.calls.fetch_add(1, Ordering::Relaxed);
            panic!("this resolver must never be called");
        }
    }

    // ---- helpers --------------------------------------------------------------

    fn config() -> HostnameConfig {
        // Small queues for the saturation tests, tiny timeout (the
        // fakes never actually wait), defaults elsewhere.
        HostnameConfig::try_new(
            true,
            Duration::from_millis(50),
            2,
            Duration::from_secs(5 * 60),
            8,
            8,
            4096,
        )
        .expect("valid config")
    }

    fn spawn_with(
        config: HostnameConfig,
        resolver: Option<Box<dyn NameResolver>>,
    ) -> (HostnameWorker, Arc<std::sync::Mutex<FakeClock>>) {
        let clock = Arc::new(std::sync::Mutex::new(FakeClock::new()));
        let worker = HostnameWorker::spawn(
            config,
            resolver,
            Arc::new(SharedFakeClock(Arc::clone(&clock))),
            Arc::new(AtomicBool::new(false)),
        )
        .expect("spawn worker");
        (worker, clock)
    }

    fn next_event(worker: &HostnameWorker) -> HostnameEvent {
        // Bounded wait for a real event; fakes answer immediately, so
        // this is never a timing dependency (§11.4).
        worker
            .events()
            .recv_timeout(Duration::from_secs(5))
            .expect("event arrives")
    }

    fn resolved_of(event: HostnameEvent) -> (Ipv4Addr, Field<Hostname>) {
        match event {
            HostnameEvent::Resolved { ip, outcome } => (ip, outcome),
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    fn known(name: &str) -> Field<Hostname> {
        Field::Known {
            value: Hostname::try_from(name).expect("valid name"),
            source: Source::ReverseDns,
        }
    }

    // ---- outcome mapping (AC-6, policy D-3) ---------------------------------

    #[test]
    fn success_maps_to_known_reverse_dns() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![host("printer.lan")],
            ))),
        );
        assert_eq!(worker.try_resolve(ip(10)), Ok(()));
        let (event_ip, outcome) = resolved_of(next_event(&worker));
        assert_eq!(event_ip, ip(10));
        assert_eq!(outcome, known("printer.lan"));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        // Counters are read after the join: shutdown() is the
        // happens-before edge that makes the last increments visible.
        worker.shutdown();
        let stats = worker.stats();
        assert_eq!(stats.queries_issued, 1);
        assert_eq!(stats.events_sent, 2); // Resolved + ShutdownAck
    }

    #[test]
    fn noerror_empty_maps_to_unknown() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![Ok(None)],
            ))),
        );
        assert_eq!(worker.try_resolve(ip(11)), Ok(()));
        let (event_ip, outcome) = resolved_of(next_event(&worker));
        assert_eq!(event_ip, ip(11));
        assert_eq!(outcome, Field::Unknown);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        worker.shutdown();
    }

    #[test]
    fn timeout_timeout_retries_exactly_once_then_failed() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![Err(ResolveError::Timeout), Err(ResolveError::Timeout)],
            ))),
        );
        assert_eq!(worker.try_resolve(ip(12)), Ok(()));
        let (event_ip, outcome) = resolved_of(next_event(&worker));
        assert_eq!(event_ip, ip(12));
        assert_eq!(outcome, Field::Unavailable(Reason::Failed));
        // Exactly one retry: two attempts, not more.
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let stats = worker.stats();
        assert_eq!(stats.queries_issued, 2);
        worker.shutdown();
    }

    #[test]
    fn attempts_one_means_no_retry() {
        let calls = Arc::new(AtomicU64::new(0));
        let one_attempt = HostnameConfig::try_new(
            true,
            Duration::from_millis(50),
            1,
            Duration::from_secs(300),
            8,
            8,
            4096,
        )
        .expect("valid");
        let (mut worker, _clock) = spawn_with(
            one_attempt,
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![Err(ResolveError::Timeout), Err(ResolveError::Timeout)],
            ))),
        );
        assert_eq!(worker.try_resolve(ip(13)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, Field::Unavailable(Reason::Failed));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        worker.shutdown();
    }

    #[test]
    fn timeout_then_success_maps_to_known() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![Err(ResolveError::Timeout), host("late.lan")],
            ))),
        );
        assert_eq!(worker.try_resolve(ip(14)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, known("late.lan"));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        worker.shutdown();
    }

    // ---- backoff and caching (AC-6, fake clock, zero sleeps) ------------------

    #[test]
    fn backoff_blocks_then_expires_with_the_fake_clock() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![
                    Err(ResolveError::Timeout),
                    Err(ResolveError::Timeout),
                    host("revived.lan"),
                ],
            ))),
        );
        // t0: fails twice → Failed, backoff until t0 + 5 min.
        assert_eq!(worker.try_resolve(ip(15)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, Field::Unavailable(Reason::Failed));
        assert_eq!(calls.load(Ordering::Relaxed), 2);

        // t0 + 4 min: still inside the backoff — answered, no query.
        clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .advance(Duration::from_secs(4 * 60));
        assert_eq!(worker.try_resolve(ip(15)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, Field::Unavailable(Reason::Failed));
        assert_eq!(calls.load(Ordering::Relaxed), 2, "no re-query in backoff");

        // t0 + 6 min: the backoff expired — one fresh query, success.
        clock
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .advance(Duration::from_secs(2 * 60));
        assert_eq!(worker.try_resolve(ip(15)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, known("revived.lan"));
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        worker.shutdown();
    }

    #[test]
    fn known_and_unknown_are_cached_for_the_session() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![host("printer.lan"), Ok(None)],
            ))),
        );
        // Known is terminal.
        assert_eq!(worker.try_resolve(ip(16)), Ok(()));
        let (_, first) = resolved_of(next_event(&worker));
        assert_eq!(first, known("printer.lan"));
        assert_eq!(worker.try_resolve(ip(16)), Ok(()));
        let (_, second) = resolved_of(next_event(&worker));
        assert_eq!(second, known("printer.lan"));
        // Unknown is terminal too (a different IP consumes the Ok(None)).
        assert_eq!(worker.try_resolve(ip(17)), Ok(()));
        let (_, third) = resolved_of(next_event(&worker));
        assert_eq!(third, Field::Unknown);
        assert_eq!(worker.try_resolve(ip(17)), Ok(()));
        let (_, fourth) = resolved_of(next_event(&worker));
        assert_eq!(fourth, Field::Unknown);
        // Two lookups total: one per distinct IP.
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let stats = worker.stats();
        assert_eq!(stats.commands_accepted, 4);
        worker.shutdown();
    }

    #[test]
    fn n_commands_for_one_ip_run_one_query_and_emit_n_events() {
        let calls = Arc::new(AtomicU64::new(0));
        let (resolver, entered, release) =
            ScriptedResolver::gated(Arc::clone(&calls), vec![host("printer.lan")]);
        let (mut worker, _clock) = spawn_with(config(), Some(Box::new(resolver)));

        // The first command enters the resolver and blocks there,
        // which guarantees the remaining commands are queued before
        // the state becomes terminal.
        assert_eq!(worker.try_resolve(ip(18)), Ok(()));
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("resolver entered");
        assert_eq!(worker.try_resolve(ip(18)), Ok(()));
        assert_eq!(worker.try_resolve(ip(18)), Ok(()));
        release.send(()).expect("release gate");

        for _ in 0..3 {
            let (event_ip, outcome) = resolved_of(next_event(&worker));
            assert_eq!(event_ip, ip(18));
            assert_eq!(outcome, known("printer.lan"));
        }
        // One query for three commands (the in-flight dedup).
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        worker.shutdown();
    }

    #[test]
    fn one_command_yields_exactly_one_event() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![host("printer.lan")],
            ))),
        );
        assert_eq!(worker.try_resolve(ip(19)), Ok(()));
        let _ = resolved_of(next_event(&worker));
        // No second event is pending, and the counters agree.
        assert!(worker.events().try_recv().is_err());
        worker.shutdown();
        let stats = worker.stats();
        assert_eq!(stats.commands_accepted, 1);
        assert_eq!(stats.events_sent, 2); // the Resolved + the ack
        assert_eq!(stats.events_dropped, 0);
    }

    // ---- disabled / no-resolver (AC-7) ----------------------------------------

    #[test]
    fn no_resolver_answers_without_any_socket_use() {
        let (mut worker, _clock) = spawn_with(config(), None);
        assert_eq!(worker.try_resolve(ip(20)), Ok(()));
        let (event_ip, outcome) = resolved_of(next_event(&worker));
        assert_eq!(event_ip, ip(20));
        assert_eq!(outcome, Field::Unavailable(Reason::NoResolver));
        let stats = worker.stats();
        assert_eq!(stats.queries_issued, 0);
        worker.shutdown();
    }

    #[test]
    fn disabled_answers_without_touching_the_resolver() {
        let calls = Arc::new(AtomicU64::new(0));
        let mut disabled = config();
        disabled.enabled = false;
        let (mut worker, _clock) = spawn_with(
            disabled,
            Some(Box::new(TouchingResolver {
                calls: Arc::clone(&calls),
            })),
        );
        assert_eq!(worker.try_resolve(ip(21)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, Field::Unavailable(Reason::Disabled));
        // The touching fake would have panicked (and failed this test)
        // had the worker queried anything.
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        let stats = worker.stats();
        assert_eq!(stats.queries_issued, 0);
        worker.shutdown();
    }

    // ---- queue behavior (AC-8) --------------------------------------------------

    #[test]
    fn full_command_queue_rejects_and_counts_never_blocks() {
        let calls = Arc::new(AtomicU64::new(0));
        let small = HostnameConfig::try_new(
            true,
            Duration::from_millis(50),
            2,
            Duration::from_secs(300),
            4,
            8,
            4096,
        )
        .expect("valid");
        let (resolver, entered, release) =
            ScriptedResolver::gated(Arc::clone(&calls), vec![host("printer.lan")]);
        let (mut worker, _clock) = spawn_with(small, Some(Box::new(resolver)));

        // The worker picks up the first command and blocks inside the
        // resolver; the channel then holds exactly its capacity of
        // further commands for the SAME IP (dedup + cache paths).
        assert_eq!(worker.try_resolve(ip(22)), Ok(()));
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("resolver entered");
        for n in 0..4u8 {
            assert_eq!(worker.try_resolve(ip(22)), Ok(()), "slot {n}");
        }
        // The queue is full: an explicit rejection, counted.
        assert_eq!(worker.try_resolve(ip(30)), Err(EnqueueError::QueueFull));
        assert_eq!(worker.stats().enqueue_rejected, 1);

        // Release: one query runs; every queued command is answered
        // from the batch memo / cache — five Resolved events in total.
        release.send(()).expect("release gate");
        let mut events = 0;
        for _ in 0..5 {
            let (event_ip, outcome) = resolved_of(next_event(&worker));
            assert_eq!(event_ip, ip(22));
            assert_eq!(outcome, known("printer.lan"));
            events += 1;
        }
        assert_eq!(events, 5);
        // The rejected command never arrived, so it yields no event.
        assert!(worker.events().try_recv().is_err());
        worker.shutdown();
    }

    #[test]
    fn saturated_event_queue_drops_and_counts_instead_of_blocking() {
        let calls = Arc::new(AtomicU64::new(0));
        let tiny_events = HostnameConfig::try_new(
            true,
            Duration::from_millis(50),
            2,
            Duration::from_secs(300),
            8,
            1,
            4096,
        )
        .expect("valid");
        let (resolver, all_queried) = ScriptedResolver::notifying(
            Arc::clone(&calls),
            vec![host("a.lan"), host("b.lan"), host("c.lan")],
            3,
        );
        let (mut worker, _clock) = spawn_with(tiny_events, Some(Box::new(resolver)));
        // Three distinct IPs, each emitting one event, into an
        // undrained queue of capacity 1: the first event fills it, the
        // others exhaust the retry budget and are dropped (counted).
        for n in 23..26u8 {
            assert_eq!(worker.try_resolve(ip(n)), Ok(()));
        }
        // Wait for the third query (the resolver signals it) so the
        // shutdown stop flag cannot race ahead of the batch.
        all_queried
            .recv_timeout(Duration::from_secs(5))
            .expect("all three queries ran");
        // Shutdown returns promptly even with the queue saturated —
        // the worker never blocks unboundedly.
        let started = Instant::now();
        worker.shutdown();
        assert!(started.elapsed() < Duration::from_secs(1));

        let stats = worker.stats();
        assert_eq!(stats.commands_accepted, 3);
        assert_eq!(stats.queries_issued, 3);
        assert_eq!(stats.events_sent, 1, "only the first event fit");
        assert_eq!(
            stats.events_dropped, 3,
            "two Resolved events plus the ack were dropped and counted"
        );
        // The one delivered event is still readable afterwards.
        assert!(matches!(
            worker.events().try_recv(),
            Ok(HostnameEvent::Resolved { .. })
        ));
    }

    // ---- the tracked-IP cap ------------------------------------------------------

    #[test]
    fn cap_rejects_new_ips_and_keeps_existing_entries() {
        let calls = Arc::new(AtomicU64::new(0));
        let capped = HostnameConfig::try_new(
            true,
            Duration::from_millis(50),
            2,
            Duration::from_secs(300),
            8,
            8,
            2,
        )
        .expect("valid");
        let (mut worker, _clock) = spawn_with(
            capped,
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![host("a.lan"), host("b.lan")],
            ))),
        );
        // Two IPs fill the cap.
        assert_eq!(worker.try_resolve(ip(1)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, known("a.lan"));
        assert_eq!(worker.try_resolve(ip(2)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, known("b.lan"));

        // The third IP: answered Unavailable(Failed), counted as
        // capped, and never queried.
        assert_eq!(worker.try_resolve(ip(3)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, Field::Unavailable(Reason::Failed));
        assert_eq!(worker.stats().capped_rejected, 1);

        // Existing entries are kept and still served from the cache.
        assert_eq!(worker.try_resolve(ip(1)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, known("a.lan"));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(worker.stats().capped_rejected, 1);
        worker.shutdown();
    }

    // ---- shutdown (AC-9) ----------------------------------------------------------

    #[test]
    fn shutdown_joins_within_the_bound_and_acks() {
        let calls = Arc::new(AtomicU64::new(0));
        let (mut worker, _clock) = spawn_with(
            config(),
            Some(Box::new(ScriptedResolver::new(
                Arc::clone(&calls),
                vec![host("printer.lan")],
            ))),
        );
        let started = Instant::now();
        worker.shutdown();
        let elapsed = started.elapsed();
        // The card's bound is 250 ms; the test asserts 1 s of wall
        // clock as the justified CI margin (see the T-203 report §6).
        assert!(
            elapsed < Duration::from_secs(1),
            "shutdown took {elapsed:?}"
        );
        // The ack arrived and nothing else is pending.
        assert_eq!(worker.events().try_recv(), Ok(HostnameEvent::ShutdownAck));
        assert!(worker.events().try_recv().is_err());
        // A second shutdown is a no-op (the join was consumed).
        worker.shutdown();
    }

    #[test]
    fn shutdown_interrupts_a_pending_lookup_and_emits_no_event() {
        // The production resolver against a bound-but-silent server
        // with a 10 s budget: shutdown must still return within the
        // bound (the stop flag interrupts the socket wait), the
        // in-flight lookup is abandoned without an event.
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let server_addr = server.local_addr().expect("local addr");
        let (query_seen_tx, query_seen_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let _ = server.recv_from(&mut buffer); // the query
            let _ = query_seen_tx.send(());
            let _ = done_rx.recv(); // stay silent until the test is done
        });

        let stop = Arc::new(AtomicBool::new(false));
        let resolver = crate::enrichment::dns::UdpResolver::new(server_addr, Arc::clone(&stop))
            .expect("resolver");
        let long_timeout = HostnameConfig::try_new(
            true,
            Duration::from_secs(10),
            2,
            Duration::from_secs(300),
            8,
            8,
            4096,
        )
        .expect("valid");
        let mut worker = HostnameWorker::spawn(
            long_timeout,
            Some(Box::new(resolver)),
            Arc::new(SystemClock),
            stop,
        )
        .expect("spawn worker");

        assert_eq!(worker.try_resolve(ip(31)), Ok(()));
        query_seen_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("query reached the silent server");

        let started = Instant::now();
        worker.shutdown();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(1),
            "shutdown took {elapsed:?}"
        );
        // The only event is the ack; the lookup was abandoned.
        assert_eq!(worker.events().try_recv(), Ok(HostnameEvent::ShutdownAck));
        assert!(worker.events().try_recv().is_err());
        let stats = worker.stats();
        assert_eq!(stats.queries_issued, 1);
        assert_eq!(stats.events_sent, 1);

        done_tx.send(()).expect("release server");
        server_thread.join().expect("server thread");
    }

    // ---- loopback integration (AC-10, timeout path with the retry count;
    // ---- authorized by the task card: 127.0.0.1, ephemeral port,
    // ---- in-process, nothing leaves the machine) ---------------------------------

    #[test]
    fn loopback_timeout_path_retries_once_against_a_silent_server() {
        // A server that counts the datagrams it receives and never
        // answers: the production worker with attempts = 2 must send
        // exactly two queries (the original and the one retry) and
        // then answer Unavailable(Failed).
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let server_addr = server.local_addr().expect("local addr");
        // A short read timeout keeps the counting loop responsive to
        // the done signal instead of blocking forever on a silent
        // socket (the test would otherwise never join this thread).
        server
            .set_read_timeout(Some(Duration::from_millis(25)))
            .expect("set read timeout");
        let (datagram_tx, datagram_rx) = mpsc::channel::<()>();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            loop {
                match server.recv_from(&mut buffer) {
                    Ok(_) => {
                        let _ = datagram_tx.send(());
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        // No datagram in this slice: check the done
                        // signal, then keep counting.
                    }
                    Err(_) => break,
                }
                if done_rx.try_recv().is_ok() {
                    break;
                }
            }
        });

        let stop = Arc::new(AtomicBool::new(false));
        let resolver = crate::enrichment::dns::UdpResolver::new(server_addr, Arc::clone(&stop))
            .expect("resolver");
        let fast = HostnameConfig::try_new(
            true,
            Duration::from_millis(50),
            2,
            Duration::from_secs(300),
            8,
            8,
            4096,
        )
        .expect("valid");
        let mut worker =
            HostnameWorker::spawn(fast, Some(Box::new(resolver)), Arc::new(SystemClock), stop)
                .expect("spawn worker");

        assert_eq!(worker.try_resolve(ip(32)), Ok(()));
        let (_, outcome) = resolved_of(next_event(&worker));
        assert_eq!(outcome, Field::Unavailable(Reason::Failed));

        // Exactly two datagrams: the attempt and its one retry. Each
        // is 50 ms apart at most, so a generous 2 s margin per
        // datagram signal suffices (real-time assertion, authorized
        // for the loopback path; justified in the T-203 report).
        datagram_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first datagram");
        datagram_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("retry datagram");
        worker.shutdown();
        let _ = done_tx.send(());
        server_thread.join().expect("server thread");
        let stats = worker.stats();
        assert_eq!(stats.queries_issued, 2);
    }

    // ---- controlled vocabulary (§5.4 / §11.7) --------------------------------------

    /// Every string this module can surface (error and stats `Display`
    /// forms) stays inside plan §5.4's controlled vocabulary.
    #[test]
    fn wording_follows_the_controlled_vocabulary() {
        const BANNED: [&str; 14] = [
            "online",
            "offline",
            "connected",
            "disconnected",
            "intruder",
            "unauthorized",
            "rogue",
            "suspicious",
            "malicious",
            "safe",
            "trusted",
            "secure",
            "verified",
            "stale",
        ];
        let texts: Vec<String> = vec![
            EnqueueError::QueueFull.to_string(),
            EnqueueError::WorkerGone.to_string(),
            HostnameStatsSnapshot {
                commands_accepted: 1,
                enqueue_rejected: 2,
                queries_issued: 3,
                events_sent: 4,
                events_dropped: 5,
                capped_rejected: 6,
            }
            .to_string(),
        ];
        for text in &texts {
            for banned in BANNED {
                assert!(
                    !text.to_lowercase().contains(banned),
                    "banned word {banned:?} in: {text}"
                );
            }
        }
    }
}
