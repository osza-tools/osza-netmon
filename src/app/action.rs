// SPDX-License-Identifier: GPL-3.0-only

//! The application's effects: what [`update`](super::update::update) asks the
//! runtime to do, and the executor that does it (plan §8.4; task
//! T-205).
//!
//! `update(state, event, clock)` is pure — no I/O, no threads, no
//! channels — so everything with a side effect comes back as an
//! [`Effect`] that the runtime executes through the
//! [`EffectsExecutor`] trait. Two effects exist:
//!
//! * [`Effect::StartScan`] — hand one discovery cycle to the T-204
//!   orchestrator. Built exclusively from scheduler decisions (the
//!   Initial/Periodic auto start via `poll`, the Manual start via the
//!   `r` key) with the binding T-204 §11.1 recipe:
//!   `ScanParams { passes: trigger.passes(), rate_pps: DEFAULT_RATE_PPS,
//!   listen_window: DEFAULT_LISTEN_WINDOW }`.
//! * [`Effect::ResolveHostname`] — queue one reverse lookup on the
//!   T-203 worker.
//!
//! **There is no `CancelScan` effect.** User quit is the only cancel
//! path: the runtime's shutdown sequence (`DiscoveryWorker::shutdown`
//! / drop) cancels a running cycle and joins it inside the T-204
//! bounds (≤ 500 ms cancel + joins) — an in-session cancel control is
//! not part of MVP 0.1.0 (plan §6.3, FR-DS-09's cancel exists for the
//! shutdown path; no user-facing cancel key is mapped in §10.3).
//!
//! [`Effect::Quit`] is informational: [`AppState::quit`](super::AppState::quit)
//! is the authoritative flag the runtime checks, and `update` sets
//! both together on every quit path (documented; the effect exists so
//! an executor sees the intent explicitly). Executors treat it as a
//! no-op.
//!
//! The production executor ([`WorkerExecutor`]) owns the worker
//! handles (ADR-012: commands flow from the main thread to the workers
//! over bounded channels; the workers never touch the registry). Its
//! error mapping is honest end to end: a start rejected by the
//! orchestrator surfaces as [`EffectError::StartScan`] with the typed
//! [`OrchestratorError`]; a lookup the worker could not accept surfaces
//! as [`EffectError::ResolveHostname`] with the typed [`EnqueueError`].

use std::net::Ipv4Addr;
use std::sync::mpsc::Receiver;

use crate::discovery::ScanParams;
use crate::discovery::scheduler::Trigger;
use crate::discovery::worker::DiscoveryWorker;
use crate::discovery::worker::OrchestratorError;
use crate::discovery::worker::OrchestratorStatsSnapshot;
use crate::enrichment::worker::EnqueueError;
use crate::enrichment::worker::HostnameEvent;
use crate::enrichment::worker::HostnameStatsSnapshot;
use crate::enrichment::worker::HostnameWorker;

/// What the runtime must do after one `update` pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Start one discovery cycle (from a scheduler decision only; the
    /// scheduler guarantees no start while a cycle runs, FR-DS-08).
    StartScan {
        /// Why the cycle starts (decides the ADR-011 pass count).
        trigger: Trigger,
        /// The cycle's tuning (the binding §2 recipe).
        params: ScanParams,
    },
    /// Queue one reverse-DNS lookup on the hostname worker.
    ResolveHostname {
        /// The address to look up.
        ip: Ipv4Addr,
    },
    /// The user asked to quit. Informational —
    /// [`AppState::quit`](super::AppState::quit) is authoritative;
    /// `update` always sets both together.
    Quit,
}

/// Why an effect could not be executed. Both arms carry the worker's
/// own typed error, verbatim — the runtime decides what to surface
/// (§5.8: a failed start becomes one honest `ScanFailed` message; a
/// rejected lookup is counted in worker stats and silently re-healed
/// by the next cycle's re-queue, cite T-203).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EffectError {
    /// `DiscoveryWorker::start_cycle` rejected the start.
    #[error("starting a discovery cycle failed: {0}")]
    StartScan(
        /// The orchestrator's typed rejection.
        OrchestratorError,
    ),
    /// `HostnameWorker::try_resolve` could not accept the lookup.
    #[error("queueing a hostname lookup failed: {0}")]
    ResolveHostname(
        /// The worker's typed rejection.
        EnqueueError,
    ),
}

/// The worker-side counters an executor can report for the
/// [`CountersSnapshot`](super::state::CountersSnapshot) refresh
/// (§5.4: counters are refreshed by the runtime, never by `update`).
///
/// The default is all-zero: executors without workers (the test
/// recording executor, a future dry-run executor) have nothing to
/// report and say so honestly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkerStats {
    /// The orchestrator's counters, or zero when no orchestrator runs.
    pub orchestrator: OrchestratorStatsSnapshot,
    /// The hostname worker's counters, or zero when none runs.
    pub hostname: HostnameStatsSnapshot,
}

/// Executes the effects `update` produced (plan §8.4: "effects (start
/// scan, queue lookups, quit) are executed by main"; here: by the
/// runtime, which is the main loop).
///
/// The trait exists so the whole application is drivable with a
/// recording executor in tests (assert the exact effect sequence) and
/// with the production [`WorkerExecutor`] against the real reviewed
/// workers (the runtime integration suite). `shutdown` is part of the
/// protocol because the workers are owned by the executor, and only
/// the owner can cancel-and-join them (T-204 bounds). The
/// `hostname_events` accessor exists because T-203's worker keeps
/// its event receiver inside the handle (a borrowed `&Receiver` —
/// there is no owned extraction API), so the runtime drains it
/// through the executor (deviation D-2, see `runtime`'s module docs).
pub trait EffectsExecutor {
    /// Executes one effect. Never blocks: both production arms are
    /// `try_send`-based against bounded channels.
    ///
    /// # Errors
    /// The typed worker rejection, verbatim ([`EffectError`]).
    fn execute(&mut self, effect: Effect) -> Result<(), EffectError>;

    /// A snapshot of the worker counters for the per-step refresh.
    /// Zeroed by default (executors without workers).
    fn worker_stats(&self) -> WorkerStats {
        WorkerStats::default()
    }

    /// The hostname worker's event receiver, when this executor owns
    /// one. `None` by default (executors without a hostname worker).
    fn hostname_events(&self) -> Option<&Receiver<HostnameEvent>> {
        None
    }

    /// Cancels and joins the owned workers, bounded (T-204's ≈ 500 ms
    /// orchestrator bound + the T-203 hostname join). Idempotent: a
    /// second call is a no-op, never a panic (the runtime may call it
    /// on quit and again on drop).
    fn shutdown(&mut self) {}
}

/// The production executor: owns the T-204 orchestrator handle and the
/// T-203 hostname worker handle (ADR-012: the main thread is the only
/// commander; both workers are driven exclusively through their
/// bounded command channels).
///
/// * `StartScan` → [`DiscoveryWorker::start_cycle`]. On
///   [`OrchestratorError::ArpWorkerGone`] the runtime appends one
///   `ScanFailed` message (§5.8). [`OrchestratorError::AlreadyInProgress`]
///   should be impossible — the scheduler guards the single-commander
///   contract — and is surfaced as the same honest message, never
///   silenced.
/// * `ResolveHostname` → [`HostnameWorker::try_resolve`].
///   [`EnqueueError::QueueFull`] / [`EnqueueError::WorkerGone`] are
///   counted in the worker's own stats (`enqueue_rejected`) and need
///   no message: the field honestly stays `Pending`, and the next
///   cycle's re-queue heals a dropped lookup (§5.9, T-203 dedup).
/// * `Quit` → no-op (the runtime's `state.quit` flag is authoritative).
pub struct WorkerExecutor {
    /// The orchestrator handle; `None` once shut down.
    discovery: Option<DiscoveryWorker>,
    /// The hostname worker handle; `None` once shut down.
    hostname: Option<HostnameWorker>,
}

impl WorkerExecutor {
    /// Wraps the two live worker handles.
    pub fn new(discovery: DiscoveryWorker, hostname: HostnameWorker) -> Self {
        WorkerExecutor {
            discovery: Some(discovery),
            hostname: Some(hostname),
        }
    }
}

impl EffectsExecutor for WorkerExecutor {
    fn execute(&mut self, effect: Effect) -> Result<(), EffectError> {
        match effect {
            Effect::StartScan { trigger, params } => {
                let Some(worker) = self.discovery.as_ref() else {
                    // Post-shutdown execution: the honest typed answer.
                    return Err(EffectError::StartScan(OrchestratorError::WorkerStopped));
                };
                worker
                    .start_cycle(trigger, params)
                    .map_err(EffectError::StartScan)
            }
            Effect::ResolveHostname { ip } => {
                let Some(worker) = self.hostname.as_ref() else {
                    return Err(EffectError::ResolveHostname(EnqueueError::WorkerGone));
                };
                worker.try_resolve(ip).map_err(EffectError::ResolveHostname)
            }
            // Informational (documented above): the state flag governs.
            Effect::Quit => Ok(()),
        }
    }

    fn worker_stats(&self) -> WorkerStats {
        WorkerStats {
            orchestrator: self
                .discovery
                .as_ref()
                .map_or_else(Default::default, DiscoveryWorker::stats),
            hostname: self
                .hostname
                .as_ref()
                .map_or_else(Default::default, HostnameWorker::stats),
        }
    }

    fn hostname_events(&self) -> Option<&Receiver<HostnameEvent>> {
        self.hostname.as_ref().map(HostnameWorker::events)
    }

    fn shutdown(&mut self) {
        // DiscoveryWorker::shutdown consumes the handle (cancel +
        // join, the T-204 ≈ 500 ms bound); taking it out of the Option
        // makes a second call a no-op (no panic on double shutdown).
        if let Some(worker) = self.discovery.take() {
            worker.shutdown();
        }
        if let Some(worker) = self.hostname.as_mut() {
            worker.shutdown();
            self.hostname = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal recording executor: answers every effect with a
    /// scripted result and records what it saw (the full-featured
    /// version lives in the runtime module for its suites).
    struct AnsweringExecutor {
        answer: Result<(), EffectError>,
        seen: Vec<Effect>,
    }

    impl EffectsExecutor for AnsweringExecutor {
        fn execute(&mut self, effect: Effect) -> Result<(), EffectError> {
            self.seen.push(effect);
            self.answer.clone()
        }
    }

    #[test]
    fn effect_error_displays_the_worker_reasons_verbatim() {
        // The error text embeds the workers' own one-line reasons —
        // the runtime stores exactly these strings as message-log
        // reasons (§5.7: verbatim worker reasons, T-401 words them).
        let start = EffectError::StartScan(OrchestratorError::ArpWorkerGone);
        assert!(
            start.to_string().contains("the arp worker has stopped"),
            "{start}"
        );
        let full = EffectError::ResolveHostname(EnqueueError::QueueFull);
        assert!(
            full.to_string().contains("hostname command queue is full"),
            "{full}"
        );
    }

    #[test]
    fn quit_is_a_no_op_and_shutdown_is_idempotent_for_any_executor() {
        // Documented contract: Quit is a no-op for every executor (the
        // state flag rules), and shutdown may be called twice without
        // a panic. Proven on a trait implementor that owns nothing.
        let mut executor = AnsweringExecutor {
            answer: Ok(()),
            seen: Vec::new(),
        };
        assert_eq!(executor.execute(Effect::Quit), Ok(()));
        assert_eq!(executor.seen, vec![Effect::Quit]);
        executor.shutdown();
        executor.shutdown(); // second call: still fine
        // The default worker_stats of an executor without workers is
        // honestly zeroed (§5.4: counters refreshed by the runtime).
        assert_eq!(executor.worker_stats(), WorkerStats::default());
    }
}
