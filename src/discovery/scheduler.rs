// SPDX-License-Identifier: GPL-3.0-only

//! The discovery scheduler: a pure state machine that decides *when*
//! discovery cycles run (plan §6.3 FR-DS-12, §8.3, §11.1; task T-204;
//! ADR-011 for the pass policy).
//!
//! # Purity (plan §11.1, task-card R-2)
//!
//! [`DiscoveryScheduler`] is a pure state machine: no I/O, no threads,
//! no clocks, no channels. Time enters only as [`Timestamp`] parameters
//! (`poll(now)`, `cycle_finished(.., finished_at)`), so the whole
//! scheduling policy is testable with the injected
//! [`FakeClock`](crate::model::FakeClock) and no sleeps
//! (plan §11.4). Executing a decided cycle is the orchestrator's job
//! ([`crate::discovery::worker`]); the application core (T-205) drives
//! this machine from its event loop per plan §8.4:
//!
//! ```text
//! loop:
//!   handle events (a discovery cycle finished -> scheduler.cycle_finished(..))
//!   decision = scheduler.poll(now)            // or manual_refresh() on Refresh
//!   match decision {
//!     StartCycle { trigger, passes } -> worker.start_cycle(trigger, ScanParams {
//!                                          passes, rate_pps: DEFAULT_RATE_PPS,
//!                                          listen_window: DEFAULT_LISTEN_WINDOW })
//!     AlreadyInProgress            -> show "scan already in progress" (FR-DS-08)
//!     AutoScansStopped             -> surface the error (FR-DS-12); manual stays allowed
//!     None                         -> nothing
//!   }
//!   wait = scheduler.next_auto_in(now)        // the event loop's recv_timeout input
//! ```
//!
//! The decision to start **is** the transition to *running*: once
//! `poll`/`manual_refresh` returns [`SchedulerDecision::StartCycle`],
//! the machine reports *running* until
//! [`cycle_finished`](DiscoveryScheduler::cycle_finished) is called, so
//! two overlapping starts are structurally impossible (Manager ruling
//! (a), task card §3.2) and a manual refresh during a cycle can only
//! produce [`SchedulerDecision::AlreadyInProgress`] (FR-DS-08).
//! [`cycle_started`](DiscoveryScheduler::cycle_started) exists for the
//! app to report the worker's *cycle started* event; it is idempotent
//! and also accepts a start the app began on its own (the machine then
//! holds *running* so every ruling stays consistent).
//!
//! # Manager rulings (task card §3.2, FR-DS-12) — implemented exactly
//!
//! * **(a) Finish-anchored cadence:** the next auto cycle is due at
//!   `cycle_finished_at + interval` — anchored at FINISH, so overlap is
//!   structurally impossible.
//! * **(b) Failure backoff:** after a `Failed` cycle the next auto
//!   attempt is due no sooner than `finished_at + max(interval, 30 s)`.
//! * **(c) Auto-stop:** three *consecutive* `Failed` cycles stop
//!   auto-scans entirely (the typed notice
//!   [`SchedulerDecision::AutoScansStopped`] is returned by
//!   `cycle_finished` at the moment the streak reaches three);
//!   manual refresh remains allowed.
//! * **(d) Streak semantics:** only `Failed` increments the streak;
//!   `Complete` and `Partial` reset it; `Cancelled` is neutral.
//! * **(e) Manual refresh:** during a running cycle it is a typed
//!   already-in-progress and nothing is queued (FR-DS-08); while
//!   auto-scans are stopped it is allowed (2 passes, ADR-011). When a
//!   manual cycle finishes, the auto timer re-anchors from its finish
//!   and the manual outcome counts toward the streak exactly like an
//!   auto outcome.
//! * **(f) Manual-only (`--interval 0`):** `poll` never issues auto
//!   starts; manual refresh and the failure rules (backoff, streak,
//!   auto-stop notice) still apply.
//!
//! One interpretation is recorded in the T-204 execution report (§6):
//! the auto-stop is *sticky* for the session — a later manual
//! `Complete` resets the streak (ruling (d)) but does not silently
//! resume auto-scans; resumption is the application's (T-205's)
//! decision to make visibly.
//!
//! # ADR-011 pass policy — the authoritative constants
//!
//! This module is the one authoritative home of the ADR-011 probe
//! policy for T-205/T-402: passes for the initial scan and manual
//! refresh ([`PASSES_INITIAL_AND_MANUAL`] = 2), passes for periodic
//! rediscovery ([`PASSES_PERIODIC`] = 1), plus the default rate and
//! listen window re-exported from the scanner so there is exactly one
//! definition of each value in the tree.

use std::time::Duration;

use crate::discovery::arp::scanner::ScanOutcome;
use crate::model::Timestamp;

pub use crate::discovery::arp::scanner::{DEFAULT_LISTEN_WINDOW, DEFAULT_RATE_PPS};

/// Passes for the initial scan and for manual refresh (ADR-011:
/// "initial scan and manual refresh use 2 passes").
pub const PASSES_INITIAL_AND_MANUAL: u8 = 2;

/// Passes for periodic rediscovery (ADR-011: "periodic rediscovery
/// uses 1 pass").
pub const PASSES_PERIODIC: u8 = 1;

/// The default rediscovery interval (FR-DS-12: "default 60 s after the
/// previous cycle finished").
pub const DEFAULT_REDISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

/// The smallest accepted non-zero rediscovery interval (FR-DS-12:
/// "minimum accepted 15 s"). `0` is also accepted — it means
/// manual-only.
pub const MIN_REDISCOVERY_INTERVAL: Duration = Duration::from_secs(15);

/// After a `Failed` cycle, the next auto attempt is due no sooner than
/// `finished_at + max(interval, 30 s)` (FR-DS-12, Manager ruling (b)).
pub const FAILURE_BACKOFF_FLOOR: Duration = Duration::from_secs(30);

/// Three consecutive `Failed` cycles stop auto-scans entirely
/// (FR-DS-12, Manager ruling (c)).
pub const AUTO_STOP_AFTER_FAILURES: u32 = 3;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Errors of the scheduler's typed constructors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SchedulerError {
    /// A rediscovery interval in `1..=14 s` was rejected (FR-DS-12:
    /// `0` = manual-only and `>= 15 s` are the accepted values).
    #[error(
        "the rediscovery interval must be 0 (manual only) or at least {minimum:?}, found {found:?}"
    )]
    IntervalTooShort {
        /// The rejected value.
        found: Duration,
        /// The smallest accepted non-zero value.
        minimum: Duration,
    },
}

impl SchedulerError {
    /// Builds the FR-DS-12 interval error for a rejected `found`
    /// duration (used by [`RediscoveryInterval::new`] and by tests).
    pub fn interval_too_short(found: Duration) -> Self {
        SchedulerError::IntervalTooShort {
            found,
            minimum: MIN_REDISCOVERY_INTERVAL,
        }
    }
}

/// The validated rediscovery interval (FR-DS-12).
///
/// * `0` — manual-only: [`DiscoveryScheduler::poll`] never issues auto
///   starts (Manager ruling (f)).
/// * `>= 15 s` — periodic rediscovery at that cadence.
/// * anything in between — rejected by [`RediscoveryInterval::new`]
///   with the typed [`SchedulerError`].
///
/// The default is 60 s ([`DEFAULT_REDISCOVERY_INTERVAL`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RediscoveryInterval(Duration);

impl RediscoveryInterval {
    /// Validates `interval` per FR-DS-12: `0` and `>= 15 s` are
    /// accepted, `1..=14 s` is rejected with the typed error.
    pub fn new(interval: Duration) -> Result<Self, SchedulerError> {
        if !interval.is_zero() && interval < MIN_REDISCOVERY_INTERVAL {
            return Err(SchedulerError::interval_too_short(interval));
        }
        Ok(RediscoveryInterval(interval))
    }

    /// The manual-only interval (`0`, FR-DS-12 `--interval 0`).
    pub const fn manual_only() -> Self {
        RediscoveryInterval(Duration::ZERO)
    }

    /// The configured interval (`Duration::ZERO` for manual-only).
    pub const fn interval(self) -> Duration {
        self.0
    }

    /// `true` for the manual-only configuration.
    pub const fn is_manual_only(self) -> bool {
        self.0.is_zero()
    }
}

impl Default for RediscoveryInterval {
    fn default() -> Self {
        RediscoveryInterval(DEFAULT_REDISCOVERY_INTERVAL)
    }
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

/// What started a discovery cycle (ADR-011 ties the pass count to
/// this; T-205 forwards it to the orchestrator and maps it to its own
/// event type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Trigger {
    /// The first cycle of a session (2 passes, ADR-011).
    Initial,
    /// A user-requested refresh (2 passes, ADR-011).
    Manual,
    /// Periodic rediscovery (1 pass, ADR-011).
    Periodic,
}

impl Trigger {
    /// The ADR-011 pass count for this trigger.
    pub const fn passes(self) -> u8 {
        match self {
            Trigger::Initial | Trigger::Manual => PASSES_INITIAL_AND_MANUAL,
            Trigger::Periodic => PASSES_PERIODIC,
        }
    }
}

impl std::fmt::Display for Trigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let word = match self {
            Trigger::Initial => "initial",
            Trigger::Manual => "manual",
            Trigger::Periodic => "periodic",
        };
        f.write_str(word)
    }
}

/// What the scheduler decided (task card §3.2: "outputs are typed
/// decisions").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerDecision {
    /// Start one cycle now, with the trigger's ADR-011 pass count.
    /// Returning this transitions the machine to *running*.
    StartCycle {
        /// Why the cycle starts (decides the pass count).
        trigger: Trigger,
        /// The ADR-011 pass count for the trigger.
        passes: u8,
    },
    /// Nothing to do.
    None,
    /// A manual refresh was requested while a cycle is running:
    /// typed already-in-progress, nothing queued (FR-DS-08).
    AlreadyInProgress,
    /// Auto-scans stopped after three consecutive `Failed` cycles
    /// (FR-DS-12, ruling (c)); returned by
    /// [`cycle_finished`](DiscoveryScheduler::cycle_finished) at the
    /// moment the streak reaches the threshold. Manual refresh stays
    /// allowed; T-205 surfaces the error.
    AutoScansStopped,
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// When the next automatic cycle is due (internal; see
/// [`DiscoveryScheduler::next_auto_in`] for the public view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextAuto {
    /// Due at the first poll: the fresh session's initial cycle
    /// (only while no cycle has ever finished and auto-scans are on).
    Immediately,
    /// Due `delay` after `anchor` (the anchor is always a cycle's
    /// finish time — Manager ruling (a)).
    At { anchor: Timestamp, delay: Duration },
    /// Never: manual-only interval (ruling (f)) or auto-scans stopped
    /// (ruling (c)).
    Never,
}

/// The FR-DS-12 scheduler state machine (pure; see the module docs).
#[derive(Debug, Clone)]
pub struct DiscoveryScheduler {
    /// The validated interval.
    interval: RediscoveryInterval,
    /// Whether a cycle is currently running (entered on a
    /// [`SchedulerDecision::StartCycle`] or on
    /// [`cycle_started`](Self::cycle_started)).
    running: bool,
    /// The next-auto notion (idle-with-next-auto-due).
    next_auto: NextAuto,
    /// Consecutive `Failed` outcomes (ruling (d)).
    failure_streak: u32,
    /// Whether auto-scans have stopped (ruling (c); sticky — see the
    /// module docs).
    auto_stopped: bool,
}

impl DiscoveryScheduler {
    /// A fresh scheduler for `interval` (the default is 60 s, FR-DS-12).
    ///
    /// The fresh state is idle with the initial cycle due immediately
    /// (ADR-011: the session's first scan), except in manual-only mode
    /// where `poll` never issues starts (ruling (f)).
    pub fn new(interval: RediscoveryInterval) -> Self {
        let next_auto = if interval.is_manual_only() {
            NextAuto::Never
        } else {
            NextAuto::Immediately
        };
        DiscoveryScheduler {
            interval,
            running: false,
            next_auto,
            failure_streak: 0,
            auto_stopped: false,
        }
    }

    /// Decides whether an automatic cycle is due at `now` (plan §8.4:
    /// the event loop calls this every iteration).
    ///
    /// Never issues a start while a cycle runs, while auto-scans are
    /// stopped, or in manual-only mode. Issuing
    /// [`SchedulerDecision::StartCycle`] transitions the machine to
    /// *running* (structural one-cycle-at-a-time, ruling (a)).
    pub fn poll(&mut self, now: Timestamp) -> SchedulerDecision {
        if self.running || self.auto_stopped {
            return SchedulerDecision::None;
        }
        let due = match self.next_auto {
            NextAuto::Never => return SchedulerDecision::None,
            NextAuto::Immediately => true,
            NextAuto::At { anchor, delay } => {
                now.mono().saturating_duration_since(anchor.mono()) >= delay
            }
        };
        if !due {
            return SchedulerDecision::None;
        }
        // The decision is the transition: structurally one cycle at a
        // time from this moment until cycle_finished.
        self.running = true;
        let trigger = match self.next_auto {
            // The session's first auto cycle is the initial scan; every
            // auto cycle after a finish is periodic rediscovery.
            NextAuto::Immediately => Trigger::Initial,
            _ => Trigger::Periodic,
        };
        SchedulerDecision::StartCycle {
            trigger,
            passes: trigger.passes(),
        }
    }

    /// A manual refresh was requested (FR-DS-08, rulings (e)/(f)).
    ///
    /// While a cycle runs: typed already-in-progress, nothing queued.
    /// Otherwise: start a manual cycle (2 passes, ADR-011) — including
    /// while auto-scans are stopped and in manual-only mode — and the
    /// machine is *running* until `cycle_finished`.
    pub fn manual_refresh(&mut self) -> SchedulerDecision {
        if self.running {
            return SchedulerDecision::AlreadyInProgress;
        }
        self.running = true;
        SchedulerDecision::StartCycle {
            trigger: Trigger::Manual,
            passes: Trigger::Manual.passes(),
        }
    }

    /// Reports that a cycle is running (the orchestrator's
    /// *cycle started* event, or an app-started cycle).
    ///
    /// Idempotent; a call while idle is tolerated — the machine then
    /// holds *running* so every ruling (already-in-progress,
    /// finish-anchoring) stays consistent with what it is told.
    pub fn cycle_started(&mut self) {
        self.running = true;
    }

    /// Reports that the cycle ended with `outcome` at `finished_at`,
    /// and re-anchors the auto cadence at that finish (ruling (a)).
    ///
    /// Streak per ruling (d): only `Failed` increments, `Complete` and
    /// `Partial` reset, `Cancelled` is neutral. When the streak reaches
    /// [`AUTO_STOP_AFTER_FAILURES`] the machine stops auto-scans
    /// entirely (ruling (c)) and returns the
    /// [`SchedulerDecision::AutoScansStopped`] notice; otherwise
    /// returns [`SchedulerDecision::None`]. The next auto attempt is
    /// due `finished_at + interval`, or `finished_at +
    /// max(interval, FAILURE_BACKOFF_FLOOR)` after a `Failed` cycle
    /// (ruling (b)); in manual-only mode and while stopped, never
    /// (rulings (f)/(c)).
    pub fn cycle_finished(
        &mut self,
        outcome: ScanOutcome,
        finished_at: Timestamp,
    ) -> SchedulerDecision {
        self.running = false;
        match outcome {
            ScanOutcome::Failed { .. } => {
                self.failure_streak = self.failure_streak.saturating_add(1)
            }
            ScanOutcome::Complete | ScanOutcome::Partial => self.failure_streak = 0,
            // Cancelled is neutral (ruling (d)).
            ScanOutcome::Cancelled => {}
        }
        let just_stopped = self.failure_streak >= AUTO_STOP_AFTER_FAILURES && !self.auto_stopped;
        if just_stopped {
            self.auto_stopped = true;
        }
        self.next_auto = if self.auto_stopped || self.interval.is_manual_only() {
            NextAuto::Never
        } else {
            let delay = match outcome {
                ScanOutcome::Failed { .. } => self.interval.interval().max(FAILURE_BACKOFF_FLOOR),
                ScanOutcome::Complete | ScanOutcome::Partial | ScanOutcome::Cancelled => {
                    self.interval.interval()
                }
            };
            NextAuto::At {
                anchor: finished_at,
                delay,
            }
        };
        if just_stopped {
            SchedulerDecision::AutoScansStopped
        } else {
            SchedulerDecision::None
        }
    }

    /// Whether a cycle is running (idle-with-next-auto-due otherwise).
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Whether auto-scans have stopped after three consecutive
    /// failures (ruling (c); sticky — see the module docs).
    pub fn auto_scans_stopped(&self) -> bool {
        self.auto_stopped
    }

    /// The current consecutive-failure streak (ruling (d)).
    pub fn failure_streak(&self) -> u32 {
        self.failure_streak
    }

    /// The configured interval (`Duration::ZERO` = manual-only).
    pub fn interval(&self) -> Duration {
        self.interval.interval()
    }

    /// How long until the next automatic cycle is due, as seen at
    /// `now` — the event loop's `recv_timeout` input (plan §8.4).
    ///
    /// `Some(Duration::ZERO)` means due right now; `None` means no
    /// auto deadline exists (a cycle is running — the next anchor
    /// comes at its finish — auto-scans are stopped, or the interval
    /// is manual-only).
    pub fn next_auto_in(&self, now: Timestamp) -> Option<Duration> {
        if self.running {
            return None;
        }
        match self.next_auto {
            NextAuto::Immediately => Some(Duration::ZERO),
            NextAuto::At { anchor, delay } => {
                let elapsed = now.mono().saturating_duration_since(anchor.mono());
                Some(delay.saturating_sub(elapsed))
            }
            NextAuto::Never => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::model::Clock;
    use crate::model::FakeClock;

    /// A local LCG twin of `model::testing::Lcg` whose draws come from
    /// the **high bits** (`(next_u64() >> 32) % n`) — the T-203
    /// follow-up note (assigned to T-404) documents that the shared
    /// helper's low-bit `% n` draws have short periods; the T-203 fuzz
    /// harnesses already use the high-bit form and this suite follows
    /// them (task card §3.5: "LCG, high-bit draws as in T-203's
    /// fuzzers").
    struct Lcg(u64);

    impl Lcg {
        fn seeded(seed: u64) -> Self {
            Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn next_below(&mut self, n: u64) -> u64 {
            (self.next_u64() >> 32) % n
        }
    }

    /// A clock advanced to a session-relative second (deterministic,
    /// readable scenario times). Each call builds its own `FakeClock`,
    /// whose monotonic base is real `Instant::now()` — two calls differ
    /// by microseconds of real time. That is harmless for due-ness
    /// comparisons (the drift only adds elapsed time, well under any
    /// 1 s margin), but exact remaining-time assertions need
    /// [`Scenario`]'s single shared clock.
    fn at(second: u64) -> Timestamp {
        let mut clock = FakeClock::new();
        clock.advance(Duration::from_secs(second));
        clock.now()
    }

    /// One shared `FakeClock` for a whole scenario, advanced forward
    /// in whole seconds — exact for remaining-time assertions.
    struct Scenario {
        clock: FakeClock,
        second: u64,
    }

    impl Scenario {
        fn new() -> Self {
            Scenario {
                clock: FakeClock::new(),
                second: 0,
            }
        }

        /// Advances (forward only) to `second` and returns the
        /// timestamp.
        fn at(&mut self, second: u64) -> Timestamp {
            assert!(second >= self.second, "scenario time must not go backwards");
            self.clock
                .advance(Duration::from_secs(second - self.second));
            self.second = second;
            self.clock.now()
        }
    }

    fn failed() -> ScanOutcome {
        ScanOutcome::Failed {
            reason: "synthetic failure".to_owned(),
        }
    }

    fn start_of(decision: SchedulerDecision) -> Option<Trigger> {
        match decision {
            SchedulerDecision::StartCycle { trigger, .. } => Some(trigger),
            other => {
                assert_eq!(other, SchedulerDecision::None, "expected a start decision");
                None
            }
        }
    }

    // ---- configuration (AC-2: interval validation) ------------------------

    #[test]
    fn interval_validation_table() {
        // 0 = manual-only is valid; 1..=14 s is rejected with the
        // typed error; 15 s and above are valid; the default is 60 s.
        let rejected: [Duration; 6] = [
            Duration::from_secs(1),
            Duration::from_secs(7),
            Duration::from_secs(14),
            Duration::from_millis(14_999),
            Duration::from_nanos(1),
            Duration::from_millis(500),
        ];
        for found in rejected {
            let err = RediscoveryInterval::new(found)
                .expect_err("sub-15 s non-zero intervals are rejected");
            assert_eq!(
                err,
                SchedulerError::IntervalTooShort {
                    found,
                    minimum: Duration::from_secs(15),
                },
                "typed error for {found:?}"
            );
            assert_eq!(
                err.to_string(),
                format!(
                    "the rediscovery interval must be 0 (manual only) or at least {:?}, found {:?}",
                    Duration::from_secs(15),
                    found
                )
            );
        }
        let zero = RediscoveryInterval::new(Duration::ZERO).expect("0 is manual-only");
        assert!(zero.is_manual_only());
        assert_eq!(zero.interval(), Duration::ZERO);
        let fifteen = RediscoveryInterval::new(Duration::from_secs(15)).expect("15 s is valid");
        assert!(!fifteen.is_manual_only());
        let sixty = RediscoveryInterval::new(Duration::from_secs(60)).expect("60 s is valid");
        assert_eq!(sixty, RediscoveryInterval::default());
        assert_eq!(
            RediscoveryInterval::default().interval(),
            DEFAULT_REDISCOVERY_INTERVAL
        );
        assert_eq!(
            RediscoveryInterval::manual_only(),
            RediscoveryInterval::new(Duration::ZERO).expect("valid")
        );
    }

    #[test]
    fn adr011_policy_constants_are_pinned() {
        // The one authoritative home of the pass policy (task card
        // §3.2): 2 passes initial/manual, 1 pass periodic, 100 pps,
        // 1.5 s listen window (ADR-011).
        assert_eq!(PASSES_INITIAL_AND_MANUAL, 2);
        assert_eq!(PASSES_PERIODIC, 1);
        assert_eq!(DEFAULT_RATE_PPS, 100);
        assert_eq!(DEFAULT_LISTEN_WINDOW, Duration::from_millis(1_500));
        assert_eq!(Trigger::Initial.passes(), 2);
        assert_eq!(Trigger::Manual.passes(), 2);
        assert_eq!(Trigger::Periodic.passes(), 1);
        assert_eq!(AUTO_STOP_AFTER_FAILURES, 3);
        assert_eq!(FAILURE_BACKOFF_FLOOR, Duration::from_secs(30));
        assert_eq!(MIN_REDISCOVERY_INTERVAL, Duration::from_secs(15));
    }

    // ---- cadence (AC-2: default cadence anchored at finish) ---------------

    #[test]
    fn default_cadence_is_anchored_at_finish() {
        let mut t = Scenario::new();
        let mut scheduler = DiscoveryScheduler::new(RediscoveryInterval::default());
        // Fresh session: the initial cycle is due immediately.
        assert_eq!(scheduler.next_auto_in(t.at(0)), Some(Duration::ZERO));
        let decision = scheduler.poll(t.at(5));
        assert_eq!(
            decision,
            SchedulerDecision::StartCycle {
                trigger: Trigger::Initial,
                passes: 2,
            }
        );
        assert!(scheduler.is_running());
        // Never a second start while running (AC-9's core rule).
        assert_eq!(scheduler.poll(t.at(6)), SchedulerDecision::None);
        assert_eq!(scheduler.next_auto_in(t.at(6)), None);
        // The cycle runs 5..=25 and finishes at t = 25: the next auto
        // cycle is due at 25 + 60 = 85 (anchored at FINISH — not at the
        // start at 5, which would be 65).
        scheduler.cycle_started();
        assert_eq!(
            scheduler.cycle_finished(ScanOutcome::Complete, t.at(25)),
            SchedulerDecision::None
        );
        assert!(!scheduler.is_running());
        assert_eq!(
            scheduler.next_auto_in(t.at(84)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(start_of(scheduler.poll(t.at(84))), None, "not due yet");
        assert_eq!(
            scheduler.poll(t.at(85)),
            SchedulerDecision::StartCycle {
                trigger: Trigger::Periodic,
                passes: 1,
            }
        );
    }

    #[test]
    fn fresh_manual_cycle_consumes_the_initial_slot_and_re_anchors() {
        // Ruling (e): a manual refresh at startup starts (2 passes);
        // when it finishes, the auto timer re-anchors from its finish
        // and the next auto cycle is periodic.
        let mut scheduler = DiscoveryScheduler::new(RediscoveryInterval::default());
        assert_eq!(
            scheduler.manual_refresh(),
            SchedulerDecision::StartCycle {
                trigger: Trigger::Manual,
                passes: 2,
            }
        );
        assert_eq!(
            scheduler.cycle_finished(ScanOutcome::Complete, at(10)),
            SchedulerDecision::None
        );
        assert_eq!(start_of(scheduler.poll(at(69))), None, "not due yet");
        assert_eq!(
            scheduler.poll(at(70)),
            SchedulerDecision::StartCycle {
                trigger: Trigger::Periodic,
                passes: 1,
            }
        );
    }

    // ---- failure backoff (AC-2: max(interval, 30 s)) ----------------------

    #[test]
    fn failure_backoff_table() {
        // (interval, expected delay after a Failed finish)
        let table: [(Duration, Duration); 4] = [
            (Duration::from_secs(15), Duration::from_secs(30)), // floor wins
            (Duration::from_secs(29), Duration::from_secs(30)), // floor wins
            (Duration::from_secs(30), Duration::from_secs(30)), // equal
            (Duration::from_secs(60), Duration::from_secs(60)), // interval wins
        ];
        for (interval, expected) in table {
            let mut scheduler =
                DiscoveryScheduler::new(RediscoveryInterval::new(interval).expect("valid"));
            // Run the initial cycle to get past the fresh state.
            assert_eq!(start_of(scheduler.poll(at(0))), Some(Trigger::Initial));
            assert_eq!(
                scheduler.cycle_finished(failed(), at(100)),
                SchedulerDecision::None,
                "one failure is only a streak of 1"
            );
            let before = expected.saturating_sub(Duration::from_secs(1));
            assert_eq!(
                start_of(scheduler.poll(at(100 + before.as_secs()))),
                None,
                "backoff not over for interval {interval:?}"
            );
            assert_eq!(
                start_of(scheduler.poll(at(100 + expected.as_secs()))),
                Some(Trigger::Periodic),
                "backoff over for interval {interval:?}"
            );
        }
    }

    #[test]
    fn backoff_applies_to_the_next_attempt_only() {
        // After the backoff-anchored attempt completes normally, the
        // cadence returns to the plain interval (ruling (b) delays one
        // attempt; it does not stretch every later one).
        let mut scheduler = DiscoveryScheduler::new(
            RediscoveryInterval::new(Duration::from_secs(15)).expect("15 s"),
        );
        assert_eq!(start_of(scheduler.poll(at(0))), Some(Trigger::Initial));
        scheduler.cycle_finished(failed(), at(1_000));
        // Backoff: due at 1030, not 1015.
        assert_eq!(start_of(scheduler.poll(at(1_029))), None);
        assert_eq!(start_of(scheduler.poll(at(1_030))), Some(Trigger::Periodic));
        scheduler.cycle_finished(ScanOutcome::Complete, at(1_031));
        // Plain cadence again: due at 1046.
        assert_eq!(start_of(scheduler.poll(at(1_045))), None);
        assert_eq!(start_of(scheduler.poll(at(1_046))), Some(Trigger::Periodic));
    }

    // ---- auto-stop (AC-2: three consecutive failures stop auto-scans) ----

    #[test]
    fn three_consecutive_failures_stop_auto_scans_with_the_typed_notice() {
        let mut scheduler = DiscoveryScheduler::new(
            RediscoveryInterval::new(Duration::from_secs(15)).expect("valid"),
        );
        assert_eq!(start_of(scheduler.poll(at(0))), Some(Trigger::Initial));
        // Failure 1: streak 1, backoff 30 s, no notice.
        assert_eq!(
            scheduler.cycle_finished(failed(), at(100)),
            SchedulerDecision::None
        );
        assert_eq!(scheduler.failure_streak(), 1);
        // Failure 2 at 130 (after the 30 s backoff).
        assert_eq!(start_of(scheduler.poll(at(130))), Some(Trigger::Periodic));
        assert_eq!(
            scheduler.cycle_finished(failed(), at(131)),
            SchedulerDecision::None
        );
        assert_eq!(scheduler.failure_streak(), 2);
        // Failure 3: the typed notice fires and auto-scans stop.
        assert_eq!(start_of(scheduler.poll(at(161))), Some(Trigger::Periodic));
        assert_eq!(
            scheduler.cycle_finished(failed(), at(162)),
            SchedulerDecision::AutoScansStopped
        );
        assert!(scheduler.auto_scans_stopped());
        assert_eq!(scheduler.failure_streak(), 3);
        assert_eq!(scheduler.next_auto_in(at(1_000)), None);
        // Auto stays stopped even far past any deadline.
        assert_eq!(scheduler.poll(at(10_000)), SchedulerDecision::None);
        // Manual refresh remains allowed (2 passes) — ruling (e).
        assert_eq!(
            scheduler.manual_refresh(),
            SchedulerDecision::StartCycle {
                trigger: Trigger::Manual,
                passes: 2,
            }
        );
    }

    #[test]
    fn the_stop_is_sticky_across_a_later_manual_success() {
        // Interpretation recorded in the module docs and the execution
        // report: a manual Complete resets the streak (ruling (d)) but
        // does not silently resume auto-scans.
        let mut scheduler = DiscoveryScheduler::new(
            RediscoveryInterval::new(Duration::from_secs(15)).expect("valid"),
        );
        // Initial cycle fails: streak 1.
        assert_eq!(start_of(scheduler.poll(at(0))), Some(Trigger::Initial));
        assert_eq!(
            scheduler.cycle_finished(failed(), at(100)),
            SchedulerDecision::None
        );
        // Backoff (30 s): the next auto attempt fails at 131 — streak 2.
        assert_eq!(start_of(scheduler.poll(at(130))), Some(Trigger::Periodic));
        assert_eq!(
            scheduler.cycle_finished(failed(), at(131)),
            SchedulerDecision::None
        );
        // Third consecutive failure at 162: the stop + notice.
        assert_eq!(start_of(scheduler.poll(at(161))), Some(Trigger::Periodic));
        assert_eq!(
            scheduler.cycle_finished(failed(), at(162)),
            SchedulerDecision::AutoScansStopped
        );
        // A manual success resets the streak but auto stays stopped.
        assert_eq!(start_of(scheduler.manual_refresh()), Some(Trigger::Manual));
        assert_eq!(
            scheduler.cycle_finished(ScanOutcome::Complete, at(200)),
            SchedulerDecision::None
        );
        assert_eq!(scheduler.failure_streak(), 0);
        assert!(scheduler.auto_scans_stopped());
        assert_eq!(scheduler.poll(at(100_000)), SchedulerDecision::None);
        assert_eq!(scheduler.next_auto_in(at(100_000)), None);
    }

    // ---- streak semantics (AC-2: ruling (d)) ------------------------------

    #[test]
    fn streak_semantics_table() {
        // (outcome sequence, expected final streak)
        let table: [(Vec<ScanOutcome>, u32); 7] = [
            (vec![], 0),
            (vec![failed()], 1),
            (vec![failed(), failed()], 2),
            (vec![failed(), failed(), failed()], AUTO_STOP_AFTER_FAILURES),
            // Complete resets.
            (vec![failed(), ScanOutcome::Complete], 0),
            // Partial resets.
            (vec![failed(), failed(), ScanOutcome::Partial], 0),
            // Cancelled is neutral: it neither increments nor resets.
            (vec![failed(), ScanOutcome::Cancelled], 1),
        ];
        for (sequence, expected) in table {
            let mut scheduler = DiscoveryScheduler::new(
                RediscoveryInterval::new(Duration::from_secs(15)).expect("valid"),
            );
            let mut t = 0;
            let mut notice_count = 0;
            for outcome in &sequence {
                // Every cycle begins from a start decision (auto where
                // one is due or allowed, manual otherwise — e.g. while
                // auto-scans are stopped) so the machine is running
                // when it finishes.
                if !scheduler.is_running() {
                    let decision = match scheduler.poll(at(t)) {
                        SchedulerDecision::None => scheduler.manual_refresh(),
                        started => started,
                    };
                    assert!(
                        start_of(decision).is_some(),
                        "the harness always manages to start a cycle"
                    );
                }
                t += 1;
                if let SchedulerDecision::AutoScansStopped =
                    scheduler.cycle_finished(outcome.clone(), at(t))
                {
                    notice_count += 1;
                }
            }
            assert_eq!(scheduler.failure_streak(), expected, "after {sequence:?}");
            // The notice fires exactly when the streak first reaches 3.
            let stopped = expected >= AUTO_STOP_AFTER_FAILURES;
            assert_eq!(scheduler.auto_scans_stopped(), stopped);
            assert_eq!(notice_count, if stopped { 1 } else { 0 });
        }
    }

    #[test]
    fn cancelled_cycles_do_not_break_a_failure_streak() {
        // Fail, cancel, fail, cancel, fail: still three consecutive
        // failures in the ruling's sense — the auto-stop fires.
        let mut scheduler = DiscoveryScheduler::new(
            RediscoveryInterval::new(Duration::from_secs(15)).expect("valid"),
        );
        assert_eq!(start_of(scheduler.poll(at(0))), Some(Trigger::Initial));
        let _ = scheduler.cycle_finished(failed(), at(1));
        assert_eq!(start_of(scheduler.poll(at(31))), Some(Trigger::Periodic));
        let _ = scheduler.cycle_finished(ScanOutcome::Cancelled, at(32));
        assert_eq!(scheduler.failure_streak(), 1);
        assert_eq!(start_of(scheduler.poll(at(47))), Some(Trigger::Periodic));
        let _ = scheduler.cycle_finished(failed(), at(48));
        assert_eq!(start_of(scheduler.poll(at(78))), Some(Trigger::Periodic));
        let _ = scheduler.cycle_finished(ScanOutcome::Cancelled, at(79));
        assert_eq!(scheduler.failure_streak(), 2);
        assert_eq!(start_of(scheduler.poll(at(94))), Some(Trigger::Periodic));
        assert_eq!(
            scheduler.cycle_finished(failed(), at(95)),
            SchedulerDecision::AutoScansStopped
        );
    }

    // ---- manual refresh rules (AC-2: rulings (e)/(f), FR-DS-08) -----------

    #[test]
    fn manual_refresh_during_a_running_cycle_is_already_in_progress() {
        let mut scheduler = DiscoveryScheduler::new(RediscoveryInterval::default());
        assert_eq!(start_of(scheduler.poll(at(0))), Some(Trigger::Initial));
        // While running: typed already-in-progress, nothing queued —
        // when the running cycle finishes, no manual cycle materializes.
        assert_eq!(
            scheduler.manual_refresh(),
            SchedulerDecision::AlreadyInProgress
        );
        assert_eq!(
            scheduler.cycle_finished(ScanOutcome::Complete, at(5)),
            SchedulerDecision::None
        );
        // Nothing was queued: the next due is the auto cadence
        // (finish 5 + 60 = 65), and it is periodic, not manual.
        assert_eq!(start_of(scheduler.poll(at(64))), None);
        assert_eq!(start_of(scheduler.poll(at(65))), Some(Trigger::Periodic));
    }

    #[test]
    fn manual_only_mode_never_auto_starts_but_failure_rules_apply() {
        // Ruling (f): interval 0 → poll never issues auto starts; the
        // failure rules still apply.
        let mut scheduler = DiscoveryScheduler::new(RediscoveryInterval::manual_only());
        assert_eq!(scheduler.poll(at(0)), SchedulerDecision::None);
        assert_eq!(scheduler.poll(at(10_000)), SchedulerDecision::None);
        assert_eq!(scheduler.next_auto_in(at(0)), None);
        // Manual cycles run (2 passes) and their outcomes count.
        assert_eq!(
            scheduler.manual_refresh(),
            SchedulerDecision::StartCycle {
                trigger: Trigger::Manual,
                passes: 2,
            }
        );
        assert_eq!(
            scheduler.cycle_finished(failed(), at(1)),
            SchedulerDecision::None
        );
        assert_eq!(scheduler.failure_streak(), 1);
        assert_eq!(
            scheduler.poll(at(10_000)),
            SchedulerDecision::None,
            "still no auto"
        );
        // Three consecutive manual failures still produce the notice.
        for _ in 0..2 {
            assert_eq!(start_of(scheduler.manual_refresh()), Some(Trigger::Manual));
            let _ = scheduler.cycle_finished(failed(), at(2));
        }
        // The third failure above reached the streak of 3? No: the
        // first failure plus two more = 3 → the notice fired on the
        // last one; capture it precisely in a clean machine instead:
        let mut stopped = DiscoveryScheduler::new(RediscoveryInterval::manual_only());
        let mut notices = 0;
        for _ in 0..3 {
            assert_eq!(start_of(stopped.manual_refresh()), Some(Trigger::Manual));
            if let SchedulerDecision::AutoScansStopped = stopped.cycle_finished(failed(), at(3)) {
                notices += 1;
            }
        }
        assert_eq!(notices, 1);
        assert!(stopped.auto_scans_stopped());
        // Manual refresh is still allowed while stopped.
        assert_eq!(start_of(stopped.manual_refresh()), Some(Trigger::Manual));
    }

    #[test]
    fn cycle_started_is_idempotent_and_tolerated_from_idle() {
        let mut scheduler = DiscoveryScheduler::new(RediscoveryInterval::default());
        // From idle: tolerated — the machine holds running so the
        // rulings stay consistent with what it is told.
        scheduler.cycle_started();
        assert!(scheduler.is_running());
        assert_eq!(scheduler.poll(at(0)), SchedulerDecision::None);
        assert_eq!(
            scheduler.manual_refresh(),
            SchedulerDecision::AlreadyInProgress
        );
        // And it resolves through cycle_finished as usual: the finish
        // re-anchors the auto cadence (due 1 + 60 = 61, periodic).
        assert_eq!(
            scheduler.cycle_finished(ScanOutcome::Complete, at(1)),
            SchedulerDecision::None
        );
        assert!(!scheduler.is_running());
        assert_eq!(
            start_of(scheduler.poll(at(2))),
            None,
            "anchored at the finish"
        );
        assert_eq!(start_of(scheduler.poll(at(61))), Some(Trigger::Periodic));
        // Double-reporting a start while running changes nothing.
        scheduler.cycle_started();
        scheduler.cycle_started();
        assert!(scheduler.is_running());
        assert_eq!(scheduler.poll(at(62)), SchedulerDecision::None);
        assert_eq!(
            scheduler.manual_refresh(),
            SchedulerDecision::AlreadyInProgress
        );
    }

    #[test]
    fn next_auto_in_reports_the_remaining_time() {
        let mut t = Scenario::new();
        let mut scheduler = DiscoveryScheduler::new(RediscoveryInterval::default());
        assert_eq!(scheduler.next_auto_in(t.at(0)), Some(Duration::ZERO));
        assert_eq!(start_of(scheduler.poll(t.at(0))), Some(Trigger::Initial));
        // Running: no pending auto deadline.
        assert_eq!(scheduler.next_auto_in(t.at(1)), None);
        let _ = scheduler.cycle_finished(ScanOutcome::Complete, t.at(10));
        assert_eq!(
            scheduler.next_auto_in(t.at(10)),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            scheduler.next_auto_in(t.at(40)),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            scheduler.next_auto_in(t.at(69)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(scheduler.next_auto_in(t.at(70)), Some(Duration::ZERO));
        assert_eq!(scheduler.next_auto_in(t.at(1_000)), Some(Duration::ZERO));
    }

    // ---- property test (AC-9) ---------------------------------------------

    /// Across arbitrary well-formed event sequences: no auto start
    /// while running; every auto start respects the finish anchor plus
    /// the ruling (a)/(b) delay; the auto-stop notice only after three
    /// consecutive failures; once stopped, never an auto start again.
    #[test]
    fn property_scheduler_is_consistent_across_random_sequences() {
        for seed in [0x2045_eed1_u64, 0x2045_eed2_u64] {
            let mut rng = Lcg::seeded(seed);
            let mut clock = FakeClock::new();
            let interval = Duration::from_secs(15 + rng.next_below(46)); // 15..=60 s
            let mut scheduler =
                DiscoveryScheduler::new(RediscoveryInterval::new(interval).expect("valid"));
            // Protocol shadow: what the harness knows about the cycle
            // lifecycle (started ⇔ the machine is running). The
            // deterministic opening below performs the first finish
            // (clearing the shadow) before the walk reads it.
            let mut running;
            let mut last: Option<(ScanOutcome, Timestamp)>; // the last finish
            let mut stopped = false;
            let mut auto_starts = 0u64;

            // Deterministic opening (non-vacuity): the fresh machine
            // issues the initial auto cycle on the first poll, which
            // then finishes with a random outcome.
            let decision = scheduler.poll(clock.now());
            assert_eq!(
                decision,
                SchedulerDecision::StartCycle {
                    trigger: Trigger::Initial,
                    passes: 2,
                },
                "fresh machine (seed {seed})"
            );
            // The shadow stays false across the opening's fixed
            // poll→finish sequence (nothing runs concurrently); the
            // walk below keeps it in lockstep from here on.
            auto_starts += 1;
            clock.advance(Duration::from_secs(rng.next_below(91)));
            let opening_outcome = match rng.next_below(4) {
                0 => ScanOutcome::Complete,
                1 => ScanOutcome::Partial,
                2 => ScanOutcome::Cancelled,
                _ => failed(),
            };
            assert_eq!(
                scheduler.cycle_finished(opening_outcome.clone(), clock.now()),
                SchedulerDecision::None,
                "one failure is never the auto-stop (seed {seed})"
            );
            running = false;
            last = Some((opening_outcome, clock.now()));

            for _ in 0..20_000 {
                // Advance time by a random 0..=90 s (always forward).
                clock.advance(Duration::from_secs(rng.next_below(91)));
                let now = clock.now();
                match rng.next_below(4) {
                    0 => {
                        let decision = scheduler.poll(now);
                        match decision {
                            SchedulerDecision::StartCycle { trigger, passes } => {
                                assert!(!running, "auto start while running (seed {seed})");
                                assert!(!stopped, "auto start while stopped (seed {seed})");
                                if let Some((outcome, finished_at)) = last.as_ref() {
                                    let delay = match outcome {
                                        ScanOutcome::Failed { .. } => {
                                            interval.max(FAILURE_BACKOFF_FLOOR)
                                        }
                                        _ => interval,
                                    };
                                    let elapsed =
                                        now.mono().saturating_duration_since(finished_at.mono());
                                    assert!(
                                        elapsed >= delay,
                                        "auto start {elapsed:?} after a finish that anchors \
                                         +{delay:?} (seed {seed})"
                                    );
                                } else {
                                    // Fresh session: the first auto cycle is Initial.
                                    assert_eq!(trigger, Trigger::Initial, "seed {seed}");
                                }
                                assert_eq!(passes, trigger.passes(), "seed {seed}");
                                running = true;
                                auto_starts += 1;
                            }
                            SchedulerDecision::None => {}
                            other => panic!("poll returned {other:?} (seed {seed})"),
                        }
                    }
                    1 => {
                        let decision = scheduler.manual_refresh();
                        match decision {
                            SchedulerDecision::StartCycle { trigger, passes } => {
                                assert!(!running, "manual start while running (seed {seed})");
                                assert_eq!(trigger, Trigger::Manual, "seed {seed}");
                                assert_eq!(passes, 2, "seed {seed}");
                                running = true;
                            }
                            SchedulerDecision::AlreadyInProgress => {
                                assert!(
                                    running,
                                    "already-in-progress without a cycle (seed {seed})"
                                );
                            }
                            other => panic!("manual_refresh returned {other:?} (seed {seed})"),
                        }
                    }
                    2 => {
                        // cycle_started: idempotent, only meaningful
                        // while running in well-formed sequences.
                        if running {
                            scheduler.cycle_started();
                        }
                    }
                    _ => {
                        if running {
                            let outcome = match rng.next_below(4) {
                                0 => ScanOutcome::Complete,
                                1 => ScanOutcome::Partial,
                                2 => ScanOutcome::Cancelled,
                                _ => failed(),
                            };
                            let decision = scheduler.cycle_finished(outcome.clone(), now);
                            running = false;
                            last = Some((outcome, now));
                            match decision {
                                SchedulerDecision::None => {}
                                SchedulerDecision::AutoScansStopped => {
                                    assert!(!stopped, "notice repeated (seed {seed})");
                                    assert_eq!(
                                        scheduler.failure_streak(),
                                        AUTO_STOP_AFTER_FAILURES,
                                        "notice before three consecutive failures (seed {seed})"
                                    );
                                    stopped = true;
                                }
                                other => panic!("cycle_finished returned {other:?} (seed {seed})"),
                            }
                            assert_eq!(
                                scheduler.auto_scans_stopped(),
                                stopped,
                                "stop state diverged (seed {seed})"
                            );
                        }
                    }
                }
                assert_eq!(scheduler.is_running(), running, "seed {seed}");
            }
            // Non-vacuity: a 20,000-step random walk must have issued
            // auto starts (the initial cycle alone guarantees ≥ 1 when
            // not stopped at once; the sequences mix outcomes).
            assert!(auto_starts >= 1, "no auto start ever issued (seed {seed})");
        }
    }
}
