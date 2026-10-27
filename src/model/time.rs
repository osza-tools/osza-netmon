// SPDX-License-Identifier: GPL-3.0-only

//! Time abstraction: [`Timestamp`], the [`Clock`] trait, and the
//! [`SystemClock`] / [`FakeClock`] implementations (plan §5.2, §8.6,
//! FR-RG-05, task T-002).
//!
//! A [`Timestamp`] pairs a monotonic [`Instant`] ("mono", for measuring
//! intervals and aging logic) with a wall-clock [`SystemTime`] ("wall",
//! for display only). All product code takes its time from an injected
//! [`Clock`] — never from direct `Instant::now()` calls — so tests drive
//! time deterministically with [`FakeClock`] and never sleep (FR-RG-05,
//! plan §11.4).

use std::time::{Duration, Instant, SystemTime};

/// A point in time: monotonic for logic, wall-clock for display
/// (plan §5.2).
///
/// Constructible only through a [`Clock`]; the fields are private and the
/// two clocks in this module are the only producers. `Timestamp` is
/// `Copy`, so passing it around is free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    mono: Instant,
    wall: SystemTime,
}

impl Timestamp {
    /// The monotonic reading (interval math, aging, deadlines).
    pub fn mono(&self) -> Instant {
        self.mono
    }

    /// The wall-clock reading (display only; may jump under system clock
    /// adjustments, which is why logic uses [`mono`](Self::mono)).
    pub fn wall(&self) -> SystemTime {
        self.wall
    }
}

/// Source of "now" for all product code (plan §8.6).
///
/// Production code uses [`SystemClock`]; tests use [`FakeClock`]. The
/// trait is object-safe, so a `&dyn Clock` can be injected anywhere.
pub trait Clock {
    /// The current [`Timestamp`].
    fn now(&self) -> Timestamp;
}

/// Production clock: both readings taken from the operating system.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp {
            mono: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

/// Deterministic test clock (plan §11.4: "No `sleep`-based timing in unit
/// tests; use the injected clock").
///
/// The wall reading starts at the Unix epoch and advances only through
/// [`advance`](Self::advance), so tests get exact, reproducible wall times;
/// the mono reading starts at real `Instant::now()` (the only way to
/// obtain an `Instant`) and advances by the same deltas, so duration
/// arithmetic behaves exactly as in production.
#[derive(Debug, Clone)]
pub struct FakeClock {
    current: Timestamp,
}

impl FakeClock {
    /// A clock frozen at wall time `1970-01-01T00:00:00Z`.
    pub fn new() -> Self {
        FakeClock {
            current: Timestamp {
                mono: Instant::now(),
                wall: SystemTime::UNIX_EPOCH,
            },
        }
    }

    /// Moves the clock forward by `delta` (both readings).
    ///
    /// Saturating semantics on the wall reading (`SystemTime` arithmetic
    /// saturates by design); negative deltas are not representable through
    /// this API.
    pub fn advance(&mut self, delta: Duration) {
        self.current.mono += delta;
        self.current.wall += delta;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_is_frozen_until_advanced() {
        let mut clock = FakeClock::new();
        let first = clock.now();
        let second = clock.now();
        assert_eq!(first, second, "no time passes between reads");

        clock.advance(Duration::from_secs(5));
        let third = clock.now();
        assert_ne!(first, third);
        // Monotonic reading advanced by exactly the delta.
        assert_eq!(
            third.mono().duration_since(first.mono()),
            Duration::from_secs(5)
        );
        // Wall reading advanced by the same delta, from the Unix epoch.
        assert_eq!(
            third
                .wall()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("after epoch"),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn fake_clock_accumulates_deltas() {
        let mut clock = FakeClock::new();
        let start = clock.now();
        clock.advance(Duration::from_millis(1500));
        clock.advance(Duration::from_millis(500));
        let end = clock.now();
        assert_eq!(
            end.mono().duration_since(start.mono()),
            Duration::from_secs(2)
        );
        assert_eq!(
            end.wall()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("after epoch"),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn fake_clock_wall_starts_at_unix_epoch() {
        let clock = FakeClock::new();
        assert_eq!(clock.now().wall(), SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn system_clock_never_moves_backwards_on_the_mono_reading() {
        let clock = SystemClock;
        let first = clock.now();
        let second = clock.now();
        assert!(second.mono() >= first.mono());
        // Wall time is for display only; no ordering is asserted for it.
    }

    #[test]
    fn clocks_are_usable_through_the_trait_and_trait_objects() {
        fn read_two<C: Clock>(clock: &C) -> (Timestamp, Timestamp) {
            (clock.now(), clock.now())
        }
        // Generic use: the frozen fake returns identical readings.
        let mut fake = FakeClock::new();
        let (a, b) = read_two(&fake);
        assert_eq!(a, b);
        fake.advance(Duration::from_secs(1));
        let c = fake.now();
        assert!(c.mono() >= b.mono());
        assert_ne!(a, c);

        // Generic use: the system clock still reads monotonic non-decreasing.
        let (s1, s2) = read_two(&SystemClock);
        assert!(s2.mono() >= s1.mono());

        // Object safety: the trait can be used as &dyn Clock.
        let dyn_clock: &dyn Clock = &fake;
        assert_eq!(dyn_clock.now(), fake.now());
    }

    /// The card asks for the date 2026-10-28 where a timestamp is needed:
    /// advancing the fake clock to `2026-10-28T00:00:00Z` (Unix seconds
    /// 1793145600) must land exactly on that civil date, verified with a
    /// self-contained epoch-to-civil conversion (Howard Hinnant's
    /// `civil_from_days` algorithm, std-only).
    #[test]
    fn fake_clock_reaches_2026_10_28_exactly() {
        const TARGET: Duration = Duration::from_secs(1_793_145_600); // 2026-10-28T00:00:00Z
        let mut clock = FakeClock::new();
        clock.advance(TARGET);
        let wall = clock.now().wall();
        let secs = wall
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs();

        // civil_from_days: days since 1970-01-01 -> (year, month, day).
        let days = (secs / 86_400) as i64;
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };

        assert_eq!((y, m, d), (2026, 10, 28));
        assert_eq!(secs % 86_400, 0); // midnight UTC
    }
}
