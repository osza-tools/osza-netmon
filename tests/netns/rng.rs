// SPDX-License-Identifier: GPL-3.0-only

//! Deterministic seeded RNG for the netns harness (task T-106).
//!
//! The impairment profiles of Appendix D (P1 loss, P2 loss + delay/jitter,
//! P3/S9 sleepy hosts) must be reproducible run to run, so the responder
//! draws every decision from a [`SplitMix64`] stream seeded with a value
//! recorded in the responder config, the receive log and the measurement
//! artifacts (plan §11.2 S8/S9; task card §5.11).
//!
//! The stream is consumed in a fixed order (ignore-first check, drop draw,
//! fraction draw, delay draw — one request at a time, arrival order), so a
//! given seed plus a given request sequence always produces the same
//! behavior. Wall-clock time never influences a decision.

/// SplitMix64: twenty lines of arithmetic, no dependency, good statistical
/// quality — the standard choice when a crate is not allowed (AGENTS.md
/// rule 3).
pub struct Rng {
    state: u64,
}

impl Rng {
    /// A new stream from `seed` (the seed is recorded wherever the stream
    /// is used).
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// The next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// The next value in `[0, 1)` with 53 bits of mantissa precision
    /// (the `f64` mapping of the integer stream).
    pub fn next_f64(&mut self) -> f64 {
        // Shift off the low 11 bits so the mantissa is exact; the divisor
        // is 2^53, representable exactly in f64.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// The next value in the inclusive integer range `[lo, hi]`
    /// (degenerate ranges return `lo`).
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.next_u64() % (hi - lo + 1)
    }

    /// `true` with probability `p` (clamped to `[0, 1]`).
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            false
        } else if p >= 1.0 {
            true
        } else {
            self.next_f64() < p
        }
    }
}

/// The seeds used by the scenario suite and the measurement matrix.
pub mod seeds {
    /// Scenario suite (S1–S7): one seed for the whole suite.
    pub const SCENARIOS: u64 = 0x0E2A_1061;

    /// Measurement matrix (S8/S9): the base seed; per-cell seeds are
    /// derived from it (`base + cell_index`) so every cell is reproducible
    /// on its own and the two consecutive measurement invocations use
    /// identical seeds (they measure determinism, not seed spread).
    pub const MEASURE_BASE: u64 = 0x7EED_1061;
}
