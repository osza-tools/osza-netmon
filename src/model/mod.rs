// SPDX-License-Identifier: GPL-3.0-only

//! Domain model: the boundary-validated core primitives (plan §5.2–5.3,
//! task T-002).
//!
//! The types in this module sit exactly on the boundary between hostile
//! external input (packets, `/proc` content, DNS answers, vendor data)
//! and the safe internal model. Everything downstream — registry,
//! enrichment, UI — consumes these validated types instead of raw strings
//! and octets (FR-EN-04, SR-04).
//!
//! * [`mac::MacAddr`] — validated unicast sender MAC.
//! * [`text::Hostname`] / [`text::DisplayText`] — validated / sanitized text.
//! * [`field::Field`] — the Known / Pending / Unknown / Unavailable state.
//! * [`time::Timestamp`] / [`time::Clock`] — injectable time.
//! * [`ipv4`] — private / link-local / CGNAT classification and
//!   [`ipv4::Ipv4Net`] subnet math with host-cap enforcement.

pub mod field;
pub mod ipv4;
pub mod mac;
pub mod text;
pub mod time;

pub use field::{Field, Reason, Source};
pub use ipv4::{
    ABSOLUTE_MAX_HOSTS, DEFAULT_MAX_HOSTS, HostRange, Ipv4Net, Ipv4NetError, is_cgnat,
    is_link_local, is_private,
};
pub use mac::{MacAddr, MacAddrParseError};
pub use text::{
    DISPLAY_TEXT_MAX_CHARS, DisplayText, HOSTNAME_MAX_CHARS, Hostname, ValidationError,
};
pub use time::{Clock, FakeClock, SystemClock, Timestamp};

/// Minimal deterministic pseudo-random generator for the property-style
/// tests of this module (task T-002).
///
/// The task card allows only `std` + `thiserror` and requires a Plan
/// Question before adding `proptest` as a dev-dependency; until that
/// approval exists, the property tests use this small splitmix-style LCG
/// (test-only, deterministic seeds, no `unsafe`), which exercises the
/// same never-panic / round-trip properties deterministically.
#[cfg(test)]
pub(crate) mod testing {
    /// A tiny linear-congruential generator (Knuth constants).
    ///
    /// Not cryptographic; not for production use. `n == 0` must not be
    /// passed to [`next_below`](Lcg::next_below).
    #[derive(Debug, Clone)]
    pub(crate) struct Lcg(u64);

    impl Lcg {
        /// Creates a generator from an explicit, reproducible seed.
        pub(crate) fn seeded(seed: u64) -> Self {
            Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
        }

        /// The next raw 64-bit value.
        pub(crate) fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        /// A value in `0..n` (`n > 0`). Slight modulo bias is acceptable
        /// for test data.
        pub(crate) fn next_below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }

        /// A random byte.
        pub(crate) fn next_u8(&mut self) -> u8 {
            (self.next_u64() >> 32) as u8
        }
    }
}

#[cfg(test)]
mod tests {
    //! The module re-exports are exercised by the per-submodule test
    //! suites; this suite checks the re-export surface itself.
    use super::*;

    #[test]
    fn re_exports_expose_the_full_model_surface() {
        // One representative construction per re-exported type, through
        // the re-exported names only (proves `model::*` is a usable API).
        let mac: MacAddr = "aa:bb:cc:dd:ee:ff".parse().expect("valid MAC");
        assert!(!mac.is_multicast());

        let host: Hostname = Hostname::try_from("router.lan").expect("valid hostname");
        assert_eq!(host.as_str(), "router.lan");

        let text: DisplayText =
            DisplayText::try_from("  Some Vendor \u{1b}[0m Name ").expect("sanitizes");
        assert_eq!(text.as_str(), "Some Vendor Name");

        let field: Field<u8> = Field::Known {
            value: 1,
            source: Source::NeighborTable,
        };
        assert!(field.is_known());
        let unavailable: Field<u8> = Field::Unavailable(Reason::Disabled);
        assert!(!unavailable.is_known());

        let mut clock = FakeClock::new();
        let before: Timestamp = clock.now();
        clock.advance(std::time::Duration::from_secs(1));
        assert!(clock.now().mono() >= before.mono());
        let _: &dyn Clock = &SystemClock;

        let net =
            Ipv4Net::new("192.168.1.1".parse().expect("valid IP"), 24).expect("valid network");
        assert_eq!(net.host_count(), 254);
        let range: HostRange = net.host_range().expect("under cap");
        assert_eq!(range.last().to_string(), "192.168.1.254");

        assert!(is_private("10.0.0.1".parse().expect("valid IP")));
        assert!(is_link_local("169.254.0.1".parse().expect("valid IP")));
        assert!(is_cgnat("100.64.0.1".parse().expect("valid IP")));

        // Error types are constructible only through the validating paths.
        assert_eq!("".parse::<MacAddr>().unwrap_err(), MacAddrParseError::Empty);
        assert_eq!(
            Hostname::try_from("").unwrap_err(),
            ValidationError::HostnameEmpty
        );
        assert_eq!(
            Ipv4Net::new("10.0.0.1".parse().expect("valid IP"), 33).unwrap_err(),
            Ipv4NetError::InvalidPrefix { found: 33 }
        );

        // The plan's cap constants are re-exported and match FR-SC-06.
        assert_eq!(DEFAULT_MAX_HOSTS, 1022);
        assert_eq!(ABSOLUTE_MAX_HOSTS, 65_534);
        assert_eq!(HOSTNAME_MAX_CHARS, 253);
        assert_eq!(DISPLAY_TEXT_MAX_CHARS, 64);
    }
}
