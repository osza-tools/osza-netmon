// SPDX-License-Identifier: GPL-3.0-only

//! Cycle and observation inputs: [`ScanId`], [`ScanOutcome`] and
//! [`Observation`] (plan §5.1, §8.5, FR-RG-03, task T-201).
//!
//! These are the registry's own view of a scan. The discovery layer
//! (T-103/T-104) has its own observation and outcome types; per the
//! dependency rules of plan §8.2 the registry must not import them, so
//! the application core (T-205) maps discovery events onto the types in
//! this module — the same mapping boundary agreed in Plan Question PQ-3
//! of the T-104 execution report.
//!
//! An [`Observation`] carries only boundary-validated model values
//! ([`MacAddr`], `Ipv4Addr`, [`Source`]): no raw network string ever
//! reaches the registry (task card §8).
//!
//! [`ScanId`] itself is defined in [`crate::model`] since T-204 (the
//! discovery layer's orchestrator stamps its events with it, and
//! `discovery` may not import `registry`, plan §8.2); this module
//! re-exports it unchanged so the registry's public API and the T-201
//! tests are untouched.

use std::fmt;

use crate::model::{MacAddr, Source};

pub use crate::model::ScanId;

/// How a scan cycle ended (plan §5.1).
///
/// Only [`ScanOutcome::Complete`] cycles age devices (ADR-007);
/// `Partial`, `Failed` and `Cancelled` never do. The registry does not
/// need — and therefore does not carry — the *reasons* behind a
/// `Partial` or `Failed` outcome: those details live in the discovery
/// layer's own event, where the application core (T-205) can still log
/// them while mapping to this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanOutcome {
    /// The cycle ran to the end without error; absent devices age.
    Complete,
    /// The cycle ran but something transient went wrong; no aging.
    Partial,
    /// The cycle failed; no aging.
    Failed,
    /// The cycle was cancelled; no aging.
    Cancelled,
}

impl ScanOutcome {
    /// `true` only for [`ScanOutcome::Complete`] — the one outcome that
    /// ages devices (ADR-007).
    pub const fn is_complete(self) -> bool {
        matches!(self, ScanOutcome::Complete)
    }
}

impl fmt::Display for ScanOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self {
            ScanOutcome::Complete => "complete",
            ScanOutcome::Partial => "partial",
            ScanOutcome::Failed => "failed",
            ScanOutcome::Cancelled => "cancelled",
        };
        f.write_str(word)
    }
}

/// One piece of evidence that `(MAC, IPv4)` exists on an interface at a
/// time, tagged with the scan cycle it came from (plan §5.1 "Observation",
/// FR-RG-03).
///
/// All field values arrive pre-validated by the model layer; the
/// registry trusts [`MacAddr`] (unicast, non-zero, non-broadcast) and
/// takes the interface index and address as-is. Observations tagged with
/// a [`ScanId`] other than the current cycle are ignored by
/// [`Registry::observe`](super::Registry::observe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Observation {
    /// The scan cycle this evidence belongs to.
    pub scan_id: ScanId,
    /// The interface the evidence was gathered on (part of the device
    /// identity, ADR-008).
    pub iface_index: u32,
    /// The validated sender MAC.
    pub mac: MacAddr,
    /// The observed IPv4 address.
    pub ip: std::net::Ipv4Addr,
    /// Where the evidence came from.
    pub source: Source,
}

impl Observation {
    /// Builds an observation from its five validated parts.
    pub const fn new(
        scan_id: ScanId,
        iface_index: u32,
        mac: MacAddr,
        ip: std::net::Ipv4Addr,
        source: Source,
    ) -> Self {
        Observation {
            scan_id,
            iface_index,
            mac,
            ip,
            source,
        }
    }
}

impl fmt::Display for Observation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "iface {} {} {} (scan {}, {})",
            self.iface_index,
            self.mac,
            self.ip,
            self.scan_id,
            source_label(self.source)
        )
    }
}

/// The factual source label used in the [`Observation`] display form
/// (plan §5.4 vocabulary; not a verdict).
const fn source_label(source: Source) -> &'static str {
    match source {
        Source::LocalInterface => "local interface",
        Source::NeighborTable => "neighbor table",
        Source::ArpReply => "arp reply",
        Source::ReverseDns => "reverse dns",
        Source::VendorDb => "vendor db",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(text: &str) -> MacAddr {
        text.parse().expect("valid MAC")
    }

    fn ip(text: &str) -> std::net::Ipv4Addr {
        text.parse().expect("valid IP")
    }

    #[test]
    fn scan_ids_compare_and_wrap_plain_counters() {
        let a = ScanId::new(7);
        let b = ScanId::from(8);
        assert_ne!(a, b);
        assert!(a < b);
        assert_eq!(a.as_u64(), 7);
        assert_eq!(b.to_string(), "8");
        assert_eq!(a, ScanId::new(7), "equality is by value");
    }

    #[test]
    fn only_complete_outcomes_age_devices() {
        assert!(ScanOutcome::Complete.is_complete());
        assert!(!ScanOutcome::Partial.is_complete());
        assert!(!ScanOutcome::Failed.is_complete());
        assert!(!ScanOutcome::Cancelled.is_complete());
        // The four outcomes are distinguishable by value.
        let all = [
            ScanOutcome::Complete,
            ScanOutcome::Partial,
            ScanOutcome::Failed,
            ScanOutcome::Cancelled,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(a == b, i == j);
            }
        }
    }

    #[test]
    fn outcome_display_words_are_factual() {
        assert_eq!(ScanOutcome::Complete.to_string(), "complete");
        assert_eq!(ScanOutcome::Partial.to_string(), "partial");
        assert_eq!(ScanOutcome::Failed.to_string(), "failed");
        assert_eq!(ScanOutcome::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn observations_carry_the_scan_tag_and_validated_parts() {
        let obs = Observation::new(
            ScanId::new(3),
            2,
            mac("aa:bb:cc:dd:ee:01"),
            ip("192.0.2.10"),
            Source::ArpReply,
        );
        assert_eq!(obs.scan_id, ScanId::new(3));
        assert_eq!(obs.iface_index, 2);
        assert_eq!(obs.mac, mac("aa:bb:cc:dd:ee:01"));
        assert_eq!(obs.ip, ip("192.0.2.10"));
        assert_eq!(obs.source, Source::ArpReply);
        // Copy: cheap to hand around and batch.
        let copy = obs;
        assert_eq!(copy, obs);
        // The display form names every part.
        assert_eq!(
            obs.to_string(),
            "iface 2 aa:bb:cc:dd:ee:01 192.0.2.10 (scan 3, arp reply)"
        );
    }
}
