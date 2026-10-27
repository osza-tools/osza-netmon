// SPDX-License-Identifier: GPL-3.0-only

//! Field state tracking: [`Field`], [`Source`] and [`Reason`]
//! (plan §5.1–5.2, task T-002).
//!
//! Every enriched device attribute (hostname, vendor, …) is a `Field<T>`:
//! the model never fills an information gap with a guess. The four states
//! and their exact semantics come from plan §5.1:
//!
//! * `Known { value, source }` — a value with its origin.
//! * `Pending` — lookup queued; the UI shows `…`.
//! * `Unknown` — the lookup was possible and returned nothing reliable.
//! * `Unavailable(reason)` — the lookup could not be performed (disabled,
//!   no resolver, or an error).

/// The origin of one piece of observed information (plan §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// The selected interface's own data (its MAC/IP; nobody ARPs itself).
    LocalInterface,
    /// The kernel neighbor table (`/proc/net/arp` or netlink).
    NeighborTable,
    /// A solicited ARP reply during an active scan.
    ArpReply,
    /// A reverse-DNS (PTR) answer.
    ReverseDns,
    /// The embedded IEEE-derived vendor database.
    VendorDb,
}

/// Why a lookup could not be performed, making a field
/// [`Field::Unavailable`] (plan §5.1: "disabled, no resolver, error").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// The lookup is disabled by user choice (e.g. `--no-hostnames`).
    Disabled,
    /// No eligible resolver is available for the lookup.
    NoResolver,
    /// The lookup was attempted and failed (timeout, transport error, …).
    Failed,
}

/// The state of one enriched field (plan §5.1–5.2).
///
/// `Unknown` and `Unavailable` are honest, distinguishable answers; the UI
/// shows the controlled-vocabulary words `Unknown` / `Unavailable` / `…`
/// for them (plan §5.4, FR-UI-05) and never substitutes a guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Field<T> {
    /// A value with the source it was learned from.
    Known {
        /// The learned value.
        value: T,
        /// Where the value came from.
        source: Source,
    },
    /// Lookup queued; not yet answered (shown as `…`).
    #[default]
    Pending,
    /// Lookup was possible and returned nothing reliable.
    Unknown,
    /// Lookup could not be performed, with the reason.
    Unavailable(Reason),
}

impl<T> Field<T> {
    /// `true` only in the [`Field::Known`] state.
    pub fn is_known(&self) -> bool {
        matches!(self, Field::Known { .. })
    }

    /// The value, if this field is [`Field::Known`].
    pub fn value(&self) -> Option<&T> {
        match self {
            Field::Known { value, .. } => Some(value),
            _ => None,
        }
    }

    /// The source, if this field is [`Field::Known`].
    pub fn source(&self) -> Option<Source> {
        match self {
            Field::Known { source, .. } => Some(*source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_carry_their_meaning() {
        let known: Field<u8> = Field::Known {
            value: 7,
            source: Source::ArpReply,
        };
        let pending: Field<u8> = Field::Pending;
        let unknown: Field<u8> = Field::Unknown;
        let unavailable: Field<u8> = Field::Unavailable(Reason::NoResolver);

        assert!(known.is_known());
        assert_eq!(known.value(), Some(&7));
        assert_eq!(known.source(), Some(Source::ArpReply));

        for field in [&pending, &unknown, &unavailable] {
            assert!(!field.is_known());
            assert_eq!(field.value(), None);
            assert_eq!(field.source(), None);
        }

        // Distinguishing Unknown from Unavailable is the point of the
        // split (plan §5.1); they must never compare equal.
        assert_ne!(unknown, unavailable);
    }

    #[test]
    fn all_five_sources_exist_and_compare_by_identity() {
        let sources = [
            Source::LocalInterface,
            Source::NeighborTable,
            Source::ArpReply,
            Source::ReverseDns,
            Source::VendorDb,
        ];
        for (i, a) in sources.iter().enumerate() {
            for (j, b) in sources.iter().enumerate() {
                assert_eq!(a == b, i == j, "sources {a:?} and {b:?}");
            }
        }
    }

    #[test]
    fn all_three_reasons_exist_and_compare_by_identity() {
        let reasons = [Reason::Disabled, Reason::NoResolver, Reason::Failed];
        for (i, a) in reasons.iter().enumerate() {
            for (j, b) in reasons.iter().enumerate() {
                assert_eq!(a == b, i == j, "reasons {a:?} and {b:?}");
            }
        }
    }

    #[test]
    fn default_state_is_pending() {
        // Fields start queued, not Unknown: a lookup has not failed to
        // find anything — it has not run yet (plan §5.1).
        assert_eq!(Field::<String>::default(), Field::Pending);
    }

    #[test]
    fn works_with_non_copy_value_types() {
        let host: Field<String> = Field::Known {
            value: String::from("printer.lan"),
            source: Source::ReverseDns,
        };
        assert_eq!(host.value().map(String::as_str), Some("printer.lan"));
        // Clone keeps the state.
        assert_eq!(host.clone(), host);
    }
}
