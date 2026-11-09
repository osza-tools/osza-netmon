// SPDX-License-Identifier: GPL-3.0-only

//! The message log: typed, UI-agnostic error/notice records (plan
//! §6.8, §13; task T-205).
//!
//! The log holds the last [`MESSAGE_LOG_CAPACITY`] (20, plan §13)
//! messages, oldest evicted. Every kind is typed ([`MessageKind`]);
//! **no user-facing sentence text lives here** — T-401 words the §6.8
//! messages and T-303 renders them. The `reason` strings carried by
//! the failure kinds are the *verbatim* worker reasons (one line each,
//! produced by the reviewed layers); they are stored, compared and
//! later displayed by T-401 — never rendered by this layer.
//!
//! # Dedup rule (FR-ER: "one message, not repeated per device")
//!
//! While a kind is already present in the log **and unchanged in its
//! reason string**, a repeat append is suppressed ([`MessageLog::append`]
//! returns `false`). Kinds without a reason compare by kind alone.
//! This makes the once-per-session kinds ([`MessageKind::ReadOnlyMode`],
//! [`MessageKind::RootWarning`], [`MessageKind::NoEligibleResolver`],
//! [`MessageKind::RegistryCapReached`], [`MessageKind::AutoScansStopped`])
//! once-per-session by construction, and caps the per-cycle kinds
//! ([`MessageKind::ScanFailed`], [`MessageKind::ScanDegraded`]) at one
//! entry per distinct reason per log window: 100 cap-dropped
//! observations produce exactly one `RegistryCapReached`. Once an
//! entry has been evicted by newer messages it is no longer "present
//! in the log" and the same fact may legitimately be appended again —
//! the rule bounds the log, it does not erase history's recurrence.
//!
//! Appending (a non-suppressed append) sets the application's dirty
//! flag — the caller does that; the log itself only reports what
//! happened ([`MessageLog::append`] -> `bool`).

use std::collections::VecDeque;

use crate::model::Timestamp;

/// How many messages the log keeps (plan §13: "message log (last
/// 20)"). The oldest entry is evicted when the capacity is exceeded.
pub const MESSAGE_LOG_CAPACITY: usize = 20;

/// One typed message (§6.8; T-401 supplies the wording).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageKind {
    /// A discovery cycle finished `Failed`. The reason is the
    /// worker's verbatim one-liner (from `ScanOutcome::Failed`).
    ScanFailed {
        /// The worker's failure reason, verbatim.
        reason: String,
    },
    /// A discovery cycle finished `Partial` with a typed degradation.
    /// The reason is the neighbor source's verbatim failure line.
    ScanDegraded {
        /// The worker's degradation reason, verbatim.
        reason: String,
    },
    /// Auto-scans stopped after three consecutive `Failed` cycles
    /// (FR-DS-12; sticky for the session — the PQ-1 ruling). No
    /// reason: the condition is self-describing.
    AutoScansStopped,
    /// The session runs in read-only mode (FR-DS-14). The reason text
    /// comes from the caller (T-301 assembly; worded by T-401) and is
    /// stored verbatim.
    ReadOnlyMode {
        /// Why, verbatim from the caller.
        reason: String,
    },
    /// The registry reached its hard cap and dropped new identities
    /// (ADR-008). Once per session by construction.
    RegistryCapReached,
    /// The process was started as root (ADR-005 item 5, §5.10).
    /// Informational; once per session by construction.
    RootWarning,
    /// A manual refresh was requested while a cycle was running
    /// (FR-DS-08: nothing queued). One entry per occurrence while it
    /// remains in the log.
    ScanAlreadyInProgress,
    /// No eligible local resolver was found, so hostname lookups will
    /// answer `Unavailable(NoResolver)` (ADR-003; once per session).
    NoEligibleResolver,
    /// A scope confirmation was attempted while the selected
    /// interface had no derivable scope (FR-SC-04). The reason is the
    /// caller's verbatim explanation.
    ScopeUnavailable {
        /// Why, verbatim from the caller.
        reason: String,
    },
}

impl MessageKind {
    /// Whether two entries of this kind are "the same message" for the
    /// dedup rule: kinds without a reason compare by kind; kinds with
    /// a reason compare by kind **and** reason string.
    fn same_as(&self, other: &MessageKind) -> bool {
        use MessageKind as M;
        match (self, other) {
            (M::ScanFailed { reason: a }, M::ScanFailed { reason: b })
            | (M::ScanDegraded { reason: a }, M::ScanDegraded { reason: b })
            | (M::ReadOnlyMode { reason: a }, M::ReadOnlyMode { reason: b })
            | (M::ScopeUnavailable { reason: a }, M::ScopeUnavailable { reason: b }) => a == b,
            (M::AutoScansStopped, M::AutoScansStopped)
            | (M::RegistryCapReached, M::RegistryCapReached)
            | (M::RootWarning, M::RootWarning)
            | (M::ScanAlreadyInProgress, M::ScanAlreadyInProgress)
            | (M::NoEligibleResolver, M::NoEligibleResolver) => true,
            _ => false,
        }
    }
}

/// One log entry: the kind plus when it happened (the injected clock's
/// reading at append time; display is T-303's job).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// What happened.
    pub kind: MessageKind,
    /// When it happened.
    pub at: Timestamp,
}

/// The bounded, deduplicating message log (last 20 entries, plan
/// §13). Plain data — no locks: it lives inside [`AppState`](super::AppState)
/// on the main thread (ADR-012).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MessageLog {
    entries: VecDeque<Message>,
}

impl MessageLog {
    /// An empty log.
    pub fn new() -> Self {
        MessageLog {
            entries: VecDeque::new(),
        }
    }

    /// Appends one message unless the dedup rule suppresses it.
    ///
    /// Returns `true` when the entry was appended (the caller marks
    /// the state dirty), `false` when an identical message is already
    /// present in the log (no state change of any kind).
    pub fn append(&mut self, kind: MessageKind, at: Timestamp) -> bool {
        if self.entries.iter().any(|entry| entry.kind.same_as(&kind)) {
            return false;
        }
        if self.entries.len() >= MESSAGE_LOG_CAPACITY {
            // Oldest evicted; capacity is fixed so this removes at
            // most one entry per append.
            self.entries.pop_front();
        }
        self.entries.push_back(Message { kind, at });
        true
    }

    /// The retained entries, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &Message> {
        self.entries.iter()
    }

    /// How many entries are retained (≤ [`MESSAGE_LOG_CAPACITY`]).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entry is retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The most recent entry, if any (the newest message the UI shows
    /// in the status line; T-303).
    pub fn latest(&self) -> Option<&Message> {
        self.entries.back()
    }

    /// How many retained entries have this kind (by kind alone, not by
    /// reason — a counting helper for tests and the T-303 badge).
    pub fn count_of(&self, kind: &MessageKind) -> usize {
        self.entries
            .iter()
            .filter(|entry| std::mem::discriminant(&entry.kind) == std::mem::discriminant(kind))
            .count()
    }

    /// Whether any retained entry has this kind (by kind alone).
    pub fn contains_kind(&self, kind: &MessageKind) -> bool {
        self.count_of(kind) > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Clock;
    use crate::model::FakeClock;
    use std::time::Duration;

    /// A fresh fake clock that starts frozen at the Unix epoch; tests
    /// advance it explicitly, so entries are individually
    /// identifiable by timestamp.
    fn stamping_clock() -> (FakeClock, Timestamp) {
        let clock = FakeClock::new();
        let first = clock.now();
        (clock, first)
    }

    fn next_stamp(clock: &mut FakeClock) -> Timestamp {
        clock.advance(Duration::from_secs(1));
        clock.now()
    }

    #[test]
    fn capacity_is_twenty_and_the_oldest_is_evicted() {
        let mut clock = FakeClock::new();
        let mut log = MessageLog::new();
        let mut stamps = Vec::new();
        stamps.push(clock.now());
        // MESSAGE_LOG_CAPACITY + 5 distinct-reason appends.
        for _ in 0..(MESSAGE_LOG_CAPACITY + 5) {
            let reason = format!("reason {}", stamps.len());
            let at = stamps[stamps.len() - 1];
            assert!(log.append(MessageKind::ScanFailed { reason }, at));
            clock.advance(Duration::from_secs(1));
            stamps.push(clock.now());
        }
        assert_eq!(log.len(), MESSAGE_LOG_CAPACITY);
        // stamps has one trailing stamp that was never an append time
        // (the post-advance push of the last iteration); drop it.
        stamps.pop();
        // The oldest retained entry is the 6th appended (the first
        // five were evicted); stamps[0] is the first append time.
        let oldest = log.iter().next().expect("non-empty").at;
        assert_eq!(oldest, stamps[5]);
        // The newest is the last appended.
        assert_eq!(
            log.latest().expect("non-empty").at,
            *stamps.last().expect("non-empty")
        );
    }

    #[test]
    fn identical_kinds_are_suppressed_while_present() {
        let (mut clock, at) = stamping_clock();
        let mut log = MessageLog::new();
        assert!(log.append(MessageKind::RegistryCapReached, at));
        // 100 repeats: exactly one entry, no growth, suppressed.
        for _ in 0..100 {
            assert!(!log.append(MessageKind::RegistryCapReached, next_stamp(&mut clock)));
        }
        assert_eq!(log.count_of(&MessageKind::RegistryCapReached), 1);
        assert_eq!(log.len(), 1);

        // The same holds for a reason-carrying kind with the same
        // reason string …
        assert!(log.append(
            MessageKind::ScanFailed {
                reason: "transport gone".to_owned()
            },
            next_stamp(&mut clock)
        ));
        for _ in 0..100 {
            assert!(!log.append(
                MessageKind::ScanFailed {
                    reason: "transport gone".to_owned()
                },
                next_stamp(&mut clock)
            ));
        }
        // … but a *changed* reason is a new message.
        assert!(log.append(
            MessageKind::ScanFailed {
                reason: "interface lost".to_owned()
            },
            next_stamp(&mut clock)
        ));
        assert_eq!(
            log.count_of(&MessageKind::ScanFailed {
                reason: String::new()
            }),
            2
        );
    }

    #[test]
    fn eviction_re_allows_an_append_of_the_same_kind() {
        let (mut clock, at) = stamping_clock();
        let mut log = MessageLog::new();
        assert!(log.append(MessageKind::AutoScansStopped, at));
        // Fill the log past capacity with distinct reasons so the
        // AutoScansStopped entry is evicted.
        for index in 0..MESSAGE_LOG_CAPACITY {
            let at = next_stamp(&mut clock);
            assert!(log.append(
                MessageKind::ScanDegraded {
                    reason: format!("read {index} failed")
                },
                at
            ));
        }
        assert!(!log.contains_kind(&MessageKind::AutoScansStopped));
        // No longer present → the same fact appends again (the rule
        // bounds the log, not history's recurrence).
        let at = next_stamp(&mut clock);
        assert!(log.append(MessageKind::AutoScansStopped, at));
        assert_eq!(log.count_of(&MessageKind::AutoScansStopped), 1);
    }

    #[test]
    fn every_kind_is_appendable_and_countable() {
        let (mut clock, _at) = stamping_clock();
        let mut log = MessageLog::new();
        let kinds = [
            MessageKind::ScanFailed {
                reason: "r1".to_owned(),
            },
            MessageKind::ScanDegraded {
                reason: "r2".to_owned(),
            },
            MessageKind::AutoScansStopped,
            MessageKind::ReadOnlyMode {
                reason: "no raw socket".to_owned(),
            },
            MessageKind::RegistryCapReached,
            MessageKind::RootWarning,
            MessageKind::ScanAlreadyInProgress,
            MessageKind::NoEligibleResolver,
            MessageKind::ScopeUnavailable {
                reason: "no IPv4".to_owned(),
            },
        ];
        for kind in &kinds {
            let at = next_stamp(&mut clock);
            assert!(log.append(kind.clone(), at), "{kind:?} appended");
        }
        assert_eq!(log.len(), kinds.len());
        for kind in &kinds {
            assert_eq!(log.count_of(kind), 1, "{kind:?}");
            assert!(log.contains_kind(kind));
        }
        // Different reason-carrying kinds never collide.
        assert_ne!(
            MessageKind::ScanFailed {
                reason: "x".to_owned()
            },
            MessageKind::ScanDegraded {
                reason: "x".to_owned()
            }
        );
    }

    #[test]
    fn a_fresh_log_is_empty() {
        let log = MessageLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        assert!(log.latest().is_none());
        assert_eq!(log.iter().count(), 0);
    }
}
