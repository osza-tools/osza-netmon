// SPDX-License-Identifier: GPL-3.0-only

//! Device-record types: [`DeviceKey`], [`IpRecord`], [`Device`],
//! [`Status`], [`Tag`]/[`Tags`], [`Note`] and [`SourceSet`]
//! (plan §5.1–5.3, §4 ADR-008, task T-201).
//!
//! A [`Device`] is one registry entry keyed by [`DeviceKey`] — the
//! `(interface_index, MAC)` pair of ADR-008. It carries the observed
//! properties of that identity: every IPv4 address seen this session
//! ([`IpRecord`] history with per-IP first/last seen), the enrichment
//! fields ([`Field`] values set by the hostname and
//! vendor workers), the factual [`Tags`], neutral [`Note`]s, and the
//! aging bookkeeping ([`Status`], `missed_cycles`).
//!
//! Devices are constructed only by the [`Registry`](super::Registry);
//! there is no public constructor, so every `Device` has at least one
//! [`IpRecord`] and a consistent `first_seen`/`last_seen` pair.

use std::fmt;

use crate::model::{Clock, DisplayText, Field, Hostname, MacAddr, Source, Timestamp};

/// The identity of one device record: `(interface_index, MAC)`
/// (plan §5.2, ADR-008).
///
/// The interface index distinguishes the same hardware address observed
/// on two interfaces; the MAC is the validated [`MacAddr`] of the model
/// layer. IPv4 addresses are deliberately absent: they are *observed
/// properties*, never part of the identity (ADR-008).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceKey {
    /// The kernel interface index the address was observed on.
    pub iface_index: u32,
    /// The validated unicast MAC of the device.
    pub mac: MacAddr,
}

impl fmt::Display for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "iface {} mac {}", self.iface_index, self.mac)
    }
}

/// One IPv4 address of a device, with the first and last time it was
/// observed for that device (ADR-008: "first/last seen per IP").
///
/// A device keeps every address seen this session; entries are never
/// removed (ADR-008: devices — and therefore their histories — are never
/// dropped during a session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRecord {
    /// The observed IPv4 address.
    pub ip: std::net::Ipv4Addr,
    /// When this address was first observed for this device.
    pub first_seen: Timestamp,
    /// When this address was last observed for this device; advanced on
    /// every re-observation.
    pub last_seen: Timestamp,
}

/// The observation-history status of a device (plan §5.1, §4 ADR-002,
/// ADR-007).
///
/// `Recent`/`Idle` describe observation history only — never current
/// association — and carry no verdict (plan §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    /// Observed in the current or a recent scan cycle; also the state any
    /// device returns to on its next observation (ADR-007).
    #[default]
    Recent,
    /// Absent from enough consecutive complete cycles and long enough
    /// since `last_seen` (both ADR-007 conditions); still kept in the
    /// registry (devices are never removed).
    Idle,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Recent => f.write_str("Recent"),
            Status::Idle => f.write_str("Idle"),
        }
    }
}

/// One factual, non-verdict label attached to a device (plan §5.1: tag
/// list; §5.3: derivation rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tag {
    /// The selected interface's own device, inserted from interface data
    /// (plan §5.3).
    ThisDevice,
    /// The device whose IP equals the default-route gateway of the
    /// selected interface (plan §5.3).
    Gateway,
    /// The MAC has the locally-administered bit set (plan §5.3; shown in
    /// the Vendor column by FR-EN-01).
    PrivateAddress,
    /// The device was observed with at least `shared_mac_threshold`
    /// distinct IPs within the idle window (ADR-008).
    MultipleIps,
}

impl Tag {
    /// The exact UI wording of the tag (plan §5.1, controlled vocabulary
    /// §5.4).
    pub const fn label(self) -> &'static str {
        match self {
            Tag::ThisDevice => "This device",
            Tag::Gateway => "Gateway",
            Tag::PrivateAddress => "Private address",
            Tag::MultipleIps => "Multiple IPs",
        }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// The set of [`Tag`]s on one device — a compact, ordered bitset over
/// the four factual labels.
///
/// Iteration order is the declaration order of [`Tag`]
/// (`This device`, `Gateway`, `Private address`, `Multiple IPs`), which
/// is the display order of plan §10.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tags(u8);

impl Tags {
    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        Tags(0)
    }

    /// Adds a tag (idempotent).
    pub fn set(&mut self, tag: Tag) {
        self.0 |= Self::bit(tag);
    }

    /// Removes a tag (idempotent).
    pub fn unset(&mut self, tag: Tag) {
        self.0 &= !Self::bit(tag);
    }

    /// `true` if the tag is present.
    #[must_use]
    pub const fn contains(&self, tag: Tag) -> bool {
        self.0 & Self::bit(tag) != 0
    }

    /// `true` if no tag is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// The number of tags present.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.0.count_ones()
    }

    /// All present tags, in [`Tag`] declaration order.
    pub fn iter(&self) -> impl Iterator<Item = Tag> + '_ {
        ALL_TAGS.iter().filter(|tag| self.contains(**tag)).copied()
    }

    const fn bit(tag: Tag) -> u8 {
        match tag {
            Tag::ThisDevice => 1 << 0,
            Tag::Gateway => 1 << 1,
            Tag::PrivateAddress => 1 << 2,
            Tag::MultipleIps => 1 << 3,
        }
    }
}

/// All tags, in declaration order (the single place listing them).
const ALL_TAGS: [Tag; 4] = [
    Tag::ThisDevice,
    Tag::Gateway,
    Tag::PrivateAddress,
    Tag::MultipleIps,
];

/// A neutral, factual note attached to a device record (ADR-008).
///
/// Notes are structured facts, not free text: every value they carry
/// (`Ipv4Addr`, [`MacAddr`], a count) is already boundary-validated by
/// the model layer, so no raw external string ever enters a note
/// (task card §8). The [`fmt::Display`] form is the wording shown in
/// Details; it is neutral and verdict-free (ADR-008: "No alert, no red,
/// no verdict").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// The IP is also present in the history of another device record
    /// (ADR-008: "also observed under MAC …"). Records are never merged
    /// across MACs; both records keep the IP and both carry the note.
    IpAlsoObservedUnder {
        /// The address observed under more than one MAC.
        ip: std::net::Ipv4Addr,
        /// The *other* device's MAC (this note is mirrored on both
        /// records, each naming the other).
        mac: MacAddr,
    },
    /// Neutral explanation attached when the [`Tag::MultipleIps`] tag is
    /// applied (ADR-008: "a neutral explanation (router, proxy ARP, or
    /// virtual interfaces)"). `distinct_ips` is the number of distinct
    /// addresses within the idle window when the threshold was reached;
    /// it is only ever raised, never lowered, while later observations
    /// push the in-window count higher.
    MultipleIps {
        /// The in-window distinct-IP count at the time the note was
        /// raised (or last raised).
        distinct_ips: u32,
    },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Note::IpAlsoObservedUnder { ip, mac } => {
                write!(f, "{ip} also observed under MAC {mac}")
            }
            Note::MultipleIps { distinct_ips } => write!(
                f,
                "Observed with {distinct_ips} distinct addresses in the \
                 recent window; this is typical of routers, proxy ARP, or \
                 virtual interfaces."
            ),
        }
    }
}

/// The set of discovery/enrichment [`Source`]s that have contributed to
/// one device record (plan §5.2 `sources: SourceSet`).
///
/// A compact bitset over the five sources of the model layer; iteration
/// order follows the [`Source`] declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SourceSet(u8);

impl SourceSet {
    /// The empty set.
    #[must_use]
    pub const fn new() -> Self {
        SourceSet(0)
    }

    /// Adds a source (idempotent).
    pub fn insert(&mut self, source: Source) {
        self.0 |= Self::bit(source);
    }

    /// `true` if the source is present.
    #[must_use]
    pub const fn contains(&self, source: Source) -> bool {
        self.0 & Self::bit(source) != 0
    }

    /// `true` if no source is present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// The number of sources present.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.0.count_ones()
    }

    /// All present sources, in [`Source`] declaration order.
    pub fn iter(&self) -> impl Iterator<Item = Source> + '_ {
        ALL_SOURCES
            .iter()
            .filter(|source| self.contains(**source))
            .copied()
    }

    const fn bit(source: Source) -> u8 {
        match source {
            Source::LocalInterface => 1 << 0,
            Source::NeighborTable => 1 << 1,
            Source::ArpReply => 1 << 2,
            Source::ReverseDns => 1 << 3,
            Source::VendorDb => 1 << 4,
        }
    }
}

/// All sources, in declaration order (the single place listing them).
const ALL_SOURCES: [Source; 5] = [
    Source::LocalInterface,
    Source::NeighborTable,
    Source::ArpReply,
    Source::ReverseDns,
    Source::VendorDb,
];

/// One registry entry: everything known about one `(interface, MAC)`
/// identity (plan §5.2).
///
/// Constructed only by the [`Registry`](super::Registry) (through its
/// crate-private constructor), so a `Device` always has at least one
/// [`IpRecord`], a primary IP, and `first_seen <= last_seen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// The identity of the record (ADR-008).
    pub key: DeviceKey,
    /// Every IPv4 address seen this session, in first-observation order,
    /// with per-IP first/last seen (ADR-008).
    pub ips: Vec<IpRecord>,
    /// The hostname field, maintained by the hostname worker (T-203);
    /// starts `Pending` (plan §5.2).
    pub hostname: Field<Hostname>,
    /// The vendor field, maintained by the vendor lookup (T-202); starts
    /// `Pending` (plan §5.2).
    pub vendor: Field<DisplayText>,
    /// The factual labels (plan §5.1).
    pub tags: Tags,
    /// When the record was created; set once per session (FR-RG-02).
    pub first_seen: Timestamp,
    /// When the device was last observed; advanced on every observation.
    pub last_seen: Timestamp,
    /// Consecutive complete scan cycles the device was absent from
    /// (ADR-007). Reset to 0 by any observation.
    pub missed_cycles: u32,
    /// Observation-history status (ADR-007).
    pub status: Status,
    /// Every source that has contributed evidence to this record.
    pub sources: SourceSet,
    /// Neutral notes (ADR-008), deduplicated, in first-added order.
    pub notes: Vec<Note>,

    /// The most recently observed IPv4 address (ADR-008: "its primary IP
    /// is the most recently observed one"). Updated on every observation,
    /// so it stays well-defined even when two addresses share a
    /// `last_seen` timestamp.
    pub(crate) last_observed_ip: std::net::Ipv4Addr,
    /// Whether the device has been observed in the cycle currently in
    /// progress; reset by `begin_cycle`, evaluated by `end_cycle`.
    pub(crate) seen_in_cycle: bool,
}

impl Device {
    /// Creates a record for its first observation. Crate-private: only
    /// the [`Registry`](super::Registry) builds devices.
    pub(crate) fn new(key: DeviceKey, ip: std::net::Ipv4Addr, now: Timestamp, tags: Tags) -> Self {
        Device {
            key,
            ips: vec![IpRecord {
                ip,
                first_seen: now,
                last_seen: now,
            }],
            hostname: Field::Pending,
            vendor: Field::Pending,
            tags,
            first_seen: now,
            last_seen: now,
            missed_cycles: 0,
            status: Status::Recent,
            sources: SourceSet::new(),
            notes: Vec::new(),
            last_observed_ip: ip,
            seen_in_cycle: true,
        }
    }

    /// The primary IP: the most recently observed address (ADR-008).
    ///
    /// Always present: a device only exists because it was observed with
    /// some address.
    #[must_use]
    pub const fn primary_ip(&self) -> std::net::Ipv4Addr {
        self.last_observed_ip
    }

    /// How long ago the device was last observed, per the given clock
    /// reading (display helper; aging itself uses the same monotonic
    /// reading).
    #[must_use]
    pub fn age(&self, now: &dyn Clock) -> std::time::Duration {
        now.now()
            .mono()
            .checked_duration_since(self.last_seen.mono())
            .unwrap_or_default()
    }

    /// `true` if the address is in this device's IP history.
    #[must_use]
    pub fn has_ip(&self, ip: std::net::Ipv4Addr) -> bool {
        self.ips.iter().any(|record| record.ip == ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FakeClock;
    use std::time::Duration;

    fn key(iface: u32, mac: &str) -> DeviceKey {
        DeviceKey {
            iface_index: iface,
            mac: mac.parse().expect("valid MAC"),
        }
    }

    fn at(seconds: u64) -> Timestamp {
        let mut clock = FakeClock::new();
        clock.advance(Duration::from_secs(seconds));
        clock.now()
    }

    #[test]
    fn device_key_orders_by_interface_then_mac() {
        // Identity is the pair: same MAC on two interfaces are different
        // keys (ADR-008).
        let a = key(2, "aa:bb:cc:dd:ee:01");
        let b = key(3, "aa:bb:cc:dd:ee:01");
        let c = key(2, "aa:bb:cc:dd:ee:02");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a < b, "interface index is the primary order");
        assert!(a < c, "MAC breaks ties within one interface");
        // Copy + Hash + Eq: usable as a HashMap key unchanged.
        let set = std::collections::HashSet::from([a, b, c, a]);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn device_key_display_shows_both_parts() {
        let k = key(7, "aa:bb:cc:dd:ee:ff");
        assert_eq!(k.to_string(), "iface 7 mac aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn new_devices_start_recent_with_one_ip_record() {
        let now = at(10);
        let device = Device::new(
            key(1, "aa:bb:cc:dd:ee:01"),
            "192.0.2.10"
                .parse::<std::net::Ipv4Addr>()
                .expect("valid IP"),
            now,
            Tags::new(),
        );
        assert_eq!(device.status, Status::Recent);
        assert_eq!(device.missed_cycles, 0);
        assert_eq!(device.ips.len(), 1);
        assert_eq!(
            device.primary_ip(),
            "192.0.2.10"
                .parse::<std::net::Ipv4Addr>()
                .expect("valid IP")
        );
        assert_eq!(device.first_seen, now);
        assert_eq!(device.last_seen, now);
        assert_eq!(device.hostname, Field::Pending);
        assert_eq!(device.vendor, Field::Pending);
        assert!(device.sources.is_empty());
        assert!(device.notes.is_empty());
        assert!(device.tags.is_empty());
        assert!(device.seen_in_cycle, "creation is itself an observation");
    }

    #[test]
    fn status_and_tag_wording_follow_the_controlled_vocabulary() {
        assert_eq!(Status::Recent.to_string(), "Recent");
        assert_eq!(Status::Idle.to_string(), "Idle");
        assert_eq!(Tag::ThisDevice.to_string(), "This device");
        assert_eq!(Tag::Gateway.to_string(), "Gateway");
        assert_eq!(Tag::PrivateAddress.to_string(), "Private address");
        assert_eq!(Tag::MultipleIps.to_string(), "Multiple IPs");
        // None of the §5.4 banned words may appear in user-facing text.
        for text in [
            Status::Recent.to_string(),
            Status::Idle.to_string(),
            Tag::ThisDevice.to_string(),
            Tag::Gateway.to_string(),
            Tag::PrivateAddress.to_string(),
            Tag::MultipleIps.to_string(),
            Note::MultipleIps { distinct_ips: 5 }.to_string(),
            Note::IpAlsoObservedUnder {
                ip: "192.0.2.1".parse::<std::net::Ipv4Addr>().expect("valid IP"),
                mac: "aa:bb:cc:dd:ee:02".parse().expect("valid MAC"),
            }
            .to_string(),
        ] {
            let lower = text.to_lowercase();
            for banned in [
                "online",
                "offline",
                "connected",
                "disconnected",
                "intruder",
                "unauthorized",
                "rogue",
                "suspicious",
                "malicious",
                "trusted",
                "secure",
                "verified",
                "stale",
            ] {
                assert!(
                    !lower.contains(banned),
                    "{text:?} contains the banned word {banned:?}"
                );
            }
        }
    }

    #[test]
    fn tags_behave_as_an_idempotent_ordered_set() {
        let mut tags = Tags::new();
        assert!(tags.is_empty());
        assert_eq!(tags.len(), 0);
        tags.set(Tag::MultipleIps);
        tags.set(Tag::ThisDevice);
        tags.set(Tag::ThisDevice); // idempotent
        assert_eq!(tags.len(), 2);
        assert!(tags.contains(Tag::ThisDevice));
        assert!(tags.contains(Tag::MultipleIps));
        assert!(!tags.contains(Tag::Gateway));
        // Iteration follows declaration order, not insertion order.
        assert_eq!(
            tags.iter().collect::<Vec<_>>(),
            vec![Tag::ThisDevice, Tag::MultipleIps]
        );
        tags.unset(Tag::ThisDevice);
        assert!(!tags.contains(Tag::ThisDevice));
        assert_eq!(tags.iter().collect::<Vec<_>>(), vec![Tag::MultipleIps]);
        tags.unset(Tag::ThisDevice); // idempotent removal
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn source_set_covers_all_five_sources_idempotently() {
        let mut set = SourceSet::new();
        assert!(set.is_empty());
        for source in ALL_SOURCES {
            set.insert(source);
            set.insert(source);
        }
        assert_eq!(set.len(), 5);
        assert_eq!(set.iter().collect::<Vec<_>>(), ALL_SOURCES.to_vec());
        assert!(set.contains(Source::ReverseDns));
    }

    #[test]
    fn notes_render_neutral_factual_wording() {
        let conflict = Note::IpAlsoObservedUnder {
            ip: "192.0.2.50"
                .parse::<std::net::Ipv4Addr>()
                .expect("valid IP"),
            mac: "aa:bb:cc:dd:ee:0a".parse().expect("valid MAC"),
        };
        assert_eq!(
            conflict.to_string(),
            "192.0.2.50 also observed under MAC aa:bb:cc:dd:ee:0a"
        );
        let shared = Note::MultipleIps { distinct_ips: 5 };
        let text = shared.to_string();
        assert!(text.starts_with("Observed with 5 distinct addresses"));
        assert!(text.contains("routers, proxy ARP, or virtual interfaces"));
        // Notes compare structurally, so deduplication by equality works.
        assert_eq!(conflict, conflict.clone());
        assert_ne!(conflict, shared);
    }

    #[test]
    fn age_is_measured_from_last_seen() {
        let mut clock = FakeClock::new();
        let device = Device::new(
            key(1, "aa:bb:cc:dd:ee:01"),
            "192.0.2.10"
                .parse::<std::net::Ipv4Addr>()
                .expect("valid IP"),
            clock.now(),
            Tags::new(),
        );
        clock.advance(Duration::from_secs(90));
        assert_eq!(device.age(&clock), Duration::from_secs(90));
        clock.advance(Duration::from_secs(30));
        assert_eq!(device.age(&clock), Duration::from_secs(120));
    }

    #[test]
    fn has_ip_searches_the_history() {
        let device = Device::new(
            key(1, "aa:bb:cc:dd:ee:01"),
            "192.0.2.10"
                .parse::<std::net::Ipv4Addr>()
                .expect("valid IP"),
            at(0),
            Tags::new(),
        );
        assert!(
            device.has_ip(
                "192.0.2.10"
                    .parse::<std::net::Ipv4Addr>()
                    .expect("valid IP")
            )
        );
        assert!(
            !device.has_ip(
                "192.0.2.11"
                    .parse::<std::net::Ipv4Addr>()
                    .expect("valid IP")
            )
        );
    }
}
