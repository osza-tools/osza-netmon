// SPDX-License-Identifier: GPL-3.0-only

//! The in-memory device registry: the single source of truth for the
//! application's state (plan §6.4 FR-RG-01…07, §4 ADR-007, ADR-008,
//! task T-201).
//!
//! The registry owns every device record and is the only writer
//! (FR-RG-01): discovery and enrichment workers never touch it, they
//! only produce the events that
//! [`begin_cycle`](Registry::begin_cycle) /
//! [`observe`](Registry::observe) /
//! [`end_cycle`](Registry::end_cycle) consume. All time comes in through
//! an injected [`Clock`] parameter (FR-RG-05), so
//! the whole aging model is testable without sleeping.
//!
//! Rules implemented here, with their authority:
//!
//! * **Identity** — `(interface_index, MAC)` (ADR-008, plan §5.2).
//!   IPv4 addresses are observed properties with per-IP first/last
//!   seen; the primary IP is the most recently observed one.
//! * **Aging** — a device becomes `Idle` only when it was absent from
//!   `idle_after_cycles` consecutive *complete* cycles **and**
//!   `now − last_seen ≥ idle_min_age` (ADR-007). Non-complete outcomes
//!   never age; any observation returns the device to `Recent`.
//! * **Tags** — `This device`, `Gateway`, `Private address`,
//!   `Multiple IPs`: factual labels, never verdicts (plan §5.1, §5.3).
//! * **Shared MACs** — one address under two MACs is kept by both
//!   records with a mirrored neutral note; one MAC with
//!   `shared_mac_threshold` distinct addresses inside the idle window
//!   gets the `Multiple IPs` tag with a neutral explanation (ADR-008).
//! * **Hard cap** — at most [`REGISTRY_CAP`] keys; beyond it new keys
//!   are dropped, existing ones keep updating, and a persistent
//!   warning is exposed (ADR-008).
//! * **Order and selection** — stable sort by primary IP or by
//!   hostname (unknown hostnames last, then by IP), with the selection
//!   bound to the [`DeviceKey`] so it survives re-sorts (FR-RG-06).
//!
//! Per the dependency rules of plan §8.2 this module depends only on
//! the model layer (which contains the clock of T-002) and `std` —
//! never on `discovery`, `enrichment`, `app` or `ui`.

mod config;
mod device;
mod observation;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::net::Ipv4Addr;

use crate::model::{Clock, DisplayText, Field, Hostname, MacAddr, Source};

pub use config::{
    ConfigError, IDLE_AFTER_CYCLES_DEFAULT, IDLE_MIN_AGE_DEFAULT, REGISTRY_CAP, RegistryConfig,
    SHARED_MAC_THRESHOLD_DEFAULT,
};
pub use device::{Device, DeviceKey, IpRecord, Note, SourceSet, Status, Tag, Tags};
pub use observation::{Observation, ScanId, ScanOutcome};

/// How the device list is ordered (FR-RG-06).
///
/// Sorting is always stable: records that compare equal keep their
/// first-observation order, so rows never jump around between frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortMode {
    /// By primary IP in numeric `Ipv4Addr` order.
    #[default]
    Ip,
    /// By hostname (ASCII case-insensitive); records without a known
    /// hostname sort last, then by primary IP. Known hostnames that
    /// differ only in case are ordered by their primary IP.
    Hostname,
}

impl fmt::Display for SortMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortMode::Ip => f.write_str("ip"),
            SortMode::Hostname => f.write_str("hostname"),
        }
    }
}

/// What an observation (or local-device insertion) did.
///
/// The registry never silently guesses (FR-RG-07): every outcome states
/// exactly what happened, including the two ignore paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// The observation was merged into a record; `new_device` tells
    /// whether the record was created by it.
    Accepted {
        /// `true` when this observation created the record.
        new_device: bool,
    },
    /// The observation's [`ScanId`] is not the cycle currently in
    /// progress (or no cycle is in progress), so it was ignored
    /// (FR-RG-03: results of superseded or cancelled scans never reach
    /// the state).
    IgnoredScanMismatch,
    /// The observation carried a new identity, but the registry is at
    /// its hard cap, so the new key was dropped (ADR-008). Existing
    /// keys keep updating; the cap warning is now persistent.
    DroppedCapFull,
}

/// The aging accounting of one finished cycle, returned by
/// [`Registry::end_cycle`].
///
/// `observed + absent` may be smaller than
/// [`device_count`](Registry::device_count): records tagged
/// [`Tag::ThisDevice`] are counted in neither bucket, because their
/// presence is structural (interface data) rather than observed (see
/// [`Registry::insert_local_device`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CycleSummary {
    /// The cycle that finished.
    pub id: ScanId,
    /// The outcome the cycle finished with.
    pub outcome: ScanOutcome,
    /// Records observed during the cycle.
    pub observed: usize,
    /// Records not observed and eligible for aging (everything except
    /// records tagged [`Tag::ThisDevice`]). Only aged when the outcome
    /// is [`ScanOutcome::Complete`].
    pub absent: usize,
    /// Records whose `missed_cycles` was advanced by this cycle
    /// (complete outcomes only).
    pub missed_advanced: usize,
    /// Records that transitioned `Recent → Idle` at this cycle's end.
    pub newly_idle: usize,
}

/// The device registry: single owner of the application state
/// (FR-RG-01).
///
/// See the [module documentation](self) for the rules it enforces. The
/// registry is not `Sync` and needs no locks: it lives on the main
/// thread of the event loop (plan §8.3) and workers send events to it.
pub struct Registry {
    /// Tuning parameters (ADR-007/ADR-008 values by default).
    config: RegistryConfig,
    /// The records, keyed by identity.
    devices: HashMap<DeviceKey, Device>,
    /// First-observation order of the keys: the stable base order every
    /// sort is applied to (FR-RG-06).
    order: Vec<DeviceKey>,
    /// Which records hold which IPv4 address, for the ADR-008
    /// one-address-two-MACs notes. Every listed key has a record, and
    /// records are never removed, so this index never dangles.
    ip_holders: HashMap<Ipv4Addr, Vec<DeviceKey>>,
    /// The cycle currently in progress, if any.
    current_cycle: Option<ScanId>,
    /// The default-route gateway address of the selected interface, once
    /// known (plan §5.3: the `Gateway` tag is applied only to observed
    /// devices that hold this address).
    gateway_ip: Option<Ipv4Addr>,
    /// Persistent cap warning (ADR-008): set the first time a new key is
    /// dropped at the cap; never cleared — records are never removed.
    cap_hit: bool,
    /// The current list ordering (FR-RG-06).
    sort: SortMode,
    /// The selected record, bound to its key so the highlight survives
    /// re-sorts and refreshes (FR-RG-06).
    selected: Option<DeviceKey>,
}

impl Default for Registry {
    /// A registry with the ADR-007/ADR-008 default configuration. The
    /// default config is valid by construction, so no panicking path is
    /// needed here.
    fn default() -> Self {
        Registry {
            config: RegistryConfig::default(),
            devices: HashMap::new(),
            order: Vec::new(),
            ip_holders: HashMap::new(),
            current_cycle: None,
            gateway_ip: None,
            cap_hit: false,
            sort: SortMode::default(),
            selected: None,
        }
    }
}

impl Registry {
    /// Builds a registry from a validated configuration.
    ///
    /// # Errors
    /// Returns the first [`ConfigError`] the configuration violates;
    /// nothing is clamped or repaired silently (plan §8.7).
    pub fn new(config: RegistryConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Registry {
            config,
            ..Registry::default()
        })
    }

    /// The configuration in force.
    #[must_use]
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }

    /// The number of device records (never decreases: records are never
    /// removed, ADR-008).
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// The configured maximum number of records (ADR-008 hard cap by
    /// default).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.config.max_devices
    }

    /// The persistent cap warning (ADR-008): `true` once a new key has
    /// been dropped because the registry was full. It never returns to
    /// `false` — records are never removed during a session.
    #[must_use]
    pub fn cap_warning(&self) -> bool {
        self.cap_hit
    }

    /// The record for `key`, if any.
    #[must_use]
    pub fn get(&self, key: &DeviceKey) -> Option<&Device> {
        self.devices.get(key)
    }

    /// All records in first-observation order — the stable base order
    /// (FR-RG-06).
    pub fn iter(&self) -> impl Iterator<Item = &Device> {
        self.order.iter().filter_map(|key| self.devices.get(key))
    }

    /// All records in the current [`SortMode`] order.
    pub fn iter_sorted(&self) -> impl Iterator<Item = &Device> {
        let keys = self.sorted_order();
        keys.into_iter()
            .filter_map(move |key| self.devices.get(&key))
    }

    /// The record keys in the current [`SortMode`] order.
    #[must_use]
    pub fn sorted_keys(&self) -> Vec<DeviceKey> {
        self.sorted_order()
    }

    /// The scan cycle currently in progress, if any.
    #[must_use]
    pub fn current_scan_id(&self) -> Option<ScanId> {
        self.current_cycle
    }

    // -- Cycle lifecycle (FR-RG-03, plan §8.5) -------------------------------

    /// Starts a new scan cycle.
    ///
    /// Devices not observed before the matching
    /// [`end_cycle`](Self::end_cycle) will age at that cycle's end if
    /// the outcome is [`ScanOutcome::Complete`] (ADR-007). Calling this
    /// while another cycle is still in progress supersedes that cycle:
    /// its (never delivered) `end_cycle` will be ignored by scan-id
    /// mismatch, so an unfinished cycle can never age devices.
    pub fn begin_cycle(&mut self, id: ScanId) {
        self.current_cycle = Some(id);
        for device in self.devices.values_mut() {
            device.seen_in_cycle = false;
        }
    }

    /// Accepts one observation for the current cycle (FR-RG-03,
    /// FR-RG-02).
    ///
    /// Observations whose [`ScanId`] is not the cycle currently in
    /// progress — including late arrivals from a superseded or
    /// cancelled scan, and anything arriving between cycles — are
    /// ignored ([`ObserveOutcome::IgnoredScanMismatch`]) and leave the
    /// state untouched. Accepted observations merge by
    /// [`DeviceKey`]: IP history, `last_seen` and `sources`
    /// update, `first_seen` stays, and the device returns to
    /// [`Status::Recent`] with `missed_cycles` reset (ADR-007).
    ///
    /// Time is taken from the injected `clock` (FR-RG-05).
    pub fn observe(&mut self, observation: Observation, clock: &dyn Clock) -> ObserveOutcome {
        if self.current_cycle != Some(observation.scan_id) {
            return ObserveOutcome::IgnoredScanMismatch;
        }
        self.absorb(
            observation.iface_index,
            observation.mac,
            observation.ip,
            observation.source,
            clock,
        )
    }

    /// Finalizes the scan cycle `id` (FR-RG-03, ADR-007).
    ///
    /// Returns `None` — and changes nothing — when `id` is not the
    /// cycle currently in progress. Otherwise the per-cycle accounting
    /// is returned as a [`CycleSummary`]: devices observed this cycle
    /// stay [`Status::Recent`]; absent devices age **only** when the
    /// outcome is [`ScanOutcome::Complete`], each gaining one
    /// `missed_cycles`, and every absent device whose miss streak has
    /// reached `idle_after_cycles` *and* whose `now − last_seen` has
    /// reached `idle_min_age` becomes [`Status::Idle`]. Records tagged
    /// [`Tag::ThisDevice`] are structurally present and never age (see
    /// [`insert_local_device`](Self::insert_local_device)).
    ///
    /// Time is taken from the injected `clock` (FR-RG-05).
    pub fn end_cycle(
        &mut self,
        id: ScanId,
        outcome: ScanOutcome,
        clock: &dyn Clock,
    ) -> Option<CycleSummary> {
        if self.current_cycle != Some(id) {
            return None;
        }
        let now = clock.now();
        let aging = outcome.is_complete();
        let idle_after_cycles = self.config.idle_after_cycles;
        let idle_min_age = self.config.idle_min_age;
        let mut summary = CycleSummary {
            id,
            outcome,
            observed: 0,
            absent: 0,
            missed_advanced: 0,
            newly_idle: 0,
        };
        for device in self.devices.values_mut() {
            if device.seen_in_cycle {
                summary.observed += 1;
                continue;
            }
            if device.tags.contains(Tag::ThisDevice) {
                // Structural presence: interface data, not scan evidence
                // (plan §5.3). See insert_local_device.
                continue;
            }
            summary.absent += 1;
            if !aging {
                // ADR-007: Partial, Failed and Cancelled cycles never age.
                continue;
            }
            device.missed_cycles = device.missed_cycles.saturating_add(1);
            summary.missed_advanced += 1;
            if device.missed_cycles >= idle_after_cycles {
                let age = now
                    .mono()
                    .checked_duration_since(device.last_seen.mono())
                    .unwrap_or_default();
                if age >= idle_min_age && device.status != Status::Idle {
                    device.status = Status::Idle;
                    summary.newly_idle += 1;
                }
            }
        }
        self.current_cycle = None;
        Some(summary)
    }

    // -- Interface data (plan §5.3) ------------------------------------------

    /// Inserts or refreshes the selected interface's own device and
    /// tags it [`Tag::ThisDevice`] (plan §5.3: interface data, source
    /// `LocalInterface`, because nobody ARPs itself).
    ///
    /// Unlike [`observe`](Self::observe) this is not bound to a scan
    /// cycle: the interface's own data is authoritative at any time.
    /// The insertion is an observation for merging purposes (IP history,
    /// `last_seen`, `Recent`), and a `This device` record never ages at
    /// `end_cycle` — its presence is structural, not observed; showing
    /// the local machine as "not seen recently" would contradict the
    /// tag. The alternative (the application re-inserting the device
    /// every cycle) is recorded as a Plan Question in the T-201
    /// execution report.
    pub fn insert_local_device(
        &mut self,
        iface_index: u32,
        mac: MacAddr,
        ip: Ipv4Addr,
        clock: &dyn Clock,
    ) -> ObserveOutcome {
        let outcome = self.absorb(iface_index, mac, ip, Source::LocalInterface, clock);
        if matches!(outcome, ObserveOutcome::Accepted { .. }) {
            let key = DeviceKey { iface_index, mac };
            edit_device(&mut self.devices, &key, |device| {
                device.tags.set(Tag::ThisDevice);
            });
        }
        outcome
    }

    /// Records the default-route gateway address of the selected
    /// interface and applies the [`Tag::Gateway`] to every observed
    /// record holding it (plan §5.3: "applied only after that device
    /// has been observed").
    ///
    /// Setting the address again re-applies the tag from scratch, so a
    /// route change moves the tag: records that hold the new address
    /// are tagged, every other record is untagged. Future observations
    /// of the address are tagged by [`observe`](Self::observe).
    pub fn set_gateway_ip(&mut self, ip: Ipv4Addr) {
        self.gateway_ip = Some(ip);
        for device in self.devices.values_mut() {
            if device.ips.iter().any(|record| record.ip == ip) {
                device.tags.set(Tag::Gateway);
            } else {
                device.tags.unset(Tag::Gateway);
            }
        }
    }

    // -- Enrichment fields (T-202/T-203 provide the values) ------------------

    /// Sets the hostname field of one record (the value arrives from
    /// the hostname worker, T-203; the registry only stores it).
    ///
    /// Returns `false` and changes nothing when `key` has no record.
    pub fn set_hostname(&mut self, key: &DeviceKey, hostname: Field<Hostname>) -> bool {
        edit_device(&mut self.devices, key, |device| {
            device.hostname = hostname;
        })
    }

    /// Sets the vendor field of one record (the value arrives from the
    /// vendor lookup, T-202; the registry only stores it).
    ///
    /// Returns `false` and changes nothing when `key` has no record.
    pub fn set_vendor(&mut self, key: &DeviceKey, vendor: Field<DisplayText>) -> bool {
        edit_device(&mut self.devices, key, |device| {
            device.vendor = vendor;
        })
    }

    // -- Ordering and selection (FR-RG-06) ------------------------------------

    /// The ordering in force.
    #[must_use]
    pub fn sort_mode(&self) -> SortMode {
        self.sort
    }

    /// Changes the ordering. The selection is bound to the
    /// [`DeviceKey`], so it survives the change (FR-RG-06).
    pub fn set_sort_mode(&mut self, mode: SortMode) {
        self.sort = mode;
    }

    /// Selects the record for `key`.
    ///
    /// Returns `false` and keeps the previous selection when `key` has
    /// no record.
    pub fn select(&mut self, key: DeviceKey) -> bool {
        if self.devices.contains_key(&key) {
            self.selected = Some(key);
            true
        } else {
            false
        }
    }

    /// The selected key, if any.
    #[must_use]
    pub fn selected_key(&self) -> Option<DeviceKey> {
        self.selected
    }

    /// The selected record, if any.
    #[must_use]
    pub fn selected_device(&self) -> Option<&Device> {
        self.selected.and_then(|key| self.devices.get(&key))
    }

    /// Clears the selection.
    pub fn clear_selection(&mut self) {
        self.selected = None;
    }

    /// Selects the first record in the current [`SortMode`] order
    /// (`None` when the registry is empty).
    pub fn select_first(&mut self) -> Option<DeviceKey> {
        let order = self.sorted_order();
        self.selected = order.first().copied();
        self.selected
    }

    /// Selects the last record in the current [`SortMode`] order
    /// (`None` when the registry is empty).
    pub fn select_last(&mut self) -> Option<DeviceKey> {
        let order = self.sorted_order();
        self.selected = order.last().copied();
        self.selected
    }

    /// Moves the selection one record down the current
    /// [`SortMode`] order; with no selection this selects the first
    /// record. The selection stays on the last record when it is
    /// already there. Returns the selection after the move (`None`
    /// only when the registry is empty).
    pub fn select_next(&mut self) -> Option<DeviceKey> {
        let order = self.sorted_order();
        self.selected = match self.selected {
            None => order.first().copied(),
            Some(current) => match order.iter().position(|key| *key == current) {
                Some(position) => match order.get(position + 1) {
                    Some(next) => Some(*next),
                    // Already the last record: stay there.
                    None => Some(current),
                },
                // A selected key always has a record (records are never
                // removed); this arm only exists to avoid guessing.
                None => order.first().copied(),
            },
        };
        self.selected
    }

    /// Moves the selection one record up the current [`SortMode`]
    /// order; with no selection this selects the first record. The
    /// selection stays on the first record when it is already there.
    /// Returns the selection after the move (`None` only when the
    /// registry is empty).
    pub fn select_previous(&mut self) -> Option<DeviceKey> {
        let order = self.sorted_order();
        self.selected = match self.selected {
            None => order.first().copied(),
            Some(current) => match order.iter().position(|key| *key == current) {
                Some(position) => match position.checked_sub(1) {
                    Some(previous) => order.get(previous).copied(),
                    // Already the first record: stay there.
                    None => Some(current),
                },
                None => order.first().copied(),
            },
        };
        self.selected
    }

    // -- Internals -------------------------------------------------------------

    /// Merges one piece of `(interface, MAC, IPv4)` evidence into the
    /// registry, creating the record when needed (ADR-008, FR-RG-02).
    ///
    /// This is the single write path shared by [`observe`](Self::observe)
    /// and [`insert_local_device`](Self::insert_local_device). It is the
    /// only place that touches `devices`, `order` and `ip_holders`
    /// together, which keeps the three structures consistent.
    fn absorb(
        &mut self,
        iface_index: u32,
        mac: MacAddr,
        ip: Ipv4Addr,
        source: Source,
        clock: &dyn Clock,
    ) -> ObserveOutcome {
        let now = clock.now();
        let key = DeviceKey { iface_index, mac };

        // Disjoint-field borrows, so record mutation and the address
        // index can both proceed in this one pass.
        let devices = &mut self.devices;
        let ip_holders = &mut self.ip_holders;
        let config = &self.config;
        let gateway_ip = self.gateway_ip;
        // Computed before the entry borrow: at the cap, new keys are
        // dropped while existing ones (the Occupied arm) still update.
        let at_cap = devices.len() >= config.max_devices;

        // Other records already holding this address under a different
        // MAC (ADR-008). Same MAC on another interface is the same
        // hardware and is deliberately not reported as a conflict.
        let others: Vec<DeviceKey> = ip_holders
            .get(&ip)
            .into_iter()
            .flatten()
            .filter(|holder| holder.mac != mac)
            .copied()
            .collect();

        // Identity lookup and merge (ADR-008: identity is the key, the
        // address is an observed property).
        let new_device = match devices.entry(key) {
            Entry::Occupied(mut occupied) => {
                let device = occupied.get_mut();
                match device.ips.iter_mut().find(|record| record.ip == ip) {
                    Some(record) => record.last_seen = now,
                    None => device.ips.push(IpRecord {
                        ip,
                        first_seen: now,
                        last_seen: now,
                    }),
                }
                device.last_seen = now;
                device.last_observed_ip = ip;
                device.sources.insert(source);
                device.seen_in_cycle = true;
                device.missed_cycles = 0;
                device.status = Status::Recent;
                if gateway_ip == Some(ip) {
                    device.tags.set(Tag::Gateway);
                }
                false
            }
            Entry::Vacant(slot) => {
                if at_cap {
                    // ADR-008 hard cap: new keys are dropped, existing
                    // ones still update, the warning persists.
                    self.cap_hit = true;
                    return ObserveOutcome::DroppedCapFull;
                }
                let mut tags = Tags::new();
                if mac.is_locally_administered() {
                    tags.set(Tag::PrivateAddress);
                }
                if gateway_ip == Some(ip) {
                    tags.set(Tag::Gateway);
                }
                let mut device = Device::new(key, ip, now, tags);
                device.sources.insert(source);
                slot.insert(device);
                self.order.push(key);
                true
            }
        };

        // Register this record as a holder of the address.
        let holders = ip_holders.entry(ip).or_default();
        if !holders.contains(&key) {
            holders.push(key);
        }

        // Mirror the neutral conflict note on every other record and on
        // this one (ADR-008: each record keeps the address; "also
        // observed under MAC …"; no verdict).
        for other in others {
            edit_device(devices, &other, |device| {
                push_note_if_absent(device, Note::IpAlsoObservedUnder { ip, mac });
            });
            edit_device(devices, &key, |device| {
                push_note_if_absent(device, Note::IpAlsoObservedUnder { ip, mac: other.mac });
            });
        }

        // Shared-MAC threshold (ADR-008): count this record's distinct
        // addresses inside the idle window (the same horizon that
        // governs Idle; an address counts while it has not aged past
        // `idle_min_age`) and tag + explain once the threshold is met.
        edit_device(devices, &key, |device| {
            let in_window = device
                .ips
                .iter()
                .filter(|record| {
                    now.mono()
                        .checked_duration_since(record.last_seen.mono())
                        .is_some_and(|age| age < config.idle_min_age)
                })
                .count() as u32;
            if in_window >= config.shared_mac_threshold {
                device.tags.set(Tag::MultipleIps);
                match device.notes.iter_mut().find_map(|note| match note {
                    Note::MultipleIps { distinct_ips } => Some(distinct_ips),
                    _ => None,
                }) {
                    Some(distinct_ips) => {
                        // The note only ever rises, never falls.
                        if *distinct_ips < in_window {
                            *distinct_ips = in_window;
                        }
                    }
                    None => device.notes.push(Note::MultipleIps {
                        distinct_ips: in_window,
                    }),
                }
            }
        });

        ObserveOutcome::Accepted { new_device }
    }

    /// The keys in the current [`SortMode`] order, stably sorted over
    /// the first-observation base order (FR-RG-06).
    fn sorted_order(&self) -> Vec<DeviceKey> {
        // (key, primary IP, hostname text when known)
        let mut entries: Vec<(DeviceKey, Ipv4Addr, Option<&str>)> = self
            .order
            .iter()
            .filter_map(|key| {
                self.devices.get(key).map(|device| {
                    (
                        *key,
                        device.primary_ip(),
                        device.hostname.value().map(|h| h.as_str()),
                    )
                })
            })
            .collect();
        match self.sort {
            SortMode::Ip => entries.sort_by_key(|entry| entry.1),
            SortMode::Hostname => entries.sort_by(|a, b| match (&a.2, &b.2) {
                (Some(x), Some(y)) => cmp_ascii_ci(x, y).then_with(|| a.1.cmp(&b.1)),
                // Unknown hostnames last, then by IP (FR-RG-06).
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => a.1.cmp(&b.1),
            }),
        }
        entries.into_iter().map(|(key, _, _)| key).collect()
    }
}

/// Applies `edit` to the record for `key`; `false` when `key` has no
/// record.
///
/// # Invariants
/// Every key in `order` and `ip_holders` has a record: the three
/// structures are written together in [`Registry::absorb`] and records
/// are never removed (ADR-008), so callers reaching this helper with a
/// listed key always get `true`. The boolean keeps the helper total —
/// it has no panicking path and never guesses (plan §8.7).
fn edit_device(
    devices: &mut HashMap<DeviceKey, Device>,
    key: &DeviceKey,
    edit: impl FnOnce(&mut Device),
) -> bool {
    match devices.get_mut(key) {
        Some(device) => {
            edit(device);
            true
        }
        None => false,
    }
}

/// Adds `note` to `device` unless an equal note is already present
/// (ADR-008 notes are deduplicated facts).
fn push_note_if_absent(device: &mut Device, note: Note) {
    if !device.notes.contains(&note) {
        device.notes.push(note);
    }
}

/// ASCII case-insensitive comparison (hostnames are ASCII by
/// construction, `crate::model::Hostname`).
///
/// Uppercase sorts adjacent to lowercase instead of before all
/// lowercase letters, which is what a person expects from a device
/// list.
fn cmp_ascii_ci(a: &str, b: &str) -> std::cmp::Ordering {
    let mut a = a.bytes().map(|byte| byte.to_ascii_lowercase());
    let mut b = b.bytes().map(|byte| byte.to_ascii_lowercase());
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) => match x.cmp(&y) {
                std::cmp::Ordering::Equal => continue,
                other => return other,
            },
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Behavioral suite of the registry (task T-201): one test per
    //! ADR-007 / ADR-008 rule and per acceptance criterion of the card,
    //! plus deterministic property tests (the T-002 `Lcg`; no
    //! `proptest` until a Plan Question approves it, no `sleep`
    //! anywhere — time only moves through `FakeClock`).
    use super::*;
    use crate::model::testing::Lcg;
    use crate::model::{FakeClock, Hostname as ModelHostname};
    use std::time::Duration;

    // -- fixtures ---------------------------------------------------------

    /// A globally-administered unicast MAC ending in `n` (the
    /// locally-administered bit is clear).
    fn mac(n: u8) -> MacAddr {
        MacAddr::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, n])
            .expect("globally administered unicast MAC")
    }

    /// A locally-administered unicast MAC ending in `n` (bit 1 set).
    fn private_mac(n: u8) -> MacAddr {
        MacAddr::from_octets([0x02, 0x11, 0x22, 0x33, 0x44, n])
            .expect("locally administered unicast MAC")
    }

    /// `192.0.2.n` (TEST-NET-1, plan §2.3: synthetic data only).
    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn key(iface: u32, mac: MacAddr) -> DeviceKey {
        DeviceKey {
            iface_index: iface,
            mac,
        }
    }

    fn observation(scan: u64, iface: u32, mac: MacAddr, ip: Ipv4Addr) -> Observation {
        Observation::new(ScanId::new(scan), iface, mac, ip, Source::ArpReply)
    }

    /// `observe` with `Source::NeighborTable` (the other scan source).
    fn neighbor_observation(scan: u64, iface: u32, mac: MacAddr, ip: Ipv4Addr) -> Observation {
        Observation::new(ScanId::new(scan), iface, mac, ip, Source::NeighborTable)
    }

    fn begin(registry: &mut Registry, scan: u64) {
        registry.begin_cycle(ScanId::new(scan));
    }

    fn end(
        registry: &mut Registry,
        clock: &FakeClock,
        scan: u64,
        outcome: ScanOutcome,
    ) -> Option<CycleSummary> {
        registry.end_cycle(ScanId::new(scan), outcome, clock)
    }

    /// Runs a complete empty cycle (no observations) at the clock's
    /// current time — the "device was absent" step of aging tests.
    fn absent_cycle(registry: &mut Registry, clock: &FakeClock, scan: u64) -> CycleSummary {
        begin(registry, scan);
        let summary = end(registry, clock, scan, ScanOutcome::Complete);
        summary.expect("matching id always finalizes")
    }

    fn device<'a>(registry: &'a Registry, k: &DeviceKey) -> &'a Device {
        registry.get(k).expect("record exists")
    }

    fn hostname(text: &str) -> Field<ModelHostname> {
        Field::Known {
            value: ModelHostname::try_from(text).expect("valid hostname"),
            source: Source::ReverseDns,
        }
    }

    // -- ADR-007: aging ----------------------------------------------------

    #[test]
    fn three_missed_cycles_below_the_age_floor_keep_the_device_recent() {
        // AC-1 (age condition unmet): the device is absent from 3
        // consecutive complete cycles, but only 30 s have passed.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));

        begin(&mut registry, 1);
        assert_eq!(
            registry.observe(observation(1, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::Accepted { new_device: true }
        );
        let seen = end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(seen.expect("cycle 1").observed, 1);

        for (scan, at) in [(2, 10), (3, 20), (4, 30)] {
            clock.advance(Duration::from_secs(at));
            let summary = absent_cycle(&mut registry, &clock, scan);
            assert_eq!(summary.absent, 1);
        }
        let record = device(&registry, &k);
        assert_eq!(record.missed_cycles, 3, "the cycle condition is met");
        assert_eq!(record.status, Status::Recent, "but the age floor is not");
        // One more complete cycle after the floor elapsed:
        clock.advance(Duration::from_secs(91)); // 30 + 91 = 121 s ≥ 120 s
        absent_cycle(&mut registry, &clock, 5);
        assert_eq!(device(&registry, &k).status, Status::Idle);
    }

    #[test]
    fn the_age_floor_is_reached_exactly_at_120_seconds() {
        // AC-1 boundary: `now − last_seen ≥ 120 s` is inclusive.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));

        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);

        clock.advance(Duration::from_secs(40));
        absent_cycle(&mut registry, &clock, 2);
        clock.advance(Duration::from_secs(40));
        absent_cycle(&mut registry, &clock, 3);
        assert_eq!(device(&registry, &k).status, Status::Recent);
        clock.advance(Duration::from_secs(40)); // exactly 120 s
        let summary = absent_cycle(&mut registry, &clock, 4);
        assert_eq!(device(&registry, &k).status, Status::Idle);
        assert_eq!(summary.newly_idle, 1);
        // 119 s would not have been enough:
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        for (scan, at) in [(2, 40), (3, 40), (4, 39)] {
            clock.advance(Duration::from_secs(at));
            absent_cycle(&mut registry, &clock, scan);
        }
        assert_eq!(device(&registry, &key(1, mac(2))).status, Status::Recent);
    }

    #[test]
    fn two_missed_cycles_are_not_enough_even_after_an_hour() {
        // AC-1 (cycle condition unmet): the age condition holds long
        // since, but the miss streak is only 2.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(3600));
        absent_cycle(&mut registry, &clock, 2);
        clock.advance(Duration::from_secs(3600));
        absent_cycle(&mut registry, &clock, 3);
        let record = device(&registry, &k);
        assert_eq!(record.missed_cycles, 2);
        assert_eq!(record.status, Status::Recent);
    }

    #[test]
    fn only_consecutive_complete_cycles_count() {
        // An observation resets the streak (ADR-007 "consecutive").
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(50));
        absent_cycle(&mut registry, &clock, 2); // streak 1
        clock.advance(Duration::from_secs(50));
        absent_cycle(&mut registry, &clock, 3); // streak 2
        clock.advance(Duration::from_secs(50));
        begin(&mut registry, 4); // seen again: streak reset
        registry.observe(observation(4, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 4, ScanOutcome::Complete);
        assert_eq!(device(&registry, &k).missed_cycles, 0);
        clock.advance(Duration::from_secs(200));
        absent_cycle(&mut registry, &clock, 5); // streak 1
        clock.advance(Duration::from_secs(200));
        absent_cycle(&mut registry, &clock, 6); // streak 2
        assert_eq!(device(&registry, &k).status, Status::Recent);
        assert_eq!(device(&registry, &k).missed_cycles, 2);
    }

    #[test]
    fn partial_failed_and_cancelled_cycles_never_age_devices() {
        // AC-2: none of the three non-complete outcomes increments
        // missed cycles or transitions a device, even after hours.
        for outcome in [
            ScanOutcome::Partial,
            ScanOutcome::Failed,
            ScanOutcome::Cancelled,
        ] {
            let mut registry = Registry::default();
            let mut clock = FakeClock::new();
            let k = key(1, mac(1));
            begin(&mut registry, 1);
            registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
            end(&mut registry, &clock, 1, ScanOutcome::Complete);
            for scan in 2..=21 {
                clock.advance(Duration::from_secs(60));
                begin(&mut registry, scan);
                let summary = end(&mut registry, &clock, scan, outcome).expect("matching id");
                assert_eq!(summary.missed_advanced, 0, "{outcome:?} must not age");
            }
            let record = device(&registry, &k);
            assert_eq!(record.missed_cycles, 0);
            assert_eq!(record.status, Status::Recent, "{outcome:?} must not idle");
        }
    }

    #[test]
    fn a_non_complete_cycle_does_not_interrupt_the_miss_streak() {
        // "3 consecutive complete cycles" counts complete cycles only:
        // a Partial in between neither ages nor resets the streak.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(50));
        absent_cycle(&mut registry, &clock, 2); // complete miss #1
        clock.advance(Duration::from_secs(50));
        begin(&mut registry, 3);
        end(&mut registry, &clock, 3, ScanOutcome::Partial); // no aging
        assert_eq!(device(&registry, &k).missed_cycles, 1);
        clock.advance(Duration::from_secs(50));
        absent_cycle(&mut registry, &clock, 4); // complete miss #2
        clock.advance(Duration::from_secs(50));
        absent_cycle(&mut registry, &clock, 5); // complete miss #3, 200 s
        let record = device(&registry, &k);
        assert_eq!(record.missed_cycles, 3);
        assert_eq!(record.status, Status::Idle);
    }

    #[test]
    fn manual_refresh_spam_does_not_idle_devices() {
        // AC-3: the age floor defeats rapid manual refreshes. Ten
        // complete cycles, one second apart, all missed.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        for scan in 2..=11 {
            clock.advance(Duration::from_secs(1));
            absent_cycle(&mut registry, &clock, scan);
        }
        let record = device(&registry, &k);
        assert_eq!(record.missed_cycles, 10);
        assert_eq!(record.status, Status::Recent, "only 10 s since last seen");
    }

    #[test]
    fn any_new_observation_returns_an_idle_device_to_recent() {
        // AC-4.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(200));
        absent_cycle(&mut registry, &clock, 2);
        clock.advance(Duration::from_secs(200));
        absent_cycle(&mut registry, &clock, 3);
        clock.advance(Duration::from_secs(200));
        absent_cycle(&mut registry, &clock, 4);
        assert_eq!(device(&registry, &k).status, Status::Idle);
        assert_eq!(device(&registry, &k).missed_cycles, 3);

        clock.advance(Duration::from_secs(1));
        begin(&mut registry, 5);
        let seen_at = clock.now();
        assert_eq!(
            registry.observe(observation(5, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::Accepted { new_device: false }
        );
        let record = device(&registry, &k);
        assert_eq!(record.status, Status::Recent, "immediately Recent");
        assert_eq!(record.missed_cycles, 0, "the streak is reset");
        assert_eq!(record.last_seen, seen_at);
        // And it does not go Idle at the end of the cycle it was seen in.
        end(&mut registry, &clock, 5, ScanOutcome::Complete);
        assert_eq!(device(&registry, &k).status, Status::Recent);
    }

    #[test]
    fn many_missed_cycles_accumulate_without_panicking() {
        // The counter saturates rather than overflowing (u32::MAX
        // cycles are not runnable; a long accumulation must stay
        // exact and panic-free).
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        for scan in 2..=201u64 {
            clock.advance(Duration::from_secs(1));
            absent_cycle(&mut registry, &clock, scan);
        }
        assert_eq!(device(&registry, &k).missed_cycles, 200);
        assert_eq!(device(&registry, &k).status, Status::Idle);
    }

    // -- ADR-008: identity and IP history -----------------------------------

    #[test]
    fn identity_is_interface_and_mac() {
        // AC-5: the same MAC on two interfaces is two records; the
        // same identity with different addresses is one record.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 2, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(1), ip(11)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(registry.device_count(), 2, "interface splits the identity");
        let on_iface_1 = device(&registry, &key(1, mac(1)));
        assert_eq!(on_iface_1.ips.len(), 2, "address change merges, not splits");
    }

    #[test]
    fn ipv4_changes_do_not_create_new_devices() {
        // AC-5.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        clock.advance(Duration::from_secs(10));
        registry.observe(observation(1, 1, mac(1), ip(42)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);

        assert_eq!(registry.device_count(), 1);
        let record = device(&registry, &k);
        assert_eq!(record.primary_ip(), ip(42));
        let ips: Vec<Ipv4Addr> = record.ips.iter().map(|r| r.ip).collect();
        assert_eq!(ips, [ip(10), ip(42)], "the old address is kept in history");
    }

    #[test]
    fn ip_history_tracks_first_and_last_seen_per_address() {
        // ADR-008: "first/last seen per IP".
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        let t0 = clock.now();
        clock.advance(Duration::from_secs(10));
        registry.observe(observation(1, 1, mac(1), ip(42)), &clock);
        let t1 = clock.now();
        clock.advance(Duration::from_secs(10));
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        let t2 = clock.now();
        end(&mut registry, &clock, 1, ScanOutcome::Complete);

        let record = device(&registry, &k);
        assert_eq!(record.first_seen, t0, "set once per session (FR-RG-02)");
        assert_eq!(record.last_seen, t2);
        let a = record.ips.iter().find(|r| r.ip == ip(10)).expect("ip 10");
        assert_eq!(a.first_seen, t0);
        assert_eq!(a.last_seen, t2, "re-observation advances last_seen");
        let b = record.ips.iter().find(|r| r.ip == ip(42)).expect("ip 42");
        assert_eq!(b.first_seen, t1);
        assert_eq!(b.last_seen, t1);
    }

    #[test]
    fn the_primary_ip_is_the_most_recently_observed_address() {
        // ADR-008 — including the tie at identical timestamps, where
        // the last write wins deterministically.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(1), ip(42)), &clock);
        assert_eq!(device(&registry, &k).primary_ip(), ip(42));
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        assert_eq!(device(&registry, &k).primary_ip(), ip(10));
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
    }

    #[test]
    fn one_address_under_two_macs_keeps_both_records_with_mirrored_notes() {
        // ADR-008: "each record keeps it in its history; neutral note
        // in Details; no alert, no red, no verdict".
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        let first = key(1, mac(1));
        let second = key(1, mac(2));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(50)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(50)), &clock);
        // A third observation of the same pairs must not duplicate.
        registry.observe(neighbor_observation(1, 1, mac(1), ip(50)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);

        assert_eq!(registry.device_count(), 2, "records are never merged");
        assert!(device(&registry, &first).has_ip(ip(50)));
        assert!(device(&registry, &second).has_ip(ip(50)));
        assert_eq!(
            device(&registry, &first).notes,
            vec![Note::IpAlsoObservedUnder {
                ip: ip(50),
                mac: mac(2)
            }]
        );
        assert_eq!(
            device(&registry, &second).notes,
            vec![Note::IpAlsoObservedUnder {
                ip: ip(50),
                mac: mac(1)
            }]
        );
        // The note wording is neutral (no verdict vocabulary).
        assert_eq!(
            device(&registry, &first).notes[0].to_string(),
            "192.0.2.50 also observed under MAC 00:11:22:33:44:02"
        );
    }

    #[test]
    fn the_same_mac_on_another_interface_is_not_a_conflict() {
        // Same hardware reachable through two interfaces keeps its
        // records clean of confusing self-referencing notes.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(50)), &clock);
        registry.observe(observation(1, 2, mac(1), ip(50)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert!(device(&registry, &key(1, mac(1))).notes.is_empty());
        assert!(device(&registry, &key(2, mac(1))).notes.is_empty());
    }

    // -- ADR-008: shared MACs ------------------------------------------------

    #[test]
    fn five_distinct_addresses_trigger_the_multiple_ips_tag_and_note() {
        // AC-6 at the default threshold, including the neutral note.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        for n in 1..=4u8 {
            registry.observe(observation(1, 1, mac(1), ip(n)), &clock);
        }
        assert!(!device(&registry, &k).tags.contains(Tag::MultipleIps));
        registry.observe(observation(1, 1, mac(1), ip(5)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);

        let record = device(&registry, &k);
        assert!(record.tags.contains(Tag::MultipleIps));
        assert_eq!(
            record.notes,
            vec![Note::MultipleIps { distinct_ips: 5 }],
            "the tag triggers the neutral explanation note"
        );
        let note_text = record.notes[0].to_string();
        assert!(note_text.contains("routers, proxy ARP, or virtual interfaces"));
        assert!(note_text.starts_with("Observed with 5 distinct addresses"));
    }

    #[test]
    fn four_addresses_do_not_trigger_the_tag_at_the_default_threshold() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        for n in 1..=4u8 {
            registry.observe(observation(1, 1, mac(1), ip(n)), &clock);
        }
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let record = device(&registry, &k);
        assert!(!record.tags.contains(Tag::MultipleIps));
        assert!(record.notes.is_empty());
    }

    #[test]
    fn addresses_outside_the_idle_window_do_not_count_toward_the_threshold() {
        // ADR-008 counts "distinct IPs seen within the idle window":
        // four addresses observed long ago have aged out of the window
        // and no longer count, so the fifth (recent) one does not trip
        // the threshold.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        for n in 1..=4u8 {
            registry.observe(observation(1, 1, mac(1), ip(n)), &clock);
        }
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(121)); // past the 120 s window
        begin(&mut registry, 2);
        registry.observe(observation(2, 1, mac(1), ip(5)), &clock);
        end(&mut registry, &clock, 2, ScanOutcome::Complete);

        let record = device(&registry, &k);
        assert_eq!(record.ips.len(), 5, "history keeps every address");
        assert!(
            !record.tags.contains(Tag::MultipleIps),
            "only one address is inside the window"
        );
        // Re-observing enough aged addresses brings them back into the
        // window and trips the threshold.
        begin(&mut registry, 3);
        for n in 1..=4u8 {
            registry.observe(observation(3, 1, mac(1), ip(n)), &clock);
        }
        end(&mut registry, &clock, 3, ScanOutcome::Complete);
        assert!(device(&registry, &k).tags.contains(Tag::MultipleIps));
    }

    #[test]
    fn the_shared_mac_threshold_is_configurable() {
        let config =
            RegistryConfig::try_new(3, Duration::from_secs(120), 2, 4096).expect("valid config");
        let mut registry = Registry::new(config).expect("valid");
        let clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(1)), &clock);
        assert!(!device(&registry, &k).tags.contains(Tag::MultipleIps));
        registry.observe(observation(1, 1, mac(1), ip(2)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let record = device(&registry, &k);
        assert!(record.tags.contains(Tag::MultipleIps));
        assert_eq!(record.notes, vec![Note::MultipleIps { distinct_ips: 2 }]);
    }

    #[test]
    fn the_multiple_ips_note_count_only_rises() {
        // The note records the in-window count when the threshold is
        // met; later observations can raise it, never lower it.
        let config =
            RegistryConfig::try_new(3, Duration::from_secs(120), 3, 4096).expect("valid config");
        let mut registry = Registry::new(config).expect("valid");
        let clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        for n in 1..=3u8 {
            registry.observe(observation(1, 1, mac(1), ip(n)), &clock);
        }
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(
            device(&registry, &k).notes,
            vec![Note::MultipleIps { distinct_ips: 3 }]
        );
        begin(&mut registry, 2);
        registry.observe(observation(2, 1, mac(1), ip(4)), &clock);
        end(&mut registry, &clock, 2, ScanOutcome::Complete);
        assert_eq!(
            device(&registry, &k).notes,
            vec![Note::MultipleIps { distinct_ips: 4 }],
            "the count rises with the window content"
        );
        assert_eq!(device(&registry, &k).notes.len(), 1, "still one note");
    }

    // -- Tags ----------------------------------------------------------------

    #[test]
    fn the_local_device_is_tagged_sourced_and_exempt_from_aging() {
        // Plan §5.3 `This device`: interface data, source
        // LocalInterface, present by construction (nobody ARPs itself).
        // T-201 execution report PQ-1 records the aging exemption.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(9));
        assert_eq!(
            registry.insert_local_device(1, mac(9), ip(1), &clock),
            ObserveOutcome::Accepted { new_device: true }
        );
        let record = device(&registry, &k);
        assert!(record.tags.contains(Tag::ThisDevice));
        assert!(record.sources.contains(Source::LocalInterface));
        assert_eq!(record.primary_ip(), ip(1));
        assert_eq!(record.status, Status::Recent);

        // Ten complete cycles without any observation, an hour later.
        clock.advance(Duration::from_secs(3600));
        for scan in 1..=10u64 {
            absent_cycle(&mut registry, &clock, scan);
        }
        let record = device(&registry, &k);
        assert_eq!(record.status, Status::Recent, "structural presence");
        assert_eq!(record.missed_cycles, 0);
    }

    #[test]
    fn locally_administered_macs_get_the_private_address_tag() {
        // Plan §5.3.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, private_mac(2), ip(20)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert!(
            !device(&registry, &key(1, mac(1)))
                .tags
                .contains(Tag::PrivateAddress)
        );
        assert!(
            device(&registry, &key(1, private_mac(2)))
                .tags
                .contains(Tag::PrivateAddress)
        );
    }

    #[test]
    fn the_gateway_tag_applies_only_to_observed_devices_holding_the_address() {
        // Plan §5.3: applied after the device has been observed — in
        // either order of the two events.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        let router = key(1, mac(1));
        let other = key(1, mac(2));

        // Order 1: device observed first, gateway learned later.
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(1)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(2)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        registry.set_gateway_ip(ip(1));
        assert!(device(&registry, &router).tags.contains(Tag::Gateway));
        assert!(!device(&registry, &other).tags.contains(Tag::Gateway));

        // Order 2: gateway learned first, device observed later.
        let mut registry = Registry::default();
        begin(&mut registry, 1);
        registry.set_gateway_ip(ip(1));
        registry.observe(observation(1, 1, mac(1), ip(1)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(3)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert!(device(&registry, &router).tags.contains(Tag::Gateway));
        assert!(!device(&registry, &other).tags.contains(Tag::Gateway));
    }

    #[test]
    fn the_gateway_tag_follows_a_gateway_address_change() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(1)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(2)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        registry.set_gateway_ip(ip(1));
        assert!(
            device(&registry, &key(1, mac(1)))
                .tags
                .contains(Tag::Gateway)
        );
        registry.set_gateway_ip(ip(2));
        assert!(
            !device(&registry, &key(1, mac(1)))
                .tags
                .contains(Tag::Gateway),
            "the old gateway loses the tag"
        );
        assert!(
            device(&registry, &key(1, mac(2)))
                .tags
                .contains(Tag::Gateway)
        );
    }

    #[test]
    fn enrichment_fields_are_stored_for_existing_records_only() {
        // The registry accepts the Field values of T-202/T-203 as-is.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let k = key(1, mac(1));
        assert_eq!(device(&registry, &k).hostname, Field::Pending);

        assert!(registry.set_hostname(&k, hostname("printer.lan")));
        assert_eq!(
            device(&registry, &k).hostname,
            Field::Known {
                value: ModelHostname::try_from("printer.lan").expect("valid"),
                source: Source::ReverseDns,
            }
        );
        assert!(registry.set_hostname(&k, Field::Unknown));
        assert_eq!(device(&registry, &k).hostname, Field::Unknown);
        let vendor = Field::Known {
            value: crate::model::DisplayText::try_from("Example Corp").expect("valid"),
            source: Source::VendorDb,
        };
        assert!(registry.set_vendor(&k, vendor.clone()));
        assert_eq!(device(&registry, &k).vendor, vendor);

        let unknown_key = key(9, mac(9));
        assert!(!registry.set_hostname(&unknown_key, Field::Unknown));
        assert!(!registry.set_vendor(&unknown_key, Field::Unknown));
    }

    // -- Hard cap (ADR-008) ---------------------------------------------------

    #[test]
    fn the_cap_drops_new_keys_but_keeps_updating_existing_ones() {
        // AC-7 at the real ADR-008 cap: 4,096 records fill the
        // registry, a new key is dropped with a persistent warning, an
        // existing key still updates.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        begin(&mut registry, 1);
        // 4,096 distinct identities, 4,096 distinct addresses.
        let mut last_octet = 1u8;
        let mut third_octet = 0u8;
        for n in 0..REGISTRY_CAP as u32 {
            if n % 254 == 0 && n > 0 {
                third_octet += 1;
                last_octet = 1;
            }
            let address = Ipv4Addr::new(192, 0, third_octet, last_octet);
            let mac_addr =
                MacAddr::from_octets([0x00, 0x11, 0x22, 0x33, (n >> 8) as u8, (n & 0xff) as u8])
                    .expect("unicast");
            let outcome = registry.observe(observation(1, 1, mac_addr, address), &clock);
            assert_eq!(
                outcome,
                ObserveOutcome::Accepted { new_device: true },
                "record {n} must be accepted"
            );
            last_octet += 1;
        }
        assert_eq!(registry.device_count(), REGISTRY_CAP);
        assert!(!registry.cap_warning(), "filled is not exceeded");

        clock.advance(Duration::from_secs(5));
        let newcomer = MacAddr::from_octets([0x00, 0x11, 0x22, 0x33, 0xff, 0xfe]).expect("unicast");
        assert_eq!(
            registry.observe(observation(1, 1, newcomer, ip(200)), &clock),
            ObserveOutcome::DroppedCapFull
        );
        assert_eq!(registry.device_count(), REGISTRY_CAP, "no record added");
        assert!(registry.cap_warning(), "the warning is raised");

        // An existing key still updates.
        let existing = MacAddr::from_octets([0x00, 0x11, 0x22, 0x33, 0x00, 0x01]).expect("unicast");
        let k = key(1, existing);
        let before = device(&registry, &k).last_seen;
        clock.advance(Duration::from_secs(5));
        assert_eq!(
            registry.observe(observation(1, 1, existing, ip(1)), &clock),
            ObserveOutcome::Accepted { new_device: false }
        );
        assert!(device(&registry, &k).last_seen > before);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
    }

    #[test]
    fn a_small_cap_behaves_identically() {
        // The same rules at a cheap size.
        let config =
            RegistryConfig::try_new(3, Duration::from_secs(120), 5, 4).expect("valid config");
        let mut registry = Registry::new(config).expect("valid");
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        for n in 1..=4u8 {
            assert_eq!(
                registry.observe(observation(1, 1, mac(n), ip(n)), &clock),
                ObserveOutcome::Accepted { new_device: true }
            );
        }
        assert_eq!(
            registry.observe(observation(1, 1, mac(5), ip(5)), &clock),
            ObserveOutcome::DroppedCapFull
        );
        assert_eq!(registry.device_count(), 4);
        assert!(registry.cap_warning());
        assert_eq!(registry.capacity(), 4);
        // Repeats of the dropped key stay dropped…
        assert_eq!(
            registry.observe(observation(1, 1, mac(5), ip(6)), &clock),
            ObserveOutcome::DroppedCapFull
        );
        // …while existing keys update.
        assert_eq!(
            registry.observe(observation(1, 1, mac(4), ip(44)), &clock),
            ObserveOutcome::Accepted { new_device: false }
        );
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(registry.device_count(), 4);
    }

    #[test]
    fn the_cap_warning_is_persistent_once_raised() {
        let config =
            RegistryConfig::try_new(3, Duration::from_secs(120), 5, 2).expect("valid config");
        let mut registry = Registry::new(config).expect("valid");
        let mut clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(1)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(2)), &clock);
        registry.observe(observation(1, 1, mac(3), ip(3)), &clock);
        assert!(registry.cap_warning());
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(300));
        for scan in 2..=5u64 {
            begin(&mut registry, scan);
            registry.observe(observation(scan, 1, mac(1), ip(1)), &clock);
            end(&mut registry, &clock, scan, ScanOutcome::Complete);
        }
        assert!(
            registry.cap_warning(),
            "records are never removed, so the warning never clears"
        );
    }

    // -- Scan discipline (FR-RG-03) -------------------------------------------

    #[test]
    fn observations_tagged_with_a_non_current_scan_are_ignored() {
        // AC-8.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 5);
        assert_eq!(
            registry.observe(observation(4, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::IgnoredScanMismatch
        );
        assert_eq!(
            registry.observe(observation(6, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::IgnoredScanMismatch
        );
        assert_eq!(registry.device_count(), 0, "ignored means no record");
        assert_eq!(
            registry.observe(observation(5, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::Accepted { new_device: true }
        );
        assert_eq!(registry.device_count(), 1);
    }

    #[test]
    fn observations_without_a_cycle_in_progress_are_ignored() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        assert_eq!(
            registry.observe(observation(1, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::IgnoredScanMismatch
        );
        begin(&mut registry, 1);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(
            registry.observe(observation(1, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::IgnoredScanMismatch,
            "the cycle is over"
        );
        assert_eq!(registry.device_count(), 0);
    }

    #[test]
    fn end_cycle_with_a_mismatched_scan_id_is_ignored() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        assert!(end(&mut registry, &clock, 2, ScanOutcome::Complete).is_none());
        // The cycle is still in progress: id 1 still observes.
        assert_eq!(
            registry.observe(observation(1, 1, mac(2), ip(20)), &clock),
            ObserveOutcome::Accepted { new_device: true }
        );
        let summary = end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(summary.expect("matching id").observed, 2);
        // A second end of the same id is a mismatch too (already over).
        assert!(end(&mut registry, &clock, 1, ScanOutcome::Complete).is_none());
    }

    #[test]
    fn late_arrivals_from_an_old_scan_do_not_corrupt_the_current_cycle() {
        // AC-8: an observation tagged with the previous scan must not
        // mark the device as seen in the current one.
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let k = key(1, mac(1));
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        clock.advance(Duration::from_secs(200));
        begin(&mut registry, 2);
        assert_eq!(
            registry.observe(observation(1, 1, mac(1), ip(10)), &clock),
            ObserveOutcome::IgnoredScanMismatch
        );
        let summary = end(&mut registry, &clock, 2, ScanOutcome::Complete).expect("matching id");
        assert_eq!(summary.absent, 1, "the device was not seen in cycle 2");
        assert_eq!(device(&registry, &k).missed_cycles, 1);
        assert_eq!(device(&registry, &k).status, Status::Recent);
    }

    #[test]
    fn beginning_a_new_cycle_supersedes_an_unfinished_one() {
        // The old cycle can never deliver a matching end_cycle, so it
        // can never age devices.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        begin(&mut registry, 2); // supersedes cycle 1
        assert!(end(&mut registry, &clock, 1, ScanOutcome::Complete).is_none());
        assert_eq!(
            registry.current_scan_id(),
            Some(ScanId::new(2)),
            "cycle 2 is still current"
        );
        let summary = end(&mut registry, &clock, 2, ScanOutcome::Complete);
        // The cycle-1 observation predates cycle 2's begin, so the
        // device counts as absent in cycle 2.
        assert_eq!(summary.expect("matching id").absent, 1);
    }

    // -- Ordering and selection (FR-RG-06) ------------------------------------

    #[test]
    fn sorting_by_ip_is_numeric_not_lexicographic() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip4(10, 0, 0, 10)), &clock);
        registry.observe(observation(1, 1, mac(2), ip4(10, 0, 0, 2)), &clock);
        registry.observe(observation(1, 1, mac(3), ip4(10, 0, 0, 100)), &clock);
        registry.observe(observation(1, 1, mac(4), ip4(10, 0, 0, 1)), &clock);
        registry.observe(observation(1, 1, mac(5), ip4(9, 255, 255, 254)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let sorted = registry.sorted_keys();
        let addresses: Vec<Ipv4Addr> = sorted
            .iter()
            .map(|k| registry.get(k).expect("record").primary_ip())
            .collect();
        assert_eq!(
            addresses,
            [
                ip4(9, 255, 255, 254),
                ip4(10, 0, 0, 1),
                ip4(10, 0, 0, 2),
                ip4(10, 0, 0, 10),
                ip4(10, 0, 0, 100),
            ],
            "numeric Ipv4Addr order, not string order"
        );
    }

    #[test]
    fn sorting_by_hostname_puts_known_first_and_unknown_last_by_ip() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(9)), &clock);
        registry.set_hostname(&key(1, mac(1)), hostname("Router.LAN"));
        registry.observe(observation(1, 1, mac(2), ip(2)), &clock);
        registry.set_hostname(&key(1, mac(2)), Field::Unknown);
        registry.observe(observation(1, 1, mac(3), ip(3)), &clock);
        registry.set_hostname(&key(1, mac(3)), hostname("ap.lan"));
        registry.observe(observation(1, 1, mac(4), ip(7)), &clock);
        // hostname stays Pending for mac(4)
        end(&mut registry, &clock, 1, ScanOutcome::Complete);

        registry.set_sort_mode(SortMode::Hostname);
        let sorted = registry.sorted_keys();
        let names: Vec<Option<String>> = sorted
            .iter()
            .map(|k| {
                registry
                    .get(k)
                    .expect("record")
                    .hostname
                    .value()
                    .map(|h| h.as_str().to_owned())
            })
            .collect();
        // Known hostnames first, ASCII case-insensitively
        // ("ap.lan" < "Router.LAN"); unknown hostnames last, by IP
        // (mac(4) ip .7 before mac(2) ip .2? no: .2 < .7).
        assert_eq!(
            names,
            [
                Some("ap.lan".to_owned()),
                Some("Router.LAN".to_owned()),
                None,
                None
            ]
        );
        let unknown_ips: Vec<Ipv4Addr> = sorted
            .iter()
            .filter_map(|k| {
                let record = registry.get(k).expect("record");
                (!record.hostname.is_known()).then_some(record.primary_ip())
            })
            .collect();
        assert_eq!(unknown_ips, [ip(2), ip(7)], "unknown hostnames last, by IP");
    }

    #[test]
    fn hostname_sort_ties_fall_back_to_the_ip() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(30)), &clock);
        registry.set_hostname(&key(1, mac(1)), hostname("node.lan"));
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        registry.set_hostname(&key(1, mac(2)), hostname("node.lan"));
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        registry.set_sort_mode(SortMode::Hostname);
        let addresses: Vec<Ipv4Addr> = registry
            .sorted_keys()
            .iter()
            .map(|k| registry.get(k).expect("record").primary_ip())
            .collect();
        assert_eq!(addresses, [ip(20), ip(30)]);
    }

    #[test]
    fn sorting_is_stable_for_equal_sort_keys() {
        // Two records sharing one address (the ADR-008 conflict case)
        // keep their first-observation order under the IP sort.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(50)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(50)), &clock);
        registry.observe(observation(1, 1, mac(3), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        for _ in 0..3 {
            assert_eq!(
                registry.sorted_keys(),
                [key(1, mac(3)), key(1, mac(1)), key(1, mac(2))],
                "equal keys keep first-observation order"
            );
        }
        // Same under the hostname sort (all unknown → by IP, equal IP
        // stable).
        registry.set_sort_mode(SortMode::Hostname);
        assert_eq!(
            registry.sorted_keys(),
            [key(1, mac(3)), key(1, mac(1)), key(1, mac(2))]
        );
    }

    #[test]
    fn a_primary_ip_change_re_sorts_the_list() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        assert_eq!(registry.sorted_keys(), [key(1, mac(1)), key(1, mac(2))]);
        begin(&mut registry, 2);
        registry.observe(observation(2, 1, mac(1), ip(30)), &clock);
        end(&mut registry, &clock, 2, ScanOutcome::Complete);
        assert_eq!(
            registry.sorted_keys(),
            [key(1, mac(2)), key(1, mac(1))],
            "mac(1) moved below mac(2) after switching to .30"
        );
    }

    #[test]
    fn selection_is_bound_to_the_device_key_not_the_row() {
        // AC-9: the highlight stays on the same device across
        // updates, re-sorts and sort-mode changes.
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        registry.observe(observation(1, 1, mac(3), ip(30)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let chosen = key(1, mac(1));
        assert!(registry.select(chosen));
        assert!(registry.selected_device().expect("selected").has_ip(ip(10)));

        // Refresh another device so the rows change…
        begin(&mut registry, 2);
        registry.observe(observation(2, 1, mac(3), ip(5)), &clock);
        end(&mut registry, &clock, 2, ScanOutcome::Complete);
        // …and flip to the hostname sort and back.
        registry.set_sort_mode(SortMode::Hostname);
        assert_eq!(registry.selected_key(), Some(chosen));
        registry.set_sort_mode(SortMode::Ip);
        assert_eq!(registry.selected_key(), Some(chosen));
        let selected = registry.selected_device().expect("selected");
        assert_eq!(selected.key, chosen);
        assert!(selected.has_ip(ip(10)), "still the same record");
        assert_eq!(
            registry.selected_key(),
            Some(chosen),
            "the selection survived every re-sort"
        );
    }

    #[test]
    fn select_next_and_previous_walk_the_order_and_stop_at_the_ends() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(30)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        registry.observe(observation(1, 1, mac(3), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        // Order by IP: mac(3) .10, mac(2) .20, mac(1) .30.

        // No selection: next selects the first.
        assert_eq!(registry.select_next(), Some(key(1, mac(3))));
        assert_eq!(registry.select_next(), Some(key(1, mac(2))));
        assert_eq!(registry.select_next(), Some(key(1, mac(1))));
        assert_eq!(
            registry.select_next(),
            Some(key(1, mac(1))),
            "the last row holds the selection"
        );
        assert_eq!(registry.select_previous(), Some(key(1, mac(2))));
        assert_eq!(registry.select_previous(), Some(key(1, mac(3))));
        assert_eq!(
            registry.select_previous(),
            Some(key(1, mac(3))),
            "the first row holds the selection"
        );
        // First/last jumps.
        assert_eq!(registry.select_last(), Some(key(1, mac(1))));
        assert_eq!(registry.select_first(), Some(key(1, mac(3))));
        // With no selection, previous also starts at the first.
        registry.clear_selection();
        assert_eq!(registry.selected_key(), None);
        assert_eq!(registry.select_previous(), Some(key(1, mac(3))));

        // A sort-mode change re-targets next/previous to the new order
        // while keeping the current selection.
        registry.set_sort_mode(SortMode::Hostname);
        assert_eq!(registry.select_next(), Some(key(1, mac(2))));
    }

    #[test]
    fn selecting_an_unknown_key_is_rejected_and_keeps_the_selection() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let chosen = key(1, mac(1));
        assert!(registry.select(chosen));
        assert!(!registry.select(key(2, mac(1))), "unknown interface part");
        assert!(!registry.select(key(1, mac(7))), "unknown MAC part");
        assert_eq!(registry.selected_key(), Some(chosen));
    }

    #[test]
    fn selection_on_an_empty_registry_is_none() {
        let mut registry = Registry::default();
        assert_eq!(registry.device_count(), 0);
        assert_eq!(registry.select_next(), None);
        assert_eq!(registry.select_previous(), None);
        assert_eq!(registry.select_first(), None);
        assert_eq!(registry.select_last(), None);
        assert!(!registry.select(key(1, mac(1))));
        assert_eq!(registry.selected_device(), None);
    }

    // -- API surface -----------------------------------------------------------

    #[test]
    fn new_rejects_invalid_configs_and_default_matches_the_adrs() {
        assert!(Registry::new(RegistryConfig::default()).is_ok());
        let bad = RegistryConfig {
            idle_after_cycles: 0,
            ..RegistryConfig::default()
        };
        assert!(Registry::new(bad).is_err(), "the boundary re-validates");
        let with_defaults = Registry::new(RegistryConfig::default()).expect("default is valid");
        let config = with_defaults.config();
        assert_eq!(config.idle_after_cycles, 3);
        assert_eq!(config.idle_min_age, Duration::from_secs(120));
        assert_eq!(config.shared_mac_threshold, 5);
        assert_eq!(config.max_devices, REGISTRY_CAP);
    }

    #[test]
    fn cycle_summaries_report_the_aging_accounting() {
        let mut registry = Registry::default();
        let mut clock = FakeClock::new();
        let local = key(1, mac(9));
        registry.insert_local_device(1, mac(9), ip(9), &clock);
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        let summary = end(&mut registry, &clock, 1, ScanOutcome::Complete).expect("matching id");
        assert_eq!(summary.id, ScanId::new(1));
        assert_eq!(summary.outcome, ScanOutcome::Complete);
        assert_eq!(summary.observed, 2);
        assert_eq!(summary.absent, 0);
        assert_eq!(summary.missed_advanced, 0);
        assert_eq!(summary.newly_idle, 0);
        // The local device is counted in neither bucket.
        assert_eq!(registry.device_count(), 3);

        clock.advance(Duration::from_secs(200));
        let summary = absent_cycle(&mut registry, &clock, 2);
        assert_eq!(summary.observed, 0);
        assert_eq!(summary.absent, 2, "only the two scan-observed devices");
        assert_eq!(summary.missed_advanced, 2);
        assert_eq!(
            summary.newly_idle, 0,
            "one miss cannot reach the 3-cycle rule"
        );
        // Two more missed cycles bring both to the threshold; the age
        // floor has long been passed.
        absent_cycle(&mut registry, &clock, 3);
        let summary = absent_cycle(&mut registry, &clock, 4);
        assert_eq!(summary.newly_idle, 2);
        assert_eq!(device(&registry, &local).status, Status::Recent);
    }

    #[test]
    fn iter_walks_records_in_first_observation_order() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(observation(1, 1, mac(3), ip(30)), &clock);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(2), ip(20)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let keys: Vec<DeviceKey> = registry.iter().map(|d| d.key).collect();
        assert_eq!(
            keys,
            [key(1, mac(3)), key(1, mac(1)), key(1, mac(2))],
            "insertion order, not key or IP order"
        );
        let sorted: Vec<DeviceKey> = registry.iter_sorted().map(|d| d.key).collect();
        assert_eq!(sorted, [key(1, mac(1)), key(1, mac(2)), key(1, mac(3))]);
        assert_eq!(
            registry.get(&key(1, mac(1))).expect("record").primary_ip(),
            ip(10)
        );
    }

    #[test]
    fn sources_accumulate_across_discovery_paths() {
        let mut registry = Registry::default();
        let clock = FakeClock::new();
        begin(&mut registry, 1);
        registry.observe(neighbor_observation(1, 1, mac(1), ip(10)), &clock);
        registry.observe(observation(1, 1, mac(1), ip(10)), &clock);
        end(&mut registry, &clock, 1, ScanOutcome::Complete);
        let record = device(&registry, &key(1, mac(1)));
        assert!(record.sources.contains(Source::NeighborTable));
        assert!(record.sources.contains(Source::ArpReply));
        assert_eq!(record.sources.len(), 2);
    }

    #[test]
    fn current_scan_id_tracks_the_cycle() {
        let mut registry = Registry::default();
        assert_eq!(registry.current_scan_id(), None);
        registry.begin_cycle(ScanId::new(41));
        assert_eq!(registry.current_scan_id(), Some(ScanId::new(41)));
        registry
            .end_cycle(ScanId::new(41), ScanOutcome::Complete, &FakeClock::new())
            .expect("matching id");
        assert_eq!(registry.current_scan_id(), None);
    }

    // -- Property tests (deterministic, std-only) -------------------------------

    /// Runs one randomized session and checks the ADR-007/ADR-008
    /// invariants after every completed cycle.
    #[test]
    fn property_sessions_preserve_the_aging_and_identity_invariants() {
        let mut rng = Lcg::seeded(0x5EED_0201);
        for _round in 0..24u64 {
            let config = RegistryConfig::try_new(
                1 + rng.next_below(4) as u32,                // cycles 1..=4
                Duration::from_secs(1 + rng.next_below(10)), // floor 1..=10 s
                2 + rng.next_below(3) as u32,                // threshold 2..=4
                16 + rng.next_below(16) as usize,            // cap 16..=31
            )
            .expect("valid random config");
            let mut registry = Registry::new(config).expect("valid config");
            let mut clock = FakeClock::new();
            let macs: Vec<MacAddr> = (0..8u8)
                .map(|n| MacAddr::from_octets([0x00, 0x11, 0x22, 0x33, 0x44, n]).expect("unicast"))
                .collect();
            let addresses: Vec<Ipv4Addr> = (1..=8u8).map(ip).collect();
            let mut attempted: Vec<DeviceKey> = Vec::new();
            let mut next_scan = 0u64;

            for _step in 0..150 {
                clock.advance(Duration::from_secs(rng.next_below(9)));
                next_scan += 1;
                registry.begin_cycle(ScanId::new(next_scan));
                for (n, mac_addr) in macs.iter().enumerate() {
                    if rng.next_below(3) == 0 {
                        let address = addresses[rng.next_below(addresses.len() as u64) as usize];
                        let obs = Observation::new(
                            ScanId::new(next_scan),
                            1 + (n % 2) as u32,
                            *mac_addr,
                            address,
                            Source::NeighborTable,
                        );
                        let outcome = registry.observe(obs, &clock);
                        if matches!(outcome, ObserveOutcome::Accepted { .. }) {
                            let k = DeviceKey {
                                iface_index: 1 + (n % 2) as u32,
                                mac: *mac_addr,
                            };
                            if !attempted.contains(&k) {
                                attempted.push(k);
                            }
                        }
                    }
                }
                // A late arrival from the previous scan is always
                // ignored.
                if next_scan > 1 {
                    let late = Observation::new(
                        ScanId::new(next_scan - 1),
                        1,
                        macs[0],
                        addresses[0],
                        Source::NeighborTable,
                    );
                    assert_eq!(
                        registry.observe(late, &clock),
                        ObserveOutcome::IgnoredScanMismatch
                    );
                }
                let outcome = match rng.next_below(4) {
                    0 => ScanOutcome::Complete,
                    1 => ScanOutcome::Partial,
                    2 => ScanOutcome::Failed,
                    _ => ScanOutcome::Cancelled,
                };
                let summary = registry
                    .end_cycle(ScanId::new(next_scan), outcome, &clock)
                    .expect("matching id always finalizes");
                let now = clock.now();
                let config = registry.config();

                // Invariant 1: the record set is exactly the accepted
                // identities, capped.
                let expected_count = attempted.len().min(config.max_devices);
                assert_eq!(registry.device_count(), expected_count);

                // Invariant 2: aging is exactly ADR-007.
                for record in registry.iter() {
                    let age = now
                        .mono()
                        .checked_duration_since(record.last_seen.mono())
                        .unwrap_or_default();
                    if record.status == Status::Idle {
                        assert!(
                            record.missed_cycles >= config.idle_after_cycles,
                            "Idle without the cycle condition"
                        );
                        assert!(age >= config.idle_min_age, "Idle below the age floor");
                    } else if outcome.is_complete()
                        && record.missed_cycles >= config.idle_after_cycles
                        && age >= config.idle_min_age
                    {
                        assert_eq!(
                            record.status,
                            Status::Idle,
                            "both conditions hold but the device is Recent"
                        );
                    }
                    // Invariant 3: history hygiene.
                    assert!(!record.ips.is_empty());
                    assert!(record.has_ip(record.primary_ip()));
                    let mut seen_ips: Vec<Ipv4Addr> = record.ips.iter().map(|r| r.ip).collect();
                    seen_ips.sort_unstable();
                    seen_ips.dedup();
                    assert_eq!(
                        seen_ips.len(),
                        record.ips.len(),
                        "no duplicate address entries"
                    );
                    let mut notes = record.notes.clone();
                    notes.dedup();
                    assert_eq!(notes.len(), record.notes.len(), "notes are unique");
                }
                assert_eq!(summary.observed + summary.absent, registry.device_count());
            }
            // Invariant 4: the cap warning is exactly "a key was
            // dropped at the cap".
            assert_eq!(
                registry.cap_warning(),
                attempted.len() > registry.capacity()
            );
        }
    }

    #[test]
    fn property_sorted_keys_are_a_stable_permutation_of_the_records() {
        let mut rng = Lcg::seeded(0x0D1C_E202);
        for _round in 0..24u64 {
            let mut registry = Registry::default();
            let clock = FakeClock::new();
            let count = 1 + rng.next_below(24) as usize;
            begin(&mut registry, 1);
            for n in 0..count {
                let mac_addr = MacAddr::from_octets([
                    0x00,
                    0x11,
                    0x22,
                    0x33,
                    (n >> 8) as u8,
                    (n & 0xff) as u8,
                ])
                .expect("unicast");
                // Two devices may share an address (stability fodder):
                // a quarter of the pool reuses .50.
                let address = if rng.next_below(4) == 0 {
                    ip(50)
                } else {
                    ip(1 + (n % 40) as u8)
                };
                registry.observe(observation(1, 1, mac_addr, address), &clock);
                if rng.next_below(3) == 0 {
                    let name = match rng.next_below(3) {
                        0 => "ap.lan",
                        1 => "Router.LAN",
                        _ => "printer.example",
                    };
                    registry.set_hostname(&key(1, mac_addr), hostname(name));
                }
            }
            end(&mut registry, &clock, 1, ScanOutcome::Complete);

            for mode in [SortMode::Ip, SortMode::Hostname] {
                registry.set_sort_mode(mode);
                let sorted = registry.sorted_keys();
                // Permutation: same set, no duplicates.
                assert_eq!(sorted.len(), registry.device_count());
                let mut unique = sorted.clone();
                unique.sort_unstable();
                unique.dedup();
                assert_eq!(unique.len(), sorted.len(), "no key twice");
                // Comparator consistency + stability: consecutive
                // entries never invert; equal entries keep their
                // first-observation positions.
                let position = |k: DeviceKey| {
                    registry
                        .iter()
                        .position(|d| d.key == k)
                        .expect("every key has a record")
                };
                for pair in sorted.windows(2) {
                    let a = registry.get(&pair[0]).expect("record");
                    let b = registry.get(&pair[1]).expect("record");
                    let ordered = match mode {
                        SortMode::Ip => a.primary_ip() <= b.primary_ip(),
                        SortMode::Hostname => {
                            let (x, y) = (
                                a.hostname.value().map(|h| h.as_str()),
                                b.hostname.value().map(|h| h.as_str()),
                            );
                            match (x, y) {
                                (Some(x), Some(y)) => {
                                    cmp_ascii_ci(x, y) != std::cmp::Ordering::Greater
                                }
                                (Some(_), None) => true,
                                (None, Some(_)) => false,
                                (None, None) => a.primary_ip() <= b.primary_ip(),
                            }
                        }
                    };
                    assert!(ordered, "{mode:?}: {a:?} must not follow {b:?}");
                    if let SortMode::Ip = mode
                        && a.primary_ip() == b.primary_ip()
                    {
                        assert!(
                            position(pair[0]) < position(pair[1]),
                            "equal keys keep first-observation order"
                        );
                    }
                }
            }
        }
    }
}
