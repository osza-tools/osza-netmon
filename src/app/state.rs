// SPDX-License-Identifier: GPL-3.0-only

//! The application state: screens, the interface snapshot, the
//! registry, the scheduler, the message log and the counters
//! (plan §8.1, §6.6 FR-UI-05/07, task T-205).
//!
//! [`AppState`] is the single owner of everything the pure
//! [`update`](super::update::update) function mutates — no locks, no atomics:
//! it lives on the main thread of the event loop (ADR-012; §8.3 "no
//! locks in AppState — single-threaded by construction"). The runtime
//! owns the state; T-301's terminal renders read-only views of it.
//!
//! # Screens and overlays
//!
//! [`Screen`] is the modal stack of §6.6: `Notice → Scope →
//! Dashboard ⇄ Details`. Help is **not** a screen — it is the
//! [`help_open`](AppState::help_open) overlay flag (`?` toggles from
//! Dashboard/Details, `Esc` closes). `too_small` is not a screen
//! either: it overlays whatever screen is active when the terminal is
//! under 80×24 (NFR-08) and recovers automatically (FR-ST-04) — the
//! underlying screen and the whole state survive a shrink/grow cycle
//! unchanged.
//!
//! # The interface snapshot ([`ScopeEntry`]) — deviation D-1
//!
//! The card names the scope-screen list `interfaces:
//! Vec<InterfaceInfo>`, but `InterfaceInfo`'s fields are private to
//! `net::interfaces` (the only production constructor is
//! `enumerate_interfaces`), so no deterministic *fake* interface list
//! can exist for `src/app/` tests — while the card's own AC-2 script
//! and AC-5 "fake interface list" require exactly that. The app
//! therefore snapshots each `InterfaceInfo` into its own
//! [`ScopeEntry`] (a plain projection of the public accessors,
//! including the derived eligibility/class views) at the
//! [`AppState::new`] boundary; [`AppState::with_scope_entries`]
//! accepts synthetic entries for tests (and any future in-crate
//! consumer). The production signature is unchanged and the snapshot
//! mirrors the source accessors one-to-one (tested relationally
//! against `enumerate_interfaces`). See the execution report §5/§8.
//!
//! # Confirmed scope
//!
//! The scope facts the card lists (`scope`, `iface_index`,
//! `iface_name`, `iface_mac`, `own_ip`, `gateway_ip` — "from the
//! confirmed interface") exist only once a scope is confirmed; before
//! that there is honestly nothing to show. They are grouped into
//! [`ConfirmedScope`], held as the private `confirmed` field:
//! `None` until the Scope screen's `Enter`, `Some` ever after.

use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::discovery::ScanOutcome;
use crate::discovery::scheduler::DiscoveryScheduler;
use crate::discovery::worker::CycleMode;
use crate::discovery::worker::Degradation;
use crate::discovery::worker::OrchestratorStatsSnapshot;
use crate::enrichment::vendor::DatabaseDate;
use crate::enrichment::vendor::VendorDb;
use crate::enrichment::worker::HostnameStatsSnapshot;
use crate::model::Clock;
use crate::model::Ipv4Net;
use crate::model::MacAddr;
use crate::model::Timestamp;
use crate::net::Eligibility;
use crate::net::InterfaceClass;
use crate::net::InterfaceInfo;
use crate::net::suggest_interface;
use crate::registry::Registry;

use super::config::AppInitError;
use super::config::AppMode;
use super::config::SessionParams;
use super::message::MessageLog;

/// The provisional page step: how many rows `PgUp`/`PgDn` move the
/// dashboard selection (§5.6).
///
/// **Provisional** — T-303 replaces it with the real visible-row count
/// derived from the terminal height; the constant exists so the key
/// semantics are testable headlessly before the table layout exists.
pub const PAGE_STEP: usize = 8;

/// The minimum terminal size (NFR-08): below 80×24 the UI shows the
/// too-small overlay instead of any screen (FR-ST-04).
pub const MIN_WIDTH: u16 = 80;
/// See [`MIN_WIDTH`].
pub const MIN_HEIGHT: u16 = 24;

/// The initial terminal size assumption before the first resize event
/// arrives (§5.4): exactly the minimum.
pub const INITIAL_SIZE: (u16, u16) = (MIN_WIDTH, MIN_HEIGHT);

/// The modal screens of §6.6 (help and too-small are overlays, not
/// screens).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    /// The first-run / legal notice (`y` acknowledges).
    Notice,
    /// The interface and scope picker (FR-SC screens).
    Scope,
    /// The device table (the main screen).
    Dashboard,
    /// One device's details (entered from the dashboard selection).
    Details,
}

/// The app's snapshot of one [`InterfaceInfo`] (deviation D-1, see the
/// module docs): everything the scope screen and the confirm path
/// need, projected from the net layer's public accessors.
///
/// Built from kernel data by [`ScopeEntry::from_interface`] (via
/// [`AppState::new`]) or synthetically for tests (via
/// [`AppState::with_scope_entries`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeEntry {
    /// Kernel interface name (`eth0`, `wlan0`, …).
    pub name: String,
    /// The interface index (`ifindex`); part of the device identity
    /// (ADR-008).
    pub index: u32,
    /// The hardware address, when the device reports a valid one
    /// (`None` for `lo`-style interfaces and rejected values).
    pub mac: Option<MacAddr>,
    /// The interface's own IPv4 address and prefix length.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// `IFF_UP` — administratively up.
    pub is_up: bool,
    /// `IFF_RUNNING` — operationally running (informational).
    pub is_running: bool,
    /// `IFF_LOOPBACK`.
    pub is_loopback: bool,
    /// The FR-SC-02 class (name-pattern derived, snapshotted).
    pub class: InterfaceClass,
    /// The FR-SC-03 eligibility (with its first failing reason,
    /// snapshotted).
    pub eligibility: Eligibility,
    /// The default-route gateway of this interface, when it carries a
    /// default-gateway route (FR-SC-01).
    pub default_gateway: Option<Ipv4Addr>,
}

impl ScopeEntry {
    /// Snapshots one interface's public data (deviation D-1).
    pub fn from_interface(info: &InterfaceInfo) -> Self {
        ScopeEntry {
            name: info.name().to_owned(),
            index: info.index(),
            mac: info.mac(),
            ipv4: info
                .ipv4()
                .map(|addr| (addr, info.prefix_len().unwrap_or(32))),
            is_up: info.is_up(),
            is_running: info.is_running(),
            is_loopback: info.is_loopback(),
            class: info.class(),
            eligibility: info.eligibility(),
            default_gateway: info.default_gateway(),
        }
    }

    /// Whether the entry is eligible for scanning (FR-SC-03).
    pub fn is_eligible(&self) -> bool {
        self.eligibility == Eligibility::Eligible
    }

    /// Derives the scan scope from the entry's own IPv4 network
    /// (FR-SC-04). Mirrors `net::interfaces::derive_scope` exactly
    /// (`Ipv4Net::new(address, prefix_len)` of the selected
    /// interface; `None` without an IPv4 address) — the net function
    /// cannot take an entry, so the same construction lives here.
    pub fn derive_scope(&self) -> Option<Ipv4Net> {
        let (addr, prefix_len) = self.ipv4?;
        // prefix_len is 0..=32 by construction, so `new` cannot fail;
        // `.ok()` keeps this total regardless (as in the net layer).
        Ipv4Net::new(addr, prefix_len).ok()
    }
}

/// The scope facts of the confirmed interface (§5.4: "from the
/// confirmed interface"). Filled once by the Scope screen's `Enter`;
/// immutable for the rest of the session (MVP: one scope per session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedScope {
    /// The confirmed scan scope (FR-SC-04/05).
    pub scope: Ipv4Net,
    /// The confirmed interface's `ifindex` (device identity part,
    /// ADR-008).
    pub iface_index: u32,
    /// The confirmed interface's name.
    pub iface_name: String,
    /// The confirmed interface's MAC, when it reported a valid one
    /// (`None` ⇒ no local-device record can exist — no identity).
    pub iface_mac: Option<MacAddr>,
    /// Our own IPv4 address on the confirmed interface.
    pub own_ip: Ipv4Addr,
    /// The default-route gateway of the confirmed interface, when it
    /// carries one (FR-SC-01; the `Gateway` tag source).
    pub gateway_ip: Option<Ipv4Addr>,
}

/// What the last finished cycle did (§5.4: the header's last-scan
/// line, FR-UI-05; T-303 renders it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastScan {
    /// Why the cycle started.
    pub trigger: crate::discovery::scheduler::Trigger,
    /// Which machinery the cycle ran.
    pub mode: CycleMode,
    /// How the cycle ended (the discovery layer's outcome, reason
    /// included — T-401 words it).
    pub outcome: ScanOutcome,
    /// The typed degradation reason, when the outcome was degraded.
    pub degraded: Option<Degradation>,
    /// When the cycle finished.
    pub finished_at: Timestamp,
}

/// The runtime-refreshed counters snapshot (§5.4: refreshed by the
/// runtime at the end of every step, never by `update`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CountersSnapshot {
    /// The T-204 orchestrator's counters.
    pub orchestrator: OrchestratorStatsSnapshot,
    /// The T-203 hostname worker's counters.
    pub hostname: HostnameStatsSnapshot,
    /// Discovery observation batches the runtime forwarder dropped
    /// after its retry budget (event-queue saturation).
    pub forwarder_dropped_batches: u64,
    /// Hostname events the runtime forwarder dropped after its retry
    /// budget.
    pub forwarder_dropped_hostnames: u64,
}

/// The application state (§5.4; module docs above). Field names are
/// the card's indicative names; the scope facts are grouped in
/// the private `confirmed` field.
///
/// Constructed via [`AppState::new`] (production: kernel interface
/// data) or [`AppState::with_scope_entries`] (synthetic entries,
/// tests). Fallible only through the registry configuration
/// ([`AppInitError`]).
pub struct AppState {
    /// The active screen (§6.6).
    pub(crate) screen: Screen,
    /// The help overlay flag (`?` from Dashboard/Details, `Esc`
    /// closes).
    pub(crate) help_open: bool,
    /// The terminal size in cells (initial 80×24, §5.4).
    pub(crate) terminal_size: (u16, u16),
    /// The NFR-08 overlay flag: `w < 80 || h < 24`.
    pub(crate) too_small: bool,
    /// The session mode (FR-DS-14).
    pub(crate) mode: AppMode,
    /// The confirmed interface's scope facts (`None` until the Scope
    /// screen's `Enter`).
    pub(crate) confirmed: Option<ConfirmedScope>,
    /// The scope screen's list (the D-1 snapshot).
    pub(crate) interfaces: Vec<ScopeEntry>,
    /// The selected row of the scope screen (an index into
    /// `interfaces`; moves among eligible entries only).
    pub(crate) scope_selected: usize,
    /// The device registry (T-201) — the single source of truth.
    pub(crate) registry: Registry,
    /// The FR-DS-12 scheduler (T-204).
    pub(crate) scheduler: DiscoveryScheduler,
    /// The embedded vendor database (T-202), shared read-only.
    pub(crate) vendor_db: Arc<VendorDb>,
    /// Whether hostname lookups are queued (§5.9; `--no-hostnames` is
    /// T-402).
    pub(crate) hostnames_enabled: bool,
    /// The bounded, deduplicating message log (§5.7).
    pub(crate) messages: MessageLog,
    /// The last finished cycle (§5.4).
    pub(crate) last_scan: Option<LastScan>,
    /// The runtime-refreshed counters (§5.4).
    pub(crate) counters: CountersSnapshot,
    /// Whether the §14 notice was acknowledged (startup parameter;
    /// `y` sets it).
    pub(crate) notice_acknowledged: bool,
    /// Whether discovery may run: set at scope confirmation; gates
    /// the runtime's scheduler poll (FR-ST-02).
    pub(crate) discovery_armed: bool,
    /// Whether auto-scans stopped (the sticky FR-DS-12 / PQ-1 ruling):
    /// persistent state surfaced with one message; no in-session
    /// resume exists.
    pub(crate) auto_stopped: bool,
    /// The authoritative quit flag (§5.3): the runtime stops when this
    /// is `true`. `update` always sets it together with
    /// [`Effect::Quit`](super::action::Effect::Quit).
    pub(crate) quit: bool,
    /// Whether anything changed that a render must reflect; cleared by
    /// the renderer (T-301). Construction starts `true` (the first
    /// frame has something to draw).
    pub(crate) dirty: bool,
}

impl AppState {
    /// Builds the state from kernel interface data (the production
    /// path: T-301 passes `enumerate_interfaces()`'s result).
    ///
    /// The scope screen's selection starts at
    /// [`suggest_interface`]'s
    /// suggestion, falling back to the first eligible entry (§5.4).
    ///
    /// # Errors
    /// [`AppInitError::Registry`] when the registry configuration is
    /// invalid (§5.4; nothing is clamped, plan §8.7).
    pub fn new(
        params: SessionParams,
        interfaces: Vec<InterfaceInfo>,
        vendor_db: Arc<VendorDb>,
        clock: &dyn Clock,
    ) -> Result<Self, AppInitError> {
        let selected = suggest_interface(&interfaces)
            .and_then(|suggested| {
                interfaces
                    .iter()
                    .position(|info| std::ptr::eq(info, suggested))
            })
            .or_else(|| {
                interfaces
                    .iter()
                    .position(|info| info.eligibility() == Eligibility::Eligible)
            })
            .unwrap_or(0);
        let entries: Vec<ScopeEntry> = interfaces.iter().map(ScopeEntry::from_interface).collect();
        Self::build(params, entries, selected, vendor_db, clock)
    }

    /// Builds the state from synthetic scope entries (the test path —
    /// deviation D-1; also usable by any in-crate caller that already
    /// holds a snapshot). The selection starts at the first eligible
    /// entry, or row 0 when none is eligible (the scope screen then
    /// has nothing confirmable and `Enter` reports
    /// [`MessageKind::ScopeUnavailable`](super::message::MessageKind::ScopeUnavailable)).
    ///
    /// # Errors
    /// [`AppInitError::Registry`] when the registry configuration is
    /// invalid.
    pub fn with_scope_entries(
        params: SessionParams,
        entries: Vec<ScopeEntry>,
        vendor_db: Arc<VendorDb>,
        clock: &dyn Clock,
    ) -> Result<Self, AppInitError> {
        let selected = entries
            .iter()
            .position(ScopeEntry::is_eligible)
            .unwrap_or(0);
        Self::build(params, entries, selected, vendor_db, clock)
    }

    /// The common construction: validated registry, fresh scheduler,
    /// initial screen, startup messages (§5.4).
    fn build(
        params: SessionParams,
        entries: Vec<ScopeEntry>,
        selected: usize,
        vendor_db: Arc<VendorDb>,
        clock: &dyn Clock,
    ) -> Result<Self, AppInitError> {
        let registry = Registry::new(params.registry).map_err(AppInitError::Registry)?;
        let scheduler = DiscoveryScheduler::new(params.interval);
        let mut state = AppState {
            screen: if params.notice_acknowledged {
                Screen::Scope
            } else {
                Screen::Notice
            },
            help_open: false,
            terminal_size: INITIAL_SIZE,
            too_small: false, // 80×24 is exactly the minimum (NFR-08)
            mode: params.mode,
            confirmed: None,
            interfaces: entries,
            scope_selected: selected,
            registry,
            scheduler,
            vendor_db,
            hostnames_enabled: params.hostnames_enabled,
            messages: MessageLog::new(),
            last_scan: None,
            counters: CountersSnapshot::default(),
            notice_acknowledged: params.notice_acknowledged,
            discovery_armed: false,
            auto_stopped: false,
            quit: false,
            dirty: true,
        };
        // The startup messages, each once by construction (and once
        // more by the log's dedup rule should anything repeat them).
        let now = clock.now();
        if params.started_as_root {
            state
                .messages
                .append(super::message::MessageKind::RootWarning, now);
        }
        if let AppMode::ReadOnly { reason } = &state.mode {
            state.messages.append(
                super::message::MessageKind::ReadOnlyMode {
                    reason: reason.clone(),
                },
                now,
            );
        }
        if params.resolver_selected.is_none() && params.hostnames_enabled {
            state
                .messages
                .append(super::message::MessageKind::NoEligibleResolver, now);
        }
        Ok(state)
    }

    // ---- Read accessors (T-301/T-303 render read-only views) ---------

    /// The active screen.
    pub fn screen(&self) -> Screen {
        self.screen
    }

    /// Whether the help overlay is open.
    pub fn help_open(&self) -> bool {
        self.help_open
    }

    /// The terminal size in cells.
    pub fn terminal_size(&self) -> (u16, u16) {
        self.terminal_size
    }

    /// Whether the NFR-08 too-small overlay is active.
    pub fn too_small(&self) -> bool {
        self.too_small
    }

    /// The session mode (FR-DS-14).
    pub fn mode(&self) -> &AppMode {
        &self.mode
    }

    /// The confirmed scope facts, once a scope is confirmed.
    pub fn confirmed_scope(&self) -> Option<&ConfirmedScope> {
        self.confirmed.as_ref()
    }

    /// The scope-screen list (the D-1 snapshot).
    pub fn interfaces(&self) -> &[ScopeEntry] {
        &self.interfaces
    }

    /// The scope screen's selected row.
    pub fn scope_selected(&self) -> usize {
        self.scope_selected
    }

    /// The last finished cycle, if any.
    pub fn last_scan(&self) -> Option<&LastScan> {
        self.last_scan.as_ref()
    }

    /// The retained message-log entries, oldest first (T-303 renders).
    pub fn messages(&self) -> impl Iterator<Item = &super::message::Message> {
        self.messages.iter()
    }

    /// The runtime-refreshed counters snapshot.
    pub fn counters(&self) -> CountersSnapshot {
        self.counters
    }

    /// Whether discovery may run (set at scope confirmation).
    pub fn discovery_armed(&self) -> bool {
        self.discovery_armed
    }

    /// Whether auto-scans stopped (sticky FR-DS-12 state).
    pub fn auto_stopped(&self) -> bool {
        self.auto_stopped
    }

    /// The authoritative quit flag.
    pub fn quit(&self) -> bool {
        self.quit
    }

    /// Whether anything changed since the last render.
    pub fn dirty(&self) -> bool {
        self.dirty
    }

    /// Observes-and-clears the dirty flag: the renderer's consume step
    /// (task T-301's pre-authorized exception E-1 — the only additive
    /// accessor this task may add to `src/app/`; every existing API
    /// could only read the flag, never clear it, so a render loop
    /// driven by `dirty` alone would re-render every wake).
    ///
    /// Returns `true` when a render is due for changes accumulated
    /// since the last call (construction starts `true`, so the first
    /// frame draws); `false` leaves the flag cleared until the next
    /// state change marks it again.
    pub fn take_dirty(&mut self) -> bool {
        core::mem::replace(&mut self.dirty, false)
    }

    /// The vendor database date (for T-304's help screen).
    pub fn vendor_database_date(&self) -> DatabaseDate {
        self.vendor_db.database_date()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FakeClock;
    use crate::net::enumerate_interfaces;
    use std::time::Duration;

    /// The embedded vendor database (committed image, T-202).
    fn db() -> Arc<VendorDb> {
        Arc::new(VendorDb::embedded().expect("committed database is valid"))
    }

    /// Default params with a resolver selected, so the
    /// NoEligibleResolver startup message (which fires under the plain
    /// defaults: `resolver_selected: None` + hostnames enabled) stays
    /// out of the way of the other message assertions.
    fn params_with_resolver() -> SessionParams {
        SessionParams {
            resolver_selected: Some("192.0.2.53:53".parse().expect("valid socket address")),
            ..SessionParams::default()
        }
    }

    /// A synthetic eligible entry: up, Ethernet-class physical link,
    /// 192.0.2.1/24 (RFC 5737 documentation range), a valid MAC, an
    /// optional default gateway.
    fn eligible_entry(name: &str, gateway: Option<Ipv4Addr>) -> ScopeEntry {
        ScopeEntry {
            name: name.to_owned(),
            index: 2,
            mac: Some("02:00:00:00:00:01".parse().expect("valid MAC")),
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 24)),
            is_up: true,
            is_running: true,
            is_loopback: false,
            class: InterfaceClass::Physical,
            eligibility: Eligibility::Eligible,
            default_gateway: gateway,
        }
    }

    /// A synthetic ineligible entry (loopback).
    fn loopback_entry() -> ScopeEntry {
        ScopeEntry {
            name: "lo".to_owned(),
            index: 1,
            mac: None,
            ipv4: Some((Ipv4Addr::new(127, 0, 0, 1), 8)),
            is_up: true,
            is_running: true,
            is_loopback: true,
            class: InterfaceClass::Virtual,
            eligibility: Eligibility::Ineligible(crate::net::IneligibleReason::Loopback),
            default_gateway: None,
        }
    }

    #[test]
    fn fresh_state_starts_on_the_notice_screen_unacknowledged() {
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            Vec::new(),
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        assert_eq!(state.screen(), Screen::Notice);
        assert!(!state.notice_acknowledged);
        assert!(!state.quit());
        assert!(!state.discovery_armed());
        assert!(!state.help_open());
        assert!(!state.too_small());
        assert_eq!(state.terminal_size(), (80, 24));
        assert!(state.dirty(), "the first frame has something to draw");
        assert!(state.confirmed_scope().is_none());
        assert!(state.last_scan().is_none());
        // The plain defaults carry no resolver while hostnames are
        // enabled, so exactly the NoEligibleResolver message fires.
        let messages: Vec<_> = state.messages().collect();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].kind,
            crate::app::message::MessageKind::NoEligibleResolver
        );
        // With a resolver selected, no startup message fires at all.
        let state = AppState::with_scope_entries(
            params_with_resolver(),
            Vec::new(),
            db(),
            &FakeClock::new(),
        )
        .expect("valid");
        assert_eq!(state.messages().count(), 0);
    }

    #[test]
    fn an_acknowledged_notice_starts_on_the_scope_screen() {
        let params = SessionParams {
            notice_acknowledged: true,
            ..SessionParams::default()
        };
        let state = AppState::with_scope_entries(params, Vec::new(), db(), &FakeClock::new())
            .expect("defaults are valid");
        assert_eq!(state.screen(), Screen::Scope);
    }

    #[test]
    fn startup_messages_fire_exactly_when_their_condition_holds() {
        // Root warning alone (a resolver is selected so the
        // no-resolver message stays out of the count).
        let params = SessionParams {
            started_as_root: true,
            ..params_with_resolver()
        };
        let state = AppState::with_scope_entries(params, Vec::new(), db(), &FakeClock::new())
            .expect("defaults are valid");
        assert_eq!(state.messages().count(), 1);
        assert!(
            state
                .messages
                .contains_kind(&crate::app::message::MessageKind::RootWarning)
        );
    }

    #[test]
    fn read_only_mode_appends_its_reason_verbatim() {
        let params = SessionParams {
            mode: AppMode::ReadOnly {
                reason: "no raw socket: EPERM".to_owned(),
            },
            ..params_with_resolver()
        };
        let state = AppState::with_scope_entries(params, Vec::new(), db(), &FakeClock::new())
            .expect("defaults are valid");
        let messages: Vec<_> = state.messages().collect();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].kind,
            crate::app::message::MessageKind::ReadOnlyMode {
                reason: "no raw socket: EPERM".to_owned()
            }
        );
    }

    #[test]
    fn no_resolver_message_only_when_hostnames_are_enabled() {
        // hostnames enabled + no resolver → the message fires.
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            Vec::new(),
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        assert_eq!(state.messages().count(), 1);
        // hostnames disabled + no resolver → lookups never run, so the
        // condition is moot: no message.
        let params = SessionParams {
            hostnames_enabled: false,
            ..SessionParams::default()
        };
        let state = AppState::with_scope_entries(params, Vec::new(), db(), &FakeClock::new())
            .expect("defaults are valid");
        assert_eq!(state.messages().count(), 0);
    }

    #[test]
    fn all_startup_messages_together_deduplicate_to_three() {
        let params = SessionParams {
            started_as_root: true,
            hostnames_enabled: true,
            mode: AppMode::ReadOnly {
                reason: "EPERM".to_owned(),
            },
            ..SessionParams::default()
        };
        let state = AppState::with_scope_entries(params, Vec::new(), db(), &FakeClock::new())
            .expect("defaults are valid");
        // Root + read-only + no-resolver (hostnames are enabled and no
        // resolver is selected).
        assert_eq!(state.messages().count(), 3);
        // With a resolver: root + read-only only.
        let params = SessionParams {
            started_as_root: true,
            mode: AppMode::ReadOnly {
                reason: "EPERM".to_owned(),
            },
            ..params_with_resolver()
        };
        let state = AppState::with_scope_entries(params, Vec::new(), db(), &FakeClock::new())
            .expect("defaults are valid");
        assert_eq!(state.messages().count(), 2);
    }

    #[test]
    fn selection_starts_at_the_first_eligible_entry() {
        let entries = vec![
            loopback_entry(),
            eligible_entry("eth9", None),
            loopback_entry(),
        ];
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            entries,
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        assert_eq!(state.scope_selected(), 1);
    }

    #[test]
    fn selection_is_row_zero_when_nothing_is_eligible() {
        let entries = vec![loopback_entry(), loopback_entry()];
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            entries,
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        assert_eq!(state.scope_selected(), 0);
    }

    #[test]
    fn the_vendor_database_date_is_exposed() {
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            Vec::new(),
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        let date = state.vendor_database_date();
        // The committed image's date (T-202 SOURCE.md: the `--date`
        // passed to gen_oui, 2026-11-03): whatever it is, the accessor
        // returns it unchanged; pin the committed value.
        assert_eq!(
            (date.year, date.month, date.day),
            (2026, 11, 3),
            "the committed vendor-db.bin date (regenerate the pin if the image is refreshed)"
        );
    }

    #[test]
    fn the_entry_snapshot_mirrors_the_interface_accessors_exactly() {
        // Deviation D-1's honesty proof: whatever interfaces the
        // machine has (possibly none), every snapshot field mirrors the
        // net layer's public accessor output one-to-one. The test is
        // relational, so it is deterministic on any machine.
        let interfaces = enumerate_interfaces();
        for info in &interfaces {
            let entry = ScopeEntry::from_interface(info);
            assert_eq!(entry.name, info.name());
            assert_eq!(entry.index, info.index());
            assert_eq!(entry.mac, info.mac());
            assert_eq!(
                entry.ipv4,
                info.ipv4()
                    .map(|addr| (addr, info.prefix_len().unwrap_or(32)))
            );
            assert_eq!(entry.is_up, info.is_up());
            assert_eq!(entry.is_running, info.is_running());
            assert_eq!(entry.is_loopback, info.is_loopback());
            assert_eq!(entry.class, info.class());
            assert_eq!(entry.eligibility, info.eligibility());
            assert_eq!(entry.default_gateway, info.default_gateway());
            // And the mirrored scope derivation agrees with the net
            // layer's own function on the same interface.
            assert_eq!(entry.derive_scope(), crate::net::derive_scope(info));
        }
    }

    #[test]
    fn production_construction_from_kernel_data_selects_the_suggestion() {
        // The production path: `new` selects suggest_interface's
        // position (or the first eligible, or row 0). Relational, so
        // deterministic on any machine — including the empty one.
        let interfaces = enumerate_interfaces();
        let expected = suggest_interface(&interfaces)
            .and_then(|suggested| {
                interfaces
                    .iter()
                    .position(|info| std::ptr::eq(info, suggested))
            })
            .or_else(|| {
                interfaces
                    .iter()
                    .position(|info| info.eligibility() == Eligibility::Eligible)
            })
            .unwrap_or(0);
        let state = AppState::new(
            SessionParams::default(),
            interfaces,
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        assert_eq!(state.scope_selected(), expected);
        assert_eq!(state.screen(), Screen::Notice);
    }

    #[test]
    fn a_minute_of_nothing_leaves_the_state_untouched() {
        // The state is inert without events: a minute of clock time
        // changes nothing (all time reaches it through `update`).
        let mut clock = FakeClock::new();
        let state =
            AppState::with_scope_entries(SessionParams::default(), Vec::new(), db(), &clock)
                .expect("defaults are valid");
        clock.advance(Duration::from_secs(60));
        assert_eq!(state.screen(), Screen::Notice);
        assert!(!state.quit());
    }

    #[test]
    fn take_dirty_observes_and_clears_the_flag_once_per_change() {
        // E-1's contract (T-301): the renderer consumes the flag —
        // `true` once per accumulated change, `false` on an idle
        // second look, `true` again only after another change. The
        // read-only `dirty()` accessor stays untouched (tested above)
        // and never clears.
        let mut state = AppState::with_scope_entries(
            SessionParams::default(),
            Vec::new(),
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        // Construction starts dirty: the first frame has something to
        // draw — the first consume sees it, the second does not.
        assert!(state.dirty());
        assert!(state.take_dirty(), "the first frame is due");
        assert!(!state.take_dirty(), "nothing changed since");
        assert!(!state.dirty(), "the cleared flag stays cleared");
        // A state change through the real `update` re-marks it…
        let effects = crate::app::update::update(
            &mut state,
            crate::app::event::AppEvent::Tick,
            &FakeClock::new(),
        );
        assert!(effects.is_empty());
        assert!(state.take_dirty(), "a tick is a change (FR-UI-07)");
        // …and an ignored (unknown) event does not.
        crate::app::update::update(
            &mut state,
            crate::app::event::AppEvent::Input(crate::app::event::InputEvent::Key(
                crate::app::event::Key::Char('x'),
            )),
            &FakeClock::new(),
        );
        assert!(!state.take_dirty(), "an unknown key changes nothing");
    }
}
