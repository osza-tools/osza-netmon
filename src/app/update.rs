// SPDX-License-Identifier: GPL-3.0-only

//! The pure application core: `update(state, event, clock) -> effects`
//! (plan §8.4; task T-205 §5.5–5.6).
//!
//! `update` is a **pure function**: no I/O, no threads, no channels,
//! no `Instant::now`/`SystemTime::now`, no randomness — every reading
//! of time comes in through the injected `&dyn Clock`, and every side
//! effect leaves as an [`Effect`] for the runtime's executor. The
//! signature admits nothing else: the whole application flow (notice →
//! scope → dashboard → details → help → refresh → sort → quit,
//! including errors, read-only mode and resize) is drivable by
//! headless scenario scripts with a [`FakeClock`](crate::model::FakeClock)
//! and zero threads (AC-2).
//!
//! # Event semantics (§5.5)
//!
//! * `Input` — the per-screen key table of §5.6 (below). Every
//!   accepted key sets `dirty`; unknown keys are ignored (no state
//!   change, not dirty).
//! * `Resize` — store the size, recompute `too_small` (NFR-08:
//!   `w < 80 || h < 24`), `dirty`. Input is still processed while too
//!   small (q quits) — the overlay hides the screen, it does not
//!   replace the state machine (FR-ST-04).
//! * `Tick` — `dirty` only (the 1 Hz relative-age redraw, FR-UI-07).
//! * `Discovery(Started)` — `registry.begin_cycle(scan_id)`. The
//!   scheduler needs no report: its *running* state is set by its own
//!   start decisions (`poll`/`manual_refresh`), and the app is the
//!   single commander, so every `Started` event follows a decision the
//!   scheduler already made.
//! * `Discovery(Observations)` — each batch item is mapped onto a
//!   registry observation (the batch carries the scanner's
//!   `{ip, mac, source}` facts; the cycle's `ScanId` comes from the
//!   event and the `iface_index` from the confirmed scope — the
//!   identity parts of ADR-008), then `registry.observe`. On
//!   `Accepted { new_device: true }` the vendor field is filled once
//!   (§5.9); on **every** `Accepted` a `ResolveHostname` effect is
//!   queued when hostnames are enabled (re-queueing is intentional:
//!   the T-203 worker dedupes in-flight IPs and applies the 5-minute
//!   failure backoff internally, and the re-queue heals a `QueueFull`
//!   drop on a later cycle). `DroppedCapFull` appends the cap message
//!   once (§5.7 dedup).
//! * `Discovery(Finished)` — first `registry.end_cycle` (aging exactly
//!   per ADR-007 under the registry's outcome), then
//!   `scheduler.cycle_finished` (the scheduler re-anchors even if the
//!   registry's scan-id guard returned `None`); an `AutoScansStopped`
//!   decision sets the sticky `auto_stopped` flag and appends its
//!   message once; `last_scan` records the cycle; the §6.8 messages
//!   fire (`Failed` ⇒ `ScanFailed`, `Partial`+degraded ⇒
//!   `ScanDegraded`, reasons verbatim from the worker).
//! * `Hostname(Resolved)` — the outcome is applied to **every** record
//!   holding the address (ADR-008 keeps both records of a shared IP;
//!   one lookup describes the reverse entry of that address).
//! * `Hostname(ShutdownAck)` — no state change.
//!
//! The scheduler is **never polled** here: `update` only reacts. The
//! runtime polls, and only once discovery is armed (FR-ST-02, AC-3).
//!
//! # Key map (§5.6, from plan §10.3)
//!
//! * **Notice**: `y` acknowledges (→ Scope); `q`/`Ctrl+C` quit; all
//!   else ignored.
//! * **Scope**: `Up`/`k`, `Down`/`j` move the selection among
//!   **eligible** entries only (skipping ineligible rows, wrapping —
//!   the house choice, tested); `Enter` confirms (below); `q`/`Ctrl+C`
//!   quit.
//! * **Dashboard**: `Up`/`k`/`Down`/`j` move the registry selection;
//!   `PgUp`/`PgDn` move it by [`PAGE_STEP`](super::state::PAGE_STEP)
//!   rows (provisional constant — T-303 replaces it with the real
//!   visible-row count); `Home`/`g`/`End`/`G` jump to the first/last
//!   row; `Enter` opens Details **of the selected row** (the registry
//!   starts unselected; the first navigation key selects the first
//!   row); `r` refreshes now (§5.6: `manual_refresh` → `StartCycle` ⇒
//!   `Effect::StartScan` with the §2 recipe; `AlreadyInProgress` ⇒ the
//!   typed message, nothing queued — FR-DS-08); `s` toggles the sort
//!   mode (`Ip` ↔ `Hostname`); `?` opens the help overlay; `q`/`Ctrl+C`
//!   quit.
//! * **Details**: `Esc` returns to Dashboard (the selection lives in
//!   the registry and survives); `Up`/`Down`/`k`/`j` move the
//!   selection (house choice — implemented and tested); `?` help;
//!   `q`/`Ctrl+C` quit.
//! * **Help overlay** (any underlying screen): `Esc` or `?` close it;
//!   `q`/`Ctrl+C` still quit; everything else is ignored (the overlay
//!   is modal).
//! * **Everywhere**: `q`/`Ctrl+C` quit (FR-UI-06, §10.3) —
//!   [`AppState::quit`](super::AppState::quit) is set together with
//!   returning [`Effect::Quit`] (§5.3: the flag is authoritative, the
//!   effect informational).
//!
//! Scope confirmation (`Enter` on Scope): the selected entry must be
//! eligible **and** have a derivable scope (FR-SC-04); otherwise the
//! screen stays and [`MessageKind::ScopeUnavailable`] is appended with
//! the net layer's own eligibility words as the reason. On success the
//! scope facts are recorded, the interface's own device is inserted
//! with the `This device` tag (its vendor is filled per §5.9), the
//! gateway address — when the interface carries a **real** default
//! gateway (`Some(0.0.0.0)` is an on-link default, not a gateway
//! address; decision, see the report) — is recorded for the `Gateway`
//! tag, a `ResolveHostname` for our own address is queued, discovery
//! is armed and the Dashboard opens. An eligible interface without a
//! valid MAC (no identity, ADR-008) skips the local-device insertion —
//! documented decision.

use crate::discovery::Observation as ScannerObservation;
use crate::discovery::ScanOutcome as DiscoveryOutcome;
use crate::discovery::ScanParams;
use crate::discovery::scheduler::SchedulerDecision;
use crate::discovery::scheduler::Trigger;
use crate::discovery::worker::CycleEvent;
use crate::discovery::worker::CycleMode;
use crate::discovery::worker::CycleSummary;
use crate::discovery::worker::Degradation;
use crate::discovery::{DEFAULT_LISTEN_WINDOW, DEFAULT_RATE_PPS};
use crate::enrichment::vendor::VendorLookup;
use crate::enrichment::worker::HostnameEvent;
use crate::model::Clock;
use crate::model::DisplayText;
use crate::model::Field;
use crate::model::MacAddr;
use crate::model::ScanId;
use crate::model::Source;
use crate::net::IneligibleReason;
use crate::registry::DeviceKey;
use crate::registry::Observation as RegistryObservation;
use crate::registry::ScanOutcome as RegistryOutcome;
use crate::registry::SortMode;

use super::action::Effect;
use super::event::AppEvent;
use super::event::InputEvent;
use super::event::Key;
use super::message::MessageKind;
use super::state::AppState;
use super::state::ConfirmedScope;
use super::state::LastScan;
use super::state::Screen;

/// The binding T-204 §11.1 wiring recipe: the pass count comes from
/// the trigger (ADR-011), the rate and listen window from the policy
/// constants the scheduler re-exports. Used by `update`'s manual
/// refresh and by the runtime's poll path, so both are identical by
/// construction.
pub(crate) fn scan_params_for(trigger: Trigger) -> ScanParams {
    ScanParams {
        passes: trigger.passes(),
        rate_pps: DEFAULT_RATE_PPS,
        listen_window: DEFAULT_LISTEN_WINDOW,
    }
}

/// The pure application core (module docs above).
pub fn update(state: &mut AppState, event: AppEvent, clock: &dyn Clock) -> Vec<Effect> {
    match event {
        AppEvent::Input(InputEvent::Key(key)) => handle_key(state, key, clock),
        AppEvent::Resize { width, height } => {
            state.terminal_size = (width, height);
            state.too_small = width < super::state::MIN_WIDTH || height < super::state::MIN_HEIGHT;
            state.dirty = true;
            Vec::new()
        }
        AppEvent::Tick => {
            // FR-UI-07: relative ages change while the screen is idle.
            state.dirty = true;
            Vec::new()
        }
        AppEvent::Discovery(discovery_event) => handle_discovery(state, discovery_event, clock),
        AppEvent::Hostname(hostname_event) => handle_hostname(state, hostname_event),
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// The per-screen key dispatch (§5.6; module docs for the table).
fn handle_key(state: &mut AppState, key: Key, clock: &dyn Clock) -> Vec<Effect> {
    // Quit works from any screen, overlay included (FR-UI-06/§10.3).
    if matches!(key, Key::Char('q') | Key::CtrlC) {
        return vec![quit_now(state)];
    }
    // The help overlay is modal: Esc/? close it; all else is ignored.
    if state.help_open {
        return match key {
            Key::Esc | Key::Char('?') => {
                state.help_open = false;
                state.dirty = true;
                Vec::new()
            }
            _ => Vec::new(),
        };
    }
    match state.screen {
        Screen::Notice => notice_key(state, key),
        Screen::Scope => scope_key(state, key, clock),
        Screen::Dashboard => dashboard_key(state, key, clock),
        Screen::Details => details_key(state, key),
    }
}

/// Sets the authoritative quit flag and returns the informational
/// [`Effect::Quit`] (§5.3: both are set together, always).
fn quit_now(state: &mut AppState) -> Effect {
    state.quit = true;
    state.dirty = true;
    Effect::Quit
}

fn notice_key(state: &mut AppState, key: Key) -> Vec<Effect> {
    match key {
        Key::Char('y') => {
            state.notice_acknowledged = true;
            state.screen = Screen::Scope;
            state.dirty = true;
            Vec::new()
        }
        // Everything else is ignored (no state change, not dirty).
        _ => Vec::new(),
    }
}

fn scope_key(state: &mut AppState, key: Key, clock: &dyn Clock) -> Vec<Effect> {
    match key {
        Key::Up | Key::Char('k') => {
            move_scope_selection(state, false);
            state.dirty = true;
            Vec::new()
        }
        Key::Down | Key::Char('j') => {
            move_scope_selection(state, true);
            state.dirty = true;
            Vec::new()
        }
        Key::Enter => confirm_scope(state, clock),
        _ => Vec::new(),
    }
}

/// Moves the scope selection to the previous/next **eligible** entry,
/// wrapping at the ends (the house choice; tested both ways). With no
/// eligible entries the selection stays where it is (an accepted key,
/// nothing to move).
fn move_scope_selection(state: &mut AppState, forward: bool) {
    let eligible: Vec<usize> = state
        .interfaces
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.is_eligible())
        .map(|(position, _)| position)
        .collect();
    if eligible.is_empty() {
        return; // no eligible rows: nothing to move
    }
    let len = eligible.len();
    let next = match eligible
        .iter()
        .position(|position| *position == state.scope_selected)
    {
        Some(current) => {
            // Wrapping step in the chosen direction.
            let stepped = if forward {
                current.saturating_add(1)
            } else {
                current.saturating_add(len - 1) // (current − 1) mod len
            };
            eligible.get(stepped % len).copied()
        }
        // The selection sits on an ineligible row (possible only when
        // nothing was eligible at construction): snap to the first
        // eligible entry.
        None => eligible.first().copied(),
    };
    if let Some(position) = next {
        state.scope_selected = position;
    }
}

/// The Scope screen's `Enter` (§5.6; module docs for the semantics).
fn confirm_scope(state: &mut AppState, clock: &dyn Clock) -> Vec<Effect> {
    let now = clock.now();
    let unavailable = |state: &mut AppState, reason: String| {
        state.dirty |= state
            .messages
            .append(MessageKind::ScopeUnavailable { reason }, now);
    };
    let Some(entry) = state.interfaces.get(state.scope_selected).cloned() else {
        // No rows at all: nothing is confirmable.
        unavailable(state, IneligibleReason::NoIpv4Address.to_string());
        return Vec::new();
    };
    if !entry.is_eligible() {
        let reason = match entry.eligibility {
            crate::net::Eligibility::Ineligible(reason) => reason.to_string(),
            crate::net::Eligibility::Eligible => String::new(), // unreachable here
        };
        unavailable(state, reason);
        return Vec::new();
    }
    let Some(scope) = entry.derive_scope() else {
        // Eligible but no derivable scope (a synthetic entry's
        // inconsistency; honest refusal, net's own words).
        unavailable(state, IneligibleReason::NoIpv4Address.to_string());
        return Vec::new();
    };
    // The confirmable case: an eligible entry always carries an IPv4
    // address (FR-SC-03), so this extraction cannot fail.
    let Some((own_ip, _prefix)) = entry.ipv4 else {
        return Vec::new();
    };

    // The interface's own device (§5.3: interface data, `This device`;
    // nobody ARPs itself). Without a valid MAC there is no identity to
    // insert (ADR-008) — documented decision.
    if let Some(mac) = entry.mac {
        state
            .registry
            .insert_local_device(entry.index, mac, own_ip, clock);
        let key = DeviceKey {
            iface_index: entry.index,
            mac,
        };
        fill_vendor(state, &key, mac);
    }
    // The gateway tag applies only to a *real* gateway address:
    // `Some(0.0.0.0)` models an on-link default route (net layer's
    // documented encoding) — no device holds 0.0.0.0, so recording it
    // would tag nothing; skip it (decision, report §6).
    if let Some(gateway) = entry.default_gateway
        && !gateway.is_unspecified()
    {
        state.registry.set_gateway_ip(gateway);
    }

    state.confirmed = Some(ConfirmedScope {
        scope,
        iface_index: entry.index,
        iface_name: entry.name.clone(),
        iface_mac: entry.mac,
        own_ip,
        gateway_ip: entry.default_gateway,
    });
    state.discovery_armed = true;
    state.screen = Screen::Dashboard;
    state.dirty = true;

    if state.hostnames_enabled {
        vec![Effect::ResolveHostname { ip: own_ip }]
    } else {
        Vec::new()
    }
}

fn dashboard_key(state: &mut AppState, key: Key, clock: &dyn Clock) -> Vec<Effect> {
    match key {
        Key::Up | Key::Char('k') => {
            state.registry.select_previous();
            state.dirty = true;
            Vec::new()
        }
        Key::Down | Key::Char('j') => {
            state.registry.select_next();
            state.dirty = true;
            Vec::new()
        }
        Key::PageUp => {
            page_selection(state, false);
            state.dirty = true;
            Vec::new()
        }
        Key::PageDown => {
            page_selection(state, true);
            state.dirty = true;
            Vec::new()
        }
        Key::Home | Key::Char('g') => {
            state.registry.select_first();
            state.dirty = true;
            Vec::new()
        }
        Key::End | Key::Char('G') => {
            state.registry.select_last();
            state.dirty = true;
            Vec::new()
        }
        Key::Enter => {
            // Details open for the selected row; with no selection
            // there is nothing to open (accepted key, dirty anyway).
            if state.registry.selected_key().is_some() {
                state.screen = Screen::Details;
            }
            state.dirty = true;
            Vec::new()
        }
        Key::Char('r') => {
            // FR-DS-08: a manual refresh during a running cycle is
            // typed already-in-progress; nothing is queued.
            match state.scheduler.manual_refresh() {
                SchedulerDecision::StartCycle { trigger, .. } => {
                    state.dirty = true;
                    vec![Effect::StartScan {
                        trigger,
                        params: scan_params_for(trigger),
                    }]
                }
                SchedulerDecision::AlreadyInProgress => {
                    state.dirty |= state
                        .messages
                        .append(MessageKind::ScanAlreadyInProgress, clock.now());
                    Vec::new()
                }
                // Unreachable from manual_refresh (the FR-DS-12
                // machine): kept honest rather than silenced.
                SchedulerDecision::None | SchedulerDecision::AutoScansStopped => {
                    state.dirty = true;
                    Vec::new()
                }
            }
        }
        Key::Char('s') => {
            let next = match state.registry.sort_mode() {
                SortMode::Ip => SortMode::Hostname,
                SortMode::Hostname => SortMode::Ip,
            };
            state.registry.set_sort_mode(next);
            state.dirty = true;
            Vec::new()
        }
        Key::Char('?') => {
            state.help_open = true;
            state.dirty = true;
            Vec::new()
        }
        // Esc has no Dashboard binding (nothing to go back from);
        // unknown keys are ignored.
        _ => Vec::new(),
    }
}

fn details_key(state: &mut AppState, key: Key) -> Vec<Effect> {
    match key {
        Key::Esc => {
            state.screen = Screen::Dashboard;
            state.dirty = true;
            Vec::new()
        }
        // House choice (§5.6 "Up/Down may move the selection"):
        // Details follows the plan §10.3 selection keys; the selection
        // lives in the registry, so the dashboard returns to it.
        Key::Up | Key::Char('k') => {
            state.registry.select_previous();
            state.dirty = true;
            Vec::new()
        }
        Key::Down | Key::Char('j') => {
            state.registry.select_next();
            state.dirty = true;
            Vec::new()
        }
        Key::Char('?') => {
            state.help_open = true;
            state.dirty = true;
            Vec::new()
        }
        _ => Vec::new(),
    }
}

/// Moves the selection by [`PAGE_STEP`](super::state::PAGE_STEP) rows
/// in the current sort order, clamped at the ends. With no selection
/// both directions select the first row (consistent with the registry's
/// own `select_next`/`select_previous` behavior).
fn page_selection(state: &mut AppState, forward: bool) {
    let keys = state.registry.sorted_keys();
    if keys.is_empty() {
        return;
    }
    let target = match state.registry.selected_key() {
        None => 0,
        Some(current) => {
            let position = keys.iter().position(|key| *key == current).unwrap_or(0);
            if forward {
                (position + super::state::PAGE_STEP).min(keys.len().saturating_sub(1))
            } else {
                position.saturating_sub(super::state::PAGE_STEP)
            }
        }
    };
    if let Some(key) = keys.get(target).cloned() {
        state.registry.select(key);
    }
}

// ---------------------------------------------------------------------------
// Discovery events
// ---------------------------------------------------------------------------

fn handle_discovery(state: &mut AppState, event: CycleEvent, clock: &dyn Clock) -> Vec<Effect> {
    match event {
        CycleEvent::Started { scan_id, .. } => {
            state.registry.begin_cycle(scan_id);
            state.dirty = true;
            Vec::new()
        }
        CycleEvent::Observations { scan_id, batch } => observe_batch(state, scan_id, batch, clock),
        CycleEvent::Finished {
            scan_id,
            trigger,
            mode,
            summary,
        } => {
            finish_cycle(state, scan_id, summary, trigger, mode, clock);
            Vec::new()
        }
    }
}

/// Maps one forwarded batch onto registry observations (§5.5; module
/// docs for the identity parts).
fn observe_batch(
    state: &mut AppState,
    scan_id: ScanId,
    batch: Vec<ScannerObservation>,
    clock: &dyn Clock,
) -> Vec<Effect> {
    // Without a confirmed interface there is no identity to merge
    // under (ADR-008: iface_index is part of it). The runtime never
    // starts discovery pre-confirmation, so this is the defensive
    // branch for hand-injected events.
    let Some(confirmed) = state.confirmed.as_ref() else {
        state.dirty = true;
        return Vec::new();
    };
    let iface_index = confirmed.iface_index;
    let now = clock.now();
    let mut effects = Vec::new();
    for observation in batch {
        let registry_observation = RegistryObservation::new(
            scan_id,
            iface_index,
            observation.mac,
            observation.ip,
            observation.source,
        );
        match state.registry.observe(registry_observation, clock) {
            crate::registry::ObserveOutcome::Accepted { new_device } => {
                if new_device {
                    // Vendor is filled exactly once per record (§5.9:
                    // the MAC is the identity — one fill per record).
                    let key = DeviceKey {
                        iface_index,
                        mac: observation.mac,
                    };
                    fill_vendor(state, &key, observation.mac);
                }
                if state.hostnames_enabled {
                    // Re-queueing on every Accepted observation is
                    // intentional (§5.9; module docs).
                    effects.push(Effect::ResolveHostname { ip: observation.ip });
                }
            }
            // A superseded or cancelled cycle's late batch: ignored by
            // the registry (FR-RG-03), ignored here.
            crate::registry::ObserveOutcome::IgnoredScanMismatch => {}
            crate::registry::ObserveOutcome::DroppedCapFull => {
                // Once (the log's dedup rule suppresses the repeats).
                state.messages.append(MessageKind::RegistryCapReached, now);
            }
        }
    }
    state.dirty = true;
    effects
}

/// The end-of-cycle bookkeeping (§5.5; module docs).
fn finish_cycle(
    state: &mut AppState,
    scan_id: ScanId,
    summary: Box<CycleSummary>,
    trigger: Trigger,
    mode: CycleMode,
    clock: &dyn Clock,
) {
    let now = clock.now();
    // 1. Aging first, exactly per the registry's own outcome class.
    let registry_outcome = to_registry_outcome(&summary.outcome);
    let _aging = state.registry.end_cycle(scan_id, registry_outcome, clock);
    // 2. The scheduler re-anchors regardless of the registry guard's
    //    answer (§5.5: "even if the registry's guard returned None").
    let decision = state.scheduler.cycle_finished(summary.outcome.clone(), now);
    if matches!(decision, SchedulerDecision::AutoScansStopped) {
        // The sticky PQ-1 ruling: persistent state + one message; no
        // in-session resume exists.
        state.auto_stopped = true;
        state.messages.append(MessageKind::AutoScansStopped, now);
    }
    // 3. The header's last-scan record (FR-UI-05).
    state.last_scan = Some(LastScan {
        trigger,
        mode,
        outcome: summary.outcome.clone(),
        degraded: summary.degraded.clone(),
        finished_at: now,
    });
    // 4. The §6.8 messages, reasons verbatim from the worker.
    match &summary.outcome {
        DiscoveryOutcome::Failed { reason } => {
            state.messages.append(
                MessageKind::ScanFailed {
                    reason: reason.clone(),
                },
                now,
            );
        }
        DiscoveryOutcome::Partial => {
            if let Some(degradation) = &summary.degraded {
                let reason = match degradation {
                    Degradation::PreReadFailed { reason }
                    | Degradation::PostReadFailed { reason } => reason.clone(),
                };
                state
                    .messages
                    .append(MessageKind::ScanDegraded { reason }, now);
            }
        }
        DiscoveryOutcome::Complete | DiscoveryOutcome::Cancelled => {}
    }
    state.dirty = true;
}

/// The registry's outcome classes are the discovery layer's without
/// the reasons (ADR-007: the registry does not need them; the reasons
/// live in the discovery event — see `registry::observation`'s docs).
fn to_registry_outcome(outcome: &DiscoveryOutcome) -> RegistryOutcome {
    match outcome {
        DiscoveryOutcome::Complete => RegistryOutcome::Complete,
        DiscoveryOutcome::Partial => RegistryOutcome::Partial,
        DiscoveryOutcome::Failed { .. } => RegistryOutcome::Failed,
        DiscoveryOutcome::Cancelled => RegistryOutcome::Cancelled,
    }
}

// ---------------------------------------------------------------------------
// Hostname events
// ---------------------------------------------------------------------------

fn handle_hostname(state: &mut AppState, event: HostnameEvent) -> Vec<Effect> {
    match event {
        HostnameEvent::Resolved { ip, outcome } => {
            // Every record holding the address (ADR-008 shared-IP
            // records are both kept).
            let holders: Vec<DeviceKey> = state
                .registry
                .iter()
                .filter(|device| device.has_ip(ip))
                .map(|device| device.key)
                .collect();
            for key in holders {
                state.registry.set_hostname(&key, outcome.clone());
            }
            state.dirty = true;
            Vec::new()
        }
        HostnameEvent::ShutdownAck => {
            // No state change (§5.5).
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Enrichment (§5.9)
// ---------------------------------------------------------------------------

/// Fills one record's vendor field from the embedded database, exactly
/// once per record (the MAC is the identity).
///
/// The mapping: `Found` ⇒ `Known { name, VendorDb }`; `PrivateAddress`
/// ⇒ `Known` with the literal "Private address" (on the §5.4
/// approved-vocabulary list, built through the validating constructor
/// — a rejection, impossible for this literal, is handled honestly as
/// `Unknown`); `Unknown` ⇒ `Unknown` (never a guess).
fn fill_vendor(state: &mut AppState, key: &DeviceKey, mac: MacAddr) {
    let field = match state.vendor_db.lookup(&mac) {
        VendorLookup::Found { name } => Field::Known {
            value: name,
            source: Source::VendorDb,
        },
        VendorLookup::PrivateAddress => match DisplayText::try_from("Private address") {
            Ok(name) => Field::Known {
                value: name,
                source: Source::VendorDb,
            },
            // Honest refusal, never a panic (the literal is valid, so
            // this arm is the defensive one).
            Err(_) => Field::Unknown,
        },
        VendorLookup::Unknown => Field::Unknown,
    };
    state.registry.set_vendor(key, field);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::config::SessionParams;
    use crate::app::message::Message;
    use crate::app::state::ScopeEntry;
    use crate::discovery::ScanCounters;
    use crate::discovery::scheduler::RediscoveryInterval;
    use crate::model::FakeClock;
    use crate::model::Hostname;
    use crate::model::testing::Lcg;
    use crate::net::Eligibility;
    use crate::net::InterfaceClass;
    use crate::registry::Tag;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    // ---- fixtures -----------------------------------------------------------

    fn db() -> Arc<crate::enrichment::vendor::VendorDb> {
        Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        )
    }

    /// A synthetic eligible interface: `eth9`, index 2, MAC
    /// `02:00:00:00:00:01` (locally administered ⇒ vendor
    /// `Private address`), 192.0.2.1/24 (RFC 5737), optional gateway.
    fn eth_entry(gateway: Option<Ipv4Addr>) -> ScopeEntry {
        ScopeEntry {
            name: "eth9".to_owned(),
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

    /// A second eligible interface (wlan9, index 3, a /25).
    fn wlan_entry() -> ScopeEntry {
        ScopeEntry {
            name: "wlan9".to_owned(),
            index: 3,
            mac: Some("02:00:00:00:00:02".parse().expect("valid MAC")),
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 129), 25)),
            is_up: true,
            is_running: true,
            is_loopback: false,
            class: InterfaceClass::Physical,
            eligibility: Eligibility::Eligible,
            default_gateway: None,
        }
    }

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
            eligibility: Eligibility::Ineligible(IneligibleReason::Loopback),
            default_gateway: None,
        }
    }

    /// Drives one key through `update`.
    fn key(state: &mut AppState, key: Key, clock: &dyn Clock) -> Vec<Effect> {
        update(state, AppEvent::Input(InputEvent::Key(key)), clock)
    }

    /// A fresh state over the entries, past the notice and the scope
    /// confirmation (the realistic path: `y` then `Enter`).
    fn confirmed(entries: Vec<ScopeEntry>) -> (AppState, FakeClock) {
        confirmed_with(SessionParams::default(), entries)
    }

    fn confirmed_with(params: SessionParams, entries: Vec<ScopeEntry>) -> (AppState, FakeClock) {
        let clock = FakeClock::new();
        let mut state = AppState::with_scope_entries(params, entries, db(), &clock).expect("valid");
        // A pre-acknowledged notice starts on Scope; otherwise drive
        // the `y` first (the realistic path).
        if state.screen() == Screen::Notice {
            key(&mut state, Key::Char('y'), &clock);
        }
        assert_eq!(state.screen(), Screen::Scope);
        key(&mut state, Key::Enter, &clock);
        assert_eq!(state.screen(), Screen::Dashboard);
        (state, clock)
    }

    /// One scanner observation (the arp/worker payload shape).
    fn scanner_obs(mac: &str, ip: Ipv4Addr) -> ScannerObservation {
        ScannerObservation {
            ip,
            mac: mac.parse().expect("valid MAC"),
            source: Source::NeighborTable,
        }
    }

    fn cycle_started(scan_id: u64, trigger: Trigger) -> CycleEvent {
        CycleEvent::Started {
            scan_id: ScanId::new(scan_id),
            trigger,
            mode: CycleMode::Active,
        }
    }

    fn cycle_finished(
        scan_id: u64,
        trigger: Trigger,
        outcome: DiscoveryOutcome,
        degraded: Option<Degradation>,
    ) -> CycleEvent {
        CycleEvent::Finished {
            scan_id: ScanId::new(scan_id),
            trigger,
            mode: CycleMode::Active,
            summary: Box::new(CycleSummary {
                outcome,
                counters: ScanCounters::default(),
                elapsed: Duration::from_secs(1),
                degraded,
            }),
        }
    }

    fn observations(scan_id: u64, batch: Vec<ScannerObservation>) -> CycleEvent {
        CycleEvent::Observations {
            scan_id: ScanId::new(scan_id),
            batch,
        }
    }

    /// The one device the confirm path inserts (the local machine).
    fn local_key(state: &AppState) -> DeviceKey {
        let confirmed = state.confirmed_scope().expect("confirmed");
        DeviceKey {
            iface_index: confirmed.iface_index,
            mac: confirmed.iface_mac.expect("eth9 has a MAC"),
        }
    }

    // ---- AC-2: the full scenario script, thread-free and channel-free ----

    #[test]
    fn ac2_full_scenario_script_notice_to_quit() {
        let (mut state, clock) = confirmed(vec![eth_entry(Some(Ipv4Addr::new(192, 0, 2, 254)))]);

        // The local device is present, tagged `This device`, vendor
        // filled (the locally-administered MAC answers PrivateAddress).
        assert_eq!(state.registry.device_count(), 1);
        let device = state
            .registry
            .get(&local_key(&state))
            .expect("local device");
        assert!(device.tags.contains(Tag::ThisDevice));
        assert_eq!(device.primary_ip(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            device.vendor,
            Field::Known {
                value: DisplayText::try_from("Private address").expect("valid"),
                source: Source::VendorDb,
            }
        );
        // The confirmed scope facts.
        let confirmed = state.confirmed_scope().expect("confirmed");
        assert_eq!(confirmed.iface_name, "eth9");
        assert_eq!(confirmed.iface_index, 2);
        assert_eq!(
            confirmed.scope,
            crate::model::Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 24).expect("valid")
        );
        assert_eq!(confirmed.gateway_ip, Some(Ipv4Addr::new(192, 0, 2, 254)));

        // Details open for the selected row; the registry starts
        // unselected, so the first navigation key selects it.
        assert_eq!(state.registry.selected_key(), None);
        key(&mut state, Key::Char('j'), &clock);
        let selected = state.registry.selected_key().expect("selected");
        assert_eq!(selected, local_key(&state));
        key(&mut state, Key::Enter, &clock);
        assert_eq!(state.screen(), Screen::Details);
        assert!(state.dirty);

        // Esc returns to Dashboard, selection preserved.
        key(&mut state, Key::Esc, &clock);
        assert_eq!(state.screen(), Screen::Dashboard);
        assert_eq!(state.registry.selected_key(), Some(local_key(&state)));

        // Help overlay: ? opens, Esc closes, the screen beneath stays.
        key(&mut state, Key::Char('?'), &clock);
        assert!(state.help_open());
        key(&mut state, Key::Esc, &clock);
        assert!(!state.help_open());
        assert_eq!(state.screen(), Screen::Dashboard);

        // `r` on the fresh (never-polled) scheduler starts a Manual
        // cycle with the exact §2 recipe (ADR-011: 2 passes).
        let effects = key(&mut state, Key::Char('r'), &clock);
        assert_eq!(
            effects,
            vec![Effect::StartScan {
                trigger: Trigger::Manual,
                params: scan_params_for(Trigger::Manual),
            }]
        );
        assert_eq!(
            scan_params_for(Trigger::Manual),
            ScanParams {
                passes: 2,
                rate_pps: DEFAULT_RATE_PPS,
                listen_window: DEFAULT_LISTEN_WINDOW,
            }
        );

        // `s` toggles the sort mode; the selection survives (FR-RG-06).
        assert_eq!(state.registry.sort_mode(), SortMode::Ip);
        key(&mut state, Key::Char('s'), &clock);
        assert_eq!(state.registry.sort_mode(), SortMode::Hostname);
        assert_eq!(state.registry.selected_key(), Some(local_key(&state)));
        key(&mut state, Key::Char('s'), &clock);
        assert_eq!(state.registry.sort_mode(), SortMode::Ip);

        // `q` quits: the authoritative flag and the informational
        // effect, together (§5.3).
        let effects = key(&mut state, Key::Char('q'), &clock);
        assert_eq!(effects, vec![Effect::Quit]);
        assert!(state.quit());
    }

    #[test]
    fn ac2_confirm_effects_and_arming() {
        // The confirm path's own effects, in isolation (AC-4's pure
        // half; the runtime half lives in the runtime suite).
        let clock = FakeClock::new();
        let mut state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![eth_entry(Some(Ipv4Addr::new(192, 0, 2, 254)))],
            db(),
            &clock,
        )
        .expect("valid");
        key(&mut state, Key::Char('y'), &clock);
        let effects = key(&mut state, Key::Enter, &clock);
        // Hostnames enabled ⇒ exactly the own-address lookup.
        assert_eq!(
            effects,
            vec![Effect::ResolveHostname {
                ip: Ipv4Addr::new(192, 0, 2, 1)
            }]
        );
        assert!(state.discovery_armed());
        assert_eq!(state.screen(), Screen::Dashboard);
    }

    #[test]
    fn ac2_confirm_without_hostnames_queues_nothing() {
        let params = SessionParams {
            hostnames_enabled: false,
            ..SessionParams::default()
        };
        let clock = FakeClock::new();
        let mut state = AppState::with_scope_entries(params, vec![eth_entry(None)], db(), &clock)
            .expect("valid");
        key(&mut state, Key::Char('y'), &clock);
        let effects = key(&mut state, Key::Enter, &clock);
        assert!(effects.is_empty());
        assert!(state.discovery_armed());
    }

    #[test]
    fn ac2_gateway_observed_in_a_cycle_gets_the_gateway_tag() {
        // The `Gateway` tag is applied to *observed* devices holding
        // the recorded address (§5.3): confirm with a gateway, then
        // observe the gateway's MAC with the gateway address.
        let (mut state, clock) = confirmed(vec![eth_entry(Some(Ipv4Addr::new(192, 0, 2, 254)))]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![scanner_obs(
                    "28:6f:b9:00:00:01",
                    Ipv4Addr::new(192, 0, 2, 254),
                )],
            )),
            &clock,
        );
        let key = DeviceKey {
            iface_index: 2,
            mac: "28:6f:b9:00:00:01".parse().expect("valid MAC"),
        };
        let device = state.registry.get(&key).expect("gateway device");
        assert!(device.tags.contains(Tag::Gateway));
        // The local device is not the gateway.
        let local = state.registry.get(&local_key(&state)).expect("local");
        assert!(!local.tags.contains(Tag::Gateway));
    }

    // ---- AC-3: nothing discovery-shaped before the confirmation ----

    #[test]
    fn ac3_key_mash_before_confirmation_produces_zero_discovery_effects() {
        // The property-style mash the card suggests (§8 test-quality):
        // LCG high-bit draws (the T-203 §11.1 form). Three phases,
        // each pre-confirmation **by construction**:
        //   (a) the Notice screen — every key except `y`/`q`/`CtrlC`;
        //   (b) the Scope screen over an eligible list — every key
        //       except `Enter`/`q`/`CtrlC` (Enter would legitimately
        //       confirm, which is AC-2's job, not this mash's);
        //   (c) the Scope screen over an ineligible-only list — Enter
        //       included: it can never confirm there.
        // No StartScan effect is ever emitted, discovery never arms,
        // and the scheduler is provably never polled: its fresh
        // `Immediately` state is still intact at the end.
        let mut lcg = Lcg::seeded(0x2050);
        let common: Vec<Key> = vec![
            Key::Up,
            Key::Down,
            Key::PageUp,
            Key::PageDown,
            Key::Home,
            Key::End,
            Key::Esc,
            Key::Char('j'),
            Key::Char('k'),
            Key::Char('g'),
            Key::Char('G'),
            Key::Char('r'),
            Key::Char('s'),
            Key::Char('?'),
            Key::Char('x'),
            Key::Char(' '),
        ];
        let clock = FakeClock::new();

        // (a) Notice: `y` excluded (it would leave the screen).
        let mut notice_state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![loopback_entry(), eth_entry(None), wlan_entry()],
            db(),
            &clock,
        )
        .expect("valid");
        let vocabulary: Vec<Key> = common.to_vec();
        for _ in 0..2000 {
            let draw = (lcg.next_u64() >> 32) % vocabulary.len() as u64;
            let pressed = vocabulary[draw as usize];
            let effects = key(&mut notice_state, pressed, &clock);
            assert!(
                effects
                    .iter()
                    .all(|effect| !matches!(effect, Effect::StartScan { .. })),
                "no StartScan may exist before confirmation (got {effects:?})"
            );
            assert_eq!(notice_state.screen(), Screen::Notice);
            assert!(!notice_state.discovery_armed());
        }

        // (b) Scope over an eligible list: `Enter` excluded.
        let mut scope_state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![loopback_entry(), eth_entry(None), wlan_entry()],
            db(),
            &clock,
        )
        .expect("valid");
        key(&mut scope_state, Key::Char('y'), &clock);
        let vocabulary: Vec<Key> = common.to_vec();
        for _ in 0..2000 {
            let draw = (lcg.next_u64() >> 32) % vocabulary.len() as u64;
            let pressed = vocabulary[draw as usize];
            let effects = key(&mut scope_state, pressed, &clock);
            assert!(
                effects
                    .iter()
                    .all(|effect| !matches!(effect, Effect::StartScan { .. })),
                "no StartScan may exist before confirmation (got {effects:?})"
            );
            assert_eq!(scope_state.screen(), Screen::Scope);
            assert!(!scope_state.discovery_armed());
        }

        // (c) Scope over an ineligible-only list: Enter included (a
        // refusal with the ScopeUnavailable message, never a confirm).
        let mut stuck_state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![loopback_entry(), loopback_entry()],
            db(),
            &clock,
        )
        .expect("valid");
        key(&mut stuck_state, Key::Char('y'), &clock);
        let mut vocabulary: Vec<Key> = common.to_vec();
        vocabulary.push(Key::Enter);
        for _ in 0..2000 {
            let draw = (lcg.next_u64() >> 32) % vocabulary.len() as u64;
            let pressed = vocabulary[draw as usize];
            let effects = key(&mut stuck_state, pressed, &clock);
            assert!(
                effects
                    .iter()
                    .all(|effect| !matches!(effect, Effect::StartScan { .. })),
                "no StartScan may exist before confirmation (got {effects:?})"
            );
            assert_eq!(stuck_state.screen(), Screen::Scope);
            assert!(!stuck_state.discovery_armed());
        }

        // The scheduler was never polled: a fresh scheduler's initial
        // cycle is still due right now, and it is not running.
        assert_eq!(
            stuck_state.scheduler.next_auto_in(clock.now()),
            Some(Duration::ZERO)
        );
        assert!(!stuck_state.scheduler.is_running());
        assert!(
            !stuck_state.quit(),
            "the mash never presses q/CtrlC (excluded from the vocabulary)"
        );
    }

    // ---- §5.6 key-map details ----------------------------------------------

    #[test]
    fn scope_navigation_skips_ineligible_rows_and_wraps() {
        // [lo (ineligible), eth9 (eligible), wlan9 (eligible)]
        let entries = vec![loopback_entry(), eth_entry(None), wlan_entry()];
        let clock = FakeClock::new();
        let mut state =
            AppState::with_scope_entries(SessionParams::default(), entries, db(), &clock)
                .expect("valid");
        // Construction selected the first eligible row: eth9 (1).
        assert_eq!(state.scope_selected(), 1);
        // Leave the notice screen, then navigate.
        key(&mut state, Key::Char('y'), &clock);
        assert_eq!(state.screen(), Screen::Scope);
        // Down moves to wlan9 (2); Down again wraps back to eth9 (1).
        key(&mut state, Key::Down, &clock);
        assert_eq!(state.scope_selected(), 2);
        key(&mut state, Key::Down, &clock);
        assert_eq!(
            state.scope_selected(),
            1,
            "wraps past the last eligible row"
        );
        // Up wraps backwards to wlan9 (2); the ineligible lo (0) is
        // never selected.
        key(&mut state, Key::Up, &clock);
        assert_eq!(state.scope_selected(), 2);
        // j/k are the same moves.
        key(&mut state, Key::Char('j'), &clock);
        assert_eq!(state.scope_selected(), 1);
        key(&mut state, Key::Char('k'), &clock);
        assert_eq!(state.scope_selected(), 2);
    }

    #[test]
    fn scope_navigation_without_eligible_rows_is_a_no_op() {
        let entries = vec![loopback_entry(), loopback_entry()];
        let clock = FakeClock::new();
        let mut state =
            AppState::with_scope_entries(SessionParams::default(), entries, db(), &clock)
                .expect("valid");
        assert_eq!(state.scope_selected(), 0);
        key(&mut state, Key::Char('y'), &clock);
        assert_eq!(state.screen(), Screen::Scope);
        key(&mut state, Key::Down, &clock);
        key(&mut state, Key::Up, &clock);
        assert_eq!(state.scope_selected(), 0);
    }

    #[test]
    fn scope_enter_on_ineligible_selection_reports_scope_unavailable() {
        // Only loopback exists: the selection sits on it, and Enter
        // refuses with the net layer's own words as the reason.
        let entries = vec![loopback_entry()];
        let clock = FakeClock::new();
        let mut state =
            AppState::with_scope_entries(SessionParams::default(), entries, db(), &clock)
                .expect("valid");
        key(&mut state, Key::Char('y'), &clock);
        let effects = key(&mut state, Key::Enter, &clock);
        assert!(effects.is_empty());
        assert_eq!(state.screen(), Screen::Scope, "the screen stays");
        assert!(!state.discovery_armed());
        // The construction-time NoEligibleResolver (default params)
        // plus the refusal.
        let messages: Vec<&Message> = state.messages().collect();
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[1].kind,
            MessageKind::ScopeUnavailable {
                reason: "loopback interface".to_owned()
            }
        );
        // Repeat Enter: the identical message is suppressed (§5.7).
        key(&mut state, Key::Enter, &clock);
        assert_eq!(state.messages().count(), 2);
    }

    #[test]
    fn unknown_keys_are_ignored_without_marking_dirty() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        state.dirty = false;
        let effects = key(&mut state, Key::Char('x'), &clock);
        assert!(effects.is_empty());
        assert!(!state.dirty, "an unknown key changes nothing");
        // `?` from Details opens the overlay; `x` inside it is
        // ignored; Esc still closes it.
        key(&mut state, Key::Char('j'), &clock);
        key(&mut state, Key::Enter, &clock);
        assert_eq!(state.screen(), Screen::Details);
        state.dirty = false;
        key(&mut state, Key::Char('x'), &clock);
        assert!(!state.dirty);
        key(&mut state, Key::Char('?'), &clock);
        assert!(state.help_open());
        state.dirty = false;
        key(&mut state, Key::Char('j'), &clock); // modal: ignored
        assert!(!state.dirty);
        assert!(state.help_open());
        key(&mut state, Key::Esc, &clock);
        assert!(!state.help_open());
        // `?` also closes the overlay (toggle semantics).
        key(&mut state, Key::Char('?'), &clock);
        key(&mut state, Key::Char('?'), &clock);
        assert!(!state.help_open());
    }

    #[test]
    fn ctrl_c_quits_from_every_screen_and_overlay() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        // Dashboard.
        let effects = key(&mut state, Key::CtrlC, &clock);
        assert_eq!(effects, vec![Effect::Quit]);
        assert!(state.quit());
        // Test-only surgery to continue the round (production never
        // un-quits).
        state.quit = false;
        // Details.
        key(&mut state, Key::Char('j'), &clock);
        key(&mut state, Key::Enter, &clock);
        assert_eq!(state.screen(), Screen::Details);
        let effects = key(&mut state, Key::CtrlC, &clock);
        assert_eq!(effects, vec![Effect::Quit]);
        state.quit = false;
        // Help overlay.
        key(&mut state, Key::Esc, &clock);
        key(&mut state, Key::Char('?'), &clock);
        assert!(state.help_open());
        let effects = key(&mut state, Key::Char('q'), &clock);
        assert_eq!(effects, vec![Effect::Quit]);
        assert!(state.quit());
    }

    #[test]
    fn page_keys_move_by_eight_rows_and_clamp() {
        // 20 devices: the local one plus 19 observed.
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        let batch: Vec<_> = (0..19)
            .map(|host| {
                scanner_obs(
                    &format!("02:11:22:33:44:{host:02x}"),
                    Ipv4Addr::new(192, 0, 2, 200),
                )
            })
            .collect();
        update(
            &mut state,
            AppEvent::Discovery(observations(1, batch)),
            &clock,
        );
        assert_eq!(state.registry.device_count(), 20);
        // No selection: both page keys select the first row.
        key(&mut state, Key::PageDown, &clock);
        let first = state.registry.selected_key().expect("selected");
        assert_eq!(
            first,
            state
                .registry
                .sorted_keys()
                .first()
                .copied()
                .expect("non-empty")
        );
        // PageDown moves 8 rows down the sorted (IP) order.
        let keys = state.registry.sorted_keys();
        key(&mut state, Key::PageDown, &clock);
        assert_eq!(state.registry.selected_key(), keys.get(8).copied());
        key(&mut state, Key::PageDown, &clock);
        assert_eq!(state.registry.selected_key(), keys.get(16).copied());
        // PageDown clamps at the last row (16 + 8 > 19).
        key(&mut state, Key::PageDown, &clock);
        assert_eq!(state.registry.selected_key(), keys.get(19).copied());
        // PageUp goes back 8; Home/End jump to the ends.
        key(&mut state, Key::PageUp, &clock);
        assert_eq!(state.registry.selected_key(), keys.get(11).copied());
        key(&mut state, Key::Home, &clock);
        assert_eq!(state.registry.selected_key(), keys.first().copied());
        key(&mut state, Key::Char('g'), &clock);
        assert_eq!(state.registry.selected_key(), keys.first().copied());
        key(&mut state, Key::End, &clock);
        assert_eq!(state.registry.selected_key(), keys.last().copied());
        key(&mut state, Key::Char('G'), &clock);
        assert_eq!(state.registry.selected_key(), keys.last().copied());
    }

    #[test]
    fn details_navigation_moves_the_selection() {
        // The house choice, tested (§5.6): Up/Down/j/k move the
        // selection while Details is open; Esc returns to Dashboard
        // with the moved selection intact.
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        let batch = vec![
            scanner_obs("02:11:22:33:44:aa", Ipv4Addr::new(192, 0, 2, 10)),
            scanner_obs("02:11:22:33:44:bb", Ipv4Addr::new(192, 0, 2, 20)),
            scanner_obs("02:11:22:33:44:cc", Ipv4Addr::new(192, 0, 2, 30)),
        ];
        update(
            &mut state,
            AppEvent::Discovery(observations(1, batch)),
            &clock,
        );
        key(&mut state, Key::Char('j'), &clock); // select first
        let keys = state.registry.sorted_keys();
        key(&mut state, Key::Enter, &clock); // Details
        assert_eq!(state.screen(), Screen::Details);
        key(&mut state, Key::Down, &clock);
        assert_eq!(state.registry.selected_key(), keys.get(1).copied());
        key(&mut state, Key::Char('j'), &clock);
        assert_eq!(state.registry.selected_key(), keys.get(2).copied());
        key(&mut state, Key::Up, &clock);
        assert_eq!(state.registry.selected_key(), keys.get(1).copied());
        key(&mut state, Key::Char('k'), &clock);
        assert_eq!(state.registry.selected_key(), keys.first().copied());
        key(&mut state, Key::Esc, &clock);
        assert_eq!(state.screen(), Screen::Dashboard);
        assert_eq!(state.registry.selected_key(), keys.first().copied());
    }

    // ---- AC-6: refresh, sort, selection survival ---------------------------

    #[test]
    fn ac6_refresh_during_a_running_cycle_is_already_in_progress_nothing_queued() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        // A cycle is "running" in the scheduler's view once a start
        // decision was made (the `r` key's own effect, or the
        // runtime's poll — same machine).
        let effects = key(&mut state, Key::Char('r'), &clock);
        assert_eq!(effects.len(), 1);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(7, Trigger::Manual)),
            &clock,
        );
        // The second `r` during the cycle: the typed message, no
        // effect, nothing queued (FR-DS-08).
        let effects = key(&mut state, Key::Char('r'), &clock);
        assert!(effects.is_empty());
        assert!(
            state
                .messages
                .contains_kind(&MessageKind::ScanAlreadyInProgress)
        );
        // And the scheduler still holds exactly one running cycle.
        assert!(state.scheduler.is_running());
    }

    #[test]
    fn ac6_after_the_finish_refresh_starts_a_manual_two_pass_cycle() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(7, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                7,
                Trigger::Manual,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        assert!(!state.scheduler.is_running());
        let effects = key(&mut state, Key::Char('r'), &clock);
        assert_eq!(
            effects,
            vec![Effect::StartScan {
                trigger: Trigger::Manual,
                params: ScanParams {
                    passes: 2,
                    rate_pps: DEFAULT_RATE_PPS,
                    listen_window: DEFAULT_LISTEN_WINDOW,
                },
            }]
        );
    }

    #[test]
    fn ac6_selection_survives_re_sort_and_row_changing_refresh() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        // Cycle 1: three devices (plus the local one).
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        let batch = vec![
            scanner_obs("02:11:22:33:44:aa", Ipv4Addr::new(192, 0, 2, 30)),
            scanner_obs("02:11:22:33:44:bb", Ipv4Addr::new(192, 0, 2, 10)),
            scanner_obs("02:11:22:33:44:cc", Ipv4Addr::new(192, 0, 2, 20)),
        ];
        update(
            &mut state,
            AppEvent::Discovery(observations(1, batch)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Initial,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        // Select the .30 device (last in IP order).
        key(&mut state, Key::End, &clock);
        let selected = state.registry.selected_key().expect("selected");
        assert_eq!(
            state.registry.get(&selected).expect("device").primary_ip(),
            Ipv4Addr::new(192, 0, 2, 30)
        );
        // Sort toggle: order changes, selection survives (FR-RG-06).
        key(&mut state, Key::Char('s'), &clock);
        assert_eq!(state.registry.sort_mode(), SortMode::Hostname);
        assert_eq!(state.registry.selected_key(), Some(selected));
        // A refresh that changes the row: the .30 device moves by
        // being re-observed under a newer primary IP.
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(2, Trigger::Periodic)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(observations(
                2,
                vec![scanner_obs(
                    "02:11:22:33:44:aa",
                    Ipv4Addr::new(192, 0, 2, 5),
                )],
            )),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                2,
                Trigger::Periodic,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        assert_eq!(state.registry.selected_key(), Some(selected));
        assert_eq!(
            state.registry.get(&selected).expect("device").primary_ip(),
            Ipv4Addr::new(192, 0, 2, 5),
            "the re-observation moved the row"
        );
    }

    // ---- AC-7: FR-DS-12 end-to-end, scripted and pure -----------------------

    #[test]
    fn ac7_three_failures_stop_auto_scans_sticky_and_manual_still_works() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        // Three Failed finishes through the full event path
        // (start decision → Started → Finished(Failed)).
        for scan_id in 1..=3u64 {
            key(&mut state, Key::Char('r'), &clock);
            update(
                &mut state,
                AppEvent::Discovery(cycle_started(scan_id, Trigger::Manual)),
                &clock,
            );
            update(
                &mut state,
                AppEvent::Discovery(cycle_finished(
                    scan_id,
                    Trigger::Manual,
                    DiscoveryOutcome::Failed {
                        reason: format!("iface gone ({scan_id})"),
                    },
                    None,
                )),
                &clock,
            );
        }
        // Exactly one AutoScansStopped message; the state flag is set.
        assert_eq!(state.messages.count_of(&MessageKind::AutoScansStopped), 1);
        assert!(state.auto_stopped());
        // Sticky (the PQ-1 ruling): a later manual Complete resets the
        // failure streak at its finish but never the stop.
        assert_eq!(state.scheduler.failure_streak(), 3);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(4, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                4,
                Trigger::Manual,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        assert_eq!(
            state.scheduler.failure_streak(),
            0,
            "Complete resets the streak"
        );
        assert!(state.auto_stopped(), "sticky across the manual success");
        assert!(state.scheduler.auto_scans_stopped());
        // poll issues nothing, ever again in-session — proven across
        // advancing time (a fresh poll would issue the initial cycle
        // immediately; a periodic would follow an anchored finish).
        for _ in 0..10 {
            let now = clock.now();
            assert_eq!(state.scheduler.poll(now), SchedulerDecision::None);
        }
        // Manual refresh still works while stopped (ruling (c)).
        let effects = key(&mut state, Key::Char('r'), &clock);
        assert_eq!(
            effects,
            vec![Effect::StartScan {
                trigger: Trigger::Manual,
                params: scan_params_for(Trigger::Manual),
            }]
        );
        // Still exactly one stop message.
        assert_eq!(state.messages.count_of(&MessageKind::AutoScansStopped), 1);
    }

    #[test]
    fn ac7_failed_backoff_and_cancelled_plain_interval_anchoring() {
        // With the 15 s minimum interval: a Failed finish anchors the
        // next auto at max(15, 30) = 30 s; a Cancelled finish at 15 s.
        let params = SessionParams {
            interval: RediscoveryInterval::new(Duration::from_secs(15))
                .expect("15 s is the minimum"),
            notice_acknowledged: true,
            ..SessionParams::default()
        };
        let (mut state, clock) = confirmed_with(params, vec![eth_entry(None)]);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Manual)),
            &clock,
        );
        let _finished_at = clock.now();
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Manual,
                DiscoveryOutcome::Failed {
                    reason: "boom".to_owned(),
                },
                None,
            )),
            &clock,
        );
        assert_eq!(
            state.scheduler.next_auto_in(clock.now()),
            Some(Duration::from_secs(30)),
            "max(interval, FAILURE_BACKOFF_FLOOR)"
        );
        let mut at_29 = clock.clone();
        at_29.advance(Duration::from_secs(29));
        assert_eq!(
            state.scheduler.next_auto_in(at_29.now()),
            Some(Duration::from_secs(1))
        );
        let mut at_30 = clock.clone();
        at_30.advance(Duration::from_secs(30));
        assert_eq!(
            state.scheduler.next_auto_in(at_30.now()),
            Some(Duration::ZERO),
            "due exactly at finish + 30 s"
        );

        // A Cancelled finish anchors at the plain interval.
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(2, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                2,
                Trigger::Manual,
                DiscoveryOutcome::Cancelled,
                None,
            )),
            &clock,
        );
        assert_eq!(
            state.scheduler.next_auto_in(clock.now()),
            Some(Duration::from_secs(15))
        );
    }

    // ---- AC-8: enrichment rules ---------------------------------------------

    #[test]
    fn ac8_new_device_gets_vendor_and_hostname_effect_all_three_lookup_arms() {
        // (MAC, expected vendor): None ⇒ Field::Unknown.
        for (mac, expected) in [
            // Found (the embedded DB, T-202's pinned real fixture):
            ("28:6f:b9:00:00:01", Some("Nokia Shanghai Bell Co., Ltd.")),
            // PrivateAddress (locally administered):
            ("02:28:6f:b9:12:34", Some("Private address")),
            // Unknown (unassigned prefix at every length):
            ("ec:ec:ec:11:22:33", None),
        ] {
            let (mut state, clock) = confirmed(vec![eth_entry(None)]);
            update(
                &mut state,
                AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
                &clock,
            );
            let effects = update(
                &mut state,
                AppEvent::Discovery(observations(
                    1,
                    vec![scanner_obs(mac, Ipv4Addr::new(192, 0, 2, 77))],
                )),
                &clock,
            );
            // New device ⇒ vendor set + hostname effect queued.
            assert_eq!(
                effects,
                vec![Effect::ResolveHostname {
                    ip: Ipv4Addr::new(192, 0, 2, 77)
                }],
                "MAC {mac}"
            );
            let key = DeviceKey {
                iface_index: 2,
                mac: mac.parse().expect("valid MAC"),
            };
            let device = state.registry.get(&key).expect("device exists");
            match expected {
                None => assert_eq!(device.vendor, Field::<DisplayText>::Unknown, "MAC {mac}"),
                Some(name) => {
                    let value = DisplayText::try_from(name).expect("valid name");
                    assert_eq!(
                        device.vendor,
                        Field::Known {
                            value,
                            source: Source::VendorDb,
                        },
                        "MAC {mac}"
                    );
                }
            }
        }
    }

    #[test]
    fn ac8_existing_device_reobserved_vendor_not_recomputed_hostname_requeued() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        let mac = "28:6f:b9:00:00:01";
        update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![scanner_obs(mac, Ipv4Addr::new(192, 0, 2, 77))],
            )),
            &clock,
        );
        let key = DeviceKey {
            iface_index: 2,
            mac: mac.parse().expect("valid MAC"),
        };
        // Overwrite the vendor with a sentinel; a re-observation that
        // recomputed it would clobber the sentinel.
        let sentinel = Field::Known {
            value: DisplayText::try_from("sentinel").expect("valid"),
            source: Source::LocalInterface,
        };
        state.registry.set_vendor(&key, sentinel.clone());
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Initial,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(2, Trigger::Periodic)),
            &clock,
        );
        let effects = update(
            &mut state,
            AppEvent::Discovery(observations(
                2,
                vec![scanner_obs(mac, Ipv4Addr::new(192, 0, 2, 77))],
            )),
            &clock,
        );
        // The vendor sentinel survived: no recompute.
        let device = state.registry.get(&key).expect("device");
        assert_eq!(device.vendor, sentinel);
        // The hostname effect was re-queued (intentional, §5.9).
        assert_eq!(
            effects,
            vec![Effect::ResolveHostname {
                ip: Ipv4Addr::new(192, 0, 2, 77)
            }]
        );
    }

    #[test]
    fn ac8_resolved_applies_to_every_record_holding_the_ip() {
        // The ADR-008 shared-IP case: one address under two MACs is
        // kept by both records; one lookup describes both.
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![
                    scanner_obs("02:11:22:33:44:aa", Ipv4Addr::new(192, 0, 2, 50)),
                    scanner_obs("28:6f:b9:00:00:01", Ipv4Addr::new(192, 0, 2, 50)),
                ],
            )),
            &clock,
        );
        assert_eq!(state.registry.device_count(), 3); // local + two MACs
        let name = Hostname::try_from("shared.lan").expect("valid hostname");
        update(
            &mut state,
            AppEvent::Hostname(HostnameEvent::Resolved {
                ip: Ipv4Addr::new(192, 0, 2, 50),
                outcome: Field::Known {
                    value: name.clone(),
                    source: Source::ReverseDns,
                },
            }),
            &clock,
        );
        for mac in ["02:11:22:33:44:aa", "28:6f:b9:00:00:01"] {
            let key = DeviceKey {
                iface_index: 2,
                mac: mac.parse().expect("valid MAC"),
            };
            let device = state.registry.get(&key).expect("device");
            assert_eq!(
                device.hostname,
                Field::Known {
                    value: name.clone(),
                    source: Source::ReverseDns,
                },
                "MAC {mac} holds the resolved name"
            );
        }
        // The local device (192.0.2.1) is untouched.
        let local = state.registry.get(&local_key(&state)).expect("local");
        assert_eq!(local.hostname, Field::<Hostname>::Pending);
    }

    #[test]
    fn ac8_hostnames_disabled_emits_zero_hostname_effects_in_the_whole_script() {
        let params = SessionParams {
            hostnames_enabled: false,
            ..SessionParams::default()
        };
        let (mut state, clock) = confirmed_with(params, vec![eth_entry(None)]);
        let mut seen: Vec<Effect> = Vec::new();
        seen.extend(update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        ));
        seen.extend(update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![
                    scanner_obs("02:11:22:33:44:aa", Ipv4Addr::new(192, 0, 2, 10)),
                    scanner_obs("28:6f:b9:00:00:01", Ipv4Addr::new(192, 0, 2, 11)),
                ],
            )),
            &clock,
        ));
        seen.extend(update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Initial,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        ));
        assert!(
            seen.iter()
                .all(|effect| !matches!(effect, Effect::ResolveHostname { .. })),
            "zero hostname effects, got {seen:?}"
        );
        assert_eq!(state.registry.device_count(), 3);
        // The vendor fill still happened (it is not hostname-gated).
        let key = DeviceKey {
            iface_index: 2,
            mac: "28:6f:b9:00:00:01".parse().expect("valid MAC"),
        };
        let device = state.registry.get(&key).expect("device");
        assert!(device.vendor.is_known());
    }

    // ---- AC-9: the message log through scripted triggers --------------------

    #[test]
    fn ac9_every_cycle_message_kind_is_produced_by_a_scripted_trigger() {
        // ScanFailed + verbatim reason.
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Manual,
                DiscoveryOutcome::Failed {
                    reason: "socket vanished".to_owned(),
                },
                None,
            )),
            &clock,
        );
        assert_eq!(
            state.messages.latest().expect("non-empty").kind,
            MessageKind::ScanFailed {
                reason: "socket vanished".to_owned()
            }
        );

        // ScanDegraded + verbatim reason.
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(2, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                2,
                Trigger::Manual,
                DiscoveryOutcome::Partial,
                Some(Degradation::PreReadFailed {
                    reason: "/proc/net/arp unreadable".to_owned(),
                }),
            )),
            &clock,
        );
        assert_eq!(
            state.messages.latest().expect("non-empty").kind,
            MessageKind::ScanDegraded {
                reason: "/proc/net/arp unreadable".to_owned()
            }
        );

        // A Partial without degradation appends nothing (the plain
        // partial is the honest outcome; §6.8 words it on the header).
        let before = state.messages().count();
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(3, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                3,
                Trigger::Manual,
                DiscoveryOutcome::Partial,
                None,
            )),
            &clock,
        );
        assert_eq!(state.messages().count(), before);

        // The construction-time kinds (ReadOnlyMode, RootWarning,
        // NoEligibleResolver) are covered by the state suite; the
        // navigation-time kinds (ScanAlreadyInProgress,
        // ScopeUnavailable) and AutoScansStopped / RegistryCapReached
        // by the tests above and below.
    }

    #[test]
    fn ac9_hundred_cap_drops_produce_one_cap_message() {
        // A tiny registry cap (the config allows small values exactly
        // so cap behavior can be tested cheaply).
        let params = SessionParams {
            registry: crate::registry::RegistryConfig {
                max_devices: 2,
                ..crate::registry::RegistryConfig::default()
            },
            ..SessionParams::default()
        };
        let (mut state, clock) = confirmed_with(params, vec![eth_entry(None)]);
        // The local device already fills one of the two slots.
        assert_eq!(state.registry.device_count(), 1);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        let batch: Vec<_> = (0..100)
            .map(|host| {
                scanner_obs(
                    &format!("02:33:44:55:66:{host:02x}"),
                    Ipv4Addr::new(192, 0, 2, 200),
                )
            })
            .collect();
        update(
            &mut state,
            AppEvent::Discovery(observations(1, batch)),
            &clock,
        );
        // One device made it in (cap 2), 99 dropped, one message.
        assert_eq!(state.registry.device_count(), 2);
        assert_eq!(
            state.messages.count_of(&MessageKind::RegistryCapReached),
            1,
            "100 cap-dropped observations produce one RegistryCapReached"
        );
        assert!(state.registry.cap_warning());
    }

    #[test]
    fn ac9_repeated_identical_failures_dedup_while_present() {
        // The §5.7 general rule applied to cycle kinds: identical
        // (kind, reason) repeats are suppressed while present (the
        // report records this reading of "once per finished cycle").
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        for scan_id in 1..=2u64 {
            key(&mut state, Key::Char('r'), &clock);
            update(
                &mut state,
                AppEvent::Discovery(cycle_started(scan_id, Trigger::Manual)),
                &clock,
            );
            update(
                &mut state,
                AppEvent::Discovery(cycle_finished(
                    scan_id,
                    Trigger::Manual,
                    DiscoveryOutcome::Failed {
                        reason: "same reason".to_owned(),
                    },
                    None,
                )),
                &clock,
            );
        }
        assert_eq!(
            state.messages.count_of(&MessageKind::ScanFailed {
                reason: String::new()
            }),
            1,
            "the identical repeat is suppressed while present"
        );
        // A different reason is a new message.
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(3, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                3,
                Trigger::Manual,
                DiscoveryOutcome::Failed {
                    reason: "another reason".to_owned(),
                },
                None,
            )),
            &clock,
        );
        assert_eq!(
            state.messages.count_of(&MessageKind::ScanFailed {
                reason: String::new()
            }),
            2
        );
    }

    // ---- AC-10: resize --------------------------------------------------------

    #[test]
    fn ac10_too_small_bounds_and_recovery() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        // Populate state so "never reset" is provable: a selection,
        // a scan record, a message.
        key(&mut state, Key::Char('j'), &clock);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Manual,
                DiscoveryOutcome::Failed {
                    reason: "pre-shrink".to_owned(),
                },
                None,
            )),
            &clock,
        );
        let selected = state.registry.selected_key();
        let scan_before = state.last_scan().cloned();

        // The boundaries (NFR-08: < 80 columns or < 24 rows).
        for (width, height) in [(79, 24), (80, 23), (79, 23)] {
            update(&mut state, AppEvent::Resize { width, height }, &clock);
            assert!(state.too_small(), "{width}x{height} is too small");
            assert_eq!(state.terminal_size(), (width, height));
        }
        // Exactly 80×24 is not too small.
        update(
            &mut state,
            AppEvent::Resize {
                width: 80,
                height: 24,
            },
            &clock,
        );
        assert!(!state.too_small());
        // And 100×30 neither.
        update(
            &mut state,
            AppEvent::Resize {
                width: 100,
                height: 30,
            },
            &clock,
        );
        assert!(!state.too_small());

        // Recovery: shrink hard, grow back — the underlying screen and
        // every piece of state survive (FR-ST-04: never a reset).
        update(
            &mut state,
            AppEvent::Resize {
                width: 10,
                height: 4,
            },
            &clock,
        );
        assert!(state.too_small());
        assert_eq!(state.screen(), Screen::Dashboard);
        update(
            &mut state,
            AppEvent::Resize {
                width: 120,
                height: 40,
            },
            &clock,
        );
        assert!(!state.too_small());
        assert_eq!(state.screen(), Screen::Dashboard);
        assert_eq!(state.registry.selected_key(), selected);
        assert_eq!(state.last_scan(), scan_before.as_ref());
        assert!(state.messages.contains_kind(&MessageKind::ScanFailed {
            reason: String::new()
        }));

        // q quits while too small.
        update(
            &mut state,
            AppEvent::Resize {
                width: 40,
                height: 10,
            },
            &clock,
        );
        assert!(state.too_small());
        let effects = key(&mut state, Key::Char('q'), &clock);
        assert_eq!(effects, vec![Effect::Quit]);
        assert!(state.quit());
    }

    #[test]
    fn ac10_tick_marks_dirty_and_shutdown_ack_changes_nothing() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        state.dirty = false;
        let effects = update(&mut state, AppEvent::Tick, &clock);
        assert!(effects.is_empty());
        assert!(state.dirty, "the 1 Hz redraw tick marks dirty");
        state.dirty = false;
        let effects = update(
            &mut state,
            AppEvent::Hostname(HostnameEvent::ShutdownAck),
            &clock,
        );
        assert!(effects.is_empty());
        assert!(!state.dirty, "ShutdownAck changes nothing");
    }

    // ---- Misc: the defensive branches ---------------------------------------

    #[test]
    fn observations_before_confirmation_are_ignored() {
        // Hand-injected events pre-confirmation (the runtime never
        // produces them — AC-3): no identity to merge under, no
        // effects, no panic.
        let clock = FakeClock::new();
        let mut state = AppState::with_scope_entries(
            SessionParams {
                notice_acknowledged: true,
                ..SessionParams::default()
            },
            vec![eth_entry(None)],
            db(),
            &clock,
        )
        .expect("valid");
        assert_eq!(state.screen(), Screen::Scope);
        let effects = update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![scanner_obs(
                    "02:11:22:33:44:aa",
                    Ipv4Addr::new(192, 0, 2, 10),
                )],
            )),
            &clock,
        );
        assert!(effects.is_empty());
        assert_eq!(state.registry.device_count(), 0);
    }

    #[test]
    fn stale_scan_batches_are_ignored_by_the_registry() {
        // A batch tagged with a superseded ScanId never reaches the
        // records (FR-RG-03) — and the app layer adds no effects.
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        // A stale batch (scan 99 never began).
        let effects = update(
            &mut state,
            AppEvent::Discovery(observations(
                99,
                vec![scanner_obs(
                    "02:11:22:33:44:aa",
                    Ipv4Addr::new(192, 0, 2, 10),
                )],
            )),
            &clock,
        );
        assert!(effects.is_empty());
        assert_eq!(state.registry.device_count(), 1, "only the local device");
        // The live cycle's batch still lands.
        let effects = update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![scanner_obs(
                    "02:11:22:33:44:aa",
                    Ipv4Addr::new(192, 0, 2, 10),
                )],
            )),
            &clock,
        );
        assert_eq!(effects.len(), 1);
        assert_eq!(state.registry.device_count(), 2);
    }

    #[test]
    fn finished_reanchors_the_scheduler_even_when_the_registry_guard_ignores() {
        // The Finished event of a cycle the registry never began (a
        // late straggler after a superseded begin): the registry
        // ignores it, the scheduler must still re-anchor (§5.5).
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Manual)),
            &clock,
        );
        // Supersede: a new begin makes scan 1 stale for the registry.
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(2, Trigger::Manual)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Manual,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        assert!(
            !state.scheduler.is_running(),
            "re-anchored despite the guard's None"
        );
        // And the next-auto anchor exists.
        assert!(state.scheduler.next_auto_in(clock.now()).is_some());
    }

    #[test]
    fn last_scan_records_the_cycle_facts() {
        let (mut state, clock) = confirmed(vec![eth_entry(None)]);
        key(&mut state, Key::Char('r'), &clock);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(9, Trigger::Manual)),
            &clock,
        );
        let finished_at = clock.now();
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                9,
                Trigger::Manual,
                DiscoveryOutcome::Partial,
                Some(Degradation::PostReadFailed {
                    reason: "read failed".to_owned(),
                }),
            )),
            &clock,
        );
        let scan = state.last_scan().expect("recorded");
        assert_eq!(scan.trigger, Trigger::Manual);
        assert_eq!(scan.mode, CycleMode::Active);
        assert_eq!(scan.outcome, DiscoveryOutcome::Partial);
        assert!(scan.degraded.is_some());
        assert_eq!(scan.finished_at, finished_at);
    }

    #[test]
    fn aging_happens_exactly_per_the_outcome_class() {
        // ADR-007 through the app path: only a Complete finish ages.
        let (mut state, mut clock) = confirmed(vec![eth_entry(None)]);
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(1, Trigger::Initial)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(observations(
                1,
                vec![scanner_obs(
                    "02:11:22:33:44:aa",
                    Ipv4Addr::new(192, 0, 2, 10),
                )],
            )),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                1,
                Trigger::Initial,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        let key = DeviceKey {
            iface_index: 2,
            mac: "02:11:22:33:44:aa".parse().expect("valid MAC"),
        };
        // Three absent complete cycles with enough wall time: idle
        // (idle_after_cycles 3, idle_min_age 120 s — 3 × 60 s).
        for scan_id in 2..=4u64 {
            clock.advance(Duration::from_secs(60));
            update(
                &mut state,
                AppEvent::Discovery(cycle_started(scan_id, Trigger::Periodic)),
                &clock,
            );
            update(
                &mut state,
                AppEvent::Discovery(cycle_finished(
                    scan_id,
                    Trigger::Periodic,
                    DiscoveryOutcome::Complete,
                    None,
                )),
                &clock,
            );
        }
        assert_eq!(
            state.registry.get(&key).expect("device").status,
            crate::registry::Status::Idle
        );
        // A Failed finish never ages: a fresh device stays Recent
        // through three failures.
        update(
            &mut state,
            AppEvent::Discovery(cycle_started(5, Trigger::Periodic)),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(observations(
                5,
                vec![scanner_obs(
                    "02:11:22:33:44:bb",
                    Ipv4Addr::new(192, 0, 2, 11),
                )],
            )),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Discovery(cycle_finished(
                5,
                Trigger::Periodic,
                DiscoveryOutcome::Complete,
                None,
            )),
            &clock,
        );
        let fresh_key = DeviceKey {
            iface_index: 2,
            mac: "02:11:22:33:44:bb".parse().expect("valid MAC"),
        };
        for scan_id in 6..=8u64 {
            clock.advance(Duration::from_secs(60));
            update(
                &mut state,
                AppEvent::Discovery(cycle_started(scan_id, Trigger::Periodic)),
                &clock,
            );
            update(
                &mut state,
                AppEvent::Discovery(cycle_finished(
                    scan_id,
                    Trigger::Periodic,
                    DiscoveryOutcome::Failed {
                        reason: "boom".to_owned(),
                    },
                    None,
                )),
                &clock,
            );
        }
        assert_eq!(
            state.registry.get(&fresh_key).expect("device").status,
            crate::registry::Status::Recent,
            "Failed cycles never age (ADR-007)"
        );
    }
}
