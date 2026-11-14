// SPDX-License-Identifier: GPL-3.0-only

//! The interface/scope screen, its confirmation dialogs and the
//! terminal-too-small screen (FR-SC-01…08, FR-ST-04; task T-302
//! §5.3–§5.5).
//!
//! # What the list shows (FR-SC-01, §5.3)
//!
//! Every interface, two lines each: name, IPv4/prefix, link type,
//! up/running state, MAC and default-route gateway — the visible
//! FR-SC-01 facts, all from the frozen [`ScopeEntry`] snapshot (the
//! index stays internal). Ineligible rows are listed disabled with the
//! net layer's own eligibility words; the FR-SC-02 suggestion is
//! marked `suggested`; virtual interfaces are labeled `virtual`.
//!
//! # What the mode line shows (FR-SC-08)
//!
//! For the selected interface: the mode (active / read-only) and, in
//! active mode, the ARP request count the initial scan will send and
//! the card-fixed duration estimate — both with "≈" and the word
//! "estimated". A read-only session, an interface without a valid MAC
//! or a `/32` network (no probe targets, FR-SC-05) read as read-only
//! with their honest explanation.
//!
//! # The reminder (ADR-004)
//!
//! "Authorized networks only. Active discovery sends ARP requests." —
//! the one-line reminder ADR-004 puts on the scope screen.
//!
//! # The dialogs (FR-SC-06/FR-SC-07, E-2b)
//!
//! [`render_confirm`] draws the open confirmation dialog over the
//! list: the large-scope refusal (read-only remains), the raised-cap
//! confirmation (packet count + estimated duration) and the
//! public-range typed-`yes` (with the letters typed so far).
//!
//! # The too-small screen (FR-ST-04)
//!
//! [`render_too_small`] draws the core's overlay: the minimum, the
//! current size and "resize to continue". It renders only — the
//! recovery is the core's (automatic, no state reset; core-tested).
//!
//! # §8.2 discipline
//!
//! This module reads the app state's read-only views and `model`
//! only; it performs no I/O beyond drawing, calls no workers and
//! mutates nothing.

use std::net::Ipv4Addr;
use std::time::Duration;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Block;
use ratatui::widgets::Borders;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;

use crate::app::AppMode;
use crate::app::AppState;
use crate::app::ConfirmKind;
use crate::app::ScopeEntry;
use crate::app::estimate_duration;
use crate::app::initial_request_count;
use crate::app::probe_target_count;
use crate::model::Ipv4Net;
use crate::net::InterfaceClass;
use crate::net::LinkType;

/// The ADR-004 reminder line (verbatim; the scope screen carries it).
pub const REMINDER_LINE: &str = "Authorized networks only. Active discovery sends ARP requests.";

/// The fixed header of the list.
const TITLE: &str = " Choose the network to monitor";

/// Renders the scope screen into `area`.
pub fn render(frame: &mut Frame, area: Rect, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(TITLE));
    lines.push(Line::from(REMINDER_LINE).dim());
    lines.push(Line::from(""));
    // The list: two lines per interface, as many pairs as fit. Seven
    // fixed lines surround the list (title, reminder, blank, blank,
    // mode, blank, keys); a truncated list spends one more on the
    // honest "+N more" note.
    let interfaces = state.interfaces();
    let mut shown = (area.height.saturating_sub(7) as usize) / 2;
    if interfaces.len() > shown {
        shown = shown.saturating_sub(1);
    }
    for (row, entry) in interfaces.iter().take(shown).enumerate() {
        lines.extend(entry_lines(state, row, entry));
    }
    if interfaces.len() > shown {
        lines.push(Line::from(format!(
            " … +{} more interfaces",
            interfaces.len() - shown
        )));
    }
    // The selected interface's mode line (FR-SC-08) — also when the
    // selection sits below the fold (the selected row is always
    // rendered: the budget starts at the selection's advantage).
    if let Some(entry) = interfaces.get(state.scope_selected()) {
        lines.push(Line::from(""));
        lines.push(Line::from(mode_line(state, entry)));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(
            " No interface is available to monitor. Nothing can be confirmed.",
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::from(" [Enter] Confirm   [↑/↓] Choose   "),
        Span::from("[q] Quit").dim(),
    ]));
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::NONE)),
        area,
    );
}

/// The two lines of one interface row.
fn entry_lines(state: &AppState, row: usize, entry: &ScopeEntry) -> Vec<Line<'static>> {
    let marker = if row == state.scope_selected() {
        "> "
    } else {
        "  "
    };
    let ipv4 = match entry.ipv4 {
        Some((address, prefix)) => format!("{address}/{prefix}"),
        None => "—".to_owned(),
    };
    let state_text = interface_state(entry);
    // Only the FR-SC-02 labels share the first line (the reason is a
    // second-line fact — the fixed columns leave 29 cells for them).
    let mut labels: Vec<String> = Vec::new();
    if row == state.scope_suggested() {
        labels.push("suggested".to_owned());
    }
    if entry.class == InterfaceClass::Virtual {
        labels.push("virtual".to_owned());
    }
    let label_text = labels.join(", ");
    let first = format!(
        "{marker}{:<10}{:<17}{:<10}{:<14}{}",
        entry.name,
        ipv4,
        link_label(entry.link_type),
        state_text,
        label_text
    );
    let mac_text = match entry.mac {
        Some(mac) => mac.to_string(),
        None => "no hardware address".to_owned(),
    };
    let detail_text = if let crate::net::Eligibility::Ineligible(reason) = entry.eligibility {
        // The wireframe's form: the net layer's own eligibility words
        // (FR-SC-03) on the detail line.
        format!("unavailable: {reason}")
    } else {
        match entry.default_gateway {
            Some(gateway) if !gateway.is_unspecified() => format!("gateway {gateway}"),
            // `Some(0.0.0.0)` is an on-link default route (the net
            // layer's documented encoding): no gateway address.
            Some(_) => "default route on-link".to_owned(),
            None => "no default-route gateway".to_owned(),
        }
    };
    vec![
        Line::from(first),
        Line::from(format!("  {mac_text:<17}{detail_text}")),
    ]
}

/// The up/running state column (FR-SC-01; "running" and "down" — the
/// §5.4 vocabulary's own words, never the banned ones).
fn interface_state(entry: &ScopeEntry) -> String {
    match (entry.is_up, entry.is_running) {
        (true, true) => "up, running".to_owned(),
        (true, false) => "up, not running".to_owned(),
        (false, _) => "down".to_owned(),
    }
}

/// The link-type column (FR-SC-01; the `ARPHRD`-derived label).
fn link_label(link_type: LinkType) -> &'static str {
    match link_type {
        LinkType::Ethernet => "Ethernet",
        LinkType::Loopback => "Loopback",
        LinkType::Other(_) => "Other",
    }
}

/// The selected interface's FR-SC-08 mode line: the mode and, when
/// active, the request count and the card-fixed duration estimate
/// (with "≈" and "estimated").
fn mode_line(state: &AppState, entry: &ScopeEntry) -> String {
    let scope = entry.derive_scope();
    let own_ip = entry
        .ipv4
        .map_or(Ipv4Addr::UNSPECIFIED, |(address, _)| address);
    let targets = scope
        .as_ref()
        .map_or(0, |net| probe_target_count(net, own_ip));
    // The per-interface mode derivation (report §5): the session's
    // mode, the interface's identity and the target count decide.
    match &state.mode() {
        AppMode::ReadOnly { reason } => {
            return format!(" Mode: read-only — {reason}");
        }
        AppMode::Active => {}
    }
    if entry.mac.is_none() {
        return " Mode: read-only — the interface reports no valid hardware address".to_owned();
    }
    let Some(scope) = scope else {
        return " Mode: read-only — no IPv4 network".to_owned();
    };
    if targets == 0 {
        // FR-SC-05: a `/32` has no probe targets — read-only only,
        // with the explanation.
        return format!(
            " Mode: read-only — the network {} has no probe targets",
            network_text(&scope)
        );
    }
    let requests = initial_request_count(targets);
    let estimated = estimate_duration(
        targets,
        crate::discovery::scheduler::Trigger::Initial.passes(),
        crate::discovery::DEFAULT_RATE_PPS,
        crate::discovery::DEFAULT_LISTEN_WINDOW,
    );
    format!(
        " Mode: active — will send {requests} ARP requests (≈ {} estimated) on {}",
        humanize(estimated),
        network_text(&scope)
    )
}

/// An `Ipv4Net` as the wireframe shows it (`192.168.1.0/24` — the
/// network address plus the prefix; `Ipv4Net` has no `Display`).
fn network_text(scope: &Ipv4Net) -> String {
    format!("{}/{}", scope.network(), scope.prefix_len())
}

/// A compact duration rendering for the estimate ("6 s", "1 m 10 s").
pub fn humanize(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds} s")
    } else {
        format!("{} m {:02} s", seconds / 60, seconds % 60)
    }
}

/// Renders the open confirmation dialog over the scope screen
/// (E-2b; FR-SC-06/FR-SC-07).
pub fn render_confirm(frame: &mut Frame, area: Rect, kind: &ConfirmKind, typed: &str) {
    // A centered box, at most 70×10, with a border.
    let width = area.width.min(70);
    let height = area.height.min(10);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    let dialog = Rect {
        x,
        y,
        width,
        height,
    };
    let (title, lines, keys) = match kind {
        ConfirmKind::LargeScopeRefusal { targets, cap } => (
            " Large network ",
            vec![
                Line::from(format!(
                    " The selected network has {targets} probe targets, above"
                )),
                Line::from(format!(
                    " the active-scan cap of {cap}. Active discovery is refused."
                )),
                Line::from(" Read-only discovery (neighbor table only) remains available."),
            ],
            " [Enter] Continue read-only   [Esc] Cancel",
        ),
        ConfirmKind::LargeScope {
            targets,
            requests,
            estimated,
        } => (
            " Large network confirmation ",
            vec![
                Line::from(format!(
                    " The selected network has {targets} probe targets. The initial"
                )),
                Line::from(format!(
                    " scan will send about {requests} ARP requests (≈ {} estimated).",
                    humanize(*estimated)
                )),
            ],
            " [Enter] Confirm   [Esc] Cancel",
        ),
        ConfirmKind::PublicRange { network } => (
            " Public network confirmation ",
            vec![
                Line::from(format!(
                    " The selected network {} is not a private network",
                    network_text(network)
                )),
                Line::from(" (RFC 1918, 169.254/16 or 100.64/10). Active discovery"),
                Line::from(" sends ARP requests to every address in it."),
                Line::from(""),
                Line::from(format!(" Type yes to confirm: {typed}_")),
            ],
            " [Enter] Submit   [Esc] Cancel",
        ),
    };
    let mut body = lines;
    body.push(Line::from(""));
    body.push(Line::from(keys).dim());
    frame.render_widget(Clear, dialog);
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::new().borders(Borders::ALL).title(title))
            .style(Style::new()),
        dialog,
    );
}

/// Renders the FR-ST-04 too-small screen: the minimum, the current
/// size and how to continue. Recovery is automatic and never resets
/// state (the core's tested behavior); this render adds no state.
pub fn render_too_small(frame: &mut Frame, area: Rect, size: (u16, u16)) {
    let lines = vec![
        Line::from(" Terminal too small"),
        Line::from(""),
        Line::from(format!(
            " This display needs at least {}×{} cells.",
            crate::app::state::MIN_WIDTH,
            crate::app::state::MIN_HEIGHT
        )),
        Line::from(format!(
            " Current size: {}×{}. Resize to continue.",
            size.0, size.1
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::NONE)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::app::SessionParams;
    use crate::model::FakeClock;
    use crate::model::Ipv4Net;
    use crate::net::Eligibility;
    use crate::net::IneligibleReason;
    use ratatui::backend::TestBackend;
    use std::sync::Arc;

    fn db() -> Arc<crate::enrichment::vendor::VendorDb> {
        Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        )
    }

    /// A mixed fixture list (§5.6): an eligible suggested physical
    /// interface, an eligible second interface, a MAC-less eligible
    /// one, an ineligible loopback and a virtual one.
    fn mixed_entries() -> Vec<ScopeEntry> {
        vec![
            ScopeEntry {
                name: "eth9".to_owned(),
                index: 2,
                mac: Some("aa:bb:cc:dd:ee:01".parse().expect("valid MAC")),
                ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 24)),
                is_up: true,
                is_running: true,
                is_loopback: false,
                link_type: LinkType::Ethernet,
                class: InterfaceClass::Physical,
                eligibility: Eligibility::Eligible,
                default_gateway: Some(Ipv4Addr::new(192, 0, 2, 6)),
            },
            ScopeEntry {
                name: "wlan9".to_owned(),
                index: 3,
                mac: Some("aa:bb:cc:dd:ee:02".parse().expect("valid MAC")),
                ipv4: Some((Ipv4Addr::new(198, 51, 100, 1), 30)),
                is_up: true,
                is_running: false,
                is_loopback: false,
                link_type: LinkType::Ethernet,
                class: InterfaceClass::Physical,
                eligibility: Eligibility::Eligible,
                default_gateway: None,
            },
            ScopeEntry {
                name: "lo".to_owned(),
                index: 1,
                mac: None,
                ipv4: Some((Ipv4Addr::new(127, 0, 0, 1), 8)),
                is_up: true,
                is_running: true,
                is_loopback: true,
                link_type: LinkType::Loopback,
                class: InterfaceClass::Virtual,
                eligibility: Eligibility::Ineligible(IneligibleReason::Loopback),
                default_gateway: None,
            },
            ScopeEntry {
                name: "docker9".to_owned(),
                index: 5,
                mac: Some("aa:bb:cc:dd:ee:03".parse().expect("valid MAC")),
                ipv4: Some((Ipv4Addr::new(172, 17, 0, 1), 22)),
                is_up: true,
                is_running: true,
                is_loopback: false,
                link_type: LinkType::Ethernet,
                class: InterfaceClass::Virtual,
                eligibility: Eligibility::Eligible,
                default_gateway: None,
            },
        ]
    }

    fn scope_state(entries: Vec<ScopeEntry>) -> AppState {
        AppState::with_scope_entries(SessionParams::default(), entries, db(), &FakeClock::new())
            .expect("valid")
    }

    fn drawn(state: &AppState, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| render(frame, frame.area(), state))
            .expect("drawing cannot fail");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_owned())
            .collect()
    }

    fn drawn_too_small(size: (u16, u16), width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| render_too_small(frame, frame.area(), size))
            .expect("drawing cannot fail");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_owned())
            .collect()
    }

    fn drawn_confirm(kind: &ConfirmKind, typed: &str, width: u16, height: u16) -> String {
        let mut terminal =
            ratatui::Terminal::new(TestBackend::new(width, height)).expect("test backend");
        terminal
            .draw(|frame| render_confirm(frame, frame.area(), kind, typed))
            .expect("drawing cannot fail");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_owned())
            .collect()
    }

    #[test]
    fn the_scope_list_shows_every_fr_sc01_fact_and_the_labels() {
        let state = scope_state(mixed_entries());
        let text = drawn(&state, 80, 24);
        // FR-SC-01's visible facts, per interface.
        assert!(text.contains("eth9"), "{text}");
        assert!(text.contains("192.0.2.1/24"), "{text}");
        assert!(text.contains("aa:bb:cc:dd:ee:01"), "{text}");
        assert!(text.contains("Ethernet"), "{text}");
        assert!(text.contains("up, running"), "{text}");
        assert!(text.contains("gateway 192.0.2.6"), "{text}");
        // FR-SC-02: the suggestion is marked, virtual interfaces are
        // labeled; FR-SC-03: the ineligible row carries the reason.
        assert!(text.contains("suggested"), "{text}");
        assert!(text.contains("virtual"), "{text}");
        assert!(text.contains("unavailable: loopback interface"), "{text}");
        assert!(text.contains("wlan9"), "{text}");
        assert!(text.contains("up, not running"), "{text}");
        assert!(text.contains("no default-route gateway"), "{text}");
        // FR-SC-08 + ADR-004's reminder.
        assert!(
            text.contains("Mode: active — will send 506 ARP requests"),
            "{text}"
        );
        assert!(text.contains("(≈ 9 s estimated)"), "{text}");
        assert!(text.contains("on 192.0.2.0/24"), "{text}");
        assert!(text.contains(REMINDER_LINE), "{text}");
        assert!(text.contains("[Enter] Confirm"), "{text}");
    }

    #[test]
    fn the_mode_line_follows_the_selection_and_the_read_only_reasons() {
        let mut state = scope_state(mixed_entries());
        let clock = FakeClock::new();
        // Leave the notice first, then j moves to wlan9 (row 1): a
        // /30 has one target.
        crate::app::update::update(
            &mut state,
            crate::app::AppEvent::Input(crate::app::InputEvent::Key(crate::app::Key::Char('y'))),
            &clock,
        );
        crate::app::update::update(
            &mut state,
            crate::app::AppEvent::Input(crate::app::InputEvent::Key(crate::app::Key::Char('j'))),
            &clock,
        );
        let text = drawn(&state, 80, 24);
        assert!(
            text.contains("Mode: active — will send 2 ARP requests"),
            "{text}"
        );
        // A read-only session shows its reason for any selection.
        let params = SessionParams {
            mode: AppMode::ReadOnly {
                reason: "no CAP_NET_RAW: read-only mode (neighbor table only)".to_owned(),
            },
            ..SessionParams::default()
        };
        let state = AppState::with_scope_entries(params, mixed_entries(), db(), &FakeClock::new())
            .expect("valid");
        let text = drawn(&state, 80, 24);
        assert!(
            text.contains("Mode: read-only — no CAP_NET_RAW: read-only mode"),
            "{text}"
        );
    }

    #[test]
    fn a_slash_32_explains_itself_as_read_only() {
        let entry = ScopeEntry {
            name: "tun9".to_owned(),
            index: 9,
            mac: Some("aa:bb:cc:dd:ee:09".parse().expect("valid MAC")),
            ipv4: Some((Ipv4Addr::new(203, 0, 113, 1), 32)),
            is_up: true,
            is_running: true,
            is_loopback: false,
            link_type: LinkType::Ethernet,
            class: InterfaceClass::Virtual,
            eligibility: Eligibility::Eligible,
            default_gateway: None,
        };
        let state = scope_state(vec![entry]);
        let text = drawn(&state, 80, 24);
        assert!(text.contains("Mode: read-only"), "{text}");
        assert!(text.contains("no probe targets"), "{text}");
    }

    #[test]
    fn each_dialog_renders_its_facts_at_both_sizes() {
        // §5.6: each confirmation dialog at 80×24 and 100×30.
        for (width, height) in [(80u16, 24u16), (100, 30)] {
            let refusal = drawn_confirm(
                &ConfirmKind::LargeScopeRefusal {
                    targets: 2046,
                    cap: 1022,
                },
                "",
                width,
                height,
            );
            assert!(refusal.contains("Large network"), "{refusal}");
            assert!(refusal.contains("2046 probe targets"), "{refusal}");
            assert!(refusal.contains("cap of 1022"), "{refusal}");
            assert!(refusal.contains("Active discovery is refused"), "{refusal}");
            assert!(refusal.contains("Continue read-only"), "{refusal}");

            let large = drawn_confirm(
                &ConfirmKind::LargeScope {
                    targets: 2046,
                    requests: 4092,
                    estimated: Duration::from_secs(46),
                },
                "",
                width,
                height,
            );
            assert!(large.contains("Large network confirmation"), "{large}");
            assert!(large.contains("4092 ARP requests"), "{large}");
            assert!(large.contains("46 s estimated"), "{large}");

            let public = drawn_confirm(
                &ConfirmKind::PublicRange {
                    network: Ipv4Net::new(Ipv4Addr::new(203, 0, 113, 0), 24)
                        .expect("valid network"),
                },
                "ye",
                width,
                height,
            );
            assert!(public.contains("Public network confirmation"), "{public}");
            assert!(public.contains("not a private network"), "{public}");
            assert!(public.contains("Type yes to confirm: ye_"), "{public}");
        }
    }

    #[test]
    fn the_too_small_screen_shows_minimum_current_and_recovery() {
        for (width, height) in [(80u16, 24u16), (100, 30)] {
            let text = drawn_too_small((79, 24), width, height);
            assert!(text.contains("Terminal too small"), "{text}");
            assert!(text.contains("80×24"), "{text}");
            assert!(text.contains("79×24"), "{text}");
            assert!(text.contains("Resize to continue"), "{text}");
        }
    }

    #[test]
    fn many_interfaces_are_truncated_honestly() {
        // Thirty interfaces do not panic at 80×24; the tail is noted.
        let entries: Vec<ScopeEntry> = (0..30)
            .map(|index| ScopeEntry {
                name: format!("if{index}"),
                index: u32::try_from(index).unwrap_or(0) + 10,
                mac: None,
                ipv4: None,
                is_up: false,
                is_running: false,
                is_loopback: false,
                link_type: LinkType::Ethernet,
                class: InterfaceClass::Physical,
                eligibility: Eligibility::Ineligible(IneligibleReason::NoIpv4Address),
                default_gateway: None,
            })
            .collect();
        let state = scope_state(entries);
        let text = drawn(&state, 80, 24);
        assert!(text.contains("more interfaces"), "{text}");
        assert!(text.contains("unavailable: no IPv4 address"), "{text}");
        assert!(text.contains("Mode: read-only"), "{text}");
    }

    #[test]
    fn the_selected_row_below_the_fold_still_drives_the_mode_line() {
        // The selection moves to the last eligible row (docker9, row
        // 3) with the fold above it: the mode line still describes
        // the selection.
        let mut state = scope_state(mixed_entries());
        let clock = FakeClock::new();
        // Leave the notice, then two `j` presses walk the eligible
        // rows 0 → 1 → 3 (the selection skips the loopback).
        crate::app::update::update(
            &mut state,
            crate::app::AppEvent::Input(crate::app::InputEvent::Key(crate::app::Key::Char('y'))),
            &clock,
        );
        for _ in 0..2 {
            crate::app::update::update(
                &mut state,
                crate::app::AppEvent::Input(crate::app::InputEvent::Key(crate::app::Key::Char(
                    'j',
                ))),
                &clock,
            );
        }
        assert_eq!(state.scope_selected(), 3);
        let text = drawn(&state, 80, 24);
        assert!(text.contains("Mode:"), "{text}");
        assert!(text.contains("172.17.0.0/22"), "{text}");
    }
}
