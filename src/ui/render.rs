// SPDX-License-Identifier: GPL-3.0-only

//! The frame dispatcher and the render decision (plan §6.6
//! FR-UI-06/07, §8.4; tasks T-301 §5.4–5.5 and T-302 §4).
//!
//! # The render decision (FR-UI-07)
//!
//! [`should_render`] is the pure factored decision: render when the
//! app state is dirty (anything changed since the last render) or a
//! tick was processed (relative ages change while the screen is
//! idle). In the assembled loop the two collapse into the dirty flag:
//! a processed tick — queued by the loop or synthesized by the
//! runtime — always marks the state dirty (T-205's tested `update`
//! behavior), so consuming the flag through
//! [`Runtime::take_dirty`](crate::app::Runtime::take_dirty) covers
//! both arms; the `tick_processed` parameter documents the rule and
//! keeps the decision honest against any future core change that
//! stops marking ticks dirty.
//!
//! # The dispatch (T-302 §4: the reworked placeholder dispatch)
//!
//! [`draw`] renders the **real** screens this task owns — the notice
//! ([`notice`]), the scope list ([`scope`]), its confirmation
//! dialogs and the too-small overlay — and keeps the deliberately
//! minimal placeholder frames for the screens T-303/T-304 own
//! (Dashboard, Details, the help overlay: screen name, live device
//! count, one marker line), each clearly marked for its task.
//!
//! # §8.2 discipline
//!
//! This module reads the app state's read-only views and `model`
//! only; it performs no I/O beyond drawing through the terminal it is
//! handed, calls no workers, and mutates nothing. The live device
//! count comes from the registry's own public
//! [`device_count`](crate::registry::Registry::device_count) through
//! the state's crate-visible `registry` field — no app change was
//! made for it (the placeholder's documented reach, PQ-2 of the T-301
//! execution report, ratified for the placeholder file only; T-303's
//! card shapes the real screen's view surface).

use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::text::Line;
use ratatui::text::Text;

use crate::app::AppState;
use crate::app::Screen;
use crate::ui::notice;
use crate::ui::scope;

/// The render decision (FR-UI-07; module docs): render when the state
/// is dirty or a tick was processed since the last render.
pub fn should_render(dirty: bool, tick_processed: bool) -> bool {
    dirty || tick_processed
}

/// Draws one frame: the real T-302 screens (notice, scope + dialogs,
/// too-small) and the T-303/T-304 placeholders (dashboard, details,
/// help) — module docs for the dispatch.
///
/// # Errors
/// Any backend draw failure, verbatim (the loop turns it into the
/// error exit path, restoring the terminal).
pub fn draw<B: Backend>(terminal: &mut Terminal<B>, state: &AppState) -> Result<(), B::Error> {
    terminal
        .draw(|frame| {
            let area = frame.area();
            if state.too_small() {
                // The NFR-08 overlay (FR-ST-04): it hides the screen,
                // never resets the state underneath.
                scope::render_too_small(frame, area, state.terminal_size());
                return;
            }
            match state.screen() {
                Screen::Notice => notice::render(frame, area),
                Screen::Scope => scope::render(frame, area, state),
                Screen::Dashboard => {
                    frame.render_widget(placeholder_text(state, "Dashboard", "T-303"), area)
                }
                Screen::Details => {
                    frame.render_widget(placeholder_text(state, "Details", "T-304"), area)
                }
            }
            if state.help_open() {
                // The help overlay placeholder (T-304 owns the real
                // help screen).
                frame.render_widget(placeholder_text(state, "Help (overlay)", "T-304"), area);
                return;
            }
            if let Some(kind) = state.confirm_kind() {
                // The confirmation dialogs overlay the scope screen
                // (E-2b); they cannot appear above another screen.
                scope::render_confirm(frame, area, kind, state.confirm_typed());
            }
        })
        .map(|_| ())
}

/// The placeholder frame for the screens T-303/T-304 own (§5.5's
/// deliberately minimal shape: screen name, live device count, one
/// marker line — default colors only).
fn placeholder_text(state: &AppState, screen: &str, owner: &str) -> Text<'static> {
    // The device count: the registry's public accessor through the
    // state's crate-visible field (the PQ-2 reach — no accessor
    // exists on AppState and E-1's one-accessor budget went to the
    // dirty flag).
    let devices = state.registry.device_count();
    Text::from(vec![
        Line::from(format!("Screen: {screen}")),
        Line::from(format!("Devices: {devices}")),
        Line::from(format!("{owner} placeholder")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppEvent;
    use crate::app::AppState;
    use crate::app::ConfirmKind;
    use crate::app::InputEvent;
    use crate::app::Key;
    use crate::app::ScopeEntry;
    use crate::app::SessionParams;
    use crate::app::update::update;
    use crate::model::FakeClock;
    use crate::net::Eligibility;
    use crate::net::InterfaceClass;
    use crate::net::LinkType;
    use ratatui::backend::TestBackend;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn db() -> Arc<crate::enrichment::vendor::VendorDb> {
        Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        )
    }

    /// The synthetic eligible entry of the T-205 fixtures: `eth9`,
    /// index 2, 192.0.2.1/29 (an RFC 5737 documentation range — a
    /// public network, so confirms walk the FR-SC-07 dialog), MAC
    /// `aa:bb:cc:dd:ee:01`, gateway .6.
    fn eth_entry() -> ScopeEntry {
        ScopeEntry {
            name: "eth9".to_owned(),
            index: 2,
            mac: Some("aa:bb:cc:dd:ee:01".parse().expect("valid MAC")),
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 29)),
            is_up: true,
            is_running: true,
            is_loopback: false,
            link_type: LinkType::Ethernet,
            class: InterfaceClass::Physical,
            eligibility: Eligibility::Eligible,
            default_gateway: Some(Ipv4Addr::new(192, 0, 2, 6)),
        }
    }

    fn notice_state() -> AppState {
        AppState::with_scope_entries(
            SessionParams::default(),
            vec![eth_entry()],
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid")
    }

    /// The whole drawn buffer at one size (lines are padded to the
    /// width, so `contains` matches per-line content).
    fn drawn_text_at(state: &AppState, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test backend");
        draw(&mut terminal, state).expect("drawing to a test backend cannot fail");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_owned())
            .collect()
    }

    fn drawn_text(state: &AppState) -> String {
        drawn_text_at(state, 80, 24)
    }

    /// Drives the full FR-SC-07 confirmation (the fixture's range is
    /// public): `Enter`, `yes`, `Enter`.
    fn confirm_public(state: &mut AppState, clock: &dyn crate::model::Clock) {
        update(state, AppEvent::Input(InputEvent::Key(Key::Enter)), clock);
        for letter in ['y', 'e', 's'] {
            update(
                state,
                AppEvent::Input(InputEvent::Key(Key::Char(letter))),
                clock,
            );
        }
        update(state, AppEvent::Input(InputEvent::Key(Key::Enter)), clock);
    }

    #[test]
    fn the_dispatch_renders_the_real_screens_and_keeps_the_placeholders() {
        // Notice and Scope are the real T-302 screens; Dashboard,
        // Details and Help stay the clearly marked placeholders.
        let mut state = notice_state();
        let clock = FakeClock::new();
        // Notice …
        let notice = drawn_text(&state);
        assert!(notice.contains("Authorization notice"), "{notice}");
        assert!(notice.contains("authorized to monitor"), "{notice}");
        // … y → Scope (the real screen: the list and the mode line) …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('y'))),
            &clock,
        );
        let scope = drawn_text(&state);
        assert!(scope.contains("Choose the network to monitor"), "{scope}");
        assert!(scope.contains("eth9"), "{scope}");
        assert!(scope.contains("suggested"), "{scope}");
        assert!(scope.contains("Mode: active"), "{scope}");
        // … the FR-SC-07 dialog over the scope screen …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &clock,
        );
        let dialog = drawn_text(&state);
        assert!(dialog.contains("Public network confirmation"), "{dialog}");
        assert!(dialog.contains("Type yes to confirm"), "{dialog}");
        // … yes + Enter → Dashboard (the placeholder, count live) …
        confirm_public(&mut state, &clock);
        let dashboard = drawn_text(&state);
        assert!(dashboard.contains("Screen: Dashboard"), "{dashboard}");
        assert!(
            dashboard.contains("Devices: 1"),
            "the confirmed interface's own device: {dashboard}"
        );
        assert!(dashboard.contains("T-303 placeholder"), "{dashboard}");
        // … j (selects the first row) + Enter → Details …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('j'))),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &clock,
        );
        let details = drawn_text(&state);
        assert!(details.contains("Screen: Details"), "{details}");
        assert!(details.contains("T-304 placeholder"), "{details}");
        // … ? → the help overlay placeholder …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('?'))),
            &clock,
        );
        let help = drawn_text(&state);
        assert!(help.contains("Help (overlay)"), "{help}");
        // … Esc closes it; the state underneath survived.
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Esc)),
            &clock,
        );
        assert!(drawn_text(&state).contains("Screen: Details"));
    }

    #[test]
    fn every_screen_renders_at_both_snapshot_sizes() {
        // §5.6: 80×24 and 100×30 for the notice, the scope list, each
        // dialog and the too-small screen — no panic, real content.
        // A fresh state per size: the drive below is per-iteration.
        for (width, height) in [(80u16, 24u16), (100, 30)] {
            let mut state = notice_state();
            let clock = FakeClock::new();
            let frame = drawn_text_at(&state, width, height);
            assert!(frame.contains("Authorization notice"), "{width}×{height}");
            update(
                &mut state,
                AppEvent::Input(InputEvent::Key(Key::Char('y'))),
                &clock,
            );
            let frame = drawn_text_at(&state, width, height);
            assert!(frame.contains("Choose the network"), "{width}×{height}");
            // The dialogs: open each one through the real update.
            update(
                &mut state,
                AppEvent::Input(InputEvent::Key(Key::Enter)),
                &clock,
            );
            let frame = drawn_text_at(&state, width, height);
            assert!(
                frame.contains("Public network confirmation"),
                "{width}×{height}"
            );
            update(
                &mut state,
                AppEvent::Input(InputEvent::Key(Key::Esc)),
                &clock,
            );
            // The too-small overlay (a hard shrink while on scope).
            update(
                &mut state,
                AppEvent::Resize {
                    width: 40,
                    height: 12,
                },
                &clock,
            );
            let frame = drawn_text_at(&state, 40, 12);
            assert!(frame.contains("Terminal too small"), "{width}×{height}");
        }
    }

    #[test]
    fn the_large_scope_dialogs_render_through_the_dispatch() {
        // The FR-SC-06 dialogs are opened through the real update on a
        // big raised-cap network, then drawn.
        let big = ScopeEntry {
            ipv4: Some((Ipv4Addr::new(198, 18, 0, 1), 21)), // 2046 targets
            ..eth_entry()
        };
        let params = SessionParams {
            max_hosts: 4_094,
            ..SessionParams::default()
        };
        let mut state =
            AppState::with_scope_entries(params, vec![big], db(), &FakeClock::new()).expect("v");
        let clock = FakeClock::new();
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('y'))),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &clock,
        );
        // 198.18.0.0/21 is benchmark space (RFC 2544) — not RFC 1918
        // private, but the cap dialog comes first anyway: 2,046 usable
        // hosts minus the own address = 2,045 targets, 4,090 requests.
        assert!(matches!(
            state.confirm_kind(),
            Some(ConfirmKind::LargeScope { .. })
        ));
        let frame = drawn_text(&state);
        assert!(frame.contains("Large network confirmation"), "{frame}");
        assert!(frame.contains("4090 ARP requests"), "{frame}");
        assert!(frame.contains("estimated"), "{frame}");
        // Esc cancels back to the list.
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Esc)),
            &clock,
        );
        assert!(state.confirm_kind().is_none());

        // At the default cap the same network is refused outright.
        let mut state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![ScopeEntry {
                ipv4: Some((Ipv4Addr::new(198, 18, 0, 1), 21)),
                ..eth_entry()
            }],
            db(),
            &FakeClock::new(),
        )
        .expect("v");
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('y'))),
            &clock,
        );
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &clock,
        );
        assert!(matches!(
            state.confirm_kind(),
            Some(ConfirmKind::LargeScopeRefusal { .. })
        ));
        let frame = drawn_text(&state);
        assert!(frame.contains("Active discovery is refused"), "{frame}");
        assert!(frame.contains("Continue read-only"), "{frame}");
    }

    #[test]
    fn the_too_small_overlay_hides_the_screen_without_resetting_state() {
        let mut state = notice_state();
        let clock = FakeClock::new();
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('y'))),
            &clock,
        );
        confirm_public(&mut state, &clock);
        // 79×24 is under the 80×24 minimum (NFR-08).
        update(
            &mut state,
            AppEvent::Resize {
                width: 79,
                height: 24,
            },
            &clock,
        );
        let shrunk = drawn_text(&state);
        assert!(shrunk.contains("Terminal too small"), "{shrunk}");
        // Recovering (FR-ST-04): the dashboard and its count survive.
        update(
            &mut state,
            AppEvent::Resize {
                width: 80,
                height: 24,
            },
            &clock,
        );
        let restored = drawn_text(&state);
        assert!(restored.contains("Screen: Dashboard"), "{restored}");
        assert!(restored.contains("Devices: 1"), "{restored}");
    }

    #[test]
    fn the_render_decision_renders_only_on_dirty_or_tick() {
        // AC-4: the pure decision.
        assert!(should_render(true, false), "dirty renders");
        assert!(should_render(false, true), "a processed tick renders");
        assert!(should_render(true, true));
        assert!(!should_render(false, false), "idle renders nothing");
    }

    #[test]
    fn renders_are_counted_over_a_scripted_event_sequence() {
        // AC-4's demonstration: the real `update` runs the scripted
        // sequence; the loop's consume step (`take_dirty`) feeds the
        // decision; only the changing events render. Mouse events
        // never appear here — the input thread consumes them as
        // no-ops before the queue.
        let mut state = AppState::with_scope_entries(
            SessionParams::default(),
            vec![eth_entry()],
            db(),
            &FakeClock::new(),
        )
        .expect("defaults are valid");
        let clock = FakeClock::new();
        let key = |k: Key| AppEvent::Input(InputEvent::Key(k));
        let sequence = [
            key(Key::Char('x')), // unknown at the notice: no render
            key(Key::Char('y')), // → Scope: render
            key(Key::Char('x')), // unknown at the scope: no render
            key(Key::Char('j')), // selection moves: render
            key(Key::Char('j')), // (single eligible row: wraps in place — still accepted)
            AppEvent::Tick,      // FR-UI-07 idle redraw: render
            key(Key::Enter),     // the FR-SC-07 dialog opens: render
            key(Key::Char('y')), // typed: render
            key(Key::Char('e')), // typed: render
            key(Key::Char('s')), // typed: render
            key(Key::Enter),     // confirm → Dashboard: render
            key(Key::Char('x')), // unknown at the dashboard: no render
            AppEvent::Resize {
                width: 100,
                height: 30,
            }, // render
            AppEvent::Tick,      // render
        ];
        // The first consume sees the construction-time dirty flag
        // (the first frame draws).
        let mut renders = usize::from(should_render(state.take_dirty(), false));
        for event in sequence {
            let tick = matches!(event, AppEvent::Tick);
            update(&mut state, event, &clock);
            if should_render(state.take_dirty(), tick) {
                renders += 1;
            }
        }
        // First frame + y + j + j + tick + dialog + 3 letters +
        // confirm + resize + tick.
        assert_eq!(renders, 12, "only the changing events rendered");
        // And the sequence really drove the app somewhere.
        assert_eq!(state.screen(), crate::app::Screen::Dashboard);
    }
}
