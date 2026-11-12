// SPDX-License-Identifier: GPL-3.0-only

//! The placeholder renderer and the render decision (plan §6.6
//! FR-UI-06/07, §8.4; task T-301 §5.4–5.5).
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
//! # The placeholder frame (§5.5)
//!
//! [`draw_placeholder`] is one small, obviously temporary frame:
//! for each screen state — Notice, Scope, Dashboard, Details, the
//! help overlay, the too-small overlay — it draws the screen name,
//! the live device count, and one marker line
//! (`T-302/T-303 placeholder`). Default colors only, no layout, no
//! vocabulary: **T-302/T-303/T-304 replace this file wholesale.**
//!
//! # §8.2 discipline
//!
//! This module reads the app state's read-only views and `model`
//! only; it performs no I/O beyond drawing through the terminal it is
//! handed, calls no workers, and mutates nothing. The live device
//! count comes from the registry's own public
//! [`device_count`](crate::registry::Registry::device_count) through
//! the state's crate-visible `registry` field — no app change was
//! made for it (the placeholder's documented reach, PQ-2 of the
//! execution report: `AppState` exposes no count accessor, and the
//! E-1 exception authorizes exactly one accessor, which the dirty
//! flag needed).

use ratatui::Terminal;
use ratatui::backend::Backend;
use ratatui::text::Line;
use ratatui::text::Text;

use crate::app::AppState;
use crate::app::Screen;

/// The render decision (FR-UI-07; module docs): render when the state
/// is dirty or a tick was processed since the last render.
pub fn should_render(dirty: bool, tick_processed: bool) -> bool {
    dirty || tick_processed
}

/// Draws the placeholder frame (§5.5; module docs — replaced wholesale
/// by T-302/T-303/T-304).
///
/// # Errors
/// Any backend draw failure, verbatim (the loop turns it into the
/// error exit path, restoring the terminal).
pub fn draw_placeholder<B: Backend>(
    terminal: &mut Terminal<B>,
    state: &AppState,
) -> Result<(), B::Error> {
    terminal
        .draw(|frame| {
            frame.render_widget(placeholder_text(state), frame.area());
        })
        .map(|_| ())
}

/// The placeholder's three lines (module docs): screen name, live
/// device count, marker — default colors only.
fn placeholder_text(state: &AppState) -> Text<'static> {
    // The device count: the registry's public accessor through the
    // state's crate-visible field (the PQ-2 reach — no accessor
    // exists on AppState and E-1's one-accessor budget went to the
    // dirty flag).
    let devices = state.registry.device_count();
    let screen = if state.too_small() {
        // The NFR-08 overlay (FR-ST-04): it hides the screen, never
        // resets the state underneath.
        "Too small"
    } else if state.help_open() {
        "Help (overlay)"
    } else {
        match state.screen() {
            Screen::Notice => "Notice",
            Screen::Scope => "Scope",
            Screen::Dashboard => "Dashboard",
            Screen::Details => "Details",
        }
    };
    Text::from(vec![
        Line::from(format!("Screen: {screen}")),
        Line::from(format!("Devices: {devices}")),
        Line::from("T-302/T-303 placeholder"),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppEvent;
    use crate::app::AppState;
    use crate::app::InputEvent;
    use crate::app::Key;
    use crate::app::ScopeEntry;
    use crate::app::SessionParams;
    use crate::app::update::update;
    use crate::model::FakeClock;
    use crate::net::Eligibility;
    use crate::net::InterfaceClass;
    use ratatui::backend::TestBackend;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn db() -> Arc<crate::enrichment::vendor::VendorDb> {
        Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        )
    }

    /// The synthetic eligible entry of the T-205 fixtures: `eth9`,
    /// index 2, 192.0.2.1/29, gateway .6.
    fn eth_entry() -> ScopeEntry {
        ScopeEntry {
            name: "eth9".to_owned(),
            index: 2,
            mac: Some("aa:bb:cc:dd:ee:01".parse().expect("valid MAC")),
            ipv4: Some((Ipv4Addr::new(192, 0, 2, 1), 29)),
            is_up: true,
            is_running: true,
            is_loopback: false,
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

    /// The whole placeholder buffer as one string (lines are padded
    /// to the width, so `contains` matches per-line content).
    fn drawn_text(state: &AppState) -> String {
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).expect("test backend");
        draw_placeholder(&mut terminal, state).expect("drawing to a test backend cannot fail");
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol().to_owned())
            .collect()
    }

    #[test]
    fn the_placeholder_shows_screen_count_and_marker() {
        let text = drawn_text(&notice_state());
        assert!(text.contains("Screen: Notice"), "{text}");
        assert!(text.contains("Devices: 0"), "{text}");
        assert!(text.contains("T-302/T-303 placeholder"), "{text}");
    }

    #[test]
    fn every_screen_state_names_itself() {
        // Notice → Scope (y) → Dashboard (Enter) → Details (Enter
        // after selecting) → Help overlay (?) — each frame names its
        // screen; the count follows the registry.
        let mut state = notice_state();
        let clock = FakeClock::new();
        // Notice …
        assert!(drawn_text(&state).contains("Screen: Notice"));
        // … y → Scope …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('y'))),
            &clock,
        );
        assert!(drawn_text(&state).contains("Screen: Scope"));
        // … Enter → Dashboard (the local device is inserted: one
        // device, the count is live) …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &clock,
        );
        let dashboard = drawn_text(&state);
        assert!(dashboard.contains("Screen: Dashboard"), "{dashboard}");
        assert!(
            dashboard.contains("Devices: 1"),
            "the confirmed interface's own device: {dashboard}"
        );
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
        assert!(drawn_text(&state).contains("Screen: Details"));
        // … ? → the help overlay (over Details) …
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Char('?'))),
            &clock,
        );
        assert!(drawn_text(&state).contains("Screen: Help (overlay)"));
        // … Esc closes it; the state underneath survived.
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Esc)),
            &clock,
        );
        assert!(drawn_text(&state).contains("Screen: Details"));
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
        update(
            &mut state,
            AppEvent::Input(InputEvent::Key(Key::Enter)),
            &clock,
        );
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
        assert!(shrunk.contains("Screen: Too small"), "{shrunk}");
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
        // First frame + y + j + j + tick + Enter + resize + tick.
        assert_eq!(renders, 8, "only the changing events rendered");
        // And the sequence really drove the app somewhere.
        assert_eq!(state.screen(), crate::app::Screen::Dashboard);
    }
}
