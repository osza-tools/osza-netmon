// SPDX-License-Identifier: GPL-3.0-only

//! The application event union: the single bounded queue's payload
//! (plan §8.3, §8.4; task T-205).
//!
//! Every input the application core reacts to is an [`AppEvent`]:
//! terminal input (T-301 maps the input library's key events onto the
//! terminal-agnostic [`Key`]), terminal resizes, the 1 Hz redraw tick
//! (FR-UI-07), and the forwarded worker events of the reviewed Phase 2
//! layers — discovery ([`CycleEvent`], T-204) and hostname enrichment
//! ([`HostnameEvent`], T-203). One queue, one consumer, one pure
//! [`update`](super::update::update) — the ADR-012 shape.
//!
//! [`Key`] is deliberately terminal-agnostic: T-301 owns the
//! input-library mapping, so this module (and the whole of `src/app/`) compiles with
//! no terminal dependency at all — the entire application core is
//! drivable headlessly by scenario scripts, which is how T-205 proves
//! it. `Char(char)` covers the letter keys of plan §10.3 (`j k g G r s
//! q y ?`); unknown keys are ignored by `update` (no state change, not
//! dirty).

use crate::discovery::worker::CycleEvent;
use crate::enrichment::worker::HostnameEvent;

/// One input to the application core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppEvent {
    /// A terminal input event (T-301 maps the input library onto this).
    Input(InputEvent),
    /// The terminal was resized to `width`×`height` cells.
    Resize {
        /// New width in cells.
        width: u16,
        /// New height in cells.
        height: u16,
    },
    /// The 1 Hz redraw tick (FR-UI-07: relative ages change while the
    /// screen is idle). The runtime synthesizes this when the tick
    /// deadline is reached; T-301 may also forward a real one.
    Tick,
    /// A forwarded discovery-cycle event (T-204 orchestrator).
    Discovery(CycleEvent),
    /// A forwarded hostname-worker event (T-203).
    Hostname(HostnameEvent),
}

/// A terminal input event.
///
/// T-305 adds mouse variants here; T-205 handles keys only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputEvent {
    /// A key press.
    Key(Key),
}

/// The terminal-agnostic key vocabulary of plan §10.3 (T-301 maps
/// the input library's key event onto this; T-305 may extend it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    /// Arrow up (plan §10.3: move selection).
    Up,
    /// Arrow down.
    Down,
    /// Page up (move the selection by [`PAGE_STEP`](super::state::PAGE_STEP) rows).
    PageUp,
    /// Page down.
    PageDown,
    /// Home / `g` (jump to the first row).
    Home,
    /// End / `G` (jump to the last row).
    End,
    /// Enter: open details (dashboard) or confirm (scope screen).
    Enter,
    /// Escape: back / close overlay.
    Esc,
    /// Ctrl+C: quit from any screen (FR-UI-06).
    CtrlC,
    /// A plain character key; covers `j k g G r s q y ?` of §10.3.
    Char(char),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_key_vocabulary_constructs_and_compares() {
        // Every variant is constructible and distinguishable — the
        // terminal-agnostic surface T-301 maps onto.
        let keys = [
            Key::Up,
            Key::Down,
            Key::PageUp,
            Key::PageDown,
            Key::Home,
            Key::End,
            Key::Enter,
            Key::Esc,
            Key::CtrlC,
            Key::Char('q'),
            Key::Char('?'),
        ];
        for (position, key) in keys.iter().enumerate() {
            for other in keys.iter().skip(position + 1) {
                assert_ne!(key, other);
            }
        }
        // The §10.3 letters ride in Char(char).
        for letter in ['j', 'k', 'g', 'G', 'r', 's', 'q', 'y', '?'] {
            assert_eq!(Key::Char(letter), Key::Char(letter));
        }
    }

    #[test]
    fn events_wrap_their_payloads_losslessly() {
        let input = AppEvent::Input(InputEvent::Key(Key::Enter));
        let resize = AppEvent::Resize {
            width: 80,
            height: 24,
        };
        let tick = AppEvent::Tick;
        assert_eq!(input, AppEvent::Input(InputEvent::Key(Key::Enter)));
        assert_ne!(input, resize);
        assert_ne!(resize, tick);
        // Discovery/Hostname variants are exercised throughout the
        // runtime and update suites; here the union merely has to
        // exist and be Debug (forwarder logging is T-301).
        let _: String = format!("{input:?} {resize:?} {tick:?}");
    }
}
