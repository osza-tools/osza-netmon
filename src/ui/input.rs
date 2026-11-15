// SPDX-License-Identifier: GPL-3.0-only

//! The input thread (plan §8.3, §10.3; task T-301 §5.2).
//!
//! One dedicated thread owns the crossterm event stream: it polls
//! with a short timeout ([`INPUT_POLL_TIMEOUT`]) and a stop flag, so
//! it shuts down cleanly and never blocks uninterruptibly. Terminal
//! events are translated onto the app core's terminal-agnostic
//! vocabulary by the pure [`map_event`] / [`map_key`] functions
//! (unit-tested without a terminal):
//!
//! * key presses → [`AppEvent::Input`] with the §10.3 map — `↑/↓`,
//!   `j/k`, `PgUp/PgDn`, `Home/End`, `g/G`, `Enter`, `r`, `s`, `Esc`,
//!   `?`, `q`, `Ctrl+C`, plus `y` (the notice acknowledgment; the
//!   vocabulary documents it among the §10.3 letters);
//! * resizes → [`AppEvent::Resize`];
//! * mouse events are **consumed here as no-ops** (T-305 owns their
//!   semantics): nothing is queued;
//! * anything else (focus changes, bracketed paste, …) is ignored
//!   without error.
//!
//! Sends go through the bounded-retry pattern documented on
//! [`AppEventSender`] (ADR-012: a send that would block keeps checking
//! the stop flag; the input side is lossy by design — a key dropped
//! after [`INPUT_RETRY_BUDGET`] attempts was, in the worst case, one
//! of several rapid repeats of the same intent).

use std::io;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::TrySendError;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use ratatui::crossterm::event::Event;
use ratatui::crossterm::event::KeyCode;
use ratatui::crossterm::event::KeyEvent;
use ratatui::crossterm::event::KeyEventKind;
use ratatui::crossterm::event::KeyModifiers;
use ratatui::crossterm::event::poll;
use ratatui::crossterm::event::read;

use crate::app::AppEvent;
use crate::app::AppEventSender;
use crate::app::InputEvent;
use crate::app::Key;

/// The poll slice: every wait is flag-checked at this granularity, so
/// the thread joins within one slice plus any in-flight retry budget
/// (§8.3 "a stop flag so it can shut down cleanly"). Non-zero (no
/// busy spin) and bounded (NFR-04's wake-ups stay timer-shaped);
/// asserted by a unit test.
pub const INPUT_POLL_TIMEOUT: Duration = Duration::from_millis(100);

/// How many total `try_send` attempts one input event gets before it
/// is dropped (the ADR-012 bounded-retry pattern; input is lossy by
/// design — the mirror of the runtime forwarder's data-event budget).
pub const INPUT_RETRY_BUDGET: u32 = 8;

/// The wait between two send attempts (the forwarder's
/// `SEND_RETRY_WAIT`).
pub const INPUT_RETRY_WAIT: Duration = Duration::from_millis(10);

/// Consecutive poll/read failures before the thread gives up: a
/// failing stream (a gone pty) never busy-spins on errors — after
/// this budget the thread exits; the exit itself is owned by the
/// signal path and the main loop.
pub const INPUT_ERROR_BUDGET: u32 = 8;

/// The input thread's name (pthread names are truncated to 15 bytes).
const INPUT_THREAD_NAME: &str = "osza-input";

/// Spawns the input thread. The thread ends when `stop` is set or the
/// stream fails [`INPUT_ERROR_BUDGET`] times in a row; both ends are
/// bounded by one poll slice plus one retry budget.
///
/// # Errors
/// The OS refused to spawn the thread (an OOM-class event; the
/// assembly turns it into an honest error exit).
pub fn spawn_input_thread(
    sender: AppEventSender,
    stop: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(INPUT_THREAD_NAME.to_owned())
        .spawn(move || input_loop(sender, stop))
}

/// The thread body: poll one slice, read-and-map what arrived, repeat
/// until stopped or the stream is gone.
fn input_loop(sender: AppEventSender, stop: Arc<AtomicBool>) {
    let mut errors = 0u32;
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        let failed = match poll(INPUT_POLL_TIMEOUT) {
            // Something arrived (or the slice elapsed with the stream
            // healthy — the count resets either way).
            Ok(false) => {
                errors = 0;
                false
            }
            Ok(true) => {
                errors = 0;
                match read() {
                    Ok(event) => {
                        if let Some(app_event) = map_event(event) {
                            deliver(app_event, &sender, &stop);
                        }
                        false
                    }
                    Err(_) => true,
                }
            }
            Err(_) => true,
        };
        if failed {
            errors = errors.saturating_add(1);
            if errors >= INPUT_ERROR_BUDGET {
                return;
            }
            // Never spin on a failing stream: wait one slice before
            // the next attempt.
            thread::sleep(INPUT_POLL_TIMEOUT);
        }
    }
}

/// Sends one event under the §5.2 policy: retry while the bounded
/// queue is full, checking the stop flag between attempts; drop after
/// the budget (input is lossy by design).
fn deliver(event: AppEvent, sender: &AppEventSender, stop: &AtomicBool) {
    let mut event = event;
    let mut tries = 0u32;
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        match sender.try_send(event) {
            Ok(()) => return,
            // Full: the event comes back; retry within the budget.
            Err(TrySendError::Full(returned)) => {
                tries += 1;
                if tries >= INPUT_RETRY_BUDGET {
                    return; // dropped and counted nowhere — by design (§5.2)
                }
                event = returned;
            }
            // The runtime is gone: nothing to deliver to.
            Err(TrySendError::Disconnected(_)) => return,
        }
        thread::sleep(INPUT_RETRY_WAIT);
    }
}

/// Translates one terminal event onto the app vocabulary (pure; the
/// §5.2 mapping table). `None` means "consumed/ignored here": mouse
/// events (no-ops until T-305) and everything the vocabulary does not
/// know.
pub fn map_event(event: Event) -> Option<AppEvent> {
    match event {
        Event::Key(key) => map_key(key).map(|key| AppEvent::Input(InputEvent::Key(key))),
        Event::Resize(width, height) => Some(AppEvent::Resize { width, height }),
        // Consumed as a no-op while capture is on: T-305 owns mouse
        // semantics; nothing is queued (§3 non-goals).
        Event::Mouse(_) => None,
        // FocusGained/FocusLost/Paste/…: unknown to the vocabulary —
        // ignored without error.
        _ => None,
    }
}

/// The §10.3 key map (pure): the crossterm key event onto the app's
/// [`Key`], or `None` for everything the vocabulary does not know.
///
/// * Only physical presses and auto-repeats act; `Release` events
///   (kitty-protocol terminals) are ignored.
/// * `Ctrl+C` is the quit chord (FR-UI-06); no other ctrl combination
///   is in §10.3.
/// * The §10.3 specials act as plain presses only — a shifted or
///   otherwise modified arrow/page/home/enter/esc is a different key,
///   outside the map.
/// * **Plain alphanumeric glyphs pass through** (task T-302's E-2b
///   reach): the FR-SC-07 typed-`yes` dialog accumulates letters —
///   `y`, `e`, `s` — and the input thread is exactly where they would
///   be lost if the map filtered to §10.3's navigation letters. The
///   app core ignores keys with no binding on the active screen
///   (T-205's tested behavior), so the wider pass-through changes no
///   navigation semantics. `Shift` is accepted because the shifted
///   glyphs (`G`) arrive with it on standard layouts; every other
///   modifier combination is rejected up front.
pub fn map_key(key: KeyEvent) -> Option<Key> {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return None;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return match key.code {
            KeyCode::Char('c') | KeyCode::Char('C') => Some(Key::CtrlC),
            _ => None,
        };
    }
    if key.modifiers.intersects(
        KeyModifiers::ALT | KeyModifiers::SUPER | KeyModifiers::HYPER | KeyModifiers::META,
    ) {
        return None;
    }
    let plain = key.modifiers.is_empty();
    let shifted = key.modifiers.contains(KeyModifiers::SHIFT);
    match key.code {
        KeyCode::Up if plain => Some(Key::Up),
        KeyCode::Down if plain => Some(Key::Down),
        KeyCode::PageUp if plain => Some(Key::PageUp),
        KeyCode::PageDown if plain => Some(Key::PageDown),
        KeyCode::Home if plain => Some(Key::Home),
        KeyCode::End if plain => Some(Key::End),
        KeyCode::Enter if plain => Some(Key::Enter),
        KeyCode::Esc if plain => Some(Key::Esc),
        // Every plain/shifted alphanumeric glyph rides `Char(char)` —
        // the typed-`yes` letters included (T-302's E-2b; §10.3's
        // navigation letters are a subset).
        KeyCode::Char(letter) if (plain || shifted) && letter.is_ascii_alphanumeric() => {
            Some(Key::Char(letter))
        }
        // The §10.3 punctuation (`?`) keeps its shifted pass-through.
        KeyCode::Char(letter @ '?') if plain || shifted => Some(Key::Char(letter)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyCode;
    use ratatui::crossterm::event::KeyEvent;
    use ratatui::crossterm::event::KeyEventKind;
    use ratatui::crossterm::event::KeyModifiers;
    use ratatui::crossterm::event::MouseEvent;
    use ratatui::crossterm::event::MouseEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn key_with(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn the_full_10_3_map_translates_exactly() {
        // Every §10.3 entry (plus the notice's `y`), as pure
        // key-event → Key translation. The letters ride with SHIFT
        // too (their shifted glyphs arrive with it); the specials
        // are plain presses only (below).
        let letters = [
            (KeyCode::Char('j'), Key::Char('j')),
            (KeyCode::Char('k'), Key::Char('k')),
            (KeyCode::Char('g'), Key::Char('g')),
            (KeyCode::Char('G'), Key::Char('G')),
            (KeyCode::Char('r'), Key::Char('r')),
            (KeyCode::Char('s'), Key::Char('s')),
            (KeyCode::Char('q'), Key::Char('q')),
            (KeyCode::Char('y'), Key::Char('y')),
            (KeyCode::Char('?'), Key::Char('?')),
        ];
        for (code, expected) in letters {
            assert_eq!(map_key(key(code)), Some(expected), "{code:?}");
            assert_eq!(
                map_key(key_with(code, KeyModifiers::SHIFT)),
                Some(expected),
                "shift {code:?}"
            );
        }
        let specials = [
            (KeyCode::Up, Key::Up),
            (KeyCode::Down, Key::Down),
            (KeyCode::PageUp, Key::PageUp),
            (KeyCode::PageDown, Key::PageDown),
            (KeyCode::Home, Key::Home),
            (KeyCode::End, Key::End),
            (KeyCode::Enter, Key::Enter),
            (KeyCode::Esc, Key::Esc),
        ];
        for (code, expected) in specials {
            assert_eq!(map_key(key(code)), Some(expected), "{code:?}");
        }
        // Ctrl+C — in both spellings the terminal may use.
        assert_eq!(
            map_key(key_with(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Key::CtrlC)
        );
        assert_eq!(
            map_key(key_with(KeyCode::Char('C'), KeyModifiers::CONTROL)),
            Some(Key::CtrlC)
        );
    }

    #[test]
    fn every_plain_letter_reaches_the_queue_including_the_yes_typing() {
        // T-302's E-2b regression: the FR-SC-07 typed-`yes` dialog
        // accumulates the letters `y`, `e`, `s` — the input thread is
        // where they would be lost if the map filtered to §10.3's
        // navigation letters (`e` is not one of them). Every plain
        // alphanumeric glyph must reach the queue; the app core
        // ignores keys with no binding on the active screen.
        for letter in ['y', 'e', 's', 'a', 'z', 'E', '0', '9'] {
            assert_eq!(
                map_key(key(KeyCode::Char(letter))),
                Some(Key::Char(letter)),
                "the typed-`yes` letter {letter:?} must pass through"
            );
        }
        // The punctuation outside §10.3 still does not.
        assert_eq!(map_key(key(KeyCode::Char('!'))), None);
        assert_eq!(map_key(key(KeyCode::Char('/'))), None);
    }

    #[test]
    fn unknown_keys_and_modifiers_are_ignored_without_error() {
        // Specials outside §10.3 …
        for code in [
            KeyCode::F(1),
            KeyCode::Tab,
            KeyCode::BackTab,
            KeyCode::Backspace,
            KeyCode::Delete,
            KeyCode::Insert,
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Null,
        ] {
            assert_eq!(map_key(key(code)), None, "{code:?}");
        }
        // … modifier combinations outside it (Ctrl+J, Alt+Q, Ctrl+R,
        // shift-arrows) …
        assert_eq!(
            map_key(key_with(KeyCode::Char('j'), KeyModifiers::CONTROL)),
            None
        );
        assert_eq!(
            map_key(key_with(KeyCode::Char('r'), KeyModifiers::CONTROL)),
            None
        );
        assert_eq!(
            map_key(key_with(KeyCode::Char('q'), KeyModifiers::ALT)),
            None
        );
        assert_eq!(map_key(key_with(KeyCode::Up, KeyModifiers::CONTROL)), None);
        assert_eq!(
            map_key(key_with(KeyCode::Up, KeyModifiers::SHIFT)),
            None,
            "a shifted arrow is not in §10.3"
        );
        // … and release events from kitty-protocol terminals.
        let mut release = key(KeyCode::Char('q'));
        release.kind = KeyEventKind::Release;
        assert_eq!(map_key(release), None);
        // Repeats act like presses (holding an arrow keeps moving).
        let mut repeat = key(KeyCode::Down);
        repeat.kind = KeyEventKind::Repeat;
        assert_eq!(map_key(repeat), Some(Key::Down));
    }

    #[test]
    fn resizes_translate_and_everything_else_is_consumed_or_ignored() {
        assert_eq!(
            map_event(Event::Resize(80, 24)),
            Some(AppEvent::Resize {
                width: 80,
                height: 24
            })
        );
        assert_eq!(
            map_event(Event::Key(key(KeyCode::Char('q')))),
            Some(AppEvent::Input(InputEvent::Key(Key::Char('q'))))
        );
        // Mouse events are consumed as no-ops: nothing queued.
        let mouse = Event::Mouse(MouseEvent {
            kind: MouseEventKind::Down(ratatui::crossterm::event::MouseButton::Left),
            column: 1,
            row: 1,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(map_event(mouse), None);
        // Other event kinds: ignored without error.
        assert_eq!(map_event(Event::FocusGained), None);
        assert_eq!(map_event(Event::FocusLost), None);
        assert_eq!(map_event(Event::Paste("x".to_owned())), None);
    }

    #[test]
    fn the_poll_timeout_is_nonzero_and_bounded() {
        // NFR-04/§5.7: a zero timeout would busy-spin; an unbounded
        // one would block shutdown past every bound. The slice stays
        // inside the house granularity (the forwarder's 100 ms).
        assert!(INPUT_POLL_TIMEOUT > Duration::ZERO);
        assert!(INPUT_POLL_TIMEOUT <= Duration::from_millis(250));
    }

    #[test]
    fn the_input_thread_stops_within_a_bounded_time() {
        // Clean shutdown (§8.3): with the stop flag set the thread
        // joins within one poll slice plus one retry budget, whatever
        // the stream's state (a healthy blocking poll, or a failing
        // /dev/tty under a headless test runner).
        let (sender, _runtime) = real_sender();
        let stop = Arc::new(AtomicBool::new(false));
        let started = std::time::Instant::now();
        let thread = spawn_input_thread(sender, Arc::clone(&stop)).expect("spawn works");
        thread::sleep(INPUT_POLL_TIMEOUT * 2);
        stop.store(true, Ordering::Release);
        let _ = thread.join();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "the thread must stop promptly after the flag (took {elapsed:?})"
        );
    }

    /// A real [`AppEventSender`] over a real (throwaway) runtime: the
    /// queue's receiver stays alive for the test's duration, so
    /// `try_send` behaves exactly as in the app.
    fn real_sender() -> (
        AppEventSender,
        crate::app::Runtime<crate::app::RecordingExecutor>,
    ) {
        use crate::app::AppState;
        use crate::app::RecordingExecutor;
        use crate::app::Runtime;
        use crate::app::SessionParams;
        use crate::discovery::worker::CycleEvent;
        use crate::model::Clock;
        use crate::model::FakeClock;
        use std::sync::Arc;
        use std::sync::mpsc::sync_channel;

        let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FakeClock::new());
        let vendor_db = Arc::new(
            crate::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
        );
        let state = AppState::with_scope_entries(
            SessionParams::default(),
            Vec::new(),
            vendor_db,
            clock.as_ref(),
        )
        .expect("defaults are valid");
        // A disconnected discovery receiver: the runtime's forwarder
        // exits immediately (the runtime tests' dummy pattern).
        let (dead_tx, dead_rx) = sync_channel::<CycleEvent>(1);
        drop(dead_tx);
        let (runtime, sender) = Runtime::new(state, RecordingExecutor::new(), dead_rx, clock);
        (sender, runtime)
    }
}
