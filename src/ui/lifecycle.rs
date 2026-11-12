// SPDX-License-Identifier: GPL-3.0-only

//! The terminal lifecycle (plan §8.8; task T-301 §5.1): everything
//! between "the process starts" and "the user's shell is usable
//! again".
//!
//! # The init order (verified against the pinned ratatui 0.30.2)
//!
//! 1. **The earlier panic hook.** ratatui 0.30's `try_init` installs
//!    a panic hook that restores the terminal and then calls the hook
//!    that was current when `init` ran — its own documentation says
//!    to install any other hook *before* init so the terminal is
//!    restored before the other hooks run (verified in the pinned
//!    0.30.2 source: `init.rs`'s `set_panic_hook` wraps
//!    `std::panic::take_hook()`). [`TerminalGuard::init`] therefore
//!    installs our hook first: it disables mouse capture (§8.8:
//!    `init`/`restore` never touch capture — it is ours to disable)
//!    and then chains to the previous hook.
//! 2. **`ratatui::try_init()`** — its hook (chained after ours), raw
//!    mode, the alternate screen, the `CrosstermBackend` on stdout.
//! 3. **Mouse capture**, explicitly and only when the assembly asked
//!    for it (`mouse_enabled = false` skips both the enable and the
//!    disable — T-402's `--no-mouse` rides the parameter).
//!
//! # The restore paths
//!
//! The explicit [`TerminalGuard::restore`] runs on the normal and
//! error exits (capture off, then ratatui's restore: raw mode off,
//! leave the alternate screen). The [`Drop`] implementation is the
//! final safety net for every path that never called it — a forced
//! panic unwinding through the loop, a future caller's mistake — and
//! is deliberately best-effort and quiet: at teardown time stdout may
//! be the broken thing, so there is nothing useful to report and no
//! §8.7 surface left to route a message to (documented in the T-301
//! report §6; the same choice ratatui's own `restore` makes when its
//! error path can only print). A panic additionally runs ratatui's
//! hook (raw mode off, alternate screen left) *and* our earlier hook
//! (capture off), so even a panic on a non-main thread — where no
//! guard unwinds — leaves a clean, capture-free terminal (a broken
//! TUI is the honest price; the reviewed workers are panic-free by
//! lint, and the user's shell stays usable).

use std::io;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::DisableMouseCapture;
use ratatui::crossterm::event::EnableMouseCapture;
use ratatui::crossterm::execute;

/// Installs the *earlier* panic hook (§8.8; the ratatui 0.30 rule).
///
/// On any panic — before or after init — mouse capture is disabled
/// best-effort, then the previously installed hook (normally the
/// default one that prints the panic message) runs. ratatui's own
/// hook, installed by `try_init` after this one, restores raw mode
/// and the alternate screen before chaining here.
fn install_earlier_panic_hook(mouse_enabled: bool) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(std::boxed::Box::new(move |info| {
        if mouse_enabled {
            // Best-effort: an escape sequence on a dying stream is
            // the most that can be done from a hook; the guard's
            // Drop is the second net on the main thread's unwind.
            let _ = execute!(std::io::stdout(), DisableMouseCapture);
        }
        previous(info);
    }));
}

/// The RAII terminal: init once, restore exactly once, on every exit
/// path (§8.8). Created only by [`TerminalGuard::init`]; the
/// alternate screen and raw mode belong to ratatui's init/restore,
/// mouse capture to this guard.
#[derive(Debug)]
pub struct TerminalGuard {
    terminal: DefaultTerminal,
    mouse_enabled: bool,
    restored: bool,
}

impl TerminalGuard {
    /// Initializes the terminal (the order documented at the module
    /// level): earlier panic hook, `ratatui::try_init`, then mouse
    /// capture when enabled.
    ///
    /// # Errors
    /// Any terminal setup failure, verbatim from ratatui/crossterm
    /// (not a tty, a broken stream, …). On failure the caller should
    /// still attempt [`ratatui::try_restore`] — ratatui's own
    /// documentation notes `init()` (the panicking form) exists
    /// because a mid-way `try_init` failure can leave raw mode on;
    /// the assembly does exactly that.
    pub fn init(mouse_enabled: bool) -> io::Result<Self> {
        install_earlier_panic_hook(mouse_enabled);
        let terminal = ratatui::try_init()?;
        if mouse_enabled {
            execute!(std::io::stdout(), EnableMouseCapture)?;
        }
        Ok(TerminalGuard {
            terminal,
            mouse_enabled,
            restored: false,
        })
    }

    /// The terminal the render loop draws through.
    pub fn terminal(&mut self) -> &mut DefaultTerminal {
        &mut self.terminal
    }

    /// The explicit restore (normal and error exits): mouse capture
    /// off first, then ratatui's restore (raw mode off, leave the
    /// alternate screen). Idempotent by construction — the guard's
    /// `restored` flag makes a double call (explicit + Drop) a no-op.
    ///
    /// # Errors
    /// The first failing step, verbatim; the steps before it have
    /// already run.
    pub fn restore(mut self) -> io::Result<()> {
        self.restore_internal()
    }

    fn restore_internal(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        if self.mouse_enabled {
            execute!(std::io::stdout(), DisableMouseCapture)?;
        }
        ratatui::try_restore()
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // The final safety net (§8.8): a path that never restored —
        // a forced panic unwinding past the loop, a dropped guard —
        // still restores. Best-effort and quiet by design (module
        // docs): both disables are idempotent escape sequences.
        if !self.restored {
            let _ = self.restore_internal();
        }
    }
}
