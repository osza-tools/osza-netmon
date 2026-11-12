// SPDX-License-Identifier: GPL-3.0-only

//! The terminal front end (plan §8.1, §8.3, §8.4, §8.8; task T-301).
//!
//! Task T-301 attaches a real terminal to the headless application
//! core delivered by T-205: this layer owns the terminal lifecycle
//! (raw mode, alternate screen, mouse capture, restore on every exit
//! path), translates terminal events onto the app's terminal-agnostic
//! [`AppEvent`](crate::app::AppEvent) vocabulary, runs the §8.4 event
//! loop with dirty-flag rendering and the 1 Hz tick, bridges
//! SIGTERM/SIGHUP into the app's normal quit path (ADR-018), and
//! assembles the real binary end to end. The actual screen content is
//! **not** this layer's: [`render`] draws one deliberately minimal
//! placeholder frame (screen name, live device count, one marker
//! line) that T-302/T-303/T-304 replace wholesale.
//!
//! # Module layout
//!
//! * [`lifecycle`] — the terminal lifecycle guard (§8.8): the earlier
//!   panic hook, `ratatui::try_init`, explicit mouse capture, and the
//!   RAII restore that is the final safety net on every exit path.
//! * [`input`] — the one dedicated input thread (§8.3): crossterm
//!   `poll` with a short timeout and a stop flag, the pure §10.3
//!   key-map translation, and the bounded-retry send documented on
//!   [`AppEventSender`](crate::app::AppEventSender).
//! * [`signals`] — the SIGTERM/SIGHUP bridge (§5.3, ADR-018): one
//!   small signal thread that quits through the app's normal quit
//!   path (the same event the Ctrl+C key produces).
//! * [`render`] — the placeholder frame and the pure dirty/tick
//!   render decision (FR-UI-07).
//! * [`assembly`] — the binary assembly (§5.6): interfaces → state →
//!   workers (ADR-005 privilege order) → runtime → the lifecycle
//!   loop; the wiring seam `main` calls and the pty harness's
//!   fake-source variant reuses.
//!
//! # Dependency discipline (§8.2)
//!
//! [`render`] depends on the app core's read-only views and `model`
//! only — it performs no I/O of its own beyond drawing through the
//! ratatui terminal it is handed, calls no workers, and mutates
//! nothing. [`assembly`] and [`lifecycle`] are *wiring* (the §8.1
//! `main` role, hosted here per the task card's suggested layout):
//! they touch the terminal, the workers' public construction APIs and
//! the process environment by definition — the reviewer's §8.2 greps
//! therefore target the render path, exactly as `src/app`'s greps
//! target its imports (see the execution report §4 for the exact
//! commands and results).

pub mod assembly;
pub mod input;
pub mod lifecycle;
pub mod render;
pub mod signals;
