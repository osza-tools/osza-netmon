// SPDX-License-Identifier: GPL-3.0-only

//! The terminal front end (plan §8.1, §8.3, §8.4, §8.8; tasks T-301,
//! T-302).
//!
//! Task T-301 attached a real terminal to the headless application
//! core delivered by T-205: this layer owns the terminal lifecycle
//! (raw mode, alternate screen, mouse capture, restore on every exit
//! path), translates terminal events onto the app's terminal-agnostic
//! [`AppEvent`](crate::app::AppEvent) vocabulary, runs the §8.4 event
//! loop with dirty-flag rendering and the 1 Hz tick, bridges
//! SIGTERM/SIGHUP into the app's normal quit path (ADR-018), and
//! assembles the real binary end to end.
//!
//! Task T-302 gave the front end its real first screens:
//! [`notice`] renders the ADR-004 authorization notice (with the
//! acknowledgment store [`ack`] — the MVP's sole persisted state),
//! [`scope`] renders the interface/scope list, the FR-SC-06/07
//! confirmation dialogs and the terminal-too-small screen, and
//! [`render`] dispatches between them while keeping the T-303/T-304
//! placeholders (dashboard, details, help) clearly marked.
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
//! * [`notice`] — the authorization-notice screen (FR-ST-01,
//!   ADR-004): the verbatim text and its keys' rendering.
//! * [`scope`] — the interface/scope screen (FR-SC-01…08), the
//!   FR-SC-06/07 confirmation dialogs and the FR-ST-04 too-small
//!   screen.
//! * [`ack`] — the notice-acknowledgment store (ADR-004/ADR-013,
//!   task T-302 §5.2): the wiring-role file I/O — read at startup,
//!   written through the E-2a effect's executor interceptor.
//! * [`render`] — the frame dispatch (the real T-302 screens + the
//!   T-303/T-304 placeholders) and the pure dirty/tick render
//!   decision (FR-UI-07).
//! * [`assembly`] — the binary assembly (§5.6): interfaces → state →
//!   workers (the ADR-005 privilege order and the PQ-3 per-interface
//!   transports) → runtime → the lifecycle loop with the post-confirm
//!   attach; the wiring seam `main` calls and the pty harness's
//!   fake-source variant reuses.
//!
//! # Dependency discipline (§8.2)
//!
//! [`render`], [`notice`] and [`scope`] depend on the app core's
//! read-only views and `model` only — they perform no I/O of their
//! own beyond drawing through the ratatui terminal they are handed,
//! call no workers, and mutate nothing. [`assembly`], [`lifecycle`]
//! and [`ack`] are *wiring* (the §8.1 `main` role, hosted here per
//! the task card's suggested layout): they touch the terminal, the
//! workers' public construction APIs, the process environment and the
//! acknowledgment file by definition — the reviewer's §8.2 greps
//! therefore target the render path, exactly as `src/app`'s greps
//! target its imports (see the execution report §4 for the exact
//! commands and results).

pub mod ack;
pub mod assembly;
pub mod input;
pub mod lifecycle;
pub mod notice;
pub mod render;
pub mod scope;
pub mod signals;
