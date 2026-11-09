// SPDX-License-Identifier: GPL-3.0-only

//! The application core: the screen state machine, the pure `update`
//! function, the bounded event queue and the runtime that wires the
//! reviewed Phase 2 workers together (plan §8.1, §8.3–8.5, §13 T-205;
//! task T-205).
//!
//! This module is deliberately **headless**: no terminal, no TUI
//! framework, no input-event library — Phase 3 (T-301…) attaches a
//! terminal to a running, fully-tested core. Everything here is
//! drivable by scenario scripts:
//!
//! * [`event`] — [`AppEvent`], the single bounded queue's payload
//!   (input, resize, tick, discovery, hostname), with the
//!   terminal-agnostic [`Key`] vocabulary of plan §10.3.
//! * [`action`] — [`Effect`] (start a scan, queue a
//!   lookup, quit — no cancel: user quit is the only cancel path) and
//!   the [`EffectsExecutor`] seam with the
//!   production [`WorkerExecutor`].
//! * [`state`] — [`AppState`]: the screens (§6.6), the interface
//!   snapshot for the scope screen, the registry, the FR-DS-12
//!   scheduler, the message log, the counters — single-threaded by
//!   construction (ADR-012), no locks.
//! * [`message`] — the typed, deduplicating message log (§6.8, plan
//!   §13: last 20; T-401 words every kind).
//! * [`config`] — [`SessionParams`]: what the
//!   startup assembly computes once (T-301/T-302).
//! * `update` — the module of the pure
//!   `update(state, event, clock) -> effects` function:
//!   the per-screen key table of §5.6/§10.3, the discovery-cycle and
//!   hostname-event bookkeeping of §5.5, and the §5.9 enrichment rules
//!   (vendor once per record; hostname effects on every accepted
//!   observation).
//! * [`runtime`] — [`Runtime`]: the §8.4 event loop (wait = the
//!   nearest of auto deadline, tick deadline, `MAX_WAIT`; drain ≤ 16;
//!   one scheduler poll per iteration when armed), the bounded queue
//!   (capacity [`APP_EVENT_CAPACITY`] =
//!   256), the discovery forwarder thread, and the bounded shutdown
//!   sequence.
//!
//! Per the §8.2 clarification ratified in plan v1.10.0, this layer may
//! use `model`, `registry`, its own `config`, the public data types of
//! `net` (`InterfaceInfo` and friends), the enrichment vendor lookup
//! and hostname worker public APIs, and the public discovery
//! scheduling/orchestration surface — never discovery or enrichment
//! internals (`arp::codec`, `arp::scanner`, `arp::transport`,
//! `neighbor_table`, `dns` internals).
//!
//! Deviations D-1 (the app-side interface snapshot) and D-2 (the
//! inline hostname drain) are documented in [`state`]'s and
//! [`runtime`]'s module docs and in the execution report §5.

pub mod action;
pub mod config;
pub mod event;
pub mod message;
pub mod runtime;
pub mod state;
pub mod update;

pub use action::{Effect, EffectError, EffectsExecutor, WorkerExecutor, WorkerStats};
pub use config::{AppInitError, AppMode, SessionParams};
pub use event::{AppEvent, InputEvent, Key};
pub use message::{MESSAGE_LOG_CAPACITY, Message, MessageKind, MessageLog};
pub use runtime::{APP_EVENT_CAPACITY, AppEventSender, MAX_WAIT, RecordingExecutor, Runtime};
pub use state::{AppState, ConfirmedScope, CountersSnapshot, LastScan, ScopeEntry, Screen};
pub use update::update;
