// SPDX-License-Identifier: GPL-3.0-only

//! The binary assembly (plan §8.1, §8.4; task T-301 §5.6): build the
//! real app end to end and run the terminal lifecycle loop.
//!
//! # The real assembly ([`run`])
//!
//! `enumerate_interfaces()` → [`AppState::new`] with default
//! [`SessionParams`] (the construction-time startup messages are the
//! app core's; this layer supplies the facts — the
//! [`running_as_root`] result, the session mode) → the real
//! [`DiscoveryWorker`] and [`HostnameWorker`] per the reviewed
//! T-203/T-204 APIs under the ADR-005 privilege order (transport with
//! privileges, then drop; the read-only fallback when privileges are
//! missing) → [`Runtime`] → the lifecycle loop.
//!
//! The discovery worker binds, at startup, to the **suggested**
//! interface and its scope (ADR-005 item 2: the socket opens "before
//! the TUI starts" bound to the selected interface; the scope screen
//! starts on the same suggestion). One scope per session is the MVP
//! model (plan §6.2), and the T-204/T-205 surface fixes the worker's
//! scope at spawn — a confirmation of a *different* eligible
//! interface would leave the scan scope on the suggested one. That
//! mismatch is a known limitation of the frozen surface, not a
//! silent behavior (execution report §10; PQ-3 proposes the
//! late-attachment fix for T-302/T-303).
//!
//! # The injection seam ([`run_with`])
//!
//! The pty harness's fake-source variant (the T-205 AC-5 pattern):
//! pre-built state, workers and channels, the same lifecycle. The
//! real [`run`] is exactly this function behind the real
//! construction.
//!
//! # The lifecycle loop
//!
//! One loop, one runtime, from launch to quit (§8.4): block in
//! [`Runtime::step`] with `wait = min(next tick deadline, MAX_WAIT)`
//! ([`loop_wait`]); the runtime itself additionally caps the wait by
//! the discovery deadline — but only while discovery is armed
//! (T-205 decision 10), which is why this loop never consults the
//! scheduler: pre-confirmation it cannot, and must not, derive a
//! zero wait from a fresh scheduler's "due now" (no busy spin; the
//! signature of [`loop_wait`] admits no discovery state at all).
//! When the tick deadline fires, one [`AppEvent::Tick`] is queued
//! through the sender — bounded, and a dropped tick is harmless: the
//! next second retries, and the runtime's own synthesized tick is
//! the safety net. Rendering follows the dirty flag
//! ([`should_render`](crate::ui::render::should_render) — a processed
//! tick always marks it), and the loop ends on the authoritative
//! `quit`.
//!
//! # Shutdown (§5.6)
//!
//! `q`/`Ctrl+C`/signal → the app's quit path (the runtime's bounded
//! idempotent shutdown already ran on the quit step) → stop the
//! input thread's flag → close the signal iterator → join both
//! threads → restore the terminal. Every wait is flag-checked or
//! close-woken; no hang is possible on any exit path — including a
//! panic, where the guards' `Drop`s run the same sequence.

use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use crate::app::AppEvent;
use crate::app::AppEventSender;
use crate::app::AppInitError;
use crate::app::AppMode;
use crate::app::AppState;
use crate::app::MAX_WAIT;
use crate::app::Runtime;
use crate::app::SessionParams;
use crate::app::WorkerExecutor;
use crate::app::runtime::TICK_INTERVAL;
use crate::discovery::ArpScanner;
use crate::discovery::ArpWorkerHandle;
use crate::discovery::DiscoveryWorker;
use crate::discovery::LinuxArpTransport;
use crate::discovery::ProcNeighborTable;
use crate::discovery::privilege::PrivilegeError;
use crate::discovery::privilege::drop_capabilities;
use crate::discovery::privilege::open_raw_socket;
use crate::discovery::privilege::running_as_root;
use crate::discovery::worker::CycleEvent;
use crate::enrichment::dns::NameResolver;
use crate::enrichment::dns::UdpResolver;
use crate::enrichment::hostname::HostnameConfig;
use crate::enrichment::hostname::select_from_system;
use crate::enrichment::vendor::VendorDb;
use crate::enrichment::worker::HostnameWorker;
use crate::model::Clock;
use crate::model::Ipv4Net;
use crate::model::SystemClock;
use crate::net::InterfaceInfo;
use crate::net::derive_scope;
use crate::net::enumerate_interfaces;
use crate::net::suggest_interface;
use crate::ui::input;
use crate::ui::lifecycle::TerminalGuard;
use crate::ui::render;
use crate::ui::signals;

/// The assembly's tunable parameters (§5.1: the assembly *accepts*
/// parameters and parses nothing — T-402 owns the CLI). Defaults are
/// the plan values: mouse capture on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyParams {
    /// Whether mouse capture is enabled after init (§8.8; the
    /// `--no-mouse` flag's effect arrives as `false` from T-402).
    pub mouse_enabled: bool,
}

impl Default for AssemblyParams {
    fn default() -> Self {
        AssemblyParams {
            mouse_enabled: true,
        }
    }
}

/// Why the assembled application exited with an error (the normal
/// quit is `Ok(())`). `main` prints the message after the terminal is
/// restored (§8.7: only `main` may talk to the standard streams, and
/// only pre-init/post-restore).
#[derive(Debug, thiserror::Error)]
pub enum AssemblyError {
    /// A terminal setup/draw/restore failure, verbatim.
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
    /// The SIGTERM/SIGHUP registration or its thread failed.
    #[error("registering the signal handler failed: {0}")]
    SignalSetup(String),
    /// The input thread could not be spawned.
    #[error("spawning the input thread failed: {0}")]
    InputSpawn(String),
    /// The embedded vendor database is unusable (a build-image
    /// corruption; the honest refusal).
    #[error("the embedded vendor database is unusable: {0}")]
    VendorDb(String),
    /// The application state could not be built (the registry
    /// configuration's typed refusal, verbatim).
    #[error(transparent)]
    AppState(#[from] AppInitError),
    /// The raw socket of the privilege order failed for a
    /// non-privilege reason (a vanished interface, a kernel refusal):
    /// fail closed before the terminal exists.
    #[error("opening the raw socket failed: {0}")]
    SocketOpen(String),
    /// The ADR-005 capability drop failed verification: fail closed
    /// (SR-06) before the terminal exists.
    #[error("dropping capabilities failed: {0}")]
    PrivilegeDrop(String),
    /// A worker thread could not be spawned (OOM-class).
    #[error("spawning a worker failed: {0}")]
    WorkerSpawn(String),
    /// A scope the assembly needed could not be built (the reserved
    /// dormant 0.0.0.0/0 is always valid — the arm is the honest
    /// refusal, never a clamp).
    #[error("a required scope is invalid: {0}")]
    Scope(String),
    /// The pty-test fault seam (§6; the report's decision list): a
    /// deterministic error exit induced from outside.
    #[error("forced fault for the T-301 pty test ({kind})")]
    ForcedFault {
        /// Which fault was induced.
        kind: &'static str,
    },
}

/// The real binary assembly (§5.6; module docs) and the lifecycle
/// loop. Called by `main` with the default parameters.
///
/// # Errors
/// Any assembly or runtime failure (the terminal is restored before
/// the error leaves this function; assembly failures happen before
/// it exists).
pub fn run(params: AssemblyParams) -> Result<(), AssemblyError> {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);

    // 1. The interface facts (§5.6) and the startup selection.
    let interfaces = enumerate_interfaces();
    let suggested = suggest_interface(&interfaces);

    // 2. The session facts the app core cannot know (§5.4: the
    //    construction-time messages are its; the facts are ours).
    let mut session = SessionParams {
        started_as_root: running_as_root(),
        ..SessionParams::default()
    };

    // 3. The discovery worker under the ADR-005 privilege order, and
    //    the hostname worker + resolver selection (ADR-003) over the
    //    same startup scope.
    let discovery = match suggested {
        Some(interface) => assemble_interface_session(interface, &mut session)?,
        None => {
            // No eligible interface: nothing is confirmable, discovery
            // can never arm, so no scan will ever start. The worker is
            // a dormant read-only one — an honest idle handle over the
            // real neighbor table filtered by a name that matches
            // nothing, over the reserved scope 0.0.0.0/0 that nothing
            // observes through; the scope screen explains itself
            // (T-302 owns the wording).
            let dormant_scope = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
                .map_err(|error| AssemblyError::Scope(error.to_string()))?;
            let (worker, events) = DiscoveryWorker::spawn_read_only(
                Box::new(ProcNeighborTable::new()),
                dormant_scope,
                String::new(),
            );
            DiscoverySetup {
                worker,
                events,
                scope: None,
            }
        }
    };

    // 4. The resolver selection (ADR-003) over the startup scope, and
    //    the hostname worker. The stop flag is one `Arc` shared by the
    //    worker and its resolver (a pending socket wait is interrupted
    //    on shutdown — the T-203 construction contract).
    let hostname_stop = Arc::new(AtomicBool::new(false));
    let (resolver, resolver_selected) = match discovery.scope {
        Some(scope) => match select_from_system(scope).resolver_socket() {
            Some(address) => match UdpResolver::new(address, Arc::clone(&hostname_stop)) {
                Ok(resolver) => (
                    Some(Box::new(resolver) as Box<dyn NameResolver>),
                    Some(address),
                ),
                // The resolver socket could not be bound: honestly no
                // resolver (not a silent Some-that-never-answers).
                Err(_) => (None, None),
            },
            None => (None, None),
        },
        None => (None, None),
    };
    session.resolver_selected = resolver_selected;
    let hostname = HostnameWorker::spawn(
        HostnameConfig::default(),
        resolver,
        Arc::clone(&clock),
        hostname_stop,
    )
    .map_err(|error| AssemblyError::WorkerSpawn(error.to_string()))?;

    // 5. The state (§5.6: `AppState::new`, the reviewed construction
    //    API) and the runtime.
    let vendor_db =
        Arc::new(VendorDb::embedded().map_err(|error| AssemblyError::VendorDb(error.to_string()))?);
    let state = AppState::new(session, interfaces, vendor_db, clock.as_ref())?;
    let executor = WorkerExecutor::new(discovery.worker, hostname);
    let (runtime, sender) = Runtime::new(state, executor, discovery.events, clock);

    lifecycle(params, runtime, sender)
}

/// One discovery worker plus the facts of its construction (the scope
/// it was spawned over, when there is one).
struct DiscoverySetup {
    worker: DiscoveryWorker,
    events: Receiver<CycleEvent>,
    scope: Option<Ipv4Net>,
}

/// The per-interface privilege order (ADR-005): the transport opens
/// while privileges are held, then every capability drops **before
/// any other thread spawns** (children inherit the dropped sets —
/// the T-104/poc order); the read-only fallback (FR-DS-14) when the
/// privileges are missing or the interface reports no usable
/// identity. Fills the session's mode and returns the worker pair.
///
/// # Errors
/// The socket opened for a non-privilege reason, or the capability
/// drop failed verification — both fail closed before the terminal
/// exists.
fn assemble_interface_session(
    interface: &InterfaceInfo,
    session: &mut SessionParams,
) -> Result<DiscoverySetup, AssemblyError> {
    // An eligible interface always carries an IPv4 address
    // (FR-SC-03), so the scope exists; the honest refusal arm stays
    // total regardless.
    let scope = derive_scope(interface)
        .or_else(|| Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).ok())
        .ok_or_else(|| AssemblyError::Scope("no derivable scope".to_owned()))?;
    let interface_name = interface.name().to_owned();
    let neighbors = Box::new(ProcNeighborTable::new());

    match open_raw_socket(&interface_name) {
        Ok(socket) => {
            // The drop happens in both arms (ADR-005 item 5: even a
            // root start drops; the function is idempotent for the
            // cap-less) and before any thread spawns.
            drop_capabilities().map_err(|error| AssemblyError::PrivilegeDrop(error.to_string()))?;
            // The scanner announces the interface's identity in every
            // request (FR-DS-03). Without a valid MAC there is no
            // honest active session (ADR-008: no identity): the
            // read-only fallback covers it — the socket is dropped
            // unused, no packet is ever sent (report decision).
            match interface.mac().zip(interface.ipv4()) {
                Some((mac, ip)) => {
                    let transport = LinuxArpTransport::new(socket);
                    let scanner = ArpScanner::new(Box::new(transport), scope, mac, ip);
                    let (arp, arp_events) = ArpWorkerHandle::spawn(scanner);
                    let (worker, events) = DiscoveryWorker::spawn_active(
                        arp,
                        arp_events,
                        neighbors,
                        scope,
                        interface_name,
                    );
                    Ok(DiscoverySetup {
                        worker,
                        events,
                        scope: Some(scope),
                    })
                }
                None => {
                    session.mode = AppMode::ReadOnly {
                        reason: "the interface reports no valid hardware address".to_owned(),
                    };
                    let (worker, events) =
                        DiscoveryWorker::spawn_read_only(neighbors, scope, interface_name);
                    Ok(DiscoverySetup {
                        worker,
                        events,
                        scope: Some(scope),
                    })
                }
            }
        }
        Err(PrivilegeError::PermissionDenied) => {
            // FR-DS-14: the read-only session, neighbor reads only.
            drop_capabilities().map_err(|error| AssemblyError::PrivilegeDrop(error.to_string()))?;
            session.mode = AppMode::ReadOnly {
                reason: "no CAP_NET_RAW: read-only mode (neighbor table only)".to_owned(),
            };
            let (worker, events) =
                DiscoveryWorker::spawn_read_only(neighbors, scope, interface_name);
            Ok(DiscoverySetup {
                worker,
                events,
                scope: Some(scope),
            })
        }
        Err(error) => Err(AssemblyError::SocketOpen(error.to_string())),
    }
}

/// The injection seam: a pre-built app on the real terminal lifecycle
/// (the pty harness's fake-source variant, §6).
///
/// # Errors
/// Any lifecycle failure (the terminal is restored before the error
/// leaves this function).
pub fn run_with(
    params: AssemblyParams,
    state: AppState,
    executor: WorkerExecutor,
    discovery_events: Receiver<CycleEvent>,
    clock: Arc<dyn Clock + Send + Sync>,
) -> Result<(), AssemblyError> {
    let (runtime, sender) = Runtime::new(state, executor, discovery_events, clock);
    lifecycle(params, runtime, sender)
}

/// The terminal lifecycle around one runtime (module docs): threads,
/// terminal, loop, teardown — with `Drop` safety nets so a panic runs
/// the same bounded shutdown.
fn lifecycle(
    params: AssemblyParams,
    mut runtime: Runtime<WorkerExecutor>,
    sender: AppEventSender,
) -> Result<(), AssemblyError> {
    // The threads first: the signal registration closes the startup
    // window (a SIGTERM during init lands in the queue and quits the
    // first step), and the input thread's pre-init window is
    // harmless (cooked-mode bytes parse the same).
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Threads::spawn(sender.clone(), Arc::clone(&stop))?;

    // The terminal (§8.8): earlier panic hook → try_init → capture.
    let mut guard = match TerminalGuard::init(params.mouse_enabled) {
        Ok(guard) => guard,
        Err(error) => {
            // ratatui's own documentation: a mid-way `try_init`
            // failure can leave raw mode on — restore before
            // propagating (best effort; the error is the answer).
            let _ = ratatui::try_restore();
            threads.shutdown();
            return Err(error.into());
        }
    };

    // The pty-test fault seam (decision D-2 of the report): one
    // deterministic induction point after init, inert unless the
    // exact variable is set.
    fault_from_env().check()?;

    // The loop (§8.4; module docs).
    let result = run_loop(&mut runtime, &sender, guard.terminal());

    // Teardown on every completing path (§5.6): the runtime's own
    // shutdown already ran on the quit step (idempotent here), then
    // the threads, then the terminal.
    runtime.shutdown();
    threads.shutdown();
    match result {
        Ok(()) => guard.restore().map_err(AssemblyError::from),
        Err(error) => {
            // Best effort: the original error is the answer.
            let _ = guard.restore();
            Err(error)
        }
    }
}

/// The input and signal threads plus their shared stop flag (§5.3:
/// exactly these two may be added). [`Threads::shutdown`] is the
/// bounded stop-close-join sequence; `Drop` runs it for the paths
/// that never called it (a panic unwinding past the loop).
struct Threads {
    stop: Arc<AtomicBool>,
    input: Option<JoinHandle<()>>,
    signals: Option<signals::SignalGuard>,
}

impl Threads {
    fn spawn(sender: AppEventSender, stop: Arc<AtomicBool>) -> Result<Self, AssemblyError> {
        let signal_guard = signals::spawn_signal_thread(sender.clone(), Arc::clone(&stop))
            .map_err(AssemblyError::SignalSetup)?;
        let input = input::spawn_input_thread(sender, Arc::clone(&stop))
            .map_err(|error| AssemblyError::InputSpawn(error.to_string()))?;
        Ok(Threads {
            stop,
            input: Some(input),
            signals: Some(signal_guard),
        })
    }

    /// Bounded shutdown: the flag first (both loops check it), then
    /// the signal iterator's close (wakes its thread), then both
    /// joins — one poll slice plus one retry budget at worst.
    fn shutdown(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(mut guard) = self.signals.take() {
            guard.shutdown();
        }
        if let Some(thread) = self.input.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Threads {
    fn drop(&mut self) {
        // The panic-path safety net: the same bounded sequence.
        self.shutdown();
    }
}

/// The loop's blocking wait (§8.4 / §5.4): never past the next tick
/// deadline, never past [`MAX_WAIT`]. The runtime's own `step` caps
/// this further by the discovery deadline — but only while discovery
/// is armed (T-205 decision 10) — so the combination is exactly the
/// card's `min(next discovery deadline, tick deadline, MAX_WAIT)`
/// while this function itself cannot busy-spin pre-confirmation: it
/// has no discovery state to consult (the unit tests pin that
/// structurally).
pub fn loop_wait(now: Instant, next_tick: Instant) -> Duration {
    next_tick.saturating_duration_since(now).min(MAX_WAIT)
}

/// The loop body (module docs for the sequence).
fn run_loop(
    runtime: &mut Runtime<WorkerExecutor>,
    sender: &AppEventSender,
    terminal: &mut ratatui::DefaultTerminal,
) -> Result<(), AssemblyError> {
    let mut next_tick = Instant::now() + TICK_INTERVAL;
    loop {
        let wait = loop_wait(Instant::now(), next_tick);
        runtime.step(wait);
        let now = Instant::now();
        if now >= next_tick {
            // The 1 Hz tick through the sender (§5.4): bounded — a
            // dropped tick is harmless; the next second retries and
            // the runtime's synthesized tick is the safety net.
            let _ = sender.try_send(AppEvent::Tick);
            next_tick = now + TICK_INTERVAL;
        }
        // The quit check precedes rendering: the last frame is never
        // drawn (the alternate screen leaves immediately after).
        if runtime.state().quit() {
            return Ok(());
        }
        // A processed tick always marks the state dirty (T-205's
        // tested update), so the consume covers both §5.4 arms.
        if render::should_render(runtime.take_dirty(), false) {
            render::draw_placeholder(terminal, runtime.state())?;
        }
    }
}

/// The pty-test fault seam (§6's AC-2b/c need a deterministic
/// induction in the real binary; no production path can be made to
/// fail or panic on demand — the lints forbid both). Inert unless
/// `OSZA_NETMON_TEST_FAULT` is exactly `panic` or `error`; checked
/// once, after init (decision D-2 of the report).
enum Fault {
    None,
    Panic,
    Error,
}

fn fault_from_env() -> Fault {
    match std::env::var("OSZA_NETMON_TEST_FAULT").as_deref() {
        Ok("panic") => Fault::Panic,
        Ok("error") => Fault::Error,
        _ => Fault::None,
    }
}

impl Fault {
    fn check(self) -> Result<(), AssemblyError> {
        match self {
            Fault::None => Ok(()),
            // The scoped allow mirrors main.rs's print allows: a
            // test seam the lints deny by default, justified by the
            // card's own AC-2c.
            #[allow(clippy::panic)]
            Fault::Panic => panic!("forced panic for the T-301 pty test"),
            Fault::Error => Err(AssemblyError::ForcedFault {
                kind: "OSZA_NETMON_TEST_FAULT=error",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loop_wait_caps_at_the_tick_deadline_and_max_wait() {
        let now = Instant::now();
        // A tick one second out: the wait is exactly the delta (the
        // runtime caps it further by the discovery deadline).
        assert_eq!(loop_wait(now, now + Duration::from_secs(1)), MAX_WAIT);
        // A tick 100 ms out: the wait is 100 ms.
        assert_eq!(
            loop_wait(now, now + Duration::from_millis(100)),
            Duration::from_millis(100)
        );
        // A tick in the past (the deadline fired): zero — one
        // immediate iteration, after which the loop re-anchors.
        assert_eq!(
            loop_wait(now, now - Duration::from_millis(5)),
            Duration::ZERO
        );
        // A tick far in the future: MAX_WAIT bounds the block (the
        // runtime's own cap is 1 s anyway).
        assert_eq!(loop_wait(now, now + Duration::from_secs(3600)), MAX_WAIT);
    }

    #[test]
    fn loop_wait_admits_no_discovery_state_so_it_cannot_spin_pre_confirmation() {
        // T-205 decision 10, pinned structurally: the pre-confirmation
        // busy-spin hazard is a loop that derives a zero wait from a
        // fresh scheduler's "due now". This loop's wait function has
        // no scheduler input — the type is the proof — and a scripted
        // idle minute over synthetic instants, modeled exactly as the
        // loop runs them, shows only tick-shaped blocks: the loop
        // wakes at the deadline, queues its tick, re-anchors, and
        // blocks for the full second again.
        let start = Instant::now();
        let mut now = start;
        let mut next_tick = now + TICK_INTERVAL;
        for wakeups in 0..60 {
            let wait = loop_wait(now, next_tick);
            assert_eq!(
                wait, TICK_INTERVAL,
                "idle wake-up #{wakeups} blocks for exactly one tick"
            );
            now += wait;
            // The loop's deadline check fires at the boundary and
            // re-anchors — the next block is a full second again.
            assert!(now >= next_tick);
            next_tick = now + TICK_INTERVAL;
        }
        // The one zero case: a deadline overrun (an event batch kept
        // the step busy past it) yields one immediate iteration —
        // after which the re-anchor restores tick-shaped blocks; it
        // can never repeat while idle, because the deadline moves
        // with every re-anchor.
        let overrun = start + TICK_INTERVAL * 3 + Duration::from_millis(200);
        let mut next_tick = overrun - Duration::from_millis(200);
        assert_eq!(loop_wait(overrun, next_tick), Duration::ZERO);
        next_tick = overrun + TICK_INTERVAL;
        assert_eq!(loop_wait(overrun, next_tick), TICK_INTERVAL);
    }

    #[test]
    fn the_fault_seam_is_inert_for_garbage_and_armed_only_by_the_exact_values() {
        // Only the two exact values arm the seam; anything else —
        // unset, empty, unknown — is inert. (The environment is not
        // set by the test runner; a leftover value from another test
        // would be one of the two exact words and arm the seam
        // exactly as designed.)
        match std::env::var("OSZA_NETMON_TEST_FAULT").as_deref() {
            Ok("panic") | Ok("error") => {
                // Someone armed the seam globally; the check below
                // still proves the mapping for the exact values.
            }
            _ => assert!(matches!(fault_from_env(), Fault::None)),
        }
        assert!(Fault::None.check().is_ok());
        let error = Fault::Error.check().expect_err("the error fault errors");
        assert!(matches!(error, AssemblyError::ForcedFault { .. }));
    }
}
