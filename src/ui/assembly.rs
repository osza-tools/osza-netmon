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

use std::collections::HashMap;
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
use crate::app::Effect;
use crate::app::EffectError;
use crate::app::EffectsExecutor;
use crate::app::MAX_WAIT;
use crate::app::Runtime;
use crate::app::SessionParams;
use crate::app::WorkerExecutor;
use crate::app::runtime::TICK_INTERVAL;
use crate::app::{NOTICE_VERSION, WorkerStats};
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
use crate::enrichment::worker::HostnameEvent;
use crate::enrichment::worker::HostnameWorker;
use crate::model::Clock;
use crate::model::Ipv4Net;
use crate::model::SystemClock;
use crate::model::ipv4::ABSOLUTE_MAX_HOSTS;
use crate::model::ipv4::DEFAULT_MAX_HOSTS;
use crate::net::Eligibility;
use crate::net::InterfaceInfo;
use crate::net::derive_scope;
use crate::net::enumerate_interfaces;
use crate::net::suggest_interface;
use crate::ui::ack::AckStore;
use crate::ui::input;
use crate::ui::lifecycle::TerminalGuard;
use crate::ui::render;
use crate::ui::signals;

/// The assembly's tunable parameters (§5.1: the assembly *accepts*
/// parameters and parses nothing — T-402 owns the CLI). Defaults are
/// the plan values: mouse capture on, the default 1,022-host cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyParams {
    /// Whether mouse capture is enabled after init (§8.8; the
    /// `--no-mouse` flag's effect arrives as `false` from T-402).
    pub mouse_enabled: bool,
    /// The active-scan host cap (FR-SC-06; the `--max-hosts` flag's
    /// effect arrives here from T-402). Default
    /// [`DEFAULT_MAX_HOSTS`] (1,022 = /22); the wiring rejects values
    /// above [`ABSOLUTE_MAX_HOSTS`] (65,534) and zero — T-402's
    /// parser re-checks.
    pub max_hosts: u32,
}

impl Default for AssemblyParams {
    fn default() -> Self {
        AssemblyParams {
            mouse_enabled: true,
            max_hosts: DEFAULT_MAX_HOSTS,
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
    /// The wiring's host cap is invalid (FR-SC-06: above the absolute
    /// ceiling, or zero) — refused before anything exists.
    #[error("the host cap {0} is invalid (1..=65,534)")]
    MaxHosts(u32),
    /// The post-confirmation discovery attach failed (E-2c).
    #[error("attaching the confirmed discovery worker failed: {0}")]
    WorkerAttach(String),
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
/// The PQ-3 shape (task T-302 §5.7, normative): one bound raw
/// transport per **eligible** interface opens while privileges are
/// held, capabilities drop **before any thread spawns** (ADR-005 item
/// 3, unchanged), the unconfirmed transports are held unused (no
/// send, no read, no thread) until the scope confirmation, and the
/// confirmed interface's worker is attached post-confirm — the first
/// Initial scan runs on the confirmed interface, never on the
/// suggestion.
///
/// # Errors
/// Any assembly or runtime failure (the terminal is restored before
/// the error leaves this function; assembly failures happen before
/// it exists).
pub fn run(params: AssemblyParams) -> Result<(), AssemblyError> {
    // 0. The wiring's own validation (FR-SC-06): the ceiling and the
    //    floor. T-402's parser re-checks.
    if params.max_hosts == 0 || params.max_hosts > ABSOLUTE_MAX_HOSTS {
        return Err(AssemblyError::MaxHosts(params.max_hosts));
    }
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock);

    // 1. The interface facts (§5.6) and the startup selection.
    let interfaces = enumerate_interfaces();
    let suggested = suggest_interface(&interfaces);

    // 2. The session facts the app core cannot know (§5.4: the
    //    construction-time messages are its; the facts are ours): the
    //    root check, the notice acknowledgment (ADR-004/013 — the
    //    first-run-or-version-change rule, O-6 resolved) and the cap.
    let mut session = SessionParams {
        started_as_root: running_as_root(),
        max_hosts: params.max_hosts,
        ..SessionParams::default()
    };
    let ack_store = AckStore::from_env();
    session.notice_acknowledged = ack_store
        .as_ref()
        .is_some_and(|store| store.acknowledges(NOTICE_VERSION));

    // 3. The PQ-3 privilege order (§5.7.1): one bound raw transport
    //    per eligible interface while privileges are held, then the
    //    single capability drop — idempotent, and before any thread
    //    spawns (the workers below spawn after it). Read-only mode
    //    (FR-DS-14) when the privileges are missing or no eligible
    //    interface reports a usable identity.
    let (pending, read_only_reason) = open_pending_discoveries(&interfaces)?;
    drop_capabilities().map_err(|error| AssemblyError::PrivilegeDrop(error.to_string()))?;
    if let Some(reason) = read_only_reason {
        session.mode = AppMode::ReadOnly { reason };
    }

    // 4. The resolver selection (ADR-003) over the suggested
    //    interface's scope, and the hostname worker. The stop flag is
    //    one `Arc` shared by the worker and its resolver (a pending
    //    socket wait is interrupted on shutdown — the T-203
    //    construction contract).
    //
    //    Known residual divergence (report §6): the resolver is
    //    selected at startup over the *suggested* scope — the frozen
    //    T-203/T-205 worker shape fixes it there; confirming a
    //    different interface may leave the resolver outside the
    //    confirmed subnet.
    let startup_scope = suggested.and_then(derive_scope);
    let hostname_stop = Arc::new(AtomicBool::new(false));
    let (resolver, resolver_selected) = match startup_scope {
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

    // 5. The dormant read-only placeholder worker (the T-301 no-
    //    eligible handle shape, now uniform): an honest idle event
    //    source over the real neighbor table filtered by a name that
    //    matches nothing, over the reserved scope 0.0.0.0/0 — it is
    //    never commanded (the detached runtime's polls stay
    //    suppressed) and is replaced at the confirmation.
    let dormant_scope = Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0)
        .map_err(|error| AssemblyError::Scope(error.to_string()))?;
    let (dormant, dormant_events) = DiscoveryWorker::spawn_read_only(
        Box::new(ProcNeighborTable::new()),
        dormant_scope,
        String::new(),
    );

    // 6. The state (§5.6: `AppState::new`, the reviewed construction
    //    API), the executor (the worker pair plus the ack store —
    //    E-2a's file I/O lives here, never in `src/app/`), and the
    //    **detached** runtime (E-2c: the placeholder worker holds the
    //    discovery seat until the confirmation's attach).
    let vendor_db =
        Arc::new(VendorDb::embedded().map_err(|error| AssemblyError::VendorDb(error.to_string()))?);
    let state = AppState::new(session, interfaces, vendor_db, clock.as_ref())?;
    let executor = AssembledExecutor::new(WorkerExecutor::new(dormant, hostname), ack_store);
    let (runtime, sender) = Runtime::new_detached(state, executor, dormant_events, clock);

    lifecycle(params, runtime, sender, pending)
}

/// Opens one bound raw transport per **eligible** interface while
/// privileges are held (PQ-3 §5.7.1) and returns the pending map plus
/// the session-wide read-only reason, when the session cannot run any
/// active discovery:
///
/// * an eligible interface with a socket **and** a valid MAC and IPv4
///   address becomes an *active* pending session — the transport is
///   held unused (no send, no read, no thread) until the
///   confirmation;
/// * an eligible interface without a valid MAC (no identity,
///   ADR-008) becomes a *read-only* pending session — its socket is
///   dropped unused, no packet is ever sent (the T-301 decision);
/// * an `EPERM` on any open makes the whole session read-only
///   (FR-DS-14): every opened transport closes and every eligible
///   interface becomes a read-only pending session;
/// * any other open failure fails closed before the terminal exists
///   (a vanished interface, a kernel refusal).
///
/// # Errors
/// A non-privilege socket failure, verbatim.
fn open_pending_discoveries(
    interfaces: &[InterfaceInfo],
) -> Result<(PendingDiscovery, Option<String>), AssemblyError> {
    let mut pending = PendingDiscovery::new();
    let mut eperm = false;
    let mut identity_less = false;
    for interface in interfaces {
        if interface.eligibility() != Eligibility::Eligible {
            continue;
        }
        // An eligible interface always carries an IPv4 address
        // (FR-SC-03); the honest refusal arm stays total regardless.
        let Some(scope) = derive_scope(interface) else {
            continue;
        };
        let name = interface.name().to_owned();
        if eperm {
            // The session is already read-only: no more opens.
            pending.insert_read_only(name, scope);
            continue;
        }
        match open_raw_socket(&name) {
            Ok(socket) => match interface.mac().zip(interface.ipv4()) {
                Some((mac, ip)) => {
                    // The transport is constructed (the socket bound
                    // at open) and held unused — the scanner and its
                    // thread exist only at the attach.
                    let transport = LinuxArpTransport::new(socket);
                    pending.insert_active(name, scope, mac, ip, transport);
                }
                None => {
                    // No identity to announce: the socket drops
                    // unused; read-only pending session.
                    identity_less = true;
                    pending.insert_read_only(name, scope);
                }
            },
            Err(PrivilegeError::PermissionDenied) => {
                // FR-DS-14: the session is read-only. Close every
                // transport opened so far (ours, unused) and restart
                // the map in read-only mode.
                eperm = true;
                pending = PendingDiscovery::new();
                for iface in interfaces {
                    if iface.eligibility() == Eligibility::Eligible
                        && let Some(scope) = derive_scope(iface)
                    {
                        pending.insert_read_only(iface.name().to_owned(), scope);
                    }
                }
                pending.insert_read_only(name, scope);
            }
            Err(error) => return Err(AssemblyError::SocketOpen(error.to_string())),
        }
    }
    let reason = if eperm {
        Some("no CAP_NET_RAW: read-only mode (neighbor table only)".to_owned())
    } else if identity_less && pending.is_all_read_only() {
        Some("the interface reports no valid hardware address".to_owned())
    } else {
        None
    };
    Ok((pending, reason))
}

/// How to build one interface's discovery worker at the confirmation
/// (PQ-3 §5.7.2): the active spawner holds the interface's raw
/// transport (opened under privileges, unused until now); the
/// read-only spawner needs no privilege — the neighbor-table read
/// binds late and free (§5.7.4).
type DiscoverySpawner = Box<dyn FnOnce() -> (DiscoveryWorker, Receiver<CycleEvent>) + Send>;

/// The per-eligible-interface pending sessions (PQ-3 §5.7.2): held
/// unused until the scope confirmation, when the confirmed interface
/// is built and every other entry closes
/// ([`PendingDiscovery::close_rest`]).
pub struct PendingDiscovery {
    spawners: HashMap<String, PendingEntry>,
}

struct PendingEntry {
    active: Option<DiscoverySpawner>,
    read_only: DiscoverySpawner,
}

impl PendingDiscovery {
    /// An empty map (no eligible interfaces).
    pub fn new() -> Self {
        PendingDiscovery {
            spawners: HashMap::new(),
        }
    }

    /// One active-capable pending session: the transport moves into
    /// the spawner and exists nowhere else until the attach.
    pub fn insert_active(
        &mut self,
        name: String,
        scope: Ipv4Net,
        mac: crate::model::MacAddr,
        ip: Ipv4Addr,
        transport: LinuxArpTransport,
    ) {
        let key = name.clone();
        let read_only =
            make_read_only_spawner(scope, name.clone(), Box::new(ProcNeighborTable::new()));
        let active: DiscoverySpawner = Box::new(move || {
            let scanner = ArpScanner::new(Box::new(transport), scope, mac, ip);
            let (arp, arp_events) = ArpWorkerHandle::spawn(scanner);
            DiscoveryWorker::spawn_active(
                arp,
                arp_events,
                Box::new(ProcNeighborTable::new()),
                scope,
                name,
            )
        });
        self.spawners.insert(
            key,
            PendingEntry {
                active: Some(active),
                read_only,
            },
        );
    }

    /// One read-only pending session (no socket, no identity needed).
    pub fn insert_read_only(&mut self, name: String, scope: Ipv4Net) {
        let spawner =
            make_read_only_spawner(scope, name.clone(), Box::new(ProcNeighborTable::new()));
        self.spawners.insert(
            name,
            PendingEntry {
                active: None,
                read_only: spawner,
            },
        );
    }

    /// A read-only spawner over the caller's neighbor source (the
    /// injection seam's fake sessions).
    pub fn insert_read_only_with(
        &mut self,
        name: String,
        scope: Ipv4Net,
        neighbors: Box<dyn crate::discovery::NeighborSource + Send>,
    ) {
        let spawner = make_read_only_spawner(scope, name.clone(), neighbors);
        self.spawners.insert(
            name,
            PendingEntry {
                active: None,
                read_only: spawner,
            },
        );
    }

    /// Whether any pending session exists.
    pub fn is_empty(&self) -> bool {
        self.spawners.is_empty()
    }

    /// Whether every pending session is read-only (the session-wide
    /// mode decision).
    pub fn is_all_read_only(&self) -> bool {
        self.spawners.values().all(|entry| entry.active.is_none())
    }

    /// Builds the named interface's worker at the confirmation
    /// (§5.7.2/3): the active spawner when the confirmation is active
    /// and one exists, else the read-only one. The entry is consumed
    /// (removed) — one attach per interface.
    pub fn build(
        &mut self,
        name: &str,
        active: bool,
    ) -> Option<(DiscoveryWorker, Receiver<CycleEvent>)> {
        let entry = self.spawners.remove(name)?;
        let read_only = entry.read_only;
        // The active spawner only exists for active-capable entries;
        // an active request on a read-only entry (or vice versa) uses
        // what exists — the honest per-interface capability.
        let spawner = if active {
            entry.active.unwrap_or(read_only)
        } else {
            read_only
        };
        Some(spawner())
    }

    /// Closes every remaining pending session (§5.7.2: "close all
    /// others") — the held transports drop, their sockets close.
    pub fn close_rest(&mut self) {
        self.spawners.clear();
    }
}

impl Default for PendingDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a read-only spawner over the given neighbor source and
/// scope (the name is the interface's — the neighbor filter keys on
/// it, FR-DS-02).
fn make_read_only_spawner(
    scope: Ipv4Net,
    name: String,
    neighbors: Box<dyn crate::discovery::NeighborSource + Send>,
) -> DiscoverySpawner {
    Box::new(move || DiscoveryWorker::spawn_read_only(neighbors, scope, name))
}

/// The production effects executor (the wiring's interceptor): the
/// worker pair plus the notice-ack store. The E-2a persistence lives
/// here — the file I/O never enters `src/app/` (§8.2) — and a write
/// failure is non-fatal by ADR-004 ("asks again next run"): the
/// effect succeeds, the session continues unchanged.
pub struct AssembledExecutor {
    workers: WorkerExecutor,
    ack: Option<AckStore>,
}

impl AssembledExecutor {
    /// Wraps the worker pair; `ack` is `None` only when no honest
    /// location exists (no `XDG_CONFIG_HOME`, no `HOME`) — reads are
    /// unacknowledged and writes are skipped, non-fatal.
    pub fn new(workers: WorkerExecutor, ack: Option<AckStore>) -> Self {
        AssembledExecutor { workers, ack }
    }
}

impl EffectsExecutor for AssembledExecutor {
    fn execute(&mut self, effect: Effect) -> Result<(), EffectError> {
        if let Effect::PersistNoticeAck { version } = effect {
            // ADR-004: non-fatal — the honest consequence of a failed
            // write is asking again next run.
            if let Some(store) = &self.ack {
                let _ = store.write(version);
            }
            return Ok(());
        }
        self.workers.execute(effect)
    }

    fn attach_discovery(
        &mut self,
        worker: crate::discovery::worker::DiscoveryWorker,
    ) -> Result<(), EffectError> {
        self.workers.attach_discovery(worker)
    }

    fn worker_stats(&self) -> WorkerStats {
        self.workers.worker_stats()
    }

    fn hostname_events(&self) -> Option<&Receiver<HostnameEvent>> {
        self.workers.hostname_events()
    }

    fn shutdown(&mut self) {
        self.workers.shutdown();
    }
}

/// The injection seam: a pre-built app on the real terminal lifecycle
/// (the pty harness's fake-source variant, §6) — the same PQ-3
/// attach machinery as the real assembly: the placeholder worker is
/// detached and the pending map's confirmed interface attaches
/// post-confirmation.
///
/// # Errors
/// Any lifecycle failure (the terminal is restored before the error
/// leaves this function).
pub fn run_with(
    params: AssemblyParams,
    state: AppState,
    executor: AssembledExecutor,
    placeholder_events: Receiver<CycleEvent>,
    pending: PendingDiscovery,
    clock: Arc<dyn Clock + Send + Sync>,
) -> Result<(), AssemblyError> {
    let (runtime, sender) = Runtime::new_detached(state, executor, placeholder_events, clock);
    lifecycle(params, runtime, sender, pending)
}

/// The terminal lifecycle around one runtime (module docs): threads,
/// terminal, loop, teardown — with `Drop` safety nets so a panic runs
/// the same bounded shutdown.
fn lifecycle(
    params: AssemblyParams,
    mut runtime: Runtime<AssembledExecutor>,
    sender: AppEventSender,
    pending: PendingDiscovery,
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
    let result = run_loop(&mut runtime, &sender, guard.terminal(), pending);

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

/// The loop body (module docs for the sequence), including the PQ-3
/// attach step (§5.7.2/3): right after a step that confirmed a scope,
/// the confirmed interface's worker is built from the pending map and
/// attached (E-2c) — before the next step's scheduler poll issues the
/// first Initial scan, which therefore runs on the confirmed
/// interface. Every other pending session closes at the same moment
/// ("close all others"); a missing map entry (structurally impossible
/// in the real assembly — every eligible interface has one) falls
/// back to an honest read-only worker over the confirmed facts.
fn run_loop(
    runtime: &mut Runtime<AssembledExecutor>,
    sender: &AppEventSender,
    terminal: &mut ratatui::DefaultTerminal,
    mut pending: PendingDiscovery,
) -> Result<(), AssemblyError> {
    let mut next_tick = Instant::now() + TICK_INTERVAL;
    let mut attached = false;
    loop {
        let wait = loop_wait(Instant::now(), next_tick);
        runtime.step(wait);
        // The PQ-3 attach (E-2c): once, on the first step that leaves
        // a confirmed scope behind.
        if !attached && let Some(confirmed) = runtime.state().confirmed_scope() {
            let (worker, events) = pending
                .build(&confirmed.iface_name, confirmed.discovery_active)
                .unwrap_or_else(|| {
                    // The total fallback: a read-only worker over the
                    // confirmed facts (the neighbor read needs no
                    // privilege — §5.7.4).
                    DiscoveryWorker::spawn_read_only(
                        Box::new(ProcNeighborTable::new()),
                        confirmed.scope,
                        confirmed.iface_name.clone(),
                    )
                });
            runtime
                .attach_discovery(worker, events)
                .map_err(|error| AssemblyError::WorkerAttach(error.to_string()))?;
            attached = true;
            pending.close_rest();
        }
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
            render::draw(terminal, runtime.state())?;
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
