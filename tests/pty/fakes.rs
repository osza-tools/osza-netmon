// SPDX-License-Identifier: GPL-3.0-only
#![forbid(unsafe_code)]
// A test binary (`harness = false` — the netns target's precedent):
// compiled without `--cfg test`, so the crate-wide clippy denies fire
// on fixture assertions; the relief is scoped to the pty harness
// files exactly as in tests/netns/main.rs.
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

//! The fake-source session (§6's "the T-205 AC-5 fake-source variant
//! under the pty"): the real terminal lifecycle — threads, terminal,
//! loop, teardown — around the real workers over the reviewed fake
//! sources (a synthetic neighbor table and a scripted resolver), the
//! exact shape of T-205's runtime integration test. Spawned by the
//! scenario runner as `tests/pty --fake-session` under `script(1)`.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use osza_netmon::app::AppMode;
use osza_netmon::app::AppState;
use osza_netmon::app::ScopeEntry;
use osza_netmon::app::SessionParams;
use osza_netmon::app::WorkerExecutor;
use osza_netmon::discovery::DiscoveryWorker;
use osza_netmon::discovery::NeighborError;
use osza_netmon::discovery::NeighborSource;
use osza_netmon::discovery::parse_arp_table;
use osza_netmon::discovery::worker::CycleEvent;
use osza_netmon::enrichment::dns::NameResolver;
use osza_netmon::enrichment::dns::ResolveError;
use osza_netmon::enrichment::worker::HostnameWorker;
use osza_netmon::model::Clock;
use osza_netmon::model::FakeClock;
use osza_netmon::model::Hostname;
use osza_netmon::model::Ipv4Net;
use osza_netmon::net::Eligibility;
use osza_netmon::net::InterfaceClass;
use osza_netmon::ui::assembly::AssemblyParams;
use osza_netmon::ui::assembly::run_with;

/// The synthetic scope of the T-205 fixtures: 192.0.2.0/29 over `eth9`.
const SCOPE_NETWORK: (Ipv4Addr, u8) = (Ipv4Addr::new(192, 0, 2, 0), 29);

/// The fake neighbor table (T-205's `FakeNeighbors::with_host(5)`):
/// one complete entry for 192.0.2.5 on eth9, inside the scope.
struct FakeNeighbors {
    table: String,
}

impl NeighborSource for FakeNeighbors {
    fn read_neighbors(
        &self,
        _scope: &Ipv4Net,
        _interface_name: &str,
    ) -> Result<Vec<osza_netmon::discovery::NeighborEntry>, NeighborError> {
        Ok(parse_arp_table(&self.table))
    }
}

/// The scripted resolver (T-205's `FakeResolver`): every query
/// answers one fixed valid name.
struct FakeResolver {
    name: &'static str,
}

impl NameResolver for FakeResolver {
    fn reverse(
        &mut self,
        _ip: Ipv4Addr,
        _timeout: Duration,
    ) -> Result<Option<Hostname>, ResolveError> {
        Ok(Some(
            Hostname::try_from(self.name).expect("a fixed valid name"),
        ))
    }
}

/// Runs the assembled application over the fakes on this process's
/// stdio (the pty). Exits 0 on a clean quit, non-zero on any failure
/// (the assembly restores the terminal on every path).
pub fn run_fake_session() -> Result<(), osza_netmon::ui::assembly::AssemblyError> {
    // A shared frozen clock (the T-203 pattern): the runtime and the
    // hostname worker read the same time.
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FakeClock::new());

    // The real read-only orchestrator over the fake neighbor source,
    // on the scope the state will confirm.
    let scope = Ipv4Net::new(SCOPE_NETWORK.0, SCOPE_NETWORK.1).expect("valid network");
    let table = "IP address HW type Flags HW address Mask Device\n\
                 192.0.2.5 0x1 0x2 02:00:00:00:00:05 * eth9\n"
        .to_owned();
    let (discovery, discovery_events) =
        DiscoveryWorker::spawn_read_only(Box::new(FakeNeighbors { table }), scope, "eth9");

    // The real hostname worker over the fake resolver.
    let hostname = HostnameWorker::spawn(
        Default::default(),
        Some(Box::new(FakeResolver {
            name: "host-five.lan",
        })),
        Arc::clone(&clock),
        Arc::new(AtomicBool::new(false)),
    )
    .expect("spawn succeeds");

    // The state: read-only mode, unacknowledged notice (the smoke
    // drives `y`), the synthetic eligible entry matching the worker's
    // scope — exactly the T-205 ac5 fixture.
    let entry = ScopeEntry {
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
    };
    let params = SessionParams {
        mode: AppMode::ReadOnly {
            reason: "fake-source session (no raw socket)".to_owned(),
        },
        ..SessionParams::default()
    };
    let vendor_db = Arc::new(
        osza_netmon::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
    );
    let state = AppState::with_scope_entries(params, vec![entry], vendor_db, clock.as_ref())
        .expect("defaults are valid");

    let executor = WorkerExecutor::new(discovery, hostname);
    run_with(
        AssemblyParams::default(),
        state,
        executor,
        discovery_events,
        clock,
    )
}

// The CycleEvent import documents the receiver's payload type for
// readers; the function below is the honest no-discovery shape any
// future harness mode would use.
const _: Option<CycleEvent> = None;
