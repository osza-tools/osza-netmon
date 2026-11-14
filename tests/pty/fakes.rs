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
//! under the pty", reworked for T-302): the real terminal lifecycle —
//! threads, terminal, loop, teardown — around the **same PQ-3 attach
//! machinery as the real assembly** ([`run_with`]), with two synthetic
//! interfaces whose discovery workers are fake read-only ones:
//!
//! * `eth9` — 192.0.2.1/29 (the RFC 5737 documentation range, a
//!   public network, so confirms walk the FR-SC-07 typed-`yes`
//!   dialog), the *suggested* row, whose fake neighbor table holds
//!   **three** hosts;
//! * `wlan9` — 198.51.100.129/25, the second eligible row, whose fake
//!   neighbor table holds **one** host.
//!
//! The pty flow scenario confirms the **non-suggested** `wlan9` and
//! asserts the exact device count (the local device plus wlan9's one
//! neighbor = 2; a scan on the wrong interface would show 4, a
//! missing attach 1) — the PQ-3 attach decided through the real loop.
//!
//! The session also carries the real notice-ack wiring: the store is
//! read at startup (the harness isolates `XDG_CONFIG_HOME` per
//! scenario) and the E-2a effect writes through the assembled
//! executor.

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
use osza_netmon::enrichment::dns::NameResolver;
use osza_netmon::enrichment::dns::ResolveError;
use osza_netmon::enrichment::worker::HostnameWorker;
use osza_netmon::model::Clock;
use osza_netmon::model::FakeClock;
use osza_netmon::model::Hostname;
use osza_netmon::model::Ipv4Net;
use osza_netmon::net::Eligibility;
use osza_netmon::net::InterfaceClass;
use osza_netmon::net::LinkType;
use osza_netmon::ui::ack::AckStore;
use osza_netmon::ui::assembly::AssembledExecutor;
use osza_netmon::ui::assembly::AssemblyParams;
use osza_netmon::ui::assembly::PendingDiscovery;
use osza_netmon::ui::assembly::run_with;

/// The fake neighbor table: one fixed `/proc/net/arp` image.
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

/// One synthetic interface of the fake session.
fn entry(name: &str, index: u32, mac: &str, ipv4: (Ipv4Addr, u8)) -> ScopeEntry {
    ScopeEntry {
        name: name.to_owned(),
        index,
        mac: Some(mac.parse().expect("valid MAC")),
        ipv4: Some(ipv4),
        is_up: true,
        is_running: true,
        is_loopback: false,
        link_type: LinkType::Ethernet,
        class: InterfaceClass::Physical,
        eligibility: Eligibility::Eligible,
        default_gateway: None,
    }
}

/// A three-host neighbor table for `eth9`'s 192.0.2.0/29 scope
/// (hosts .2–.4; the own address is .1).
fn eth9_table() -> String {
    let header = "IP address HW type Flags HW address Mask Device\n";
    let rows = [
        ("192.0.2.2", "02:00:00:00:00:02"),
        ("192.0.2.3", "02:00:00:00:00:03"),
        ("192.0.2.4", "02:00:00:00:00:04"),
    ];
    let mut table = String::from(header);
    for (ip, mac) in rows {
        table.push_str(&format!("{ip} 0x1 0x2 {mac} * eth9\n"));
    }
    table
}

/// A one-host neighbor table for `wlan9`'s 198.51.100.128/25 scope.
fn wlan9_table() -> String {
    "IP address HW type Flags HW address Mask Device\n\
     198.51.100.130 0x1 0x2 02:00:00:00:01:30 * wlan9\n"
        .to_owned()
}

/// Runs the assembled fake session on this process's stdio (the pty).
/// Exits 0 on a clean quit, non-zero on any failure (the assembly
/// restores the terminal on every path).
pub fn run_fake_session() -> Result<(), osza_netmon::ui::assembly::AssemblyError> {
    // A shared frozen clock (the T-203 pattern): the runtime and the
    // hostname worker read the same time.
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FakeClock::new());

    // The notice-ack wiring (the harness isolates XDG_CONFIG_HOME per
    // scenario): the first-run-or-version-change rule (O-6).
    let ack_store = AckStore::from_env();
    let notice_acknowledged = ack_store
        .as_ref()
        .is_some_and(|store| store.acknowledges(osza_netmon::app::NOTICE_VERSION));

    // The two synthetic interfaces (eth9 is the suggested row — the
    // first eligible entry; wlan9 the non-suggested one).
    let entries = vec![
        entry(
            "eth9",
            2,
            "aa:bb:cc:dd:ee:01",
            (Ipv4Addr::new(192, 0, 2, 1), 29),
        ),
        entry(
            "wlan9",
            3,
            "aa:bb:cc:dd:ee:02",
            (Ipv4Addr::new(198, 51, 100, 129), 25),
        ),
    ];
    let eth9_scope =
        Ipv4Net::new(Ipv4Addr::new(192, 0, 2, 0), 29).expect("the eth9 scope is valid");
    let wlan9_scope =
        Ipv4Net::new(Ipv4Addr::new(198, 51, 100, 128), 25).expect("the wlan9 scope is valid");

    // The PQ-3 pending map, fakes edition: one read-only spawner per
    // interface over its own fake neighbor table (no raw sockets in
    // the fake session).
    let mut pending = PendingDiscovery::new();
    pending.insert_read_only_with(
        "eth9".to_owned(),
        eth9_scope,
        Box::new(FakeNeighbors {
            table: eth9_table(),
        }),
    );
    pending.insert_read_only_with(
        "wlan9".to_owned(),
        wlan9_scope,
        Box::new(FakeNeighbors {
            table: wlan9_table(),
        }),
    );

    // The dormant read-only placeholder (the real assembly's shape).
    let dormant_scope =
        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("the reserved scope is valid");
    let (dormant, placeholder_events) = DiscoveryWorker::spawn_read_only(
        Box::new(osza_netmon::discovery::ProcNeighborTable::new()),
        dormant_scope,
        String::new(),
    );

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

    // The state: read-only mode, the notice per the stored ack, the
    // two-entry scope list.
    let params = SessionParams {
        mode: AppMode::ReadOnly {
            reason: "fake-source session (no raw socket)".to_owned(),
        },
        notice_acknowledged,
        ..SessionParams::default()
    };
    let vendor_db = Arc::new(
        osza_netmon::enrichment::vendor::VendorDb::embedded().expect("committed database is valid"),
    );
    let state = AppState::with_scope_entries(params, entries, vendor_db, clock.as_ref())
        .expect("defaults are valid");

    let executor = AssembledExecutor::new(WorkerExecutor::new(dormant, hostname), ack_store);
    run_with(
        AssemblyParams::default(),
        state,
        executor,
        placeholder_events,
        pending,
        clock,
    )
}
