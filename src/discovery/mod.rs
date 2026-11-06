// SPDX-License-Identifier: GPL-3.0-only

//! Discovery sources (plan §8.1): the kernel neighbor-table reader
//! (T-102), the ARP wire-format codec (T-103), the active ARP sweep
//! with its privilege handling (T-104), and the scheduling and
//! orchestration layer (T-204, plan §13).
//!
//! [`neighbor_table`] implements plan §6.3 FR-DS-01/FR-DS-02 for the
//! `/proc/net/arp` source — the interim ADR-010 path.
//!
//! [`arp`] implements the active half of discovery: the codec
//! (FR-DS-03/FR-DS-06, T-103), the transport boundary, the sweep engine
//! and the worker thread (FR-DS-03…11, ADR-005/009/011/012, T-104).
//! This is the first code that sends packets: every active run happens
//! behind [`privilege`]'s capability model — the socket opens with
//! `CAP_NET_RAW`, capabilities drop, `no_new_privs` is set and verified
//! (SR-06), and an `EPERM` at open time means read-only mode (ADR-005).
//!
//! [`scheduler`] (T-204) is the pure FR-DS-12 state machine that
//! decides *when* cycles run — finish-anchored cadence, failure
//! backoff, auto-stop after three consecutive failures, manual-refresh
//! rules — plus the ADR-011 pass-policy constants.
//!
//! [`worker`] (T-204) is the orchestrator thread that *executes* one
//! discovery cycle per §8.5 (neighbor read → paced ARP sweep → listen
//! window → neighbor read → outcome) through a real
//! [`ArpWorkerHandle`], stamping every event with a `model::ScanId`
//! (FR-DS-08/09/10/11/14).
//!
//! [`privilege`] is the privilege boundary of the whole application:
//! [`open_raw_socket`] and
//! [`drop_capabilities`] (plus the
//! `/proc/thread-self/status` verification parser).
//!
//! Per plan §8.2 this tree imports from `model` (and std) only — never
//! from `registry`, `app` or `ui`; the application core (T-205) maps
//! [`DiscoveryEvent`] and [`CycleEvent`] onto its own `AppEvent`.

pub mod arp;
pub mod neighbor_table;
pub mod privilege;
pub mod scheduler;
pub mod worker;

pub use arp::{
    ARP_FRAME_LEN, ArpReply, ArpReplyContext, ArpReplyCounters, ArpScanner, ArpTransport,
    ArpWorkerHandle, COMMAND_CAPACITY, DEFAULT_LISTEN_WINDOW, DEFAULT_PASS_GAP, DEFAULT_RATE_PPS,
    DEFAULT_RESPONSE_CAP, DiscoveryEvent, EVENT_CAPACITY, InvalidReply, LinuxArpTransport,
    MAX_BATCH_SIZE, MAX_PASSES, MAX_RATE_PPS, Observation, ScanCommand, ScanCounters, ScanOutcome,
    ScanParams, ScanResult, ScanSummary, TransportError, WorkerError, build_arp_request,
    parse_arp_reply,
};
pub use neighbor_table::{
    NeighborEntry, NeighborError, NeighborSource, ProcNeighborTable, filter_neighbors,
    parse_arp_table,
};
pub use privilege::{
    PrivilegeError, RawSocket, StatusParseError, ThreadCapsStatus, ThreadStatusError,
    drop_capabilities, open_raw_socket, parse_thread_status, read_thread_status,
};
pub use scheduler::{
    AUTO_STOP_AFTER_FAILURES, DEFAULT_REDISCOVERY_INTERVAL, DiscoveryScheduler,
    FAILURE_BACKOFF_FLOOR, MIN_REDISCOVERY_INTERVAL, PASSES_INITIAL_AND_MANUAL, PASSES_PERIODIC,
    RediscoveryInterval, SchedulerDecision, SchedulerError, Trigger,
};
pub use worker::{
    CYCLE_COMMAND_CAPACITY, CYCLE_EVENT_CAPACITY, CycleEvent, CycleMode, CycleSummary, Degradation,
    DiscoveryWorker, OrchestratorError, OrchestratorStats, OrchestratorStatsSnapshot,
};
