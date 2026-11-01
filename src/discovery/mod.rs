// SPDX-License-Identifier: GPL-3.0-only

//! Discovery sources (plan §8.1): the kernel neighbor-table reader
//! (T-102), the ARP wire-format codec (T-103), and — with T-104 — the
//! privilege boundary of the active discovery path; the scanner and
//! scheduler arrive with their own tasks (T-104, T-204, plan §13).
//!
//! [`neighbor_table`] implements plan §6.3 FR-DS-01/FR-DS-02 for the
//! `/proc/net/arp` source — the interim ADR-010 path.
//!
//! [`arp`] implements plan §6.3 FR-DS-03 (the request builder) and
//! FR-DS-06 (the total solicited-only reply validator) at the byte
//! level; sending and receiving belong to T-104.
//!
//! [`privilege`] is the privilege boundary of the whole application:
//! [`open_raw_socket`] opens the `AF_PACKET` socket (ADR-005 step 2),
//! [`drop_capabilities`] drops every capability and sets
//! `no_new_privs`, verified by reading `/proc/thread-self/status`
//! (SR-06).

pub mod arp;
pub mod neighbor_table;
pub mod privilege;

pub use arp::{
    ARP_FRAME_LEN, ArpReply, ArpReplyContext, ArpReplyCounters, InvalidReply, build_arp_request,
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
