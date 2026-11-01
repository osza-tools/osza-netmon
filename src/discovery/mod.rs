// SPDX-License-Identifier: GPL-3.0-only

//! Discovery sources (plan §8.1): the kernel neighbor-table reader
//! (T-102) and the ARP wire-format codec (T-103) now; the active
//! scanner and scheduler arrive with their own tasks (T-104, plan
//! §13).
//!
//! [`neighbor_table`] implements plan §6.3 FR-DS-01 (the neighbor-table
//! read at the start and end of every scan cycle) and FR-DS-02 (the
//! entry filters) for the `/proc/net/arp` source — the interim ADR-010
//! path; a possible netlink source is T-105's decision. Nothing in this
//! module opens a socket or sends a packet (plan §2.3): reading the
//! neighbor table is a bounded file read, and the first active-network
//! code belongs to T-104.
//!
//! [`arp`] implements plan §6.3 FR-DS-03 (the request builder) and
//! FR-DS-06 (the total solicited-only reply validator, with rejection
//! counters) at the byte level, transport-agnostic per the pending
//! ADR-009; sending and receiving belong to T-104. Nothing there opens
//! a socket either.

pub mod arp;
pub mod neighbor_table;

pub use arp::{
    ARP_FRAME_LEN, ArpReply, ArpReplyContext, ArpReplyCounters, InvalidReply, build_arp_request,
    parse_arp_reply,
};
pub use neighbor_table::{
    NeighborEntry, NeighborError, NeighborSource, ProcNeighborTable, filter_neighbors,
    parse_arp_table,
};
