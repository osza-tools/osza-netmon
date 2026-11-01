// SPDX-License-Identifier: GPL-3.0-only

//! Discovery sources (plan §8.1): the kernel neighbor-table reader now
//! (T-102); the ARP codec, active scanner and scheduler arrive with
//! their own tasks (T-103/T-104, plan §13).
//!
//! [`neighbor_table`] implements plan §6.3 FR-DS-01 (the neighbor-table
//! read at the start and end of every scan cycle) and FR-DS-02 (the
//! entry filters) for the `/proc/net/arp` source — the interim ADR-010
//! path; a possible netlink source is T-105's decision. Nothing in this
//! module opens a socket or sends a packet (plan §2.3): reading the
//! neighbor table is a bounded file read, and the first active-network
//! code belongs to T-104.

pub mod neighbor_table;

pub use neighbor_table::{
    NeighborEntry, NeighborError, NeighborSource, ProcNeighborTable, filter_neighbors,
    parse_arp_table,
};
