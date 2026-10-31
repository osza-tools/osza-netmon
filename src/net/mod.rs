// SPDX-License-Identifier: GPL-3.0-only

//! Network-side layers (plan §8.1): interface discovery and scope
//! derivation now; the neighbor-table reader (T-102) and the ARP codec
//! (T-103) arrive with their own tasks.
//!
//! [`interfaces`] implements plan §6.2 FR-SC-01…05 for task T-101: the
//! interface inventory, eligibility with reasons, the FR-SC-02 ranking
//! and suggestion, the total `/proc/net/route` parser for the default
//! gateway, and scope derivation from the selected interface's own IPv4
//! network. The data-source decision behind the inventory is ADR-017
//! (`getifaddrs(3)` via the `nix` safe wrapper).
//!
//! Nothing in this module opens a socket or sends a packet (plan §2.3);
//! the first active-network code lands with T-104.

pub mod interfaces;

pub use interfaces::{
    Eligibility, IneligibleReason, InterfaceClass, InterfaceInfo, LinkType, RouteEntry,
    derive_scope, enumerate_interfaces, find_default_gateway, parse_routes, suggest_interface,
};
