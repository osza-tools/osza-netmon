// SPDX-License-Identifier: GPL-3.0-only

//! The ARP wire format (plan §8.1 `discovery/arp/`; task T-103).
//!
//! [`codec`] is the whole of T-103: the 42-byte Ethernet+ARP request
//! builder (FR-DS-03) and the total, solicited-only reply validator
//! (FR-DS-06) with its rejection counters. The scanner that will send
//! the requests and receive the replies is `discovery::arp::scanner`,
//! T-104's deliverable — the codec here is deliberately
//! transport-agnostic because ADR-009 (discovery transport library) is
//! Pending until the T-105 PoC report.
//!
//! Nothing in this module opens a socket or sends a packet (plan §2.3);
//! it is pure byte assembly and validation, and it depends only on
//! `model` (§8.2).

pub mod codec;

pub use codec::{
    ARP_FRAME_LEN, ArpReply, ArpReplyContext, ArpReplyCounters, InvalidReply, build_arp_request,
    parse_arp_reply,
};
