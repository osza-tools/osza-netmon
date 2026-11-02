// SPDX-License-Identifier: GPL-3.0-only

//! Ethernet + ARP frame helpers for the netns harness (task T-106).
//!
//! The production codec (`src/discovery/arp/codec.rs`) builds *requests*
//! and *parses* replies; the dev-only responder of this harness needs the
//! other two directions — build *replies* (and deliberately hostile
//! variants) and minimally *parse requests* — so those live here, in test
//! code, without touching `src/` (task card §4).
//!
//! Layout reference: plan Appendix E (42-byte Ethernet+ARP frame; MAC
//! bits: first octet bit 0 = multicast, bit 1 = locally administered).

use std::net::Ipv4Addr;

use osza_netmon::model::MacAddr;

/// Ethernet + ARP header size in bytes (plan Appendix E).
pub const ETH_ARP_LEN: usize = 42;

/// Ethernet header size in bytes.
pub const ETH_LEN: usize = 14;

/// EtherType ARP.
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];

/// One minimally parsed ARP request (what the responder needs to answer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpRequestView {
    /// Ethernet source MAC (the requester — where the reply goes).
    pub requester_mac: MacAddr,
    /// ARP sender IP (the requester's address — the reply's target IP).
    pub requester_ip: Ipv4Addr,
    /// ARP target IP (the address being asked about — who should answer).
    pub target_ip: Ipv4Addr,
}

/// Views a raw frame as an ARP request, if it is one.
///
/// Total and forgiving (AGENTS.md rule 4): anything that is not a full
/// 42-byte Ethernet + well-formed ARP *request* is `None` — the responder
/// logs the frame and moves on; it never panics on hostile or truncated
/// input.
pub fn parse_arp_request(frame: &[u8]) -> Option<ArpRequestView> {
    if frame.len() < ETH_ARP_LEN {
        return None;
    }
    if frame[12..14] != ETHERTYPE_ARP {
        return None;
    }
    // htype 1, ptype 0x0800, hlen 6, plen 4, opcode 1 — a request.
    if frame[14..16] != [0x00, 0x01]
        || frame[16..18] != [0x08, 0x00]
        || frame[18] != 6
        || frame[19] != 4
        || frame[20..22] != [0x00, 0x01]
    {
        return None;
    }
    let requester_mac = MacAddr::from_octets([
        frame[22], frame[23], frame[24], frame[25], frame[26], frame[27],
    ])
    .ok()?;
    let requester_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    let target_ip = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
    Some(ArpRequestView {
        requester_mac,
        requester_ip,
        target_ip,
    })
}

/// The EtherType of a frame, when the Ethernet header is complete.
pub fn ethertype(frame: &[u8]) -> Option<u16> {
    if frame.len() < ETH_LEN {
        return None;
    }
    Some(u16::from_be_bytes([frame[12], frame[13]]))
}

/// The Ethernet source MAC of a frame, when the header is complete.
pub fn eth_src(frame: &[u8]) -> Option<MacAddr> {
    if frame.len() < ETH_LEN {
        return None;
    }
    MacAddr::from_octets([frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]]).ok()
}

/// The Ethernet destination MAC of a frame, when the header is complete.
pub fn eth_dst(frame: &[u8]) -> Option<MacAddr> {
    if frame.len() < ETH_LEN {
        return None;
    }
    MacAddr::from_octets([frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]]).ok()
}

/// Builds a 42-byte ARP *reply* frame: Ethernet `dst → src` plus ARP
/// opcode 2, `sha/spa` = the answering device, `tha/tpa` = the requester
/// (the mirror of plan Appendix E's request layout).
///
/// `sha` is raw octets, NOT a [`MacAddr`]: the model type only
/// constructs valid unicast MACs (T-002 boundary), while the hostile
/// `multicast_mac` mode must deliberately build an invalid sender —
/// the scanner's parser is the authority that rejects it (FR-DS-06).
pub fn build_arp_reply(
    dst: MacAddr,
    sha: [u8; 6],
    spa: Ipv4Addr,
    tha: MacAddr,
    tpa: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_ARP_LEN);
    frame.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&sha);
    frame.extend_from_slice(&ETHERTYPE_ARP);
    frame.extend_from_slice(&[0x00, 0x01]); // htype Ethernet
    frame.extend_from_slice(&[0x08, 0x00]); // ptype IPv4
    frame.push(6); // hlen
    frame.push(4); // plen
    frame.extend_from_slice(&[0x00, 0x02]); // opcode: reply
    frame.extend_from_slice(&sha);
    frame.extend_from_slice(&spa.octets());
    frame.extend_from_slice(&tha.octets());
    frame.extend_from_slice(&tpa.octets());
    frame
}

/// Self-tests of this module (task card §11.4): the harness target has
/// no libtest runner (`harness = false`), so these run as the suite's
/// first scenario — see `main.rs`'s `SCENARIOS` table.
pub mod selftests {
    use super::*;

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    pub fn synthetic_like_macs_are_well_formed() {
        for (host, salt) in [(1u8, 0u8), (2, 0), (251, 3), (42, 9)] {
            let mac = MacAddr::from_octets([0x02, 0x00, 0x00, 0x00, salt, host])
                .unwrap_or_else(|_| panic!("02:… must parse for {host}/{salt}"));
            assert!(mac.is_locally_administered());
            assert!(!mac.is_multicast());
            assert!(!mac.is_broadcast());
            assert!(!mac.is_zero());
        }
    }

    pub fn reply_round_trips_through_the_production_parser() {
        use osza_netmon::discovery::arp::ArpReplyContext;
        use osza_netmon::discovery::arp::parse_arp_reply;
        use osza_netmon::model::ipv4::Ipv4Net;
        use std::collections::HashSet;

        let dst = mac("32:5e:d9:91:36:68"); // the scanner side
        let sha = mac("02:00:00:00:00:0c");
        let spa = "192.0.2.12".parse().unwrap();
        let tpa = "192.0.2.1".parse().unwrap();
        let frame = build_arp_reply(dst, sha.octets(), spa, dst, tpa);
        assert_eq!(frame.len(), 42);

        let scope = Ipv4Net::new("192.0.2.0".parse().unwrap(), 24).unwrap();
        let mut solicited = HashSet::new();
        solicited.insert(spa);
        let ctx = ArpReplyContext::new(dst, tpa, scope, &solicited);
        let reply = parse_arp_reply(&frame, &ctx)
            .unwrap_or_else(|err| panic!("harness reply must parse: {err}"));
        assert_eq!(reply.sender_mac, sha);
        assert_eq!(reply.sender_ip, spa);
    }

    pub fn request_parsing_rejects_non_requests_and_short_frames() {
        let our_mac = mac("32:5e:d9:91:36:68");
        // A reply-shaped frame is not a request.
        let reply = build_arp_reply(
            our_mac,
            mac("02:00:00:00:00:0c").octets(),
            "192.0.2.12".parse().unwrap(),
            our_mac,
            "192.0.2.1".parse().unwrap(),
        );
        assert!(parse_arp_request(&reply).is_none());
        // Short frames are not requests.
        assert!(parse_arp_request(&reply[..20]).is_none());
        // A well-formed request parses.
        let request = osza_netmon::discovery::arp::build_arp_request(
            our_mac,
            "192.0.2.1".parse().unwrap(),
            "192.0.2.12".parse().unwrap(),
        );
        let view = parse_arp_request(&request).unwrap();
        assert_eq!(view.requester_mac, our_mac);
        let target: Ipv4Addr = "192.0.2.12".parse().unwrap();
        assert_eq!(view.target_ip, target);
    }
}
