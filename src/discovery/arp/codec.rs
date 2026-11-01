// SPDX-License-Identifier: GPL-3.0-only

//! ARP wire-format codec: the request builder and the total reply
//! validator (plan §6.3 FR-DS-03/FR-DS-06, §7.2 SR-02/SR-05, Appendix
//! E; task T-103).
//!
//! This is the byte layer of active discovery. [`build_arp_request`]
//! produces the 42-byte Ethernet+ARP frame that T-104's scanner will
//! send (FR-DS-03: sender MAC/IP are the interface's own, the target IP
//! is the probed address, layout per Appendix E), and [`parse_arp_reply`]
//! validates a received frame against **all** FR-DS-06 conditions
//! before it may become an observation. The codec is transport-agnostic
//! (ADR-009 stays Pending until T-105): it moves and checks bytes only;
//! sockets, pacing, privileges and orchestration belong to T-104, and
//! nothing here opens a socket or sends a packet (plan §2.3).
//!
//! Frame layout (Appendix E; ARP over Ethernet, all fields big-endian):
//!
//! ```text
//! offset  size  field          request (builder)      reply (validator)
//! ------  ----  -------------  ---------------------  -------------------------------
//! 0       6     Ethernet dst   ff:ff:ff:ff:ff:ff      our MAC          (condition 7)
//! 6       6     Ethernet src   our MAC                = ARP sender MAC (condition 8)
//! 12      2     EtherType      0x0806 (ARP)           0x0806           (condition 1)
//! 14      2     hardware type  1 (Ethernet)           1                (condition 2)
//! 16      2     protocol type  0x0800 (IPv4)          0x0800           (condition 3)
//! 18      1     hardware len   6                      6                (condition 4)
//! 19      1     protocol len   4                      4                (condition 5)
//! 20      2     opcode         1 (request)            2 (reply)        (condition 6)
//! 22      6     sender MAC     our MAC                valid unicast    (condition 9)
//! 28      4     sender IP      our IPv4               usable + solicited(conditions 10–12)
//! 32      6     target MAC     00:00:00:00:00:00      — (not validated)
//! 38      4     target IP      the probed IPv4        — (not validated)
//! ```
//!
//! Totality (SR-02): [`parse_arp_reply`] accepts any `&[u8]` and maps
//! every input to `Ok(ArpReply)` or `Err(InvalidReply)` — no panic
//! reachable from external data, no `unwrap`/`expect`, no indexing (the
//! denied clippy lints enforce it mechanically; the property tests and
//! the `fuzz/arp_frame.rs` target re-prove it on hostile input). A
//! frame shorter than 42 bytes is [`InvalidReply::Truncated`]; bytes
//! past 42 are Ethernet minimum-frame padding (a real 28-byte ARP
//! reply arrives padded to 60 bytes) and are ignored — only the first
//! 42 bytes are interpreted.
//!
//! Solicited-only (the last FR-DS-06 clause): the set of addresses
//! actually requested in the current scan is an explicit parameter of
//! the validator ([`ArpReplyContext`]); a reply for any other address —
//! however well-formed — is [`InvalidReply::NotSolicited`]. This is the
//! anti-forgery posture of plan §7.1 ("hostile LAN host floods or
//! forges ARP replies"): the registry never sees an unsolicited reply.
//!
//! Counters (FR-DS-06 "dropped and counted"): [`ArpReplyCounters`]
//! tallies accepted and rejected replies by reason. They are
//! informational — for the Details→debug view of T-204 — and recording
//! never changes an outcome: the parser still returns `Err` for every
//! invalid reply, counted or not.
//!
//! Per §8.2 this module depends only on `model` (and `std`): the
//! interface's own MAC and IPv4 address arrive as plain parameters, not
//! as a `net::interfaces::InterfaceInfo` value, so the `discovery` →
//! `model` dependency rule stays green.

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;

use crate::model::ipv4::Ipv4Net;
use crate::model::mac::{MacAddr, MacAddrParseError};

// ---------------------------------------------------------------------------
// Wire constants (Appendix E)
// ---------------------------------------------------------------------------

/// Total length of an Ethernet+ARP frame: a 14-byte Ethernet header
/// plus a 28-byte ARP payload (FR-DS-03; task card R3).
pub const ARP_FRAME_LEN: usize = 42;

/// Ethernet EtherType for ARP (RFC 7042 §2.2.4).
const ETHERTYPE_ARP: u16 = 0x0806;

/// Ethernet EtherType for IPv4 — the same value the ARP protocol type
/// field uses for IPv4 addresses.
const ETHERTYPE_IPV4: u16 = 0x0800;

/// ARP hardware type "Ethernet" (RFC 826).
const ARP_HTYPE_ETHERNET: u16 = 1;

/// ARP protocol type for IPv4 (`0x0800`, the IPv4 EtherType).
const ARP_PTYPE_IPV4: u16 = ETHERTYPE_IPV4;

/// ARP hardware address length for Ethernet MACs, in octets.
const ARP_HLEN_ETHERNET: u8 = 6;

/// ARP protocol address length for IPv4, in octets.
const ARP_PLEN_IPV4: u8 = 4;

/// ARP opcode "request" (RFC 826).
const ARP_OP_REQUEST: u16 = 1;

/// ARP opcode "reply" (RFC 826).
const ARP_OP_REPLY: u16 = 2;

/// The Ethernet broadcast destination of every ARP request.
const ETHERNET_BROADCAST: [u8; 6] = [0xff; 6];

/// The conventional ignored target MAC of an ARP request (Appendix E:
/// "target MAC zero").
const ARP_TARGET_UNKNOWN: [u8; 6] = [0x00; 6];

// Field offsets inside the 42-byte frame (the doc table above is the
// readable version; these are the machine ones).
const ETH_DST: usize = 0;
const ETH_SRC: usize = 6;
const ETH_ETHERTYPE: usize = 12;
const ARP_HTYPE: usize = 14;
const ARP_PTYPE: usize = 16;
const ARP_HLEN: usize = 18;
const ARP_PLEN: usize = 19;
const ARP_OP: usize = 20;
const ARP_SHA: usize = 22;
const ARP_SPA: usize = 28;

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// One accepted ARP reply, already reduced to the FR-DS-06 output
/// contract.
///
/// Both fields are public because the value is plain validated data:
/// `sender_mac` is a [`MacAddr`], so it is always a valid unicast
/// sender address, and `sender_ip` has passed every scope, usability
/// and solicited-only check. In practice the type is produced by
/// [`parse_arp_reply`]; wrapping it into
/// `Field::Known { source: Source::ArpReply, .. }` observations is
/// T-201's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArpReply {
    /// The validated ARP sender hardware address; always a valid
    /// unicast MAC (the T-002 boundary constructor made it).
    pub sender_mac: MacAddr,
    /// The ARP sender IPv4 address; inside the scan scope, a usable
    /// host address, and one this scan actually requested.
    pub sender_ip: Ipv4Addr,
}

// ---------------------------------------------------------------------------
// Error type (every FR-DS-06 failure is its own variant — task card R4)
// ---------------------------------------------------------------------------

/// Why a frame is not a valid solicited ARP reply (FR-DS-06; task card
/// R2/R4).
///
/// One variant per failure reason, in the order the conditions appear
/// in FR-DS-06, so the first failing condition is the reported one.
/// Every variant that names a field value carries it as `found`, the
/// same convention as the model's parse errors; the counters key on
/// the variant, which is what the Details→debug view shows (FR-DS-06
/// "dropped and counted").
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidReply {
    /// The frame is shorter than the fixed 42-byte Ethernet+ARP header.
    /// Not one of the twelve FR-DS-06 conditions — it is the totality
    /// precondition that makes the other twelve checkable (SR-02).
    #[error("frame is too short for an Ethernet+ARP header: need {needed} bytes, found {found}")]
    Truncated {
        /// The fixed header length that was needed (42).
        needed: usize,
        /// The rejected frame's length.
        found: usize,
    },
    /// FR-DS-06 condition 1: the Ethernet EtherType is not ARP.
    #[error("Ethernet EtherType is not ARP (0x0806): found 0x{found:04x}")]
    WrongEtherType {
        /// The EtherType that was found.
        found: u16,
    },
    /// FR-DS-06 condition 2: the ARP hardware type is not Ethernet.
    #[error("ARP hardware type is not Ethernet (1): found {found}")]
    WrongHardwareType {
        /// The hardware type that was found.
        found: u16,
    },
    /// FR-DS-06 condition 3: the ARP protocol type is not IPv4.
    #[error("ARP protocol type is not IPv4 (0x0800): found 0x{found:04x}")]
    WrongProtocolType {
        /// The protocol type that was found.
        found: u16,
    },
    /// FR-DS-06 condition 4: the hardware address length is not 6.
    #[error("ARP hardware address length is not 6: found {found}")]
    WrongHardwareLength {
        /// The hardware address length that was found.
        found: u8,
    },
    /// FR-DS-06 condition 5: the protocol address length is not 4.
    #[error("ARP protocol address length is not 4: found {found}")]
    WrongProtocolLength {
        /// The protocol address length that was found.
        found: u8,
    },
    /// FR-DS-06 condition 6: the opcode is not "reply".
    #[error("ARP opcode is not reply (2): found {found}")]
    WrongOpcode {
        /// The opcode that was found (e.g. `1` for a request).
        found: u16,
    },
    /// FR-DS-06 conditions 7/8: the Ethernet destination is not the
    /// interface's own MAC, or the Ethernet source is not the ARP
    /// sender MAC.
    #[error(
        "Ethernet destination/source does not match the interface's own MAC / the ARP sender MAC"
    )]
    MacMismatch,
    /// FR-DS-06 condition 9: the sender MAC is not a valid unicast
    /// address (§5.3: all-zero, broadcast or multicast), as classified
    /// by the T-002 boundary constructor.
    #[error("ARP sender MAC is not a valid unicast address: {reason}")]
    InvalidMac {
        /// Which §5.3 rule the sender MAC violated.
        reason: MacAddrParseError,
    },
    /// FR-DS-06 condition 10: the sender IP lies outside the scan
    /// scope.
    #[error("ARP sender IP is outside the scan scope: {found}")]
    OutOfScope {
        /// The out-of-scope sender IP.
        found: Ipv4Addr,
    },
    /// FR-DS-06 condition 11 (FR-SC-05): the sender IP is the network
    /// address of the scope. Prefixes up to /30 only — a /31 uses both
    /// addresses (RFC 3021) and a /32 is a single host, the same split
    /// as `Ipv4Net::host_range`.
    #[error("ARP sender IP is the network address of the scope: {found}")]
    NetworkAddress {
        /// The network address that was claimed.
        found: Ipv4Addr,
    },
    /// FR-DS-06 condition 11 (FR-SC-05): the sender IP is the broadcast
    /// address of the scope (prefixes up to /30 only; see
    /// [`NetworkAddress`](InvalidReply::NetworkAddress)).
    #[error("ARP sender IP is the broadcast address of the scope: {found}")]
    BroadcastAddress {
        /// The broadcast address that was claimed.
        found: Ipv4Addr,
    },
    /// FR-DS-06 condition 11 (FR-SC-05): the sender IP is the
    /// interface's own address.
    #[error("ARP sender IP is the interface's own address")]
    OwnAddress,
    /// FR-DS-06 condition 12: the sender IP was not requested in the
    /// current scan (solicited-only).
    #[error("ARP sender IP was not requested in the current scan: {found}")]
    NotSolicited {
        /// The unsolicited sender IP.
        found: Ipv4Addr,
    },
}

// ---------------------------------------------------------------------------
// The validation context (FR-DS-06 conditions 7, 10–12)
// ---------------------------------------------------------------------------

/// Everything the reply validator needs to know about the current scan.
///
/// Built once per scan by the caller (T-104): the interface's own MAC
/// and IPv4 address, the scan scope, and the set of addresses actually
/// requested — the solicited-only set of FR-DS-06's last clause. The
/// own MAC/IP arrive as plain parameters rather than a
/// `net::interfaces::InterfaceInfo` so that `discovery` keeps depending
/// only on `model` (§8.2); T-104 owns that bridging.
///
/// The context describes the scan and is not itself validated: choosing
/// which addresses to request (FR-SC-05 target selection) is the
/// caller's contract, and the validator re-derives every sender-IP rule
/// from the scope on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReplyContext<'a> {
    /// The selected interface's own MAC (FR-DS-06 condition 7).
    our_mac: MacAddr,
    /// The selected interface's own IPv4 address (condition 11).
    our_ip: Ipv4Addr,
    /// The scan scope (condition 10).
    scope: Ipv4Net,
    /// The addresses requested in the current scan (condition 12).
    solicited: &'a HashSet<Ipv4Addr>,
}

impl<'a> ArpReplyContext<'a> {
    /// Collects the scan facts a reply is validated against.
    pub fn new(
        our_mac: MacAddr,
        our_ip: Ipv4Addr,
        scope: Ipv4Net,
        solicited: &'a HashSet<Ipv4Addr>,
    ) -> Self {
        Self {
            our_mac,
            our_ip,
            scope,
            solicited,
        }
    }

    /// The selected interface's own MAC.
    pub fn our_mac(&self) -> MacAddr {
        self.our_mac
    }

    /// The selected interface's own IPv4 address.
    pub fn our_ip(&self) -> Ipv4Addr {
        self.our_ip
    }

    /// The scan scope.
    pub fn scope(&self) -> Ipv4Net {
        self.scope
    }

    /// The addresses requested in the current scan.
    pub fn solicited(&self) -> &HashSet<Ipv4Addr> {
        self.solicited
    }

    /// `true` if `ip` is one of the addresses this scan requested
    /// (FR-DS-06 condition 12).
    pub fn is_solicited(&self, ip: Ipv4Addr) -> bool {
        self.solicited.contains(&ip)
    }
}

// ---------------------------------------------------------------------------
// Request builder (FR-DS-03)
// ---------------------------------------------------------------------------

/// Builds the 42-byte Ethernet+ARP request frame for one probe
/// (FR-DS-03, Appendix E).
///
/// The Ethernet header addresses the broadcast and names our MAC as the
/// source; the ARP payload announces our MAC/IP as the sender and asks
/// for `target_ip` with the conventional zero target MAC. The returned
/// vector is always exactly [`ARP_FRAME_LEN`] bytes — the length is
/// fixed by construction, one fixed-size field after another.
///
/// The builder is pure byte assembly: it performs no I/O, holds no
/// state and cannot fail (every input is a typed value). Which
/// addresses may be probed at all (FR-SC-05: exclude the network,
/// broadcast and own addresses; cap per FR-SC-06) is T-104's target
/// selection, not the wire format's.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
///
/// use osza_netmon::discovery::arp::{ARP_FRAME_LEN, build_arp_request};
/// use osza_netmon::model::mac::MacAddr;
///
/// // Synthetic values (RFC 5737 TEST-NET-1, documentation MAC).
/// let our_mac: MacAddr = "02:00:00:aa:bb:01".parse().expect("valid sender MAC");
/// let frame = build_arp_request(
///     our_mac,
///     Ipv4Addr::new(192, 0, 2, 1),
///     Ipv4Addr::new(192, 0, 2, 10),
/// );
/// assert_eq!(frame.len(), ARP_FRAME_LEN);
/// // Ethernet broadcast destination, our source, EtherType ARP.
/// assert_eq!(frame[0], 0xff);
/// assert_eq!(frame[5], 0xff);
/// assert_eq!(frame[6], 0x02);
/// assert_eq!(frame[12], 0x08);
/// assert_eq!(frame[13], 0x06);
/// // The probed address is the target IP (last four bytes).
/// assert_eq!(frame[38], 192);
/// assert_eq!(frame[41], 10);
/// ```
pub fn build_arp_request(our_mac: MacAddr, our_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
    // Ethernet header (Appendix E): broadcast destination, our source,
    // EtherType ARP.
    frame.extend_from_slice(&ETHERNET_BROADCAST);
    frame.extend_from_slice(&our_mac.octets());
    frame.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    // ARP payload: Ethernet hardware, IPv4 protocol, 6+4 octet
    // addresses, opcode "request".
    frame.extend_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    frame.extend_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    frame.push(ARP_HLEN_ETHERNET);
    frame.push(ARP_PLEN_IPV4);
    frame.extend_from_slice(&ARP_OP_REQUEST.to_be_bytes());
    // Sender is us; target MAC is the conventional zero (ignored on the
    // wire), target IP is the address being probed.
    frame.extend_from_slice(&our_mac.octets());
    frame.extend_from_slice(&u32::from(our_ip).to_be_bytes());
    frame.extend_from_slice(&ARP_TARGET_UNKNOWN);
    frame.extend_from_slice(&u32::from(target_ip).to_be_bytes());
    frame
}

// ---------------------------------------------------------------------------
// Reply parser/validator (FR-DS-06)
// ---------------------------------------------------------------------------

/// The fixed 42 header bytes of a received frame, decoded field by
/// field. The reply's own target fields (offsets 32..42) carry no
/// FR-DS-06 weight and are not decoded.
struct DecodedFrame {
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    ether_type: u16,
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    opcode: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
}

/// The first `size` bytes at `offset`, or `None` if the frame ends
/// early or the range would overflow. The offsets and sizes used here
/// are compile-time constants, so after the length check this cannot
/// fail — but nothing in this module indexes instead of asking.
fn slice_at(frame: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    frame.get(offset..offset.checked_add(size)?)
}

/// A big-endian `u16` at `offset`, or `None` if the frame ends early.
fn u16_at(frame: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = slice_at(frame, offset, 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Six MAC octets at `offset`, or `None` if the frame ends early.
fn mac_at(frame: &[u8], offset: usize) -> Option<[u8; 6]> {
    slice_at(frame, offset, 6)?.try_into().ok()
}

/// A big-endian IPv4 address at `offset`, or `None` if the frame ends
/// early.
fn ipv4_at(frame: &[u8], offset: usize) -> Option<Ipv4Addr> {
    let bytes: [u8; 4] = slice_at(frame, offset, 4)?.try_into().ok()?;
    Some(Ipv4Addr::from(u32::from_be_bytes(bytes)))
}

/// Decodes the fixed header fields; `None` if any field would reach
/// past the end of `frame`.
fn decode(frame: &[u8]) -> Option<DecodedFrame> {
    Some(DecodedFrame {
        eth_dst: mac_at(frame, ETH_DST)?,
        eth_src: mac_at(frame, ETH_SRC)?,
        ether_type: u16_at(frame, ETH_ETHERTYPE)?,
        htype: u16_at(frame, ARP_HTYPE)?,
        ptype: u16_at(frame, ARP_PTYPE)?,
        hlen: frame.get(ARP_HLEN).copied()?,
        plen: frame.get(ARP_PLEN).copied()?,
        opcode: u16_at(frame, ARP_OP)?,
        sender_mac: mac_at(frame, ARP_SHA)?,
        sender_ip: ipv4_at(frame, ARP_SPA)?,
    })
}

/// Parses and validates one received frame as a solicited ARP reply
/// (FR-DS-06; task card R2/R4/R6/R7).
///
/// The parser is total (SR-02): for any byte sequence it returns either
/// the accepted [`ArpReply`] or the first FR-DS-06 condition the frame
/// fails, as an [`InvalidReply`]. The twelve conditions are checked in
/// the order FR-DS-06 lists them — header fields (EtherType, hardware
/// type/length, protocol type/length, opcode), then the two Ethernet/MAC
/// consistency checks, then the sender-MAC boundary, then the three
/// sender-IP rules (scope, usability, solicited-only). Bytes past the
/// 42-byte header are Ethernet padding and are ignored.
///
/// The reply's own target fields (offsets 32..42) are not validated:
/// FR-DS-06 gives them no weight, and the sender fields plus the
/// Ethernet header carry all of it.
///
/// # Examples
///
/// ```
/// use std::collections::HashSet;
/// use std::net::Ipv4Addr;
///
/// use osza_netmon::discovery::arp::{ArpReply, ArpReplyContext, InvalidReply, parse_arp_reply};
/// use osza_netmon::model::ipv4::Ipv4Net;
/// use osza_netmon::model::mac::MacAddr;
///
/// // Synthetic fixture (RFC 5737 TEST-NET-1, documentation MACs).
/// let our_mac: MacAddr = "02:00:00:aa:bb:01".parse().expect("valid sender MAC");
/// let our_ip = Ipv4Addr::new(192, 0, 2, 1);
/// let scope = Ipv4Net::new(our_ip, 24).expect("valid network");
/// let solicited = HashSet::from([Ipv4Addr::new(192, 0, 2, 10)]);
/// let ctx = ArpReplyContext::new(our_mac, our_ip, scope, &solicited);
///
/// // A well-formed reply from 192.0.2.10 (aa:bb:cc:dd:ee:10): 42 bytes.
/// let frame: [u8; 42] = [
///     0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01, // Ethernet dst: our MAC
///     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10, // Ethernet src: the sender
///     0x08, 0x06, // EtherType: ARP
///     0x00, 0x01, 0x08, 0x00, 0x06, 0x04, // htype, ptype, hlen, plen
///     0x00, 0x02, // opcode: reply
///     0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10, // ARP sender MAC
///     192, 0, 2, 10, // ARP sender IP (solicited)
///     0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01, // ARP target MAC (us)
///     192, 0, 2, 1, // ARP target IP (us)
/// ];
/// assert_eq!(
///     parse_arp_reply(&frame, &ctx),
///     Ok(ArpReply {
///         sender_mac: "aa:bb:cc:dd:ee:10".parse().expect("valid sender MAC"),
///         sender_ip: Ipv4Addr::new(192, 0, 2, 10),
///     })
/// );
///
/// // The same well-formed frame for an address nobody asked about is
/// // rejected (solicited-only, FR-DS-06's last clause).
/// let empty = HashSet::new();
/// let ctx = ArpReplyContext::new(our_mac, our_ip, scope, &empty);
/// assert_eq!(
///     parse_arp_reply(&frame, &ctx),
///     Err(InvalidReply::NotSolicited {
///         found: Ipv4Addr::new(192, 0, 2, 10),
///     })
/// );
/// ```
pub fn parse_arp_reply(frame: &[u8], ctx: &ArpReplyContext<'_>) -> Result<ArpReply, InvalidReply> {
    // Totality precondition: the fixed header must be present in full.
    // (Frames longer than 42 bytes keep their trailing padding — it is
    // never read.)
    let found = frame.len();
    if found < ARP_FRAME_LEN {
        return Err(InvalidReply::Truncated {
            needed: ARP_FRAME_LEN,
            found,
        });
    }
    // The length check above covers every field; the Option here is the
    // no-indexing discipline, not a second opinion.
    let raw = decode(frame).ok_or(InvalidReply::Truncated {
        needed: ARP_FRAME_LEN,
        found,
    })?;

    // FR-DS-06 conditions, in the plan's order. Each failure is its own
    // variant (task card R4) and its own counter (FR-DS-06 "dropped and
    // counted").
    if raw.ether_type != ETHERTYPE_ARP {
        return Err(InvalidReply::WrongEtherType {
            found: raw.ether_type,
        });
    }
    if raw.htype != ARP_HTYPE_ETHERNET {
        return Err(InvalidReply::WrongHardwareType { found: raw.htype });
    }
    if raw.ptype != ARP_PTYPE_IPV4 {
        return Err(InvalidReply::WrongProtocolType { found: raw.ptype });
    }
    if raw.hlen != ARP_HLEN_ETHERNET {
        return Err(InvalidReply::WrongHardwareLength { found: raw.hlen });
    }
    if raw.plen != ARP_PLEN_IPV4 {
        return Err(InvalidReply::WrongProtocolLength { found: raw.plen });
    }
    if raw.opcode != ARP_OP_REPLY {
        return Err(InvalidReply::WrongOpcode { found: raw.opcode });
    }
    // Condition 7: the frame must be addressed to this interface.
    if raw.eth_dst != ctx.our_mac.octets() {
        return Err(InvalidReply::MacMismatch);
    }
    // Condition 8: the Ethernet source must be the ARP sender MAC —
    // a frame whose claimed sender differs from its link-layer source
    // is a forgery attempt, not an observation.
    if raw.eth_src != raw.sender_mac {
        return Err(InvalidReply::MacMismatch);
    }
    // Condition 9 (§5.3 boundary): all-zero, broadcast and multicast
    // sender MACs are rejected by the T-002 validating constructor.
    let sender_mac = MacAddr::from_octets(raw.sender_mac)
        .map_err(|reason| InvalidReply::InvalidMac { reason })?;
    // Conditions 10–12: the sender IP must be inside the scope, a
    // usable host address, and one this scan requested.
    let sender_ip = raw.sender_ip;
    if !ctx.scope.contains(sender_ip) {
        return Err(InvalidReply::OutOfScope { found: sender_ip });
    }
    // FR-SC-05 applied to replies: the network and broadcast addresses
    // are not usable hosts for prefixes up to /30; a /31 uses both
    // addresses (RFC 3021) and a /32 is a single host — the same split
    // as `Ipv4Net::host_range`.
    if ctx.scope.prefix_len() <= 30 {
        if sender_ip == ctx.scope.network() {
            return Err(InvalidReply::NetworkAddress { found: sender_ip });
        }
        if sender_ip == ctx.scope.broadcast() {
            return Err(InvalidReply::BroadcastAddress { found: sender_ip });
        }
    }
    if sender_ip == ctx.our_ip {
        return Err(InvalidReply::OwnAddress);
    }
    if !ctx.is_solicited(sender_ip) {
        return Err(InvalidReply::NotSolicited { found: sender_ip });
    }
    Ok(ArpReply {
        sender_mac,
        sender_ip,
    })
}

// ---------------------------------------------------------------------------
// Counters (FR-DS-06 "dropped and counted")
// ---------------------------------------------------------------------------

/// Tallies of accepted and rejected replies, by reason (FR-DS-06).
///
/// The scanner (T-104) feeds every parser outcome to
/// [`record`](ArpReplyCounters::record); the Details→debug view (T-204)
/// shows the counts. Counting is informational only: it never changes a
/// parser outcome, and the parser rejects every invalid reply whether
/// or not anyone counts it.
///
/// # Examples
///
/// ```
/// use std::net::Ipv4Addr;
///
/// use osza_netmon::discovery::arp::{ArpReplyCounters, InvalidReply};
///
/// let mut counters = ArpReplyCounters::default();
/// counters.record(&Err(InvalidReply::WrongOpcode { found: 1 }));
/// counters.record(&Err(InvalidReply::WrongOpcode { found: 3 }));
/// counters.record(&Err(InvalidReply::NotSolicited {
///     found: Ipv4Addr::new(192, 0, 2, 30),
/// }));
/// assert_eq!(counters.accepted(), 0);
/// assert_eq!(counters.rejected(), 3);
/// assert_eq!(
///     counters.rejected_with(&InvalidReply::WrongOpcode { found: 1 }),
///     2
/// );
/// assert_eq!(
///     counters.to_string(),
///     "accepted=0 rejected=3 wrong_opcode=2 not_solicited=1"
/// );
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ArpReplyCounters {
    /// Replies that passed all FR-DS-06 conditions.
    accepted: u64,
    /// Frames shorter than the fixed header.
    truncated: u64,
    /// [`InvalidReply::WrongEtherType`] (condition 1).
    wrong_ether_type: u64,
    /// [`InvalidReply::WrongHardwareType`] (condition 2).
    wrong_hardware_type: u64,
    /// [`InvalidReply::WrongProtocolType`] (condition 3).
    wrong_protocol_type: u64,
    /// [`InvalidReply::WrongHardwareLength`] (condition 4).
    wrong_hardware_length: u64,
    /// [`InvalidReply::WrongProtocolLength`] (condition 5).
    wrong_protocol_length: u64,
    /// [`InvalidReply::WrongOpcode`] (condition 6).
    wrong_opcode: u64,
    /// [`InvalidReply::MacMismatch`] (conditions 7/8).
    mac_mismatch: u64,
    /// [`InvalidReply::InvalidMac`] (condition 9).
    invalid_mac: u64,
    /// [`InvalidReply::OutOfScope`] (condition 10).
    out_of_scope: u64,
    /// [`InvalidReply::NetworkAddress`] (condition 11).
    network_address: u64,
    /// [`InvalidReply::BroadcastAddress`] (condition 11).
    broadcast_address: u64,
    /// [`InvalidReply::OwnAddress`] (condition 11).
    own_address: u64,
    /// [`InvalidReply::NotSolicited`] (condition 12).
    not_solicited: u64,
}

impl ArpReplyCounters {
    /// Records one parser outcome in the tallies.
    ///
    /// `Ok` counts as accepted, `Err` as one rejection of exactly that
    /// reason. Recording is pure bookkeeping — it inspects the outcome
    /// and never the frame.
    pub fn record(&mut self, outcome: &Result<ArpReply, InvalidReply>) {
        match outcome {
            Ok(_) => self.accepted += 1,
            Err(InvalidReply::Truncated { .. }) => self.truncated += 1,
            Err(InvalidReply::WrongEtherType { .. }) => self.wrong_ether_type += 1,
            Err(InvalidReply::WrongHardwareType { .. }) => self.wrong_hardware_type += 1,
            Err(InvalidReply::WrongProtocolType { .. }) => self.wrong_protocol_type += 1,
            Err(InvalidReply::WrongHardwareLength { .. }) => self.wrong_hardware_length += 1,
            Err(InvalidReply::WrongProtocolLength { .. }) => self.wrong_protocol_length += 1,
            Err(InvalidReply::WrongOpcode { .. }) => self.wrong_opcode += 1,
            Err(InvalidReply::MacMismatch) => self.mac_mismatch += 1,
            Err(InvalidReply::InvalidMac { .. }) => self.invalid_mac += 1,
            Err(InvalidReply::OutOfScope { .. }) => self.out_of_scope += 1,
            Err(InvalidReply::NetworkAddress { .. }) => self.network_address += 1,
            Err(InvalidReply::BroadcastAddress { .. }) => self.broadcast_address += 1,
            Err(InvalidReply::OwnAddress) => self.own_address += 1,
            Err(InvalidReply::NotSolicited { .. }) => self.not_solicited += 1,
        }
    }

    /// Replies that passed all FR-DS-06 conditions.
    pub fn accepted(&self) -> u64 {
        self.accepted
    }

    /// Rejected replies of every reason combined.
    pub fn rejected(&self) -> u64 {
        self.truncated
            + self.wrong_ether_type
            + self.wrong_hardware_type
            + self.wrong_protocol_type
            + self.wrong_hardware_length
            + self.wrong_protocol_length
            + self.wrong_opcode
            + self.mac_mismatch
            + self.invalid_mac
            + self.out_of_scope
            + self.network_address
            + self.broadcast_address
            + self.own_address
            + self.not_solicited
    }

    /// All outcomes seen: accepted plus rejected.
    pub fn total(&self) -> u64 {
        self.accepted + self.rejected()
    }

    /// How many replies were rejected with exactly this reason.
    pub fn rejected_with(&self, reason: &InvalidReply) -> u64 {
        match reason {
            InvalidReply::Truncated { .. } => self.truncated,
            InvalidReply::WrongEtherType { .. } => self.wrong_ether_type,
            InvalidReply::WrongHardwareType { .. } => self.wrong_hardware_type,
            InvalidReply::WrongProtocolType { .. } => self.wrong_protocol_type,
            InvalidReply::WrongHardwareLength { .. } => self.wrong_hardware_length,
            InvalidReply::WrongProtocolLength { .. } => self.wrong_protocol_length,
            InvalidReply::WrongOpcode { .. } => self.wrong_opcode,
            InvalidReply::MacMismatch => self.mac_mismatch,
            InvalidReply::InvalidMac { .. } => self.invalid_mac,
            InvalidReply::OutOfScope { .. } => self.out_of_scope,
            InvalidReply::NetworkAddress { .. } => self.network_address,
            InvalidReply::BroadcastAddress { .. } => self.broadcast_address,
            InvalidReply::OwnAddress => self.own_address,
            InvalidReply::NotSolicited { .. } => self.not_solicited,
        }
    }
}

impl fmt::Display for ArpReplyCounters {
    /// One line: the accepted/rejected totals followed by every nonzero
    /// rejection reason, in FR-DS-06 order. The format is for the
    /// Details→debug view (T-204) and the fuzz harness summary; it is
    /// not a user-facing sentence (plan §5.4).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "accepted={} rejected={}", self.accepted, self.rejected())?;
        let reasons: [(&str, u64); 14] = [
            ("truncated", self.truncated),
            ("wrong_ether_type", self.wrong_ether_type),
            ("wrong_hardware_type", self.wrong_hardware_type),
            ("wrong_protocol_type", self.wrong_protocol_type),
            ("wrong_hardware_length", self.wrong_hardware_length),
            ("wrong_protocol_length", self.wrong_protocol_length),
            ("wrong_opcode", self.wrong_opcode),
            ("mac_mismatch", self.mac_mismatch),
            ("invalid_mac", self.invalid_mac),
            ("out_of_scope", self.out_of_scope),
            ("network_address", self.network_address),
            ("broadcast_address", self.broadcast_address),
            ("own_address", self.own_address),
            ("not_solicited", self.not_solicited),
        ];
        for (label, count) in reasons {
            if count != 0 {
                write!(f, " {label}={count}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;

    // -----------------------------------------------------------------------
    // Fixtures (plan §14.3 rule 8: RFC 5737 ranges, documentation MACs)
    // -----------------------------------------------------------------------

    /// Our side: locally-administered documentation MAC on TEST-NET-1.
    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01];
    const OUR_IP: [u8; 4] = [192, 0, 2, 1];
    /// A responder: globally-administered documentation MAC.
    const PEER_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10];
    /// Another responder: locally-administered (a Wi-Fi privacy style
    /// MAC — a valid sender per §5.3).
    const PEER_MAC_2: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const PEER_IP: [u8; 4] = [192, 0, 2, 10];
    const PEER_IP_2: [u8; 4] = [192, 0, 2, 20];

    fn mac(octets: [u8; 6]) -> MacAddr {
        MacAddr::from_octets(octets).expect("fixture MAC is valid")
    }

    fn ip(octets: [u8; 4]) -> Ipv4Addr {
        let [a, b, c, d] = octets;
        Ipv4Addr::new(a, b, c, d)
    }

    fn scope() -> Ipv4Net {
        Ipv4Net::new(ip(OUR_IP), 24).expect("fixture scope is valid")
    }

    /// The solicited set of the default fixture: both peer addresses.
    fn solicited() -> HashSet<Ipv4Addr> {
        [ip(PEER_IP), ip(PEER_IP_2)].into_iter().collect()
    }

    fn ctx(solicited: &HashSet<Ipv4Addr>) -> ArpReplyContext<'_> {
        ArpReplyContext::new(mac(OUR_MAC), ip(OUR_IP), scope(), solicited)
    }

    /// A valid 42-byte reply frame from (`sender_mac`, `sender_ip`) to
    /// our fixture interface, assembled field by field per Appendix E.
    fn reply(sender_mac: [u8; 6], sender_ip: [u8; 4]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ARP_FRAME_LEN);
        frame.extend_from_slice(&OUR_MAC); // Ethernet dst: us
        frame.extend_from_slice(&sender_mac); // Ethernet src: the sender
        frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
        frame.extend_from_slice(&1u16.to_be_bytes()); // htype: Ethernet
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype: IPv4
        frame.push(6); // hlen
        frame.push(4); // plen
        frame.extend_from_slice(&2u16.to_be_bytes()); // opcode: reply
        frame.extend_from_slice(&sender_mac); // ARP sender MAC
        frame.extend_from_slice(&sender_ip); // ARP sender IP
        frame.extend_from_slice(&OUR_MAC); // ARP target MAC (us)
        frame.extend_from_slice(&OUR_IP); // ARP target IP (us)
        frame
    }

    /// `frame` with `replacement` written at `offset` (tests may index).
    fn patched(frame: &[u8], offset: usize, replacement: &[u8]) -> Vec<u8> {
        let mut copy = frame.to_vec();
        copy.splice(
            offset..offset + replacement.len(),
            replacement.iter().copied(),
        );
        copy
    }

    /// The acceptance invariants every `Ok` reply must satisfy, derived
    /// independently of the parser's own checks (the property-test
    /// oracle): solicited, in scope, usable, not our own address.
    fn invariants_hold(reply: &ArpReply, context: &ArpReplyContext<'_>) -> bool {
        context.is_solicited(reply.sender_ip)
            && context.scope().contains(reply.sender_ip)
            && reply.sender_ip != context.our_ip()
            && (context.scope().prefix_len() > 30
                || (reply.sender_ip != context.scope().network()
                    && reply.sender_ip != context.scope().broadcast()))
    }

    // -----------------------------------------------------------------------
    // Request builder (FR-DS-03, AC-1)
    // -----------------------------------------------------------------------

    #[test]
    fn request_matches_the_golden_vector() {
        let frame = build_arp_request(mac(OUR_MAC), ip(OUR_IP), ip(PEER_IP));
        let expected: [u8; ARP_FRAME_LEN] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Ethernet dst: broadcast
            0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01, // Ethernet src: our MAC
            0x08, 0x06, // EtherType: ARP
            0x00, 0x01, // htype: Ethernet
            0x08, 0x00, // ptype: IPv4
            0x06, // hlen
            0x04, // plen
            0x00, 0x01, // opcode: request
            0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01, // sender MAC: ours
            192, 0, 2, 1, // sender IP: ours
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC: zero
            192, 0, 2, 10, // target IP: the probed address
        ];
        assert_eq!(frame, expected);
    }

    #[test]
    fn request_builder_is_total_for_any_target() {
        // Every Ipv4Addr is encodable — including the extreme and the
        // other RFC 5737 ranges — and the length is always 42 (R3).
        for target in [
            ip([0, 0, 0, 0]),
            ip([255, 255, 255, 255]),
            ip([198, 51, 100, 1]),
            ip([203, 0, 113, 9]),
            ip(PEER_IP),
        ] {
            let frame = build_arp_request(mac(OUR_MAC), ip(OUR_IP), target);
            assert_eq!(frame.len(), ARP_FRAME_LEN, "for target {target}");
            let target_bytes = u32::from(target).to_be_bytes();
            assert_eq!(frame[38..42].to_vec(), target_bytes.to_vec());
        }
        // Deterministic for the same target, distinct across targets.
        let a = build_arp_request(mac(OUR_MAC), ip(OUR_IP), ip(PEER_IP));
        let b = build_arp_request(mac(OUR_MAC), ip(OUR_IP), ip(PEER_IP_2));
        assert_eq!(a, build_arp_request(mac(OUR_MAC), ip(OUR_IP), ip(PEER_IP)));
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Valid replies (AC-2)
    // -----------------------------------------------------------------------

    #[test]
    fn valid_reply_matches_the_golden_vector() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let frame = reply(PEER_MAC, PEER_IP);
        // The fixture helper itself is pinned to the golden bytes, so
        // the doctest vector and this suite cannot drift apart.
        let expected: [u8; ARP_FRAME_LEN] = [
            0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01, // Ethernet dst: us
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10, // Ethernet src: sender
            0x08, 0x06, // EtherType: ARP
            0x00, 0x01, // htype
            0x08, 0x00, // ptype
            0x06, // hlen
            0x04, // plen
            0x00, 0x02, // opcode: reply
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10, // sender MAC
            192, 0, 2, 10, // sender IP
            0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01, // target MAC (us)
            192, 0, 2, 1, // target IP (us)
        ];
        assert_eq!(frame, expected);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Ok(ArpReply {
                sender_mac: mac(PEER_MAC),
                sender_ip: ip(PEER_IP),
            })
        );
    }

    #[test]
    fn both_solicited_addresses_are_accepted() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // The second solicited address, from a locally-administered MAC
        // (a Wi-Fi privacy style sender — §5.3 keeps it valid).
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC_2, PEER_IP_2), &context),
            Ok(ArpReply {
                sender_mac: mac(PEER_MAC_2),
                sender_ip: ip(PEER_IP_2),
            })
        );
    }

    #[test]
    fn ethernet_padding_beyond_42_bytes_is_ignored() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // A real ARP reply on Ethernet is padded to the 60-byte minimum
        // frame; the 18 trailing bytes are padding, never read.
        let mut padded = reply(PEER_MAC, PEER_IP);
        padded.extend_from_slice(&[0x00; 18]);
        assert_eq!(padded.len(), 60);
        assert_eq!(
            parse_arp_reply(&padded, &context),
            Ok(ArpReply {
                sender_mac: mac(PEER_MAC),
                sender_ip: ip(PEER_IP),
            })
        );
        // Padding content is irrelevant — non-zero padding is equally
        // ignored (it is never validated).
        let mut noisy = reply(PEER_MAC, PEER_IP);
        noisy.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(parse_arp_reply(&noisy, &context).is_ok());
    }

    #[test]
    fn reply_target_fields_carry_no_validation_weight() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // FR-DS-06 says nothing about the reply's own target MAC/IP;
        // garbage there is accepted — the sender fields and the
        // Ethernet header carry all the weight.
        let mut frame = reply(PEER_MAC, PEER_IP);
        for slot in frame.iter_mut().take(42).skip(32) {
            *slot = 0xee;
        }
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Ok(ArpReply {
                sender_mac: mac(PEER_MAC),
                sender_ip: ip(PEER_IP),
            })
        );
    }

    // -----------------------------------------------------------------------
    // Truncation (R2 precondition)
    // -----------------------------------------------------------------------

    #[test]
    fn every_shorter_length_is_truncated() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let frame = reply(PEER_MAC, PEER_IP);
        for len in 0..ARP_FRAME_LEN {
            let short = &frame[0..len];
            assert_eq!(
                parse_arp_reply(short, &context),
                Err(InvalidReply::Truncated {
                    needed: ARP_FRAME_LEN,
                    found: len,
                }),
                "a {len}-byte frame cannot hold the header"
            );
        }
        // Exactly 42 is the boundary: not truncated.
        assert!(parse_arp_reply(&frame, &context).is_ok());
    }

    // -----------------------------------------------------------------------
    // Negative vectors: one per FR-DS-06 condition (AC-3…AC-14)
    // -----------------------------------------------------------------------

    #[test]
    fn wrong_ether_type_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // An IPv4 EtherType where ARP belongs.
        let frame = patched(&reply(PEER_MAC, PEER_IP), ETH_ETHERTYPE, &[0x08, 0x00]);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::WrongEtherType { found: 0x0800 })
        );
    }

    #[test]
    fn wrong_hardware_type_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // Hardware type 6 (IEEE 802.x) instead of 1 (Ethernet).
        let frame = patched(&reply(PEER_MAC, PEER_IP), ARP_HTYPE, &6u16.to_be_bytes());
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::WrongHardwareType { found: 6 })
        );
    }

    #[test]
    fn wrong_protocol_type_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // Protocol type 0x86DD (IPv6) instead of 0x0800 (IPv4).
        let frame = patched(
            &reply(PEER_MAC, PEER_IP),
            ARP_PTYPE,
            &0x86ddu16.to_be_bytes(),
        );
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::WrongProtocolType { found: 0x86dd })
        );
    }

    #[test]
    fn wrong_hardware_length_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // EUI-64-sized hardware addresses instead of 6.
        let frame = patched(&reply(PEER_MAC, PEER_IP), ARP_HLEN, &[8]);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::WrongHardwareLength { found: 8 })
        );
    }

    #[test]
    fn wrong_protocol_length_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // IPv6-sized protocol addresses instead of 4.
        let frame = patched(&reply(PEER_MAC, PEER_IP), ARP_PLEN, &[16]);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::WrongProtocolLength { found: 16 })
        );
    }

    #[test]
    fn wrong_opcode_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let valid = reply(PEER_MAC, PEER_IP);
        // Opcode 1: our own request echoed back.
        let request = patched(&valid, ARP_OP, &ARP_OP_REQUEST.to_be_bytes());
        assert_eq!(
            parse_arp_reply(&request, &context),
            Err(InvalidReply::WrongOpcode { found: 1 })
        );
        // Opcode 3: "reply" is 2; anything else is refused.
        let nak = patched(&valid, ARP_OP, &3u16.to_be_bytes());
        assert_eq!(
            parse_arp_reply(&nak, &context),
            Err(InvalidReply::WrongOpcode { found: 3 })
        );
    }

    #[test]
    fn ethernet_destination_not_our_mac_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // A reply addressed to someone else (condition 7).
        let frame = patched(&reply(PEER_MAC, PEER_IP), ETH_DST, &PEER_MAC_2);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::MacMismatch)
        );
    }

    #[test]
    fn ethernet_source_not_sender_mac_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // The link-layer source differs from the claimed ARP sender
        // (condition 8) — the classic forgery shape.
        let frame = patched(&reply(PEER_MAC, PEER_IP), ETH_SRC, &PEER_MAC_2);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::MacMismatch)
        );
    }

    #[test]
    fn zero_broadcast_and_multicast_sender_macs_are_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // Each invalid sender MAC keeps the Ethernet source equal to it
        // so condition 8 passes and condition 9 is what fires.
        let cases: [([u8; 6], MacAddrParseError); 3] = [
            (
                [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                MacAddrParseError::ZeroAddress,
            ),
            (
                [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                MacAddrParseError::BroadcastAddress,
            ),
            // IPv4 multicast MAC prefix 01:00:5e.
            (
                [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
                MacAddrParseError::MulticastAddress,
            ),
        ];
        for (sender, reason) in cases {
            let frame = reply(sender, PEER_IP);
            assert_eq!(
                parse_arp_reply(&frame, &context),
                Err(InvalidReply::InvalidMac { reason }),
                "sender {sender:02x?}"
            );
        }
    }

    #[test]
    fn out_of_scope_sender_ips_are_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // TEST-NET-2, TEST-NET-3 and the /24 adjacent to our scope.
        for outside in [[198, 51, 100, 5], [203, 0, 113, 9], [192, 0, 3, 1]] {
            let frame = reply(PEER_MAC, outside);
            assert_eq!(
                parse_arp_reply(&frame, &context),
                Err(InvalidReply::OutOfScope { found: ip(outside) }),
                "sender {outside:?}"
            );
        }
    }

    #[test]
    fn network_broadcast_and_own_addresses_are_rejected_even_when_solicited() {
        // The reserved addresses are in the solicited set on purpose:
        // condition 11 must reject them regardless of condition 12.
        let solicited: HashSet<Ipv4Addr> = [
            ip([192, 0, 2, 0]),
            ip([192, 0, 2, 255]),
            ip(OUR_IP),
            ip(PEER_IP),
        ]
        .into_iter()
        .collect();
        let context = ctx(&solicited);
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, [192, 0, 2, 0]), &context),
            Err(InvalidReply::NetworkAddress {
                found: ip([192, 0, 2, 0])
            })
        );
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, [192, 0, 2, 255]), &context),
            Err(InvalidReply::BroadcastAddress {
                found: ip([192, 0, 2, 255])
            })
        );
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, OUR_IP), &context),
            Err(InvalidReply::OwnAddress)
        );
        // The plain solicited host stays accepted in the same context.
        assert!(parse_arp_reply(&reply(PEER_MAC, PEER_IP), &context).is_ok());
    }

    #[test]
    fn point_to_point_and_host_scopes_follow_fr_sc_05() {
        // /31 (RFC 3021): both addresses are usable hosts. The lower
        // one is NOT a "network address" to reject — the parity
        // `Ipv4Net::host_range` already defines.
        let solicited_31: HashSet<Ipv4Addr> = [ip([192, 0, 2, 0])].into_iter().collect();
        let context_31 = ArpReplyContext::new(
            mac(OUR_MAC),
            ip([192, 0, 2, 1]),
            Ipv4Net::new(ip([192, 0, 2, 1]), 31).expect("valid /31"),
            &solicited_31,
        );
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, [192, 0, 2, 0]), &context_31),
            Ok(ArpReply {
                sender_mac: mac(PEER_MAC),
                sender_ip: ip([192, 0, 2, 0]),
            })
        );
        // Our own /31 address is still our own.
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, [192, 0, 2, 1]), &context_31),
            Err(InvalidReply::OwnAddress)
        );

        // /32: a single-host network; the address is usable when it is
        // not the interface's own.
        let host = ip([198, 51, 100, 7]);
        let scope_32 = Ipv4Net::new(host, 32).expect("valid /32");
        let solicited_32: HashSet<Ipv4Addr> = [host].into_iter().collect();
        let elsewhere =
            ArpReplyContext::new(mac(OUR_MAC), ip([203, 0, 113, 9]), scope_32, &solicited_32);
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, [198, 51, 100, 7]), &elsewhere),
            Ok(ArpReply {
                sender_mac: mac(PEER_MAC),
                sender_ip: host,
            })
        );
        let own = ArpReplyContext::new(mac(OUR_MAC), host, scope_32, &solicited_32);
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, [198, 51, 100, 7]), &own),
            Err(InvalidReply::OwnAddress)
        );
    }

    #[test]
    fn unsolicited_sender_ip_is_rejected() {
        let solicited = solicited();
        let context = ctx(&solicited);
        // Inside the scope, a usable host, but nobody asked about it.
        let frame = reply(PEER_MAC, [192, 0, 2, 30]);
        assert_eq!(
            parse_arp_reply(&frame, &context),
            Err(InvalidReply::NotSolicited {
                found: ip([192, 0, 2, 30])
            })
        );
        // An empty solicited set rejects everything (the degenerate
        // "nothing requested" scan).
        let empty: HashSet<Ipv4Addr> = HashSet::new();
        let context = ctx(&empty);
        assert_eq!(
            parse_arp_reply(&reply(PEER_MAC, PEER_IP), &context),
            Err(InvalidReply::NotSolicited { found: ip(PEER_IP) })
        );
    }

    #[test]
    fn the_first_fr_ds_06_condition_to_fail_wins() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let valid = reply(PEER_MAC, PEER_IP);

        // Conditions 1 and 6 both violated: the earlier one is reported.
        let mut both = valid.clone();
        both.splice(ETH_ETHERTYPE..ETH_ETHERTYPE + 2, 0x0800u16.to_be_bytes());
        both.splice(ARP_OP..ARP_OP + 2, ARP_OP_REQUEST.to_be_bytes());
        assert_eq!(
            parse_arp_reply(&both, &context),
            Err(InvalidReply::WrongEtherType { found: 0x0800 })
        );

        // Conditions 6 and 7 both violated (our own broadcast request
        // is exactly this shape): opcode is checked first.
        let mut request_shaped = valid.clone();
        request_shaped.splice(ARP_OP..ARP_OP + 2, ARP_OP_REQUEST.to_be_bytes());
        request_shaped.splice(ETH_DST..ETH_DST + 6, [0xff; 6]);
        assert_eq!(
            parse_arp_reply(&request_shaped, &context),
            Err(InvalidReply::WrongOpcode { found: 1 })
        );

        // Conditions 10 and 12 both violated: scope is checked first.
        let mut far_away = valid;
        far_away.splice(ARP_SPA..ARP_SPA + 4, [198, 51, 100, 5]);
        assert_eq!(
            parse_arp_reply(&far_away, &context),
            Err(InvalidReply::OutOfScope {
                found: ip([198, 51, 100, 5])
            })
        );
    }

    #[test]
    fn the_builder_s_request_rejected_as_reply_and_as_own_identity() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let request = build_arp_request(mac(OUR_MAC), ip(OUR_IP), ip(PEER_IP));
        // A request is not a reply: opcode (condition 6) fires before
        // the Ethernet destination (condition 7), so the broadcast
        // destination is not even reached.
        assert_eq!(
            parse_arp_reply(&request, &context),
            Err(InvalidReply::WrongOpcode { found: 1 })
        );
        // Forged into a "reply" (opcode 2, addressed to us), it claims
        // our own MAC and IP as the sender: rejected as our own
        // address (FR-SC-05) — nobody ARPs the interface itself.
        let mut forged = request;
        forged.splice(ETH_DST..ETH_DST + 6, OUR_MAC);
        forged.splice(ARP_OP..ARP_OP + 2, ARP_OP_REPLY.to_be_bytes());
        assert_eq!(
            parse_arp_reply(&forged, &context),
            Err(InvalidReply::OwnAddress)
        );
    }

    // -----------------------------------------------------------------------
    // Context surface
    // -----------------------------------------------------------------------

    #[test]
    fn context_exposes_the_scan_facts() {
        let solicited = solicited();
        let context = ctx(&solicited);
        assert_eq!(context.our_mac(), mac(OUR_MAC));
        assert_eq!(context.our_ip(), ip(OUR_IP));
        assert_eq!(context.scope(), scope());
        assert_eq!(context.solicited().len(), 2);
        assert!(context.is_solicited(ip(PEER_IP)));
        assert!(!context.is_solicited(ip([192, 0, 2, 30])));
    }

    // -----------------------------------------------------------------------
    // Counters (FR-DS-06 "dropped and counted")
    // -----------------------------------------------------------------------

    #[test]
    fn counters_tally_every_reason_independently() {
        let mut counters = ArpReplyCounters::default();
        // One of each rejection reason, built directly: the variant is
        // the counter key (R4), so this pins every arm of `record`.
        let reasons = [
            InvalidReply::Truncated {
                needed: ARP_FRAME_LEN,
                found: 41,
            },
            InvalidReply::WrongEtherType { found: 0x0800 },
            InvalidReply::WrongHardwareType { found: 6 },
            InvalidReply::WrongProtocolType { found: 0x86dd },
            InvalidReply::WrongHardwareLength { found: 8 },
            InvalidReply::WrongProtocolLength { found: 16 },
            InvalidReply::WrongOpcode { found: 1 },
            InvalidReply::MacMismatch,
            InvalidReply::InvalidMac {
                reason: MacAddrParseError::MulticastAddress,
            },
            InvalidReply::OutOfScope {
                found: ip([198, 51, 100, 5]),
            },
            InvalidReply::NetworkAddress {
                found: ip([192, 0, 2, 0]),
            },
            InvalidReply::BroadcastAddress {
                found: ip([192, 0, 2, 255]),
            },
            InvalidReply::OwnAddress,
            InvalidReply::NotSolicited {
                found: ip([192, 0, 2, 30]),
            },
        ];
        for reason in &reasons {
            counters.record(&Err(*reason));
        }
        counters.record(&Ok(ArpReply {
            sender_mac: mac(PEER_MAC),
            sender_ip: ip(PEER_IP),
        }));
        for reason in &reasons {
            assert_eq!(counters.rejected_with(reason), 1, "for {reason}");
        }
        assert_eq!(counters.accepted(), 1);
        assert_eq!(counters.rejected(), 14);
        assert_eq!(counters.total(), 15);
        // Re-recording one reason moves only its own bucket.
        counters.record(&Err(InvalidReply::NotSolicited {
            found: ip([192, 0, 2, 30]),
        }));
        assert_eq!(
            counters.rejected_with(&InvalidReply::NotSolicited {
                found: ip([192, 0, 2, 30])
            }),
            2
        );
        assert_eq!(
            counters.rejected_with(&InvalidReply::WrongOpcode { found: 1 }),
            1
        );
        assert_eq!(counters.rejected(), 15);
        assert_eq!(counters.total(), 16);
    }

    #[test]
    fn counters_track_a_mixed_batch_of_real_frames() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let frames = [
            reply(PEER_MAC, PEER_IP),                 // accepted
            reply(PEER_MAC_2, PEER_IP_2),             // accepted
            reply(PEER_MAC, [192, 0, 2, 30]),         // not solicited
            reply(PEER_MAC, [198, 51, 100, 5]),       // out of scope
            Vec::new(),                               // truncated (empty)
            reply(PEER_MAC, PEER_IP)[0..20].to_vec(), // truncated (short)
        ];
        let mut counters = ArpReplyCounters::default();
        for frame in &frames {
            counters.record(&parse_arp_reply(frame, &context));
        }
        assert_eq!(counters.accepted(), 2);
        assert_eq!(counters.rejected(), 4);
        assert_eq!(counters.total(), 6);
        assert_eq!(
            counters.rejected_with(&InvalidReply::NotSolicited {
                found: ip([192, 0, 2, 30])
            }),
            1
        );
        assert_eq!(
            counters.rejected_with(&InvalidReply::OutOfScope {
                found: ip([198, 51, 100, 5])
            }),
            1
        );
        assert_eq!(
            counters.rejected_with(&InvalidReply::Truncated {
                needed: ARP_FRAME_LEN,
                found: 0
            }),
            2
        );
        // Display: totals first, then every nonzero reason in FR-DS-06
        // order (the Details→debug line T-204 will show).
        assert_eq!(
            counters.to_string(),
            "accepted=2 rejected=4 truncated=2 out_of_scope=1 not_solicited=1"
        );
        // A fresh counter displays as the two zero totals only.
        assert_eq!(
            ArpReplyCounters::default().to_string(),
            "accepted=0 rejected=0"
        );
    }

    // -----------------------------------------------------------------------
    // Property tests (SR-02, AC-15; deterministic, std-only)
    // -----------------------------------------------------------------------

    /// Property: the parser never panics on 1,000 random byte strings —
    /// every input maps to `Ok` or an `Err`, and every `Ok` satisfies
    /// the acceptance invariants re-derived independently above.
    #[test]
    fn property_parse_never_panics_on_random_bytes() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let mut rng = Lcg::seeded(0x0A2C_0103_0000_0042);
        let mut saw_truncated = false;
        let mut saw_wrong_ether_type = false;
        for _ in 0..1000 {
            // Random length around the header size: shorter, exact and
            // padded frames all occur (0..=96 bytes).
            let len = rng.next_below(97) as usize;
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(rng.next_u8());
            }
            match parse_arp_reply(&bytes, &context) {
                Ok(reply) => assert!(
                    invariants_hold(&reply, &context),
                    "accepted reply violates the invariants: {reply:?}"
                ),
                Err(InvalidReply::Truncated { .. }) => saw_truncated = true,
                Err(InvalidReply::WrongEtherType { .. }) => saw_wrong_ether_type = true,
                Err(_) => {}
            }
        }
        // Non-vacuity: the random inputs actually reach the parser and
        // fall on both sides of the length rule (pure-random frames
        // essentially never pass all twelve conditions, which is the
        // point — the corruption property below covers the Ok path).
        assert!(
            saw_truncated && saw_wrong_ether_type,
            "random inputs never exercised both length classes"
        );
    }

    /// Property: single-byte corruption of a valid frame never panics,
    /// and corruption that FR-DS-06 does not weigh (the reply's target
    /// fields, offsets 32..42) keeps the frame accepted — so the Ok
    /// path is exercised, not just the error path.
    #[test]
    fn property_single_byte_corruptions_never_panic() {
        let solicited = solicited();
        let context = ctx(&solicited);
        let seed = reply(PEER_MAC, PEER_IP);
        let mut accepted = 0u32;
        for position in 0..ARP_FRAME_LEN {
            for mask in [0x01u8, 0x02, 0x55, 0x80, 0xff] {
                let mut bytes = seed.clone();
                if let Some(slot) = bytes.get_mut(position) {
                    *slot ^= mask;
                }
                if let Ok(reply) = parse_arp_reply(&bytes, &context) {
                    assert!(
                        invariants_hold(&reply, &context),
                        "accepted corrupted frame violates the invariants: {reply:?}"
                    );
                    accepted += 1;
                }
            }
        }
        // 10 target-field positions × 5 masks = 50 corruptions that
        // must stay accepted; anything less means a weighed field was
        // wrongly read from the target region (or worse).
        assert!(
            accepted >= 50,
            "only {accepted} of 210 corruptions stayed accepted; the target-field region must not be weighed"
        );
    }
}
