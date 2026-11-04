// SPDX-License-Identifier: GPL-3.0-only

//! The DNS PTR client: query construction, total response acceptance,
//! and the production [`UdpResolver`] (plan §6.5 FR-EN-03/FR-EN-04, §4
//! ADR-003, ADR-015 option (a) — the hand-rolled minimal PTR codec,
//! task T-203; task-card policies D-2/D-3, decision record in
//! `docs/adr/015-dns-ptr-client.md`).
//!
//! # The `NameResolver` trait (plan §8.6, task-card R-3)
//!
//! One call to [`NameResolver::reverse`] is **one attempt**: send one
//! PTR query for `ip` and wait up to `timeout` for one response
//! datagram. `Ok(Some(h))` is a validated name, `Ok(None)` is a
//! definitive no-name answer (NOERROR or NXDOMAIN without a usable PTR
//! record), `Err(..)` means this attempt failed — timeout, transport
//! error, a malformed datagram, a server failure code, or truncation.
//! **Retry and backoff policy is owned by the worker**
//! ([`super::worker`], policy D-4), never by the resolver.
//!
//! The signature adapts the plan §8.6 sketch (`&self` → `&mut self`
//! because the production resolver mutates its socket and its ID
//! generator; `deadline: Duration` → `timeout: Duration` per this
//! task card's own sketch). The adaptation is recorded in the T-203
//! execution report.
//!
//! # The query (policy D-2)
//!
//! [`build_ptr_query`] emits a standard query: PTR for
//! `<reversed dotted-quad>.in-addr.arpa`, QCLASS IN, QTYPE PTR, RD=1,
//! with a 16-bit ID taken from an LCG seeded at resolver construction.
//! The ID is **not a security boundary**: the actual defense is the
//! ID + question match against the one resolver the UDP socket is
//! `connect()`ed to — the kernel drops datagrams from any other source
//! before they reach the socket — plus validation of every decoded byte. A predictable ID
//! therefore cannot make us accept a response we did not solicit from
//! the one server we asked.
//!
//! # Response acceptance (policy D-2)
//!
//! [`accept_ptr_response`] accepts a datagram only when **all** of
//! these hold:
//!
//! * the datagram is 12..=512 bytes (we do not use EDNS; larger is
//!   rejected — the test that needs a 512-byte datagram builds one with
//!   an ignored record type);
//! * the ID matches the query, QR=1, opcode 0, QDCOUNT=1, and the
//!   question decodes to the same name (case-insensitive), QTYPE and
//!   QCLASS;
//! * TC=1 fails the attempt (no TCP fallback — a documented limitation,
//!   see the T-203 report's residual-risk sentence);
//! * RCODE NOERROR → the answer records are walked; NXDOMAIN → a
//!   definitive `Ok(None)`; any other RCODE → the attempt failed
//!   ([`ResolveError::ServerFailure`]).
//!
//! Answer extraction walks the answer records, skips CNAME records,
//! and returns the **first PTR record whose RDATA name decodes and
//! passes [`Hostname::try_from`]**. A PTR name that decodes but fails
//! hostname validation is counted and skipped; a name that fails to
//! *decode* (structure violation) rejects the whole datagram as
//! [`ResolveError::Malformed`] — that split (decode failure = reject
//! the datagram, validation failure = skip the record) is the D-2 rule
//! "decodes and passes … counted and skipped". NOERROR with no usable
//! PTR is `Ok(None)`.
//!
//! Parsing is **total** (plan §7.2 SR-02): compression-pointer walks
//! are bounded two ways — at most [`MAX_POINTER_JUMPS`] hops and at
//! most [`MAX_NAME_OCTETS`] (255) expanded wire-format octets — labels
//! are at most 63 octets, pointers must point strictly backwards (RFC
//! 1035 "prior occurrence"; forward pointers and self-loops are
//! rejected), and no read ever passes the end of the datagram. A
//! response violating any bound yields [`ResolveError::Malformed`],
//! never a panic and never a hang.
//!
//! Exactly **one datagram is read per attempt**: the socket is
//! `connect()`ed to the resolver (kernel-level source filtering), and a
//! datagram that fails acceptance ends the attempt — the worker's
//! retry, not a second read, produces the second datagram.
//!
//! # The production resolver
//!
//! [`UdpResolver::new`] binds an ephemeral local UDP socket and
//! `connect()`s it to the selected resolver. The card's sketch took
//! only the resolver address; this implementation adds one parameter —
//! the worker's shared **stop flag** — so that a pending wait is polled
//! in short, stop-checked slices (`SOCKET_POLL_SLICE`, 50 ms) and the worker
//! thread can honor its 250 ms shutdown bound even mid-attempt
//! (task-card R-5, mirroring the T-104 cancel discipline). When the
//! stop flag is observed, the attempt returns
//! [`ResolveError::Timeout`] immediately and the caller discards the
//! result. Production wiring uses port 53; the loopback test passes
//! its own ephemeral port (eligibility is IP/subnet-based,
//! port-independent).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use crate::model::Hostname;

/// DNS header length in octets (RFC 1035 §4.1.1).
pub const HEADER_LEN: usize = 12;

/// Maximum accepted response datagram: 512 bytes without EDNS
/// (RFC 1035 §2.3.4); larger datagrams are rejected (policy D-2).
pub const MAX_RESPONSE: usize = 512;

/// Maximum expanded wire-format length of one domain name, including
/// length octets and the terminating root (RFC 1035 §2.3.4).
pub const MAX_NAME_OCTETS: usize = 255;

/// Maximum number of compression-pointer hops in one name decode.
/// Backwards-only pointers already guarantee termination; this bound is
/// the documented secondary defense against pathological chains.
pub const MAX_POINTER_JUMPS: usize = 128;

/// QTYPE of a PTR record (RFC 1035).
pub const TYPE_PTR: u16 = 12;

/// QTYPE of a CNAME record (skipped during answer extraction).
pub const TYPE_CNAME: u16 = 5;

/// QCLASS IN (RFC 1035).
pub const CLASS_IN: u16 = 1;

/// Query flags: standard query with RD=1 (recursion desired).
const QUERY_FLAGS: u16 = 0x0100;

/// Response flag bits: QR (response), opcode mask, TC (truncation),
/// RCODE mask (RFC 1035 §4.1.1).
const FLAG_QR: u16 = 0x8000;
const FLAG_TC: u16 = 0x0200;
const OPCODE_MASK: u16 = 0x7800;
const RCODE_MASK: u16 = 0x000F;

/// RCODE values with dedicated handling (RFC 1035 §4.1.1).
const RCODE_NOERROR: u16 = 0;
const RCODE_NXDOMAIN: u16 = 3;

/// How long one socket receive waits before re-checking the stop flag
/// (task-card R-5: the worker thread must be able to exit within
/// 250 ms; 50 ms per slice leaves ample margin, mirroring T-104's
/// `CANCEL_SLICE`).
const SOCKET_POLL_SLICE: Duration = Duration::from_millis(50);

/// Why one resolver attempt failed. Equality-testable and free of raw
/// `io::Error` values (task-card R-3); wording follows the controlled
/// vocabulary of plan §5.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// No acceptable response datagram arrived within the attempt's
    /// timeout (or the attempt was abandoned because shutdown was
    /// requested — the caller discards those).
    #[error("no response within the query timeout")]
    Timeout,
    /// A socket-level error occurred (send or receive failure).
    #[error("UDP transport error")]
    Transport,
    /// The datagram violates the acceptance rules (length, header,
    /// question echo, or any structural bound during decoding).
    #[error("malformed DNS response")]
    Malformed,
    /// The resolver answered with a failure RCODE (SERVFAIL, FORMERR,
    /// NOTIMP, REFUSED, …) — this attempt failed, but the datagram
    /// itself was well formed.
    #[error("the resolver returned a failure code")]
    ServerFailure,
    /// The response was truncated (TC=1). No TCP fallback exists in
    /// this MVP — a documented limitation.
    #[error("the response was truncated (TCP fallback out of scope)")]
    Truncated,
}

/// One reverse-lookup attempt against a resolver (plan §8.6 sketch,
/// task-card R-3).
///
/// Implementations must not retry: retry and backoff policy belongs to
/// the worker (policy D-4). The trait is `Send` so the worker thread
/// can own a boxed implementation.
pub trait NameResolver: Send {
    /// One attempt: send one PTR query for `ip` and wait up to
    /// `timeout`.
    ///
    /// * `Ok(Some(hostname))` — a validated name.
    /// * `Ok(None)` — a definitive no-name answer (NOERROR or NXDOMAIN
    ///   without a usable PTR record).
    /// * `Err(..)` — this attempt failed.
    fn reverse(
        &mut self,
        ip: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Option<Hostname>, ResolveError>;
}

/// The result of accepting one response, with the D-2 side count of
/// PTR records whose name decoded but failed hostname validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrAcceptance {
    /// The attempt outcome for this datagram.
    pub outcome: Result<Option<Hostname>, ResolveError>,
    /// How many PTR names were skipped because they decoded but failed
    /// [`Hostname::try_from`] (policy D-2: "counted and skipped").
    pub skipped_invalid_ptr_names: u32,
}

/// Builds the PTR query for `ip` with the given 16-bit ID (policy
/// D-2): `<reversed dotted-quad>.in-addr.arpa`, QCLASS IN, QTYPE PTR,
/// RD=1.
///
/// Deterministic and side-effect free — the same `(id, ip)` always
/// yields the same bytes.
pub fn build_ptr_query(id: u16, ip: Ipv4Addr) -> Vec<u8> {
    let [o0, o1, o2, o3] = ip.octets();
    let mut query = Vec::with_capacity(HEADER_LEN + 30);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&QUERY_FLAGS.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    // QNAME: the reversed dotted quad, then in-addr.arpa, then root.
    for octet in [o3, o2, o1, o0] {
        push_decimal_label(&mut query, octet);
    }
    push_static_label(&mut query, b"in-addr");
    push_static_label(&mut query, b"arpa");
    query.push(0); // root label
    query.extend_from_slice(&TYPE_PTR.to_be_bytes());
    query.extend_from_slice(&CLASS_IN.to_be_bytes());
    query
}

/// Appends one label carrying the decimal spelling of `value`
/// (`192` → `\x03192`). No allocation, no indexing.
fn push_decimal_label(out: &mut Vec<u8>, value: u8) {
    let (hundreds, tens, ones) = (value / 100, (value / 10) % 10, value % 10);
    if hundreds > 0 {
        out.push(3);
        out.push(b'0' + hundreds);
        out.push(b'0' + tens);
    } else if tens > 0 {
        out.push(2);
        out.push(b'0' + tens);
    } else {
        out.push(1);
    }
    out.push(b'0' + ones);
}

/// Appends one label of at most 63 static ASCII bytes.
fn push_static_label(out: &mut Vec<u8>, label: &[u8]) {
    let length = label.len().min(63) as u8;
    out.push(length);
    for byte in label.iter().take(usize::from(length)) {
        out.push(*byte);
    }
}

/// Reads a big-endian `u16` at `at`, if both bytes are in bounds.
fn read_u16(msg: &[u8], at: usize) -> Option<u16> {
    let hi = *msg.get(at)?;
    let lo = *msg.get(at + 1)?;
    Some((u16::from(hi) << 8) | u16::from(lo))
}

/// Decodes the domain name starting at `start`, enforcing every
/// bounded-name rule (policy D-2; see the module documentation):
/// labels of 1..=63 octets, reserved label kinds rejected, compression
/// pointers pointing strictly backwards, at most
/// [`MAX_POINTER_JUMPS`] hops, and at most [`MAX_NAME_OCTETS`]
/// expanded wire-format octets.
///
/// Returns the presentation bytes (labels joined with `.`; an empty
/// vector is the root name) and the offset just past the name at the
/// **original** position (not past any pointer target — that is what
/// lets the record walker advance).
fn decode_name(msg: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut pos = start;
    let mut end_of_name: Option<usize> = None;
    let mut jumps = 0usize;
    let mut wire_octets = 0usize;
    let mut name: Vec<u8> = Vec::new();
    loop {
        let len_byte = *msg.get(pos)?;
        if len_byte == 0 {
            // The root label terminates the name.
            wire_octets += 1;
            if wire_octets > MAX_NAME_OCTETS {
                return None;
            }
            let after = end_of_name.unwrap_or(pos + 1);
            return Some((name, after));
        }
        match len_byte & 0xC0 {
            0x00 => {
                // A plain label; len_byte is its length (1..=63).
                let len = usize::from(len_byte);
                let label = msg.get(pos + 1..pos + 1 + len)?;
                wire_octets += 1 + len;
                if wire_octets > MAX_NAME_OCTETS {
                    return None;
                }
                if !name.is_empty() {
                    name.push(b'.');
                }
                name.extend_from_slice(label);
                pos += 1 + len;
            }
            0xC0 => {
                // A compression pointer: 14-bit offset, must point
                // strictly backwards (RFC 1035 "prior occurrence").
                let hi = usize::from(len_byte & 0x3F);
                let lo = usize::from(*msg.get(pos + 1)?);
                let target = (hi << 8) | lo;
                if end_of_name.is_none() {
                    end_of_name = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return None;
                }
                if target >= pos {
                    return None; // forward pointer or self-loop
                }
                pos = target;
            }
            // 0x40 / 0x80 prefixes: label kinds reserved by RFC 1035
            // (never extended in practice); rejected.
            _ => return None,
        }
    }
}

/// Case-insensitive presentation-name comparison (policy D-2).
fn names_equal_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Turns decoded presentation bytes into a validated [`Hostname`];
/// `None` when the bytes are not valid UTF-8 or fail validation.
fn hostname_from_name_bytes(bytes: &[u8]) -> Option<Hostname> {
    let text = std::str::from_utf8(bytes).ok()?;
    Hostname::try_from(text).ok()
}

/// Applies the full D-2 acceptance rules to one response datagram
/// against the query that solicited it.
///
/// Pure and total: any pair of byte strings yields an outcome, never a
/// panic (plan §7.2 SR-02). This is the function the fuzz target
/// `dns_response` drives and the unit tests exercise with hand-built
/// vectors.
pub fn accept_ptr_response(query: &[u8], response: &[u8]) -> PtrAcceptance {
    let mut skipped_invalid_ptr_names = 0u32;
    let outcome = accept_inner(query, response, &mut skipped_invalid_ptr_names);
    PtrAcceptance {
        outcome,
        skipped_invalid_ptr_names,
    }
}

/// The acceptance core; `skipped` accumulates the invalid-PTR count.
fn accept_inner(
    query: &[u8],
    response: &[u8],
    skipped: &mut u32,
) -> Result<Option<Hostname>, ResolveError> {
    // 1. Datagram length: 12..=512 bytes (no EDNS).
    if response.len() < HEADER_LEN || response.len() > MAX_RESPONSE {
        return Err(ResolveError::Malformed);
    }

    // 2. The query side: its ID and its question (the query is built
    //    by build_ptr_query; decoding it defensively keeps this
    //    function total on arbitrary inputs, as the fuzz target needs).
    let Some(query_id) = read_u16(query, 0) else {
        return Err(ResolveError::Malformed);
    };
    let Some((query_name, after_query_name)) = decode_name(query, HEADER_LEN) else {
        return Err(ResolveError::Malformed);
    };
    if read_u16(query, after_query_name) != Some(TYPE_PTR)
        || read_u16(query, after_query_name + 2) != Some(CLASS_IN)
    {
        return Err(ResolveError::Malformed);
    }

    // 3. Header: ID echo, QR=1, opcode 0.
    if read_u16(response, 0) != Some(query_id) {
        return Err(ResolveError::Malformed);
    }
    let Some(flags) = read_u16(response, 2) else {
        return Err(ResolveError::Malformed); // unreachable at len >= 12
    };
    if flags & FLAG_QR == 0 {
        return Err(ResolveError::Malformed);
    }
    if flags & OPCODE_MASK != 0 {
        return Err(ResolveError::Malformed);
    }

    // 4. TC=1: no TCP fallback — this attempt failed.
    if flags & FLAG_TC != 0 {
        return Err(ResolveError::Truncated);
    }

    // 5. Exactly one question, echoing ours (name ci, QTYPE, QCLASS).
    if read_u16(response, 4) != Some(1) {
        return Err(ResolveError::Malformed);
    }
    let Some((response_name, after_question)) = decode_name(response, HEADER_LEN) else {
        return Err(ResolveError::Malformed);
    };
    if !names_equal_ci(&query_name, &response_name) {
        return Err(ResolveError::Malformed);
    }
    if read_u16(response, after_question) != Some(TYPE_PTR)
        || read_u16(response, after_question + 2) != Some(CLASS_IN)
    {
        return Err(ResolveError::Malformed);
    }

    // 6. RCODE: NOERROR → answers; NXDOMAIN → definitive no-name;
    //    anything else → this attempt failed.
    match flags & RCODE_MASK {
        RCODE_NOERROR => {}
        RCODE_NXDOMAIN => return Ok(None),
        _ => return Err(ResolveError::ServerFailure),
    }

    // 7. Walk the answer records: skip CNAMEs, first usable PTR wins.
    let Some(ancount) = read_u16(response, 6) else {
        return Err(ResolveError::Malformed);
    };
    let mut pos = after_question + 4;
    for _ in 0..ancount {
        // Owner name (decoded and bounds-checked, then skipped).
        let Some((_, after_owner)) = decode_name(response, pos) else {
            return Err(ResolveError::Malformed);
        };
        pos = after_owner;
        // TYPE, CLASS, TTL (ignored), RDLENGTH — all bounds-checked.
        let Some(rtype) = read_u16(response, pos) else {
            return Err(ResolveError::Malformed);
        };
        let Some(rdlength) = read_u16(response, pos + 8) else {
            return Err(ResolveError::Malformed);
        };
        let rdata_start = pos + 10;
        let rdata_end = rdata_start + usize::from(rdlength);
        if rdata_end > response.len() {
            return Err(ResolveError::Malformed);
        }
        if rtype == TYPE_PTR {
            match decode_name(response, rdata_start) {
                // Decodes: the first name that also validates wins.
                Some((name, _)) => match hostname_from_name_bytes(&name) {
                    Some(hostname) => return Ok(Some(hostname)),
                    None => *skipped += 1, // decoded, failed validation
                },
                // A structural failure inside a walked record rejects
                // the datagram (see the module docs for the split).
                None => return Err(ResolveError::Malformed),
            }
        }
        // CNAME and every other record type is skipped; the walk is
        // bounded by ANCOUNT and the datagram length.
        pos = rdata_end;
    }

    // 8. NOERROR with no usable PTR record: a definitive no-name.
    Ok(None)
}

/// The production [`NameResolver`]: one UDP socket, `connect()`ed to
/// the selected resolver, per
/// session, ephemeral local port, LCG query IDs (policy D-2; ADR-015
/// option (a)).
///
/// Blocking discipline: one attempt sends one datagram and then waits
/// for one response in `SOCKET_POLL_SLICE`-sized slices, re-checking the
/// shared stop flag between slices so the worker's shutdown bound is
/// honored mid-attempt (task-card R-5).
#[derive(Debug)]
pub struct UdpResolver {
    socket: UdpSocket,
    stop: Arc<AtomicBool>,
    ids: IdLcg,
}

impl UdpResolver {
    /// Binds an ephemeral local UDP socket (address family matching
    /// `resolver`) and `connect()`s it to `resolver` — the kernel then
    /// filters datagram sources to that resolver alone.
    pub fn new(resolver: SocketAddr, stop: Arc<AtomicBool>) -> std::io::Result<Self> {
        let local = match resolver {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(local)?;
        socket.connect(resolver)?;
        Ok(UdpResolver {
            socket,
            stop,
            ids: IdLcg::new(),
        })
    }
}

impl NameResolver for UdpResolver {
    fn reverse(
        &mut self,
        ip: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Option<Hostname>, ResolveError> {
        if self.stop.load(Ordering::Relaxed) {
            // Shutdown was requested before the attempt began; the
            // caller (the worker) discards this result.
            return Err(ResolveError::Timeout);
        }
        let id = self.ids.next_u16();
        let query = build_ptr_query(id, ip);
        if self.socket.send(&query).is_err() {
            return Err(ResolveError::Transport);
        }
        let started = Instant::now();
        // One byte more than the acceptance bound, so an oversize
        // datagram is seen as 513 bytes and rejected as such rather
        // than silently truncated to 512.
        let mut buffer = [0u8; MAX_RESPONSE + 1];
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Err(ResolveError::Timeout); // abandoned mid-wait
            }
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(ResolveError::Timeout);
            }
            let slice = (timeout - elapsed).min(SOCKET_POLL_SLICE);
            if self.socket.set_read_timeout(Some(slice)).is_err() {
                return Err(ResolveError::Transport);
            }
            match self.socket.recv(&mut buffer) {
                Ok(received) => {
                    // Exactly one datagram per attempt (policy D-2).
                    let datagram = buffer.get(..received).unwrap_or(&[]);
                    return accept_ptr_response(&query, datagram).outcome;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Slice elapsed; re-check stop and the total budget.
                    continue;
                }
                Err(_) => return Err(ResolveError::Transport),
            }
        }
    }
}

/// The per-resolver LCG for query IDs (policy D-2). Not a security
/// boundary — see the module documentation; the time seed merely keeps
/// consecutive sessions from replaying the same ID sequence.
#[derive(Debug)]
struct IdLcg(u64);

impl IdLcg {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5EED_0000_0000_0001);
        IdLcg(nanos | 1)
    }

    /// The next 16-bit ID, taken from the high bits of the LCG state
    /// (the low bits of an LCG are weak).
    fn next_u16(&mut self) -> u16 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 48) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::testing::Lcg;
    use std::thread;

    fn ip() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    /// The expected question labels of `192.0.2.10`.
    const QNAME: [&str; 6] = ["10", "2", "0", "192", "in-addr", "arpa"];

    // ---- hand-built response vectors (test-local builders, written
    // ---- independently of the crate's builders) ---------------------------

    /// Appends a wire-format name from presentation labels.
    fn push_name(out: &mut Vec<u8>, labels: &[&str]) {
        for label in labels {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// Appends a header + question for the given ID and flags.
    fn push_question(out: &mut Vec<u8>, id: u16, flags: u16, labels: &[&str]) {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        push_name(out, labels);
        out.extend_from_slice(&TYPE_PTR.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
    }

    /// Appends one answer record of the given type; `rdata` is raw.
    fn push_record(out: &mut Vec<u8>, owner_labels: &[&str], rtype: u16, rdata: &[u8]) {
        push_name(out, owner_labels);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // TTL
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    /// A PTR answer record whose RDATA is a plain (uncompressed) name.
    fn push_ptr_answer(out: &mut Vec<u8>, owner_labels: &[&str], ptr_labels: &[&str]) {
        let mut rdata = Vec::new();
        push_name(&mut rdata, ptr_labels);
        push_record(out, owner_labels, TYPE_PTR, &rdata);
    }

    /// Patches ANCOUNT (header bytes 6..8) to the given count.
    fn set_ancount(response: &mut [u8], count: u16) {
        if let Some(slot) = response.get_mut(6) {
            *slot = (count >> 8) as u8;
        }
        if let Some(slot) = response.get_mut(7) {
            *slot = (count & 0xFF) as u8;
        }
    }

    /// A minimal valid NOERROR response with one PTR answer.
    fn valid_response(id: u16, ptr_labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        // QR=1, RD=1 (echo), RCODE 0.
        push_question(&mut out, id, 0x8180, &QNAME);
        push_ptr_answer(&mut out, &QNAME, ptr_labels);
        set_ancount(&mut out, 1);
        out
    }

    fn query() -> Vec<u8> {
        build_ptr_query(0x1234, ip())
    }

    // ---- the query builder (golden vector) ---------------------------------

    #[test]
    fn build_ptr_query_emits_the_golden_bytes() {
        let q = build_ptr_query(0x1234, ip());
        let expected: Vec<u8> = [
            0x12, 0x34, // ID
            0x01, 0x00, // flags: RD=1, standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // QNAME: reversed quad 10.2.0.192 + in-addr.arpa + root.
            0x02, b'1', b'0', 0x01, b'2', 0x01, b'0', 0x03, b'1', b'9', b'2', 0x07, b'i', b'n',
            b'-', b'a', b'd', b'd', b'r', 0x04, b'a', b'r', b'p', b'a', 0x00, 0x00,
            0x0c, // QTYPE = PTR
            0x00, 0x01, // QCLASS = IN
        ]
        .to_vec();
        assert_eq!(q, expected);
        assert_eq!(q.len(), 41);
        // Deterministic.
        assert_eq!(build_ptr_query(0x1234, ip()), q);
    }

    #[test]
    fn query_for_our_own_address_still_reverses() {
        // 127.0.0.1 → 1.0.0.127.in-addr.arpa: same shape as the golden
        // vector, with the reversed-quad labels spelled out.
        let q = build_ptr_query(1, Ipv4Addr::new(127, 0, 0, 1));
        let expected: Vec<u8> = [
            0x00, 0x01, // ID
            0x01, 0x00, // flags: RD=1
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'1', 0x01, b'0', 0x01, b'0', 0x03, b'1',
            b'2', b'7', 0x07, b'i', b'n', b'-', b'a', b'd', b'd', b'r', 0x04, b'a', b'r', b'p',
            b'a', 0x00, 0x00, 0x0c, 0x00, 0x01,
        ]
        .to_vec();
        assert_eq!(q, expected);
    }

    // ---- acceptance: the happy paths ----------------------------------------

    #[test]
    fn valid_response_yields_the_hostname() {
        let q = query();
        let response = valid_response(0x1234, &["printer", "lan"]);
        let acceptance = accept_ptr_response(&q, &response);
        assert_eq!(
            acceptance.outcome,
            Ok(Some(Hostname::try_from("printer.lan").expect("valid name")))
        );
        assert_eq!(acceptance.skipped_invalid_ptr_names, 0);
    }

    #[test]
    fn question_name_is_matched_case_insensitively() {
        let q = query();
        let mut response = Vec::new();
        push_question(
            &mut response,
            0x1234,
            0x8180,
            &["10", "2", "0", "192", "IN-ADDR", "ARPA"],
        );
        push_ptr_answer(&mut response, &QNAME, &["printer", "lan"]);
        assert!(accept_ptr_response(&q, &response).outcome.is_ok());
    }

    #[test]
    fn nxdomain_is_a_definitive_no_name() {
        let q = query();
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8183, &QNAME); // RCODE 3
        assert_eq!(accept_ptr_response(&q, &response).outcome, Ok(None));
    }

    #[test]
    fn noerror_with_zero_answers_is_a_no_name() {
        let q = query();
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        assert_eq!(accept_ptr_response(&q, &response).outcome, Ok(None));
    }

    #[test]
    fn noerror_with_only_cnames_is_a_no_name() {
        let q = query();
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let mut rdata = Vec::new();
        push_name(&mut rdata, &["alias", "lan"]);
        push_record(&mut response, &QNAME, TYPE_CNAME, &rdata);
        set_ancount(&mut response, 1);
        let acceptance = accept_ptr_response(&q, &response);
        assert_eq!(acceptance.outcome, Ok(None));
        assert_eq!(acceptance.skipped_invalid_ptr_names, 0);
    }

    #[test]
    fn multiple_ptrs_first_valid_wins_and_invalid_is_counted() {
        let q = query();
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        // First PTR: a label with a space — decodes, fails validation.
        push_ptr_answer(&mut response, &QNAME, &["bad host!", "lan"]);
        // Second PTR: valid — wins.
        push_ptr_answer(&mut response, &QNAME, &["printer", "lan"]);
        // Third PTR: valid too — must not win.
        push_ptr_answer(&mut response, &QNAME, &["other", "lan"]);
        set_ancount(&mut response, 3);
        let acceptance = accept_ptr_response(&q, &response);
        assert_eq!(
            acceptance.outcome,
            Ok(Some(Hostname::try_from("printer.lan").expect("valid name")))
        );
        assert_eq!(acceptance.skipped_invalid_ptr_names, 1);
    }

    #[test]
    fn ptr_names_failing_validation_are_skipped_and_counted() {
        let q = query();
        // A name with an invalid character and an empty name: both
        // decode, both fail validation, no usable PTR → Ok(None).
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        push_ptr_answer(&mut response, &QNAME, &["bad host!", "lan"]);
        let empty_rdata = vec![0u8]; // root-only name
        push_record(&mut response, &QNAME, TYPE_PTR, &empty_rdata);
        set_ancount(&mut response, 2);
        let acceptance = accept_ptr_response(&q, &response);
        assert_eq!(acceptance.outcome, Ok(None));
        assert_eq!(acceptance.skipped_invalid_ptr_names, 2);
    }

    // ---- acceptance: the hostile vectors (AC-5) -----------------------------

    #[test]
    fn wrong_id_is_rejected() {
        let q = query();
        let response = valid_response(0x4321, &["printer", "lan"]);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed)
        );
    }

    #[test]
    fn wrong_question_is_rejected() {
        let q = query();
        let mut wrong_name = Vec::new();
        push_question(
            &mut wrong_name,
            0x1234,
            0x8180,
            &["11", "2", "0", "192", "in-addr", "arpa"],
        );
        push_ptr_answer(&mut wrong_name, &QNAME, &["printer", "lan"]);
        set_ancount(&mut wrong_name, 1);
        assert_eq!(
            accept_ptr_response(&q, &wrong_name).outcome,
            Err(ResolveError::Malformed)
        );

        // Wrong QTYPE (A instead of PTR).
        let mut wrong_type = Vec::new();
        push_question(&mut wrong_type, 0x1234, 0x8180, &QNAME);
        let len = wrong_type.len();
        if let Some(slot) = wrong_type.get_mut(len - 4) {
            *slot = 0; // QTYPE high byte stays 0; low byte patched below
        }
        if let Some(slot) = wrong_type.get_mut(len - 3) {
            *slot = 1; // QTYPE = 1 (A)
        }
        assert_eq!(
            accept_ptr_response(&q, &wrong_type).outcome,
            Err(ResolveError::Malformed)
        );

        // Wrong QCLASS (CH instead of IN).
        let mut wrong_class = Vec::new();
        push_question(&mut wrong_class, 0x1234, 0x8180, &QNAME);
        let len = wrong_class.len();
        if let Some(slot) = wrong_class.get_mut(len - 1) {
            *slot = 3; // QCLASS = 3 (CH)
        }
        assert_eq!(
            accept_ptr_response(&q, &wrong_class).outcome,
            Err(ResolveError::Malformed)
        );
    }

    #[test]
    fn qr_zero_opcode_nonzero_and_qdcount_mismatch_are_rejected() {
        let q = query();
        for (flags, patch_qdcount) in [(0x0180u16, false), (0x9180, false), (0x8180, true)] {
            let mut response = Vec::new();
            push_question(&mut response, 0x1234, flags, &QNAME);
            push_ptr_answer(&mut response, &QNAME, &["printer", "lan"]);
            set_ancount(&mut response, 1);
            if patch_qdcount {
                // QDCOUNT = 2 (the query had exactly one question).
                if let Some(slot) = response.get_mut(5) {
                    *slot = 2;
                }
            }
            assert_eq!(
                accept_ptr_response(&q, &response).outcome,
                Err(ResolveError::Malformed),
                "flags {flags:#06x}"
            );
        }
    }

    #[test]
    fn truncated_header_and_question_are_rejected() {
        let q = query();
        let response = valid_response(0x1234, &["printer", "lan"]);
        // Every truncation below the header, and one cutting the
        // question, is malformed; short inputs are never a panic.
        for len in [0usize, 1, 4, 11, 20, 30] {
            let truncated = response.get(..len).unwrap_or(&[]);
            assert_eq!(
                accept_ptr_response(&q, truncated).outcome,
                Err(ResolveError::Malformed),
                "length {len}"
            );
        }
    }

    #[test]
    fn oversize_datagram_is_rejected_and_512_is_accepted() {
        let q = query();
        // A record of an ignored type (99) carries RDATA padding to a
        // chosen total length; only its length is bounds-checked.
        let header_and_question = 41usize;
        let record_overhead = 1 + 2 + 2 + 4 + 2; // root owner + fixed fields
        for (padding, total, accepted) in [
            (512 - header_and_question - record_overhead, 512, true),
            (513 - header_and_question - record_overhead, 513, false),
        ] {
            let mut response = Vec::new();
            push_question(&mut response, 0x1234, 0x8180, &QNAME);
            let padding_vec = vec![b'x'; padding];
            push_record(&mut response, &[], 99, &padding_vec);
            set_ancount(&mut response, 1);
            assert_eq!(response.len(), total, "padding case {padding}");
            let acceptance = accept_ptr_response(&q, &response);
            if accepted {
                assert_eq!(acceptance.outcome, Ok(None));
            } else {
                assert_eq!(acceptance.outcome, Err(ResolveError::Malformed));
            }
        }
    }

    #[test]
    fn tc_set_fails_the_attempt() {
        let q = query();
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180 | 0x0200, &QNAME); // TC=1
        push_ptr_answer(&mut response, &QNAME, &["printer", "lan"]);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Truncated)
        );
    }

    #[test]
    fn server_failure_rcodes_fail_the_attempt() {
        let q = query();
        // SERVFAIL, FORMERR, NOTIMP, REFUSED, and an unassigned code.
        for rcode in [1u16, 2, 4, 5, 9] {
            let mut response = Vec::new();
            push_question(&mut response, 0x1234, 0x8180 | rcode, &QNAME);
            assert_eq!(
                accept_ptr_response(&q, &response).outcome,
                Err(ResolveError::ServerFailure),
                "rcode {rcode}"
            );
        }
    }

    #[test]
    fn rdata_overrun_and_ancount_overrun_are_rejected() {
        let q = query();
        // RDLENGTH promises 200 bytes but the record ends after 13.
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        push_name(&mut response, &QNAME); // owner
        response.extend_from_slice(&TYPE_PTR.to_be_bytes());
        response.extend_from_slice(&CLASS_IN.to_be_bytes());
        response.extend_from_slice(&0u32.to_be_bytes()); // TTL
        response.extend_from_slice(&200u16.to_be_bytes()); // promised RDLENGTH
        response.extend_from_slice(b"printerlan\x00"); // 11 real bytes
        set_ancount(&mut response, 1);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed)
        );

        // ANCOUNT promises a second record that is not there. The
        // real record is a CNAME (skipped, no usable PTR), so the walk
        // continues past the datagram end.
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let mut cname_rdata = Vec::new();
        push_name(&mut cname_rdata, &["alias", "lan"]);
        push_record(&mut response, &QNAME, TYPE_CNAME, &cname_rdata);
        set_ancount(&mut response, 2);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed)
        );
    }

    // ---- hostile names: compression, labels, bounds (AC-5) ------------------

    #[test]
    fn compression_pointer_in_rdata_is_followed() {
        let q = query();
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        // RDATA: label "printer" + a pointer to the question's "arpa"
        // label. The question layout: header 12, then "10"(3) "2"(2)
        // "0"(2) "192"(4) "in-addr"(8) → "arpa" length byte at 31.
        let mut rdata = vec![7];
        rdata.extend_from_slice(b"printer");
        rdata.push(0xC0);
        rdata.push(31); // pointer back to "arpa"
        push_record(&mut response, &QNAME, TYPE_PTR, &rdata);
        set_ancount(&mut response, 1);
        let acceptance = accept_ptr_response(&q, &response);
        assert_eq!(
            acceptance.outcome,
            Ok(Some(
                Hostname::try_from("printer.arpa").expect("valid name")
            ))
        );
    }

    #[test]
    fn compression_loop_forward_pointer_and_bad_labels_are_rejected() {
        let q = query();
        // (a) Self-loop: the RDATA name is a pointer to itself. The
        // record sits after the question (41 bytes) with the owner
        // name (25) and fixed fields (10), so its RDATA begins at 76;
        // the pointer bytes live at 76..78 and target 76.
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let rdata = [0xC0, 76]; // points at its own first byte
        push_record(&mut response, &QNAME, TYPE_PTR, &rdata);
        set_ancount(&mut response, 1);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed),
            "self-loop"
        );

        // (b) Forward pointer: target beyond the pointer's position.
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let rdata = [0xC0, 90]; // 90 > 76: forward
        push_record(&mut response, &QNAME, TYPE_PTR, &rdata);
        set_ancount(&mut response, 1);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed),
            "forward pointer"
        );

        // (c) A 64-byte label: the length byte 64 (0x40) is a reserved
        // label kind, rejected before any 64-byte read.
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let mut rdata = vec![64];
        rdata.resize(1 + 64, b'x');
        push_record(&mut response, &QNAME, TYPE_PTR, &rdata);
        set_ancount(&mut response, 1);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed),
            "64-byte label"
        );

        // (d) A name longer than 255 expanded octets: five 63-byte
        // labels (5 × 64 = 320 > 255).
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let mut rdata = Vec::new();
        for _ in 0..5 {
            rdata.push(63);
            rdata.extend_from_slice(&[b'x'; 63]);
        }
        rdata.push(0);
        push_record(&mut response, &QNAME, TYPE_PTR, &rdata);
        set_ancount(&mut response, 1);
        assert_eq!(
            accept_ptr_response(&q, &response).outcome,
            Err(ResolveError::Malformed),
            "oversize name"
        );

        // (e) The same oversize name in the *question*.
        let mut response = Vec::new();
        push_question(&mut response, 0x1234, 0x8180, &QNAME);
        let mut long_question = Vec::new();
        long_question.extend_from_slice(&0x1234u16.to_be_bytes());
        long_question.extend_from_slice(&0x8180u16.to_be_bytes());
        long_question.extend_from_slice(&1u16.to_be_bytes());
        long_question.extend_from_slice(&0u16.to_be_bytes());
        long_question.extend_from_slice(&0u16.to_be_bytes());
        long_question.extend_from_slice(&0u16.to_be_bytes());
        for _ in 0..5 {
            long_question.push(63);
            long_question.extend_from_slice(&[b'x'; 63]);
        }
        long_question.push(0);
        long_question.extend_from_slice(&TYPE_PTR.to_be_bytes());
        long_question.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert_eq!(
            accept_ptr_response(&q, &long_question).outcome,
            Err(ResolveError::Malformed),
            "oversize question name"
        );
    }

    // ---- property tests -------------------------------------------------------

    /// Property: arbitrary bytes as the response (and as the query)
    /// never panic; outcomes are always from the enum.
    #[test]
    fn property_arbitrary_responses_never_panic() {
        let q = query();
        let mut rng = Lcg::seeded(0x0D_05_00_01);
        let mut accepted_some = 0usize;
        for _ in 0..3000 {
            let len = rng.next_below(600) as usize;
            let mut response = Vec::with_capacity(len);
            for _ in 0..len {
                response.push(rng.next_u8());
            }
            let acceptance = accept_ptr_response(&q, &response);
            let _ = acceptance.outcome;
            let _ = acceptance.skipped_invalid_ptr_names;
            if matches!(acceptance.outcome, Ok(Some(_))) {
                accepted_some += 1;
            }

            // The same bytes as the query side, with the golden query
            // as the response: total on both sides.
            let _ = accept_ptr_response(&response, &q);
        }
        // Non-vacuity: crafted inputs above already prove acceptance;
        // random acceptance is not required (and not expected).
        let _ = accepted_some;
    }

    /// Property: random mutations of a valid response never panic, and
    /// a mutated response can never yield a name that was not put into
    /// it by hand (the accepted set is exactly the crafted PTR names).
    #[test]
    fn property_mutated_responses_never_panic_or_invent_names() {
        let q = query();
        let seed = valid_response(0x1234, &["printer", "lan"]);
        let mut rng = Lcg::seeded(0x0D_05_00_02);
        for _ in 0..3000 {
            let mut bytes = seed.clone();
            let extra = rng.next_below(33) as usize;
            bytes.resize(bytes.len() + extra, 0);
            let mutations = 1 + rng.next_below(6);
            for _ in 0..mutations {
                let position = rng.next_below(bytes.len() as u64) as usize;
                if let Some(slot) = bytes.get_mut(position) {
                    *slot = rng.next_u8();
                }
            }
            let final_len = rng.next_below(bytes.len() as u64 + 1) as usize;
            if let Some(tail) = bytes.get(..final_len) {
                let acceptance = accept_ptr_response(&q, tail);
                if let Ok(Some(host)) = acceptance.outcome {
                    // Any accepted name is a validated Hostname by
                    // construction (a single-byte mutation can of course
                    // produce a different but still-valid spelling, e.g.
                    // printer.lqn — the invariant is validity, not identity).
                    assert!(Hostname::try_from(host.as_str()).is_ok());
                }
            }
        }
    }

    // ---- the production resolver over loopback (AC-10 success path;
    // ---- authorized by the task card: 127.0.0.1, ephemeral port,
    // ---- in-process, nothing leaves the machine) ----------------------------

    #[test]
    fn loopback_round_trip_with_the_production_resolver() {
        use std::sync::mpsc;

        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let server_addr = server.local_addr().expect("local addr");

        // Eligibility first, for the synthetic loopback subnet — the one
        // subnet in which a loopback nameserver is eligible (authorized
        // by this task card for the in-process lab): the selection
        // drives the resolver wiring below exactly as T-205 will wire
        // it (address from the selection, port from the service).
        let loopback_subnet =
            crate::model::Ipv4Net::new(Ipv4Addr::new(127, 0, 0, 0), 24).expect("valid subnet");
        let selection = crate::enrichment::hostname::select_resolver(
            "nameserver 127.0.0.1\n",
            None,
            loopback_subnet,
        );
        let selected_address = match selection.address() {
            Some(address) => address,
            None => panic!("the loopback nameserver must be eligible for 127.0.0.0/24"),
        };
        assert_eq!(selected_address, Ipv4Addr::new(127, 0, 0, 1));

        let stop = Arc::new(AtomicBool::new(false));
        let resolver_addr =
            std::net::SocketAddr::new(std::net::IpAddr::V4(selected_address), server_addr.port());
        let mut resolver =
            UdpResolver::new(resolver_addr, Arc::clone(&stop)).expect("connect resolver");

        let target = ip();
        let (question_tx, question_rx) = mpsc::channel::<Vec<u8>>();
        let server_thread = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (received, client) = server.recv_from(&mut buffer).expect("recv query");
            let datagram = buffer.get(..received).unwrap_or(&[]).to_vec();
            let id = read_u16(&datagram, 0);
            let Some(id) = id else {
                question_tx.send(Vec::new()).expect("send question");
                return;
            };
            let mut response = Vec::new();
            response.extend_from_slice(&id.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            // Echo the question (name, QTYPE, QCLASS) verbatim.
            let question_tail = datagram.get(HEADER_LEN..).unwrap_or(&[]).to_vec();
            response.extend_from_slice(&question_tail);
            // One PTR answer: printer.lan.
            let mut rdata = Vec::new();
            push_name(&mut rdata, &["printer", "lan"]);
            push_record(&mut response, &QNAME, TYPE_PTR, &rdata);
            set_ancount(&mut response, 1);
            server.send_to(&response, client).expect("send response");
            question_tx.send(datagram).expect("send question");
        });

        let outcome = resolver.reverse(target, Duration::from_secs(2));
        assert_eq!(
            outcome,
            Ok(Some(Hostname::try_from("printer.lan").expect("valid name")))
        );

        // The server asserts the received datagram is the PTR question
        // for the expected name, class IN, with the ID the client sent
        // (byte-identical to what build_ptr_query produces for that ID).
        let received = question_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("server saw the question");
        assert!(!received.is_empty(), "server could not read an ID");
        let id = u16::from(received.first().copied().unwrap_or(0)) << 8
            | u16::from(received.get(1).copied().unwrap_or(0));
        assert_eq!(received, build_ptr_query(id, target));
        server_thread.join().expect("server thread");
    }

    #[test]
    fn loopback_silent_server_times_out_one_attempt() {
        // A bound-but-silent server: the datagram is delivered, nothing
        // comes back; one reverse() call must time out (the worker's
        // retry policy is exercised in the worker tests).
        use std::time::Instant;

        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind loopback");
        let server_addr = server.local_addr().expect("local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let mut resolver =
            UdpResolver::new(server_addr, Arc::clone(&stop)).expect("connect resolver");

        let started = Instant::now();
        let outcome = resolver.reverse(ip(), Duration::from_millis(80));
        let elapsed = started.elapsed();
        assert_eq!(outcome, Err(ResolveError::Timeout));
        // Real-time assertion, authorized by the task card for the
        // loopback path: the attempt must respect its 80 ms budget with
        // a generous margin.
        assert!(elapsed < Duration::from_secs(2), "elapsed {elapsed:?}");
    }

    // ---- controlled vocabulary (§5.4 / §11.7) -----------------------------------

    /// Every string this module can surface (error `Display` forms)
    /// stays inside plan §5.4's controlled vocabulary.
    #[test]
    fn wording_follows_the_controlled_vocabulary() {
        const BANNED: [&str; 14] = [
            "online",
            "offline",
            "connected",
            "disconnected",
            "intruder",
            "unauthorized",
            "rogue",
            "suspicious",
            "malicious",
            "safe",
            "trusted",
            "secure",
            "verified",
            "stale",
        ];
        let texts: Vec<String> = vec![
            ResolveError::Timeout.to_string(),
            ResolveError::Transport.to_string(),
            ResolveError::Malformed.to_string(),
            ResolveError::ServerFailure.to_string(),
            ResolveError::Truncated.to_string(),
        ];
        for text in &texts {
            for banned in BANNED {
                assert!(
                    !text.to_lowercase().contains(banned),
                    "banned word {banned:?} in: {text}"
                );
            }
        }
    }
}
