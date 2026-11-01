// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target `arp_frame` — plan §7.2 SR-05, §8.1 (`fuzz/arp_frame.rs`,
//! separate package), task T-103 AC-16.
//!
//! What is fuzzed: [`parse_arp_reply`] and [`build_arp_request`] from
//! `osza_netmon::discovery::arp` — the FR-DS-03 request builder and the
//! total FR-DS-06 reply validator.
//!
//! Why it is std-only: wiring this target into `cargo-fuzz` requires the
//! `libfuzzer-sys` crate, and the T-103 card forbids new dependencies
//! without a Plan Question (§14.5). The target therefore drives the
//! parser with a deterministic PRNG and structure-aware mutations — the
//! same approach as the crate's property tests, at a larger scale — and
//! the card's AC-16 explicitly allows a minimal stub until the fuzzing
//! infrastructure is decided. Promoting this to a real `cargo-fuzz`
//! target (corpus committed, CI smoke run) is a suggested follow-up for
//! the Manager.
//!
//! The stages, in order:
//!
//! 1. known-answer checks — the request builder's output shape, our own
//!    request parsed as a reply (`WrongOpcode`), three valid synthetic
//!    replies (accepted, with exact sender identities), one unsolicited
//!    reply (`NotSolicited`);
//! 2. every truncation of every seed (lengths `0..=seed.len()`);
//! 3. systematic corruption — every offset × every mask of
//!    `{01, 02, 55, 80, ff}` (non-vacuity: the reply's target fields,
//!    offsets 32..42, carry no FR-DS-06 weight, so some corrupted
//!    frames must still be accepted), plus correlated two-site
//!    corruption of the duplicated sender-MAC fields (Ethernet source
//!    and ARP sender MAC patched identically, probing the §5.3
//!    boundary directly);
//! 4. random byte strings of random lengths (`0..=128`);
//! 5. random multi-byte mutations of the seeds — random overwrites plus
//!    a random extension and a random truncation.
//!
//! Every outcome is fed to `ArpReplyCounters` (the counters are fuzzed
//! too) and every accepted reply is checked against an independent
//! re-derivation of the acceptance rules (the oracle below). The target
//! never panics by construction — no asserts, no `unwrap`/`expect`, no
//! indexing, the lints denied in `fuzz/Cargo.toml` — and reports a
//! violation as a message plus exit status 1.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::ExitCode;

use osza_netmon::discovery::arp::{
    ArpReply, ArpReplyContext, ArpReplyCounters, InvalidReply, build_arp_request, parse_arp_reply,
};
use osza_netmon::model::ipv4::Ipv4Net;
use osza_netmon::model::mac::MacAddr;

/// Random-input count for stage 4. Deterministic; raise for longer runs.
const RANDOM_INPUTS: u32 = 400_000;
/// Mutated-input count for stage 5. Deterministic; raise for longer runs.
const MUTATED_INPUTS: u32 = 400_000;
/// How many offending inputs to print before the summary cuts them off.
const MAX_REPORTED_INPUTS: u32 = 8;

/// The fixed header length of an Ethernet+ARP frame — written out as a
/// local literal on purpose: the harness re-derives the layout
/// independently of the crate's constants, so a bug in those constants
/// cannot make the fuzzer agree with the code under test.
const FRAME_LEN: usize = 42;

/// A tiny linear-congruential generator (Knuth constants), mirroring
/// the crate's test-only `model::testing::Lcg` — which is `#[cfg(test)]`
/// and therefore not importable from this package. Not cryptographic;
/// deterministic seeds make every run reproducible.
struct Lcg(u64);

impl Lcg {
    fn seeded(seed: u64) -> Self {
        Lcg(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    /// A value in `0..n`. Callers must pass `n > 0` — division by zero
    /// is the one panic this binary could otherwise reach.
    fn next_below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

/// One fuzz case's verdict: the postcondition oracle failed (`Invalid`),
/// or the outcome was consistent with the rules (`Ok`/`Err` as reported
/// by the parser).
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The parser accepted the frame AND the reply satisfies the
    /// independently re-derived acceptance rules.
    Accepted,
    /// The parser rejected the frame (any reason; the counters tally it).
    Rejected,
    /// The parser accepted a reply that violates the acceptance rules —
    /// a real finding.
    Invalid,
}

/// The acceptance oracle: a re-derivation of FR-DS-06's output
/// contract, written from the plan rather than from the parser's code.
fn acceptance_invariants_hold(reply: &ArpReply, ctx: &ArpReplyContext<'_>) -> bool {
    // Condition 12: solicited-only.
    ctx.is_solicited(reply.sender_ip)
        // Condition 10: inside the scope.
        && ctx.scope().contains(reply.sender_ip)
        // Condition 11: not the interface's own address.
        && reply.sender_ip != ctx.our_ip()
        // Condition 11: not the network/broadcast address (prefixes up
        // to /30 only — /31 uses both addresses, /32 is a single host).
        && (ctx.scope().prefix_len() > 30
            || (reply.sender_ip != ctx.scope().network()
                && reply.sender_ip != ctx.scope().broadcast()))
    // Condition 9: the sender MAC is valid by construction (the
    // T-002 boundary type); nothing further to re-check.
}

/// Runs one input through the parser, records the outcome and checks
/// the oracle.
fn run_case(frame: &[u8], ctx: &ArpReplyContext<'_>, counters: &mut ArpReplyCounters) -> Verdict {
    let outcome = parse_arp_reply(frame, ctx);
    counters.record(&outcome);
    match outcome {
        Ok(reply) if acceptance_invariants_hold(&reply, ctx) => Verdict::Accepted,
        Ok(_) => Verdict::Invalid,
        Err(_) => Verdict::Rejected,
    }
}

/// Lowercase hex rendering of a byte string, for failure reports.
fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// Assembles one Ethernet+ARP reply frame (Appendix E layout, written
/// out locally — see [`FRAME_LEN`]) from the sender identity, with
/// `padding` extra trailing bytes to model the Ethernet minimum-frame
/// padding a real reply carries.
fn reply_frame(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    padding: usize,
    ctx: &ArpReplyContext<'_>,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FRAME_LEN + padding);
    frame.extend_from_slice(&ctx.our_mac().octets()); // Ethernet dst: us
    frame.extend_from_slice(&sender_mac); // Ethernet src: the sender
    frame.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
    frame.extend_from_slice(&1u16.to_be_bytes()); // hardware type: Ethernet
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol type: IPv4
    frame.push(6); // hardware address length
    frame.push(4); // protocol address length
    frame.extend_from_slice(&2u16.to_be_bytes()); // opcode: reply
    frame.extend_from_slice(&sender_mac); // ARP sender MAC
    frame.extend_from_slice(&sender_ip); // ARP sender IP
    frame.extend_from_slice(&ctx.our_mac().octets()); // ARP target MAC (us)
    frame.extend_from_slice(&u32::from(ctx.our_ip()).to_be_bytes()); // ARP target IP (us)
    frame.resize(FRAME_LEN + padding, 0);
    frame
}

/// Runs the fuzz stages; see the module documentation for the list.
///
/// The one narrowly scoped print allow of this package: a fuzz binary
/// reports its own summary on stdout and findings on stderr, exactly
/// like the root `main.rs` pattern for the CLI boundary (plan §7.2
/// SR-03 concerns TUI-reachable code; this binary has none).
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> ExitCode {
    // ---- the fixed synthetic scan (RFC 5737 TEST-NET-1, documentation
    // MACs; plan §14.3 rule 8 — no real identifiers) --------------------
    let our_mac = match MacAddr::from_octets([0x02, 0x00, 0x00, 0xaa, 0xbb, 0x01]) {
        Ok(mac) => mac,
        Err(error) => {
            eprintln!("arp_frame: seed MAC rejected by the boundary constructor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let our_ip = Ipv4Addr::new(192, 0, 2, 1);
    let scope = match Ipv4Net::new(our_ip, 24) {
        Ok(scope) => scope,
        Err(error) => {
            eprintln!("arp_frame: seed scope rejected: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut solicited = HashSet::new();
    solicited.insert(Ipv4Addr::new(192, 0, 2, 10));
    solicited.insert(Ipv4Addr::new(192, 0, 2, 20));
    let ctx = ArpReplyContext::new(our_mac, our_ip, scope, &solicited);

    let mut counters = ArpReplyCounters::default();
    let mut failures: u32 = 0;
    let mut reported: u32 = 0;

    // A violation of the oracle or of a known answer: count it, and
    // print the first few offending inputs.
    let mut flag = |label: &str, input: &[u8], detail: &str| {
        failures += 1;
        if reported < MAX_REPORTED_INPUTS {
            reported += 1;
            eprintln!("arp_frame: {label} ({detail}): {}", hex_string(input));
        }
    };

    // ---- stage 1: known answers ----------------------------------------
    let request = build_arp_request(our_mac, our_ip, Ipv4Addr::new(192, 0, 2, 10));
    if request.len() != FRAME_LEN {
        flag("request builder length", &request, "not 42 bytes");
    }
    // Our own (broadcast) request parsed as a reply: FR-DS-06 checks the
    // opcode (condition 6) before the Ethernet destination (condition 7).
    let outcome = parse_arp_reply(&request, &ctx);
    counters.record(&outcome);
    if !matches!(outcome, Err(InvalidReply::WrongOpcode { .. })) {
        flag(
            "our own request parsed as a reply",
            &request,
            "expected WrongOpcode",
        );
    }

    // Valid seeds: two senders on the two solicited addresses, one with
    // Ethernet padding; plus one unsolicited reply (in scope, usable,
    // never requested).
    let seeds = [
        reply_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10],
            [192, 0, 2, 10],
            0,
            &ctx,
        ),
        reply_frame(
            [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 0, 2, 20],
            0,
            &ctx,
        ),
        reply_frame(
            [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e],
            [192, 0, 2, 10],
            18,
            &ctx,
        ),
    ];
    for seed in &seeds {
        match run_case(seed, &ctx, &mut counters) {
            Verdict::Accepted => {}
            Verdict::Rejected => flag("valid seed rejected", seed, "expected acceptance"),
            Verdict::Invalid => flag("valid seed accepted wrongly", seed, "oracle"),
        }
    }
    let unsolicited = reply_frame(
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10],
        [192, 0, 2, 30],
        0,
        &ctx,
    );
    let outcome = parse_arp_reply(&unsolicited, &ctx);
    counters.record(&outcome);
    if !matches!(outcome, Err(InvalidReply::NotSolicited { .. })) {
        flag("unsolicited reply", &unsolicited, "expected NotSolicited");
    }

    // ---- stage 2: every truncation of every seed ------------------------
    for seed in &seeds {
        for len in 0..=seed.len() {
            match seed.get(..len) {
                Some(short) => {
                    if run_case(short, &ctx, &mut counters) == Verdict::Invalid {
                        flag("truncated seed", short, "oracle");
                    }
                }
                None => flag("truncation range", seed, "get(..len) failed"),
            }
        }
    }

    // ---- stage 3: systematic single-byte corruption ---------------------
    let mut accepted_corruptions: u32 = 0;
    for seed in &seeds {
        for position in 0..FRAME_LEN {
            for mask in [0x01u8, 0x02, 0x55, 0x80, 0xff] {
                let mut bytes = seed.clone();
                if let Some(slot) = bytes.get_mut(position) {
                    *slot ^= mask;
                }
                match run_case(&bytes, &ctx, &mut counters) {
                    Verdict::Accepted => accepted_corruptions += 1,
                    Verdict::Rejected => {}
                    Verdict::Invalid => flag("corrupted seed", &bytes, "oracle"),
                }
            }
        }
    }
    // Non-vacuity: offsets 32..42 (the reply's target MAC/IP) carry no
    // FR-DS-06 weight, so at least 10 positions × 5 masks × 3 seeds of
    // the corruptions must still be accepted.
    if accepted_corruptions < 150 {
        flag(
            "corruption stage",
            &[0; 0],
            &format!("only {accepted_corruptions} corruptions accepted; expected >= 150"),
        );
    }

    // ---- stage 3b: correlated two-site MAC corruption --------------------
    // The Ethernet source (offsets 6..12) and the ARP sender MAC
    // (offsets 22..28) are two copies of the same address; corrupting
    // one alone yields MacMismatch. Corrupting both identically keeps
    // condition 8 satisfiable and probes condition 9 directly — mask
    // 0x01 on the first octet always produces a multicast sender.
    for seed in &seeds {
        for site in 0..6 {
            for mask in [0x01u8, 0x02, 0x55, 0x80, 0xff] {
                let mut bytes = seed.clone();
                for offset in [6, 22] {
                    if let Some(slot) = bytes.get_mut(offset + site) {
                        *slot ^= mask;
                    }
                }
                match run_case(&bytes, &ctx, &mut counters) {
                    Verdict::Accepted => {}
                    Verdict::Rejected => {}
                    Verdict::Invalid => flag("correlated MAC corruption", &bytes, "oracle"),
                }
            }
        }
    }

    // ---- stage 4: random byte strings ------------------------------------
    let mut rng = Lcg::seeded(0x41_52_50_30_31_00_01);
    for _ in 0..RANDOM_INPUTS {
        let len = rng.next_below(129) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.next_u8());
        }
        if run_case(&bytes, &ctx, &mut counters) == Verdict::Invalid {
            flag("random input", &bytes, "oracle");
        }
    }

    // ---- stage 5: random multi-byte mutations of the seeds ---------------
    let mut rng = Lcg::seeded(0x41_52_50_30_31_00_02);
    for index in 0..MUTATED_INPUTS {
        let seed = match seeds.get((index as usize) % seeds.len()) {
            Some(seed) => seed,
            None => {
                flag("mutation stage", &[0; 0], "seed lookup failed");
                continue;
            }
        };
        let mut bytes = seed.clone();
        let extra = rng.next_below(33) as usize;
        bytes.resize(bytes.len() + extra, 0);
        let mutations = 1 + rng.next_below(8);
        for _ in 0..mutations {
            let position = rng.next_below(bytes.len() as u64) as usize;
            let value = rng.next_u8();
            if let Some(slot) = bytes.get_mut(position) {
                *slot = value;
            }
        }
        let final_len = rng.next_below(bytes.len() as u64 + 1) as usize;
        match bytes.get(..final_len) {
            Some(tail) => {
                if run_case(tail, &ctx, &mut counters) == Verdict::Invalid {
                    flag("mutated seed", tail, "oracle");
                }
            }
            None => flag("mutation stage", &bytes, "get(..final_len) failed"),
        }
    }

    // ---- summary ----------------------------------------------------------
    println!("arp_frame fuzz target (T-103, SR-05) — std-only deterministic harness");
    println!("  stages: known answers, truncations, systematic corruption,");
    println!("          {RANDOM_INPUTS} random inputs, {MUTATED_INPUTS} mutated inputs");
    println!("  outcomes: {}", counters);
    println!("  accepted-by-corruption (non-vacuity): {accepted_corruptions}");
    if failures == 0 {
        println!("  result: OK — no panic path, no oracle violation");
        ExitCode::SUCCESS
    } else {
        eprintln!("arp_frame: {failures} failure(s)");
        ExitCode::FAILURE
    }
}
