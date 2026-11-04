// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target `dns_response` — plan §7.2 SR-05, §8.1 (`fuzz/`,
//! separate package), task T-203 R-8.
//!
//! What is fuzzed: [`build_ptr_query`] and [`accept_ptr_response`]
//! from `osza_netmon::enrichment::dns` — the D-2 query builder and the
//! total, bounded response-acceptance core of the hostname resolver.
//!
//! Why it is std-only: the same decision as `arp_frame.rs` (T-103
//! report §6) — wiring `libfuzzer-sys` needs a crates.io dependency,
//! which the task cards forbid without a Plan Question (§14.5). The
//! target drives the acceptance path with a deterministic PRNG and
//! structure-aware mutations, the same approach as the crate's
//! property tests at a larger scale.
//!
//! The stages, in order:
//!
//! 1. known-answer checks — the query builder's exact length for a
//!    known input, our own query fed back as a response (QR=0 →
//!    malformed), a valid crafted response (accepted, exact name), an
//!    NXDOMAIN response (`Ok(None)`), a NOERROR-empty response
//!    (`Ok(None)`), TC=1 (truncated) and SERVFAIL (server failure);
//! 2. every truncation of every crafted seed (lengths `0..=len`);
//! 3. systematic single-byte corruption — every offset × every mask of
//!    `{01, 02, 55, 80, ff}` (non-vacuity: TTL and owner-name bytes
//!    carry no acceptance weight, so some corrupted responses must
//!    still be accepted);
//! 4. structure-aware mutations — flag-bit flips (QR/TC/RCODE), ID
//!    patches (matching and random), label-length patches (1/63/64/
//!    192), and pointer patches (self-loop, forward, past-the-end) at
//!    the DNS structural offsets;
//! 5. random byte strings of random lengths (`0..=600`, covering the
//!    over-512 rejection), also used as the *query* side (the
//!    acceptance path decodes both datagrams and must stay total);
//! 6. random multi-byte mutations of the seeds — overwrites, an
//!    extension and a truncation per case.
//!
//! Every accepted response is checked against an independent oracle:
//! the hostname must be a valid `Hostname` and the response's RDATA
//! must actually contain the name's labels. The target never panics by
//! construction — no asserts, no `unwrap`/`expect`, no indexing, the
//! lints denied in `fuzz/Cargo.toml` — and reports a violation as a
//! message plus exit status 1.

use std::net::Ipv4Addr;
use std::process::ExitCode;

use osza_netmon::enrichment::dns::{
    ResolveError, accept_ptr_response, build_ptr_query,
};
use osza_netmon::model::Hostname;

/// Random-input count for stage 5. Deterministic; raise for longer runs.
const RANDOM_INPUTS: u32 = 300_000;
/// Mutated-input count for stages 4 and 6. Deterministic.
const MUTATED_INPUTS: u32 = 200_000;
/// How many offending inputs to print before the summary cuts off.
const MAX_REPORTED_INPUTS: u32 = 8;

/// The query's fixed header length — written out locally on purpose
/// (the harness re-derives the layout independently of the crate).
const HEADER_LEN: usize = 12;

/// The acceptance path's datagram bound (no EDNS).
const MAX_RESPONSE: usize = 512;

/// A tiny linear-congruential generator (Knuth constants), mirroring
/// the crate's test-only `model::testing::Lcg`. Deterministic seeds
/// make every run reproducible. Not cryptographic.
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

    /// A value in `0..n`; callers must pass `n > 0`. Drawn from the
    /// HIGH bits: an LCG's low bits have short periods (the low 4
    /// bits repeat with period 16), which correlates consecutive
    /// modulo draws; the high bits have full period.
    fn next_below(&mut self, n: u64) -> u64 {
        (self.next_u64() >> 32) % n
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

/// Outcome counters for the summary.
#[derive(Default)]
struct Counters {
    known_name: u64,
    no_name: u64,
    malformed: u64,
    timeout_transport: u64,
    server_failure: u64,
    truncated: u64,
    accepted_corruptions: u64,
}

impl Counters {
    fn record(&mut self, outcome: &Result<Option<Hostname>, ResolveError>) {
        match outcome {
            Ok(Some(_)) => self.known_name += 1,
            Ok(None) => self.no_name += 1,
            Err(ResolveError::Malformed) => self.malformed += 1,
            Err(ResolveError::Timeout) | Err(ResolveError::Transport) => {
                self.timeout_transport += 1;
            }
            Err(ResolveError::ServerFailure) => self.server_failure += 1,
            Err(ResolveError::Truncated) => self.truncated += 1,
        }
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

// ---- locally re-derived wire-format builders (independent of the
// ---- crate's builder, so a bug there cannot hide here) -----------------

/// Appends a wire-format name from presentation labels.
fn push_name(out: &mut Vec<u8>, labels: &[&str]) {
    for label in labels {
        let len = label.len().min(63) as u8;
        out.push(len);
        for byte in label.as_bytes().iter().take(usize::from(len)) {
            out.push(*byte);
        }
    }
    out.push(0);
}

/// Appends header + question for the given ID and flags.
fn push_question(out: &mut Vec<u8>, id: u16, flags: u16, labels: &[&str]) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    push_name(out, labels);
    out.extend_from_slice(&12u16.to_be_bytes()); // QTYPE PTR
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
}

/// Appends one answer record of the given type with raw RDATA.
fn push_record(out: &mut Vec<u8>, owner: &[&str], rtype: u16, rdata: &[u8]) {
    push_name(out, owner);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    out.extend_from_slice(&0u32.to_be_bytes()); // TTL
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// Patches ANCOUNT to `count`.
fn set_ancount(out: &mut [u8], count: u16) {
    if let Some(slot) = out.get_mut(6) {
        *slot = (count >> 8) as u8;
    }
    if let Some(slot) = out.get_mut(7) {
        *slot = (count & 0xFF) as u8;
    }
}

/// The expected question labels of the fixed fuzz IP 192.0.2.10
/// (reversed: 10.2.0.192.in-addr.arpa).
const QNAME: [&str; 6] = ["10", "2", "0", "192", "in-addr", "arpa"];

fn ip() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 10)
}

/// The independent oracle for accepted responses: the returned
/// hostname must validate, and its label bytes must occur in the
/// datagram (the answer must come from the wire, not from nowhere).
fn acceptance_is_sound(hostname: &Hostname, response: &[u8]) -> bool {
    let name = hostname.as_str();
    if Hostname::try_from(name).is_err() {
        return false;
    }
    // Every label of the name must appear verbatim in the datagram
    // (compression cannot invent bytes).
    for label in name.split('.') {
        if label.is_empty() {
            // A leading/trailing/doubled dot yields an empty label;
            // nothing to search for (the model's charset allows it).
            continue;
        }
        let needle = label.as_bytes();
        let mut found = false;
        for window in response.windows(needle.len()) {
            if window == needle {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

/// Runs one fuzz case through the acceptance path and checks the
/// oracle; `true` when a violation was found.
fn run_case(
    query: &[u8],
    response: &[u8],
    counters: &mut Counters,
    corrupt_rejects: &mut u32,
) -> bool {
    let acceptance = accept_ptr_response(query, response);
    counters.record(&acceptance.outcome);
    match &acceptance.outcome {
        Ok(Some(hostname)) => {
            if acceptance_is_sound(hostname, response) {
                false
            } else {
                *corrupt_rejects += 1;
                true
            }
        }
        _ => false,
    }
}

/// The one narrowly scoped print allow of this package: a fuzz binary
/// reports its own summary on stdout and findings on stderr, exactly
/// like the root `main.rs` pattern for the CLI boundary.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> ExitCode {
    let query = build_ptr_query(0x1234, ip());
    let mut counters = Counters::default();
    let mut failures: u32 = 0;
    let mut reported: u32 = 0;
    let mut corrupt_rejects: u32 = 0;

    let mut flag = |label: &str, input: &[u8], detail: &str| {
        failures += 1;
        if reported < MAX_REPORTED_INPUTS {
            reported += 1;
            eprintln!("dns_response: {label} ({detail}): {}", hex_string(input));
        }
    };

    // ---- stage 1: known answers ----------------------------------------
    if query.len() != 41 {
        flag("query builder length", &query, "expected 41 bytes");
    }
    // Our own query fed back as a response: QR=0 → malformed.
    let acceptance = accept_ptr_response(&query, &query);
    counters.record(&acceptance.outcome);
    if !matches!(acceptance.outcome, Err(ResolveError::Malformed)) {
        flag("query echoed as response", &query, "expected malformed (QR=0)");
    }

    // A valid crafted response: accepted with the exact name.
    let mut valid = Vec::new();
    push_question(&mut valid, 0x1234, 0x8180, &QNAME);
    let mut rdata = Vec::new();
    push_name(&mut rdata, &["printer", "lan"]);
    push_record(&mut valid, &QNAME, 12, &rdata);
    set_ancount(&mut valid, 1);
    if run_case(&query, &valid, &mut counters, &mut corrupt_rejects) {
        flag("valid seed", &valid, "oracle violation");
    }
    match accept_ptr_response(&query, &valid).outcome {
        Ok(Some(ref hostname)) if hostname.as_str() == "printer.lan" => {}
        _ => flag("valid seed", &valid, "expected printer.lan"),
    }

    // NXDOMAIN: definitive no-name.
    let mut nxdomain = Vec::new();
    push_question(&mut nxdomain, 0x1234, 0x8183, &QNAME);
    let outcome = accept_ptr_response(&query, &nxdomain).outcome;
    counters.record(&outcome);
    match outcome {
        Ok(None) => {}
        _ => flag("nxdomain seed", &nxdomain, "expected Ok(None)"),
    }

    // NOERROR, zero answers: no-name.
    let mut empty = Vec::new();
    push_question(&mut empty, 0x1234, 0x8180, &QNAME);
    let outcome = accept_ptr_response(&query, &empty).outcome;
    counters.record(&outcome);
    match outcome {
        Ok(None) => {}
        _ => flag("noerror-empty seed", &empty, "expected Ok(None)"),
    }

    // TC=1 and SERVFAIL: the attempt fails.
    let mut truncated = Vec::new();
    push_question(&mut truncated, 0x1234, 0x8380, &QNAME);
    let outcome = accept_ptr_response(&query, &truncated).outcome;
    counters.record(&outcome);
    match outcome {
        Err(ResolveError::Truncated) => {}
        _ => flag("tc seed", &truncated, "expected Truncated"),
    }
    let mut servfail = Vec::new();
    push_question(&mut servfail, 0x1234, 0x8182, &QNAME);
    let outcome = accept_ptr_response(&query, &servfail).outcome;
    counters.record(&outcome);
    match outcome {
        Err(ResolveError::ServerFailure) => {}
        _ => flag("servfail seed", &servfail, "expected ServerFailure"),
    }

    // A response with an invalid-char PTR then a valid one: first
    // valid wins, the invalid one is counted and skipped.
    let mut two_ptrs = Vec::new();
    push_question(&mut two_ptrs, 0x1234, 0x8180, &QNAME);
    let mut bad = Vec::new();
    push_name(&mut bad, &["bad host!", "lan"]);
    push_record(&mut two_ptrs, &QNAME, 12, &bad);
    let mut good = Vec::new();
    push_name(&mut good, &["printer", "lan"]);
    push_record(&mut two_ptrs, &QNAME, 12, &good);
    set_ancount(&mut two_ptrs, 2);
    let acceptance = accept_ptr_response(&query, &two_ptrs);
    match acceptance.outcome {
        Ok(Some(ref hostname)) if hostname.as_str() == "printer.lan" => {}
        _ => flag("two-ptr seed", &two_ptrs, "expected printer.lan"),
    }
    if acceptance.skipped_invalid_ptr_names != 1 {
        flag("two-ptr seed", &two_ptrs, "expected one skipped invalid PTR");
    }
    counters.record(&acceptance.outcome);

    let seeds = [valid.clone(), nxdomain, empty, two_ptrs];

    // ---- stage 2: every truncation of every seed ------------------------
    for seed in &seeds {
        for len in 0..=seed.len() {
            if let Some(short) = seed.get(..len) {
                if run_case(&query, short, &mut counters, &mut corrupt_rejects) {
                    flag("truncated seed", short, "oracle");
                }
            }
        }
    }

    // ---- stage 3: systematic single-byte corruption ---------------------
    for seed in &seeds {
        for position in 0..seed.len() {
            for mask in [0x01u8, 0x02, 0x55, 0x80, 0xff] {
                let mut bytes = seed.clone();
                if let Some(slot) = bytes.get_mut(position) {
                    *slot ^= mask;
                }
                let before = counters.known_name + counters.no_name;
                if run_case(&query, &bytes, &mut counters, &mut corrupt_rejects) {
                    flag("corrupted seed", &bytes, "oracle");
                }
                // Non-vacuity: corruptions that keep the response
                // acceptable (TTL and owner-name bytes carry no
                // acceptance weight) must occur.
                if counters.known_name + counters.no_name > before {
                    counters.accepted_corruptions += 1;
                }
            }
        }
    }
    if counters.accepted_corruptions < 50 {
        flag(
            "corruption stage",
            &[0; 0],
            &format!(
                "only {} accepted corruptions; expected >= 50",
                counters.accepted_corruptions
            ),
        );
    }

    // ---- stage 4: structure-aware mutations ------------------------------
    let mut rng = Lcg::seeded(0x0D_05_F7_5A_00_01);
    for index in 0..MUTATED_INPUTS / 2 {
        let seed = match seeds.get((index as usize) % seeds.len()) {
            Some(seed) => seed.clone(),
            None => Vec::new(),
        };
        let mut bytes = seed;
        // One structural mutation per case, at a DNS-meaningful place.
        let position = match rng.next_below(7) {
            0 => rng.next_below(bytes.len() as u64) as usize, // anywhere
            1..=2 => {
                // ID bytes: matching the query or random.
                let at = rng.next_below(2) as usize;
                if let Some(slot) = bytes.get_mut(at) {
                    *slot = if rng.next_below(2) == 0 {
                        *query.get(at).unwrap_or(&0)
                    } else {
                        rng.next_u8()
                    };
                }
                at
            }
            3 => {
                // Flag bits: QR / TC / RCODE.
                let at = 2 + rng.next_below(2) as usize;
                if let Some(slot) = bytes.get_mut(at) {
                    *slot ^= 1u8 << rng.next_below(8);
                }
                at
            }
            4 => {
                // Label length bytes: 1, 63, 64 (reserved), 192 (pointer).
                let at = HEADER_LEN + rng.next_below(30) as usize;
                if let Some(slot) = bytes.get_mut(at) {
                    *slot = *[1u8, 63, 64, 192]
                        .get(rng.next_below(4) as usize)
                        .unwrap_or(&1);
                }
                at
            }
            5 => {
                // Pointer bytes: self-loop / forward / past-the-end.
                let at = HEADER_LEN + rng.next_below(70) as usize;
                if let Some(slot) = bytes.get_mut(at) {
                    *slot = 0xC0;
                }
                let pointer_target = bytes.len().saturating_sub(1).min(at + 1);
                if let Some(slot) = bytes.get_mut(pointer_target) {
                    *slot = *[0u8, 13, 100, 255]
                        .get(rng.next_below(4) as usize)
                        .unwrap_or(&0);
                }
                at
            }
            _ => {
                // ANCOUNT / QDCOUNT / RDLENGTH patches.
                let at = match rng.next_below(3) {
                    0 => 6,
                    1 => 4,
                    _ => bytes.len().saturating_sub(3),
                };
                if let Some(slot) = bytes.get_mut(at) {
                    *slot = rng.next_u8();
                }
                at
            }
        };
        let _ = position;
        // Random extension and truncation, as in arp_frame's stage 5.
        let extra = rng.next_below(33) as usize;
        bytes.resize(bytes.len() + extra, 0);
        let mutations = 1 + rng.next_below(4);
        for _ in 0..mutations {
            let at = rng.next_below(bytes.len() as u64) as usize;
            if let Some(slot) = bytes.get_mut(at) {
                *slot = rng.next_u8();
            }
        }
        let final_len = rng.next_below(bytes.len() as u64 + 1) as usize;
        if let Some(tail) = bytes.get(..final_len) {
            if run_case(&query, tail, &mut counters, &mut corrupt_rejects) {
                flag("structurally mutated seed", tail, "oracle");
            }
        }
    }

    // ---- stage 5: random byte strings (also as the query side) -----------
    let mut rng = Lcg::seeded(0x0D_05_F7_5A_00_02);
    for _ in 0..RANDOM_INPUTS {
        let len = rng.next_below(601) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.next_u8());
        }
        if run_case(&query, &bytes, &mut counters, &mut corrupt_rejects) {
            flag("random input", &bytes, "oracle");
        }
        // The same bytes as the query side: the acceptance path decodes
        // both datagrams and must stay total.
        let _ = accept_ptr_response(&bytes, &valid);
    }

    // ---- stage 6: random multi-byte mutations of the seeds ---------------
    let mut rng = Lcg::seeded(0x0D_05_F7_5A_00_03);
    for index in 0..MUTATED_INPUTS / 2 {
        let seed = match seeds.get((index as usize) % seeds.len()) {
            Some(seed) => seed.clone(),
            None => Vec::new(),
        };
        let mut bytes = seed;
        let extra = rng.next_below(65) as usize;
        bytes.resize(bytes.len() + extra, 0);
        let mutations = 1 + rng.next_below(8);
        for _ in 0..mutations {
            let at = rng.next_below(bytes.len() as u64) as usize;
            if let Some(slot) = bytes.get_mut(at) {
                *slot = rng.next_u8();
            }
        }
        let final_len = rng.next_below(bytes.len() as u64 + 1) as usize;
        if let Some(tail) = bytes.get(..final_len) {
            if run_case(&query, tail, &mut counters, &mut corrupt_rejects) {
                flag("mutated seed", tail, "oracle");
            }
        }
    }

    // ---- summary ----------------------------------------------------------
    println!("dns_response fuzz target (T-203, SR-05) — std-only deterministic harness");
    println!(
        "  stages: known answers, truncations, systematic corruption, structural mutations,"
    );
    println!(
        "          {RANDOM_INPUTS} random inputs, {} mutated inputs",
        MUTATED_INPUTS
    );
    println!(
        "  outcomes: known-name {}, no-name {}, malformed {}, server-failure {}, truncated {}, timeout/transport {}",
        counters.known_name,
        counters.no_name,
        counters.malformed,
        counters.server_failure,
        counters.truncated,
        counters.timeout_transport
    );
    println!(
        "  accepted-by-corruption (non-vacuity): {}",
        counters.accepted_corruptions
    );
    if failures == 0 && corrupt_rejects == 0 {
        println!("  result: OK — no panic path, no oracle violation");
        ExitCode::SUCCESS
    } else {
        eprintln!("dns_response: {failures} failure(s), {corrupt_rejects} oracle rejection(s)");
        ExitCode::FAILURE
    }
}
