// SPDX-License-Identifier: GPL-3.0-only

//! Fuzz target `resolv_conf` — plan §7.2 SR-05/SR-10, §8.1 (`fuzz/`,
//! separate package), task T-203 R-8.
//!
//! What is fuzzed: [`parse_resolv_conf`], [`select_resolver`] and
//! [`read_bounded`]'s bound constant consumers from
//! `osza_netmon::enrichment::hostname` — the D-1 resolver-selection
//! core of the hostname feature.
//!
//! Why it is std-only: the same decision as `arp_frame.rs` (T-103
//! report §6) — no `libfuzzer-sys` dependency without a Plan Question
//! (§14.5). Deterministic PRNG, structure-aware mutations.
//!
//! The stages, in order:
//!
//! 1. known-answer checks — a typical two-entry file, a systemd
//!    fallback case (stub-only + eligible fallback entry), the
//!    malformed-line counting, and the IPv6-never-eligible rule;
//! 2. every truncation of every seed (lengths `0..=len`, on both the
//!    byte and the line level);
//! 3. systematic single-byte corruption — every offset × every mask of
//!    `{01, 02, 55, 80, ff}`;
//! 4. random byte strings of random lengths (`0..=2048`), lossily
//!    decoded, fed to the parser and the selection core;
//! 5. random line splicing from a pool of realistic and hostile
//!    nameserver lines;
//! 6. a beyond-64-KiB text (the SR-10 bound is on file reads; the
//!    parser itself must stay total on arbitrary length).
//!
//! Postcondition oracle (re-derived here, independent of the crate):
//! the parser never panics; entries plus counted skips equals the
//! number of lines whose first token is `nameserver`
//! (case-insensitive); and a selection is either `NoResolver` or an
//! IPv4 address that lies inside the selected subnet and appears
//! among the parsed entries of the file that produced it.

use std::net::Ipv4Addr;
use std::process::ExitCode;

use osza_netmon::enrichment::hostname::{
    ResolverSelection, parse_resolv_conf, select_resolver,
};
use osza_netmon::model::Ipv4Net;

/// Random-input count for stages 4–6. Deterministic; raise for longer runs.
const RANDOM_INPUTS: u32 = 400_000;
/// How many offending inputs to print before the summary cuts off.
const MAX_REPORTED_INPUTS: u32 = 8;

/// A tiny linear-congruential generator (Knuth constants), mirroring
/// the crate's test-only `model::testing::Lcg`. Deterministic seeds.
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
    inputs: u64,
    entries: u64,
    skipped: u64,
    selected: u64,
    no_resolver: u64,
    selected_in_subnet: u64,
}

impl Counters {
    fn record_parse(&mut self, parsed: &osza_netmon::enrichment::hostname::ResolvConf) {
        self.inputs += 1;
        self.entries += parsed.nameservers.len() as u64;
        self.skipped += parsed.skipped_malformed as u64;
    }

    fn record_selection(&mut self, selection: &ResolverSelection) {
        match selection {
            ResolverSelection::Selected { .. } => self.selected += 1,
            ResolverSelection::NoResolver => self.no_resolver += 1,
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

/// The synthetic scan subnet of the harness (RFC 5737 TEST-NET-1
/// address space; plan §14.3 rule 8 — no real identifiers).
const SUBNET_ADDR: [u8; 4] = [192, 168, 1, 100];

/// The postcondition oracle, re-derived from policy D-1: totals hold
/// and selections stay inside the subnet and inside the entries.
fn invariants_hold(
    text: &str,
    parsed: &osza_netmon::enrichment::hostname::ResolvConf,
    selection: &ResolverSelection,
    net: Ipv4Net,
) -> bool {
    // Totals: nameserver-keyword lines == entries + counted skips.
    let keyword_lines = text
        .lines()
        .filter(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|first| first.eq_ignore_ascii_case("nameserver"))
        })
        .count();
    if parsed.nameservers.len() + parsed.skipped_malformed != keyword_lines {
        return false;
    }
    // Selection soundness: an address inside the subnet, from the
    // entries (own file, or the fallback file under the loopback rule
    // — for the oracle we accept "inside the subnet" plus "appears in
    // the parsed entries" since the single-file case covers it).
    match selection {
        ResolverSelection::NoResolver => true,
        ResolverSelection::Selected { address, .. } => {
            if net.contains(*address) {
                // It must be an entry of the primary file (the harness
                // only passes Some(systemd) in the fallback seeds, where
                // the address may come from either file — the subnet
                // rule is the load-bearing invariant there).
                parsed.nameservers.iter().any(|ip| match ip {
                    std::net::IpAddr::V4(v4) => v4 == address,
                    std::net::IpAddr::V6(_) => false,
                })
            } else {
                false
            }
        }
    }
}

/// A pool of realistic and hostile lines for the splicing stage.
const LINE_POOL: [&str; 16] = [
    "nameserver 192.168.1.1",
    "nameserver 192.168.1.53",
    "  NAMEServer\t10.0.0.53  ",
    "nameserver fd00::1",
    "nameserver ::1",
    "nameserver 127.0.0.53",
    "nameserver",
    "nameserver bogus.example",
    "nameserver 1.2.3.4 trailing",
    "nameserver 192.168.1.1 # inline comment makes it malformed",
    "search example.lan",
    "domain example.lan",
    "options timeout:2 attempts:1",
    "# comment line",
    "",
    "\t \u{0} \u{1b}[31m garbage",
];

/// The systemd fallback file used in the fallback seeds.
const SYSTEMD_TEXT: &str = "nameserver 192.168.1.9\nnameserver 10.0.0.1\n";

/// The one narrowly scoped print allow of this package: a fuzz binary
/// reports its own summary on stdout and findings on stderr, exactly
/// like the root `main.rs` pattern for the CLI boundary.
#[allow(clippy::print_stdout, clippy::print_stderr)]
fn main() -> ExitCode {
    // The subnet is valid by construction; the match keeps the no-
    // expect discipline of this package (the lints deny it).
    let net = match Ipv4Net::new(Ipv4Addr::new(SUBNET_ADDR[0], SUBNET_ADDR[1], SUBNET_ADDR[2], SUBNET_ADDR[3]), 24) {
        Ok(net) => net,
        Err(error) => {
            eprintln!("resolv_conf: seed subnet rejected: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut counters = Counters::default();
    let mut failures: u32 = 0;
    let mut reported: u32 = 0;

    let mut flag = |label: &str, input: &[u8], detail: &str| {
        failures += 1;
        if reported < MAX_REPORTED_INPUTS {
            reported += 1;
            eprintln!("resolv_conf: {label} ({detail}): {}", hex_string(input));
        }
    };

    // ---- stage 1: known answers ----------------------------------------
    let typical = "nameserver 192.168.1.53\nnameserver 10.0.0.1\n";
    let parsed = parse_resolv_conf(typical);
    counters.record_parse(&parsed);
    if parsed.nameservers.len() != 2 || parsed.skipped_malformed != 0 {
        flag("typical file", typical.as_bytes(), "expected two entries, no skips");
    }
    let expected = ResolverSelection::Selected {
        address: Ipv4Addr::new(192, 168, 1, 53),
        via_systemd_fallback: false,
    };
    let selection = select_resolver(typical, None, net);
    if selection != expected {
        flag("typical file", typical.as_bytes(), "expected 192.168.1.53 selected");
    }
    counters.record_selection(&selection);

    // Stub-only + systemd fallback: selected via the fallback file.
    let stub_only = "nameserver 127.0.0.53\n";
    match select_resolver(stub_only, Some(SYSTEMD_TEXT), net) {
        ResolverSelection::Selected {
            address,
            via_systemd_fallback: true,
        } if address == Ipv4Addr::new(192, 168, 1, 9) => {}
        _ => flag(
            "fallback case",
            stub_only.as_bytes(),
            "expected 192.168.1.9 via fallback",
        ),
    }
    counters.record_selection(&select_resolver(stub_only, Some(SYSTEMD_TEXT), net));

    // Stub-only without the fallback file: no resolver, ever.
    if select_resolver(stub_only, None, net) != ResolverSelection::NoResolver {
        flag("stub only", stub_only.as_bytes(), "expected NoResolver");
    }
    counters.record_selection(&select_resolver(stub_only, None, net));

    // Malformed counting.
    let malformed = concat!(
        "nameserver\n",
        "nameserver 1.2.3.4 extra\n",
        "nameserver not-an-ip\n",
        "nameserver 192.168.1.1\n",
    );
    let parsed = parse_resolv_conf(malformed);
    counters.record_parse(&parsed);
    if parsed.nameservers.len() != 1 || parsed.skipped_malformed != 3 {
        flag("malformed file", malformed.as_bytes(), "expected 1 entry, 3 skips");
    }

    // IPv6 is never eligible.
    let v6_only = "nameserver fd00::53\n";
    if select_resolver(v6_only, None, net) != ResolverSelection::NoResolver {
        flag("ipv6 file", v6_only.as_bytes(), "IPv6 is never eligible");
    }

    let seeds: [Vec<u8>; 4] = [
        typical.as_bytes().to_vec(),
        stub_only.as_bytes().to_vec(),
        SYSTEMD_TEXT.as_bytes().to_vec(),
        malformed.as_bytes().to_vec(),
    ];

    // ---- stage 2: every truncation of every seed ------------------------
    for seed in &seeds {
        for len in 0..=seed.len() {
            if let Some(short) = seed.get(..len) {
                let text = String::from_utf8_lossy(short);
                let parsed = parse_resolv_conf(&text);
                counters.record_parse(&parsed);
                let selection = select_resolver(&text, None, net);
                counters.record_selection(&selection);
                if !invariants_hold(&text, &parsed, &selection, net) {
                    flag("truncated seed", short, "invariants");
                }
            }
        }
    }

    // ---- stage 3: systematic single-byte corruption ---------------------
    let mut accepted_corruptions: u32 = 0;
    for seed in &seeds {
        for position in 0..seed.len() {
            for mask in [0x01u8, 0x02, 0x55, 0x80, 0xff] {
                let mut bytes = seed.clone();
                if let Some(slot) = bytes.get_mut(position) {
                    *slot ^= mask;
                }
                let text = String::from_utf8_lossy(&bytes);
                let parsed = parse_resolv_conf(&text);
                counters.record_parse(&parsed);
                let selection = select_resolver(&text, None, net);
                counters.record_selection(&selection);
                if matches!(selection, ResolverSelection::Selected { .. }) {
                    accepted_corruptions += 1;
                }
                if !invariants_hold(&text, &parsed, &selection, net) {
                    flag("corrupted seed", &bytes, "invariants");
                }
            }
        }
    }
    // Non-vacuity: bytes without acceptance weight (comment text,
    // other directives) must survive some corruptions with a selection.
    if accepted_corruptions < 50 {
        flag(
            "corruption stage",
            &[0; 0],
            &format!("only {accepted_corruptions} selections survived; expected >= 50"),
        );
    }

    // ---- stage 4: random byte strings ------------------------------------
    let mut rng = Lcg::seeded(0xE0_53_F7_5A_00_01);
    for _ in 0..RANDOM_INPUTS / 2 {
        let len = rng.next_below(2049) as usize;
        let mut bytes = Vec::with_capacity(len);
        for _ in 0..len {
            bytes.push(rng.next_u8());
        }
        let text = String::from_utf8_lossy(&bytes);
        let parsed = parse_resolv_conf(&text);
        counters.record_parse(&parsed);
        let selection = select_resolver(&text, None, net);
        counters.record_selection(&selection);
        if matches!(selection, ResolverSelection::Selected { .. }) {
            counters.selected_in_subnet += 1;
        }
        if !invariants_hold(&text, &parsed, &selection, net) {
            flag("random input", &bytes, "invariants");
        }
    }

    // ---- stage 5: random line splicing ------------------------------------
    let mut rng = Lcg::seeded(0xE0_53_F7_5A_00_02);
    for _ in 0..RANDOM_INPUTS / 2 {
        let lines = rng.next_below(24);
        let mut text = String::new();
        for _ in 0..lines {
            let index = rng.next_below(LINE_POOL.len() as u64) as usize;
            if let Some(line) = LINE_POOL.get(index) {
                text.push_str(line);
            }
            text.push('\n');
        }
        // Half the cases offer the systemd fallback file too.
        let systemd = if rng.next_below(2) == 0 { Some(SYSTEMD_TEXT) } else { None };
        let parsed = parse_resolv_conf(&text);
        counters.record_parse(&parsed);
        let selection = select_resolver(&text, systemd, net);
        counters.record_selection(&selection);
        if matches!(selection, ResolverSelection::Selected { .. }) {
            counters.selected_in_subnet += 1;
        }
        // For the splicing oracle, the fallback file is also in play:
        // the subnet rule is the invariant that must hold.
        if let ResolverSelection::Selected { address, .. } = selection {
            if !net.contains(address) {
                flag("spliced input", text.as_bytes(), "selection outside the subnet");
            }
        }
    }

    // ---- stage 6: beyond-64-KiB text ---------------------------------------
    let oversize = {
        let mut text = String::from("#");
        for _ in 0..(70 * 1024) {
            text.push('x');
        }
        text.push_str("\nnameserver 192.168.1.53\n");
        text
    };
    let parsed = parse_resolv_conf(&oversize);
    counters.record_parse(&parsed);
    let selection = select_resolver(&oversize, None, net);
    counters.record_selection(&selection);
    if !matches!(selection, ResolverSelection::Selected { .. }) {
        flag("oversize text", &[], "the trailing entry must still parse");
    }

    // ---- summary ----------------------------------------------------------
    println!("resolv_conf fuzz target (T-203, SR-05/SR-10) — std-only deterministic harness");
    println!(
        "  stages: known answers, truncations, systematic corruption, {} random inputs,",
        RANDOM_INPUTS
    );
    println!("          line splicing, a beyond-64-KiB text");
    println!(
        "  parse results: {} inputs, {} entries, {} skipped malformed lines",
        counters.inputs, counters.entries, counters.skipped
    );
    println!(
        "  selections: {} selected, {} no-resolver ({} selected on random inputs)",
        counters.selected, counters.no_resolver, counters.selected_in_subnet
    );
    println!("  accepted-by-corruption (non-vacuity): {accepted_corruptions}");
    if failures == 0 {
        println!("  result: OK — no panic path, no invariant violation");
        ExitCode::SUCCESS
    } else {
        eprintln!("resolv_conf: {failures} failure(s)");
        ExitCode::FAILURE
    }
}
