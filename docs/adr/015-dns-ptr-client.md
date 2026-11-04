# ADR-015: DNS PTR client implementation

- **Status:** Pending (T-203 evidence delivered; Manager ratification with the task decision)
- **Date:** 2026-11-05 (T-203 decision record; original entry 2026-10-28, task T-001)
- **Deciding task / owner:** T-203 (Hostname resolver) — this record; the Manager ratifies.

## Context

Task T-203 must implement the PTR query/response client that the
Accepted ADR-003 policy requires: PTR queries sent directly to one
eligible local resolver, one datagram per attempt, strict total
acceptance parsing (SR-04/SR-05), no TCP fallback, no EDNS, no DNSSEC,
no IPv6 (`ip6.arpa`) — the full out-of-scope list is plan §2.2. Plan
§9.1 names two candidate crates ("DNS wire format: `simple-dns` /
`hickory-proto` (T-203)") to be evaluated against the §9.2 criteria;
the T-203 task card additionally allows the hand-rolled minimal codec
(option (a)) without any approval, and pre-authorizes exactly one of
the two crates **only if** its license is in the `deny.toml` allowlist
and it pulls no async runtime and no network-egress feature.

## Options considered

1. **(a) Hand-rolled minimal PTR codec** — the ~40-line query builder
   plus a ~290-line total, bounded response-acceptance parser (the
   D-2 rules), all behind the `NameResolver` trait.
2. **(b) `simple-dns` 0.13.0** — a small, MIT-licensed DNS
   wire-format crate.
3. **(c) `hickory-proto` 0.26.3** — the DNS protocol crate of the
   hickory-dns project (default features off).

### §9.2 evaluation (all seven criteria, measured 2026-11-05)

| §9.2 criterion | (a) hand-rolled | (b) simple-dns 0.13.0 | (c) hickory-proto 0.26.3 |
|---|---|---|---|
| 1. Necessity — smallest alternative | ~330 lines of our code; **the D-2 acceptance layer (≤512-byte datagrams, single-question echo, TC→failure, CNAME skip, first-valid-PTR-wins, `Hostname` gate, jump-count + 255-octet bounds) must be hand-written around *any* crate** — a crate only replaces ~200 of those lines | removes the message encode/decode, keeps our acceptance + validation layer | same as (b); the acceptance + validation layer remains ours |
| 2. Maintenance (release date, advisories, health) | zero upstream exposure; covered by our own property + fuzz harnesses (`fuzz/dns_response.rs`) | active: 0.13.0 released 2026-10-30; six releases in 16 months (0.11.0 2025-07 → 0.13.0 2026-10); ≈3.8 M recent downloads; no RustSec advisory | very active: 0.26.3 released 2026-09-10; ≈32.6 M recent downloads; no RustSec advisory |
| 3. License in `deny.toml` allowlist | not applicable (no new crate) | MIT — in allowlist | MIT OR Apache-2.0 — in allowlist |
| 4. `unsafe` footprint | 0 (`unsafe_code = "forbid"` in our package) | 0 `unsafe` in its own `src/`; one transitive crate (bitflags 2.13.2) carries 2 `unsafe impl` of bytemuck traits inside a macro arm, compiled only under bitflags' external-types machinery — not reached | 0 `unsafe` in its own `src/`; transitively pulls the ICU4X stack — measured: zerovec 231, yoke 86, icu_collections 15, rand 16 `unsafe` blocks/fns — a large review surface under plan SR-01 |
| 5. Transitive dependency count + build cost (measured, fresh empty crate) | +0 crates, +0 s | +1 crate (bitflags); build **1.4 s** | **+64 crates** (65 incl. self: data-encoding, idna → icu_* → zerovec/yoke/zerofrom, ipnet, once_cell, rand, thiserror, tinyvec, tracing, url); build **11.1 s**; no async runtime with `default-features = false` |
| 6. MSRV vs our 1.89 pin | ours — `cargo build --locked` green on 1.89.0 | no `rust-version` declared; `cargo build` green on 1.89.0 (measured) | `rust-version = 1.88`; `cargo build` green on 1.89.0 (measured) |
| 7. Our constraints (no runtime network, no build-time fetch) | ✓ by construction | ✓ (no `build.rs`, no network) | ✓ (no `build.rs`; the `jni` dependency is Android-target-only) |

## Decision

**Option (a): the hand-rolled minimal PTR codec** (`src/enrichment/dns.rs`),
fully behind the `NameResolver` trait. No new crate is added to
`[dependencies]`; the pre-authorization for (b)/(c) is therefore not
exercised.

Rationale: the acceptance policy D-2 is narrower *and* stricter than
what either crate exposes — a generic decoder returns typed records
but does not enforce the 512-byte no-EDNS bound, the single-question
echo, TC-as-failure, first-valid-PTR-wins with `Hostname` validation,
or the bounded compression-pointer walk. That layer must be written,
owned and fuzzed by us regardless of the codec choice, so both crates
would add supply-chain surface — (c) adds 64 crates and 300+
transitive `unsafe` blocks — without removing the security-relevant
code. Option (a) needs no approval, matches the T-103 ARP-codec
precedent (same total-parser discipline, same fuzz coverage), and
keeps the wire format swappable: like the interim transport under
ADR-009, the decision is contained behind one trait, so adopting a
crate later is a one-module change.

## Consequences (positive, negative, follow-ups)

- Positive: zero new dependencies (the tree stays at ratatui,
  thiserror, nix, pnet_datalink, caps + dev-only csv); the DNS parsing
  code is `unsafe`-free, fuzz- and property-covered in-repo
  (`fuzz/dns_response.rs`, SR-05); no MSRV exposure from upstream.
- Negative: we own ~330 lines of DNS wire-format code that a crate
  would otherwise provide, including its edge cases (compression
  pointers, label kinds); the bounded walker must be kept total by
  tests, not by a maintained upstream.
- The 16-bit query ID is LCG-generated and **not a security boundary**
  (D-2): the actual defense is the ID + question match against a
  single resolver the UDP socket is `connect()`ed to (kernel-level
  source filtering) plus total
  validation of every decoded byte. Documented in `dns.rs`.
- No TCP fallback for TC=1 responses and no EDNS: a resolver that
  truncates PTR answers is answered `Unavailable(Failed)` after the
  retry policy — the residual-risk sentence for `docs/limitations.md`
  (T-405) is proposed in the T-203 execution report §10.
- Follow-up (suggested, not ordered): the same LCG low-bit-period
  observation found while building the fuzz harnesses (see the T-203
  report §11) applies to `model::testing::Lcg` and `fuzz/arp_frame.rs`.

## Evidence (links to PoC data, reports, benchmarks)

- Measured data and commands: `docs/reports/T-203/execution-01.md` §7
  (the §9.2 table above reproduces it; fresh-crate `cargo tree` and
  build-time measurements for both candidates, 1.89.0 MSRV builds,
  transitive `unsafe` counts, crates.io metadata as of 2026-11-05).
- Implementation: `src/enrichment/dns.rs` (query builder, bounded
  acceptance parser, `UdpResolver`); tests: 27 unit/property tests in
  the module, two loopback integration tests; fuzz:
  `fuzz/dns_response.rs` (known answers, truncations, systematic
  corruption, structure-aware mutations, 300,000 random + 200,000
  mutated inputs, deterministic summary).
