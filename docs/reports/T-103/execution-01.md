# Execution Report — T-103 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-01 · **Branch/commits:** `task/T-103-arp-codec` — `480d904` (`src/discovery/arp/` implementation and module wiring), `3d92fe3` (`fuzz/arp_frame.rs` and the fuzz package), plus this report · **Plan version:** 1.3.0 (repository copy, commit `eea151e`)

## 1. Summary (≤ 5 lines)

The ARP wire-format layer is implemented in `src/discovery/arp/codec.rs`: `build_arp_request` (the 42-byte Ethernet+ARP frame of FR-DS-03/Appendix E, pure byte assembly) and `parse_arp_reply` — a total, solicited-only validator that checks **all** FR-DS-06 conditions in the plan's order, one distinct `InvalidReply` variant per failure, plus the "dropped and counted" tallies (`ArpReplyCounters`). Std-only (no new crates; `thiserror` was already locked), no network I/O, depends only on `model` (§8.2). 27 new unit tests + 3 doctests (golden vectors, a negative vector per FR-DS-06 clause, /31 and /32 scope edges, order-of-checks, counters, 2 property tests); the `fuzz/arp_frame.rs` target (separate std-only package per §8.1) runs 800,872 deterministic inputs with no panic and no oracle violation. All gates green on the pinned toolchain.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1: request builder produces a 42-byte frame with correct Ethernet and ARP fields | Met | `request_matches_the_golden_vector` (byte-exact 42-byte golden vector, every field), `request_builder_is_total_for_any_target` (length 42 for `0.0.0.0`, `255.255.255.255`, TEST-NET-2/3; target IP encoded at bytes 38..42; deterministic per target, distinct across targets), doctest `build_arp_request`. |
| AC-2: valid reply (all conditions met) → `Ok(ArpReply)` | Met | `valid_reply_matches_the_golden_vector`, `both_solicited_addresses_are_accepted` (second address, locally-administered sender MAC), `ethernet_padding_beyond_42_bytes_is_ignored` (60-byte padded and non-zero padded), doctest `parse_arp_reply`. |
| AC-3: wrong EtherType → `WrongEtherType` | Met | `wrong_ether_type_is_rejected` (EtherType `0x0800` where ARP belongs; `found` payload asserted). |
| AC-4: wrong hardware type → `WrongHardwareType` | Met | `wrong_hardware_type_is_rejected` (hardware type 6, IEEE 802.x). |
| AC-5: wrong protocol type → `WrongProtocolType` | Met | `wrong_protocol_type_is_rejected` (protocol type `0x86dd`, IPv6). |
| AC-6: wrong hardware length → `WrongHardwareLength` | Met | `wrong_hardware_length_is_rejected` (hlen 8). |
| AC-7: wrong protocol length → `WrongProtocolLength` | Met | `wrong_protocol_length_is_rejected` (plen 16). |
| AC-8: wrong opcode → `WrongOpcode` | Met | `wrong_opcode_is_rejected` (opcodes 1 and 3), `the_builder_s_request_rejected_as_reply_and_as_own_identity` (our own broadcast request → `WrongOpcode`, and forged into a reply → `OwnAddress`). |
| AC-9: Ethernet destination ≠ our MAC → `MacMismatch` | Met | `ethernet_destination_not_our_mac_is_rejected`. |
| AC-10: Ethernet source ≠ ARP sender MAC → `MacMismatch` | Met | `ethernet_source_not_sender_mac_is_rejected` (the forgery shape). |
| AC-11: sender MAC zero/broadcast/multicast → `InvalidMac` | Met | `zero_broadcast_and_multicast_sender_macs_are_rejected` — all three §5.3 classes, with the Ethernet source kept equal so condition 9 is what fires; the `reason` payload distinguishes `ZeroAddress`/`BroadcastAddress`/`MulticastAddress`. |
| AC-12: sender IP outside scope → `OutOfScope` | Met | `out_of_scope_sender_ips_are_rejected` (TEST-NET-2, TEST-NET-3, the adjacent `192.0.3.1`). |
| AC-13: sender IP is network/broadcast/own → `OutOfScope` **or a distinct variant** | Met | Distinct variants: `network_broadcast_and_own_addresses_are_rejected_even_when_solicited` (`NetworkAddress`, `BroadcastAddress`, `OwnAddress` — all placed in the solicited set to prove condition 11 fires regardless of condition 12); `point_to_point_and_host_scopes_follow_fr_sc_05` (a /31's lower address is a usable RFC 3021 host and is accepted; a /32 host is accepted when not our own). |
| AC-14: sender IP not in solicited set → `NotSolicited` | Met | `unsolicited_sender_ip_is_rejected` (in-scope usable `192.0.2.30`, and the empty-set degenerate scan), doctest `parse_arp_reply`. |
| AC-15: property test — never panics on 1,000 random byte strings | Met | `property_parse_never_panics_on_random_bytes` (exactly 1,000 Lcg-driven inputs, lengths 0..=96; every `Ok` re-checked against an independent invariant oracle; non-vacuity: both length classes exercised), plus `property_single_byte_corruptions_never_panic` (210 corruptions; ≥ 50 must stay accepted — the unweighed target-field region). |
| AC-16: fuzz target exists and does not panic | Met | `fuzz/arp_frame.rs` in the standalone `fuzz/` package (§8.1): known answers, every truncation, systematic single-site + correlated two-site corruption, 400,000 random and 400,000 mutated inputs — 800,872 outcomes, exit 0, no panic (§4 has the run output). Std-only stub per the card's allowance; see D-9/follow-up 1 for the `cargo-fuzz` promotion. |
| AC-17: all engineering gates pass | Met | §4: `fmt --check`, `clippy --locked --all-targets --all-features -- -D warnings` (also on the fuzz package), `test --locked --all-features` (128 unit + 9 doctests), `doc --no-deps` (plain and CI's `RUSTDOCFLAGS="-D warnings"` variant), `audit` (0 findings, 188 crates), `deny check` (exit 0, warnings byte-identical to the unmodified-`main` baseline), MSRV `cargo build --locked` at 1.89.0 (root and fuzz package). |
| AC-18: no `unsafe`, no `println!`/`eprintln!` in non-test code | Met | §4 greps: no `unsafe`, no `println!`/`eprintln!` anywhere in `src/discovery/arp/`; every `unwrap`/`expect` match is inside the `#[cfg(test)] mod tests` that opens at line 790 or in four `///` doc-example lines (361, 491, 493, 512) that are doctest code, compiled only by rustdoc — clippy `allow-*-in-tests` is the authoritative enforcement and the non-test region has zero matches (awk cross-check in §4). |
| AC-19: every new `.rs` file starts with the SPDX header | Met | §4: `find src/discovery/arp -name "*.rs" -exec head -1 {} \; | sort | uniq -c` → 2 × `// SPDX-License-Identifier: GPL-3.0-only`; `fuzz/arp_frame.rs` carries it too, and the CI SPDX `find` over the whole tree (excluding `./target`) passes. |

## 3. What changed

On `task/T-103-arp-codec` (base: `main` at `844dafa`):

- `480d904` — the codec:
  - `src/discovery/arp/codec.rs` (1,567 lines incl. tests) — `ArpReply` (public `sender_mac`/`sender_ip`, card §3), `InvalidReply` (14 variants: `Truncated` precondition + one per FR-DS-06 clause, `found` payloads, thiserror `Display`), `ArpReplyContext<'a>` (own MAC/IP + scope + borrowed solicited set; getters + `is_solicited`), `build_arp_request` (42 bytes by construction), `parse_arp_reply` (length gate → field decode → the twelve conditions in FR-DS-06 order), `ArpReplyCounters` (`record`, `accepted`/`rejected`/`total`/`rejected_with`, `Display` for Details→debug), private helpers (`slice_at`/`u16_at`/`mac_at`/`ipv4_at`/`decode` — `get` + `try_into`, no indexing); `#[cfg(test)] mod tests` with 27 tests.
  - `src/discovery/arp/mod.rs` — module declaration and re-exports of the 7 public items.
  - `src/discovery/mod.rs` — `pub mod arp;` + re-exports + module-doc note (the only changes to the two existing files besides `src/lib.rs`'s doc paragraph).
  - `src/lib.rs` — one doc paragraph for T-103 (no code change; `pub mod discovery;` already existed from T-102).
- `3d92fe3` — the fuzz target:
  - `fuzz/Cargo.toml` — the standalone package of §8.1 (empty `[workspace]`, path dependency on `..`, `[[bin]] arp_frame`, the same lint denies as the root package, `rust-version = 1.89`).
  - `fuzz/.cargo/config.toml` — keeps this package's artifacts in the git-ignored `../target` (no `fuzz/target` ever exists for the CI SPDX `find` to scan).
  - `fuzz/arp_frame.rs` (409 lines) — the deterministic std-only harness: Lcg, acceptance oracle, 5 stages + correlated-corruption sub-stage, `ArpReplyCounters` summary, exit-status reporting, zero panic paths.
  - `fuzz/Cargo.lock` — pins the exact same 179 dependency versions as the root lockfile (only the `osza-netmon-fuzz` package entry differs; §7).
- report commit — `docs/reports/T-103/execution-01.md` (this file).

`plan.md`, the root `Cargo.toml`/`Cargo.lock`, `deny.toml`, the workflows, the model/net/neighbor-table sources and all ADRs are untouched. No ADR was added: ADR-009 (transport) stays Pending for T-105, and this task made no architecture decision beyond interpreting the card.

## 4. Verification results

Card §9 commands, executed 2026-11-01 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from the CI-pinned, SHA-256-verified release tarballs):

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.69s
[exit 0]

$ cargo test --locked --all-features 2>&1 | grep -E "(running|test result)"
running 128 tests
test result: ok. 128 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 9 tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[128 unit tests (27 new for T-103 + 101 pre-existing T-000/T-002/T-101/T-102) + 9 doctests (3 new: build_arp_request, parse_arp_reply, ArpReplyCounters; 6 pre-existing)]

$ cargo doc --no-deps
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.26s
    Generated /home/z/my-project/osza-netmon/target/doc/osza_netmon/index.html
[exit 0; CI variant with RUSTDOCFLAGS="-D warnings": also exit 0]

$ cargo audit
    Fetching advisory database from `https://github.com/rustsec/advisory-db.git`
      Loaded 1395 security advisories (from /home/z/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (188 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings, no yanked crates]

$ cargo deny check
warning[duplicate]: found 2 duplicate entries for crate 'syn'
warning[license-not-encountered]: license was not encountered   (×3: BSD-2-Clause, BSD-3-Clause, ISC)
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — the four warnings are byte-identical to the unmodified main checkout (verified with a detached `git worktree` at main, re-running, diffing); they are the known benign T-000 baseline, not introduced here]

$ grep -rn "unsafe" src/discovery/arp/ || echo "No unsafe found"
No unsafe found

$ grep -rn "println!\|eprintln!" src/discovery/arp/ || echo "No println/eprintln found"
No println/eprintln found

$ grep -rn "unwrap\|expect" src/discovery/arp/ --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" || echo "No unwrap/expect in non-test code"
[13 matches — 8 inside the #[cfg(test)] mod tests that opens at line 790 of src/discovery/arp/codec.rs (lines 811, 820, 1237, 1256 are fixture constructors; 880, 894, 931, 945 match the word "expected" in golden-vector assertions), plus 4 in `///` doc-example lines (361, 491, 493, 512) that are doctest code, compiled only by rustdoc as separate test crates, plus 1 module-doc prose line (38) that names `unwrap`/`expect` in backticks. Cross-checked directly: awk 'NR<790 && /unwrap\(|expect\(/' → exactly the four doc-example lines; the compiled non-test region contains none. Test-only and doctest unwrap/expect is permitted by clippy.toml (allow-*-in-tests); clippy is the authoritative enforcement and is green.]

$ find src/discovery/arp -name "*.rs" -exec head -1 {} \; | sort | uniq -c
      2 // SPDX-License-Identifier: GPL-3.0-only
```

Additional task-specific verification:

- **The fuzz target, run for real** (`cd fuzz && cargo run --release --locked --bin arp_frame`, artifacts redirected to `../target` by `fuzz/.cargo/config.toml`):

```text
arp_frame fuzz target (T-103, SR-05) — std-only deterministic harness
  stages: known answers, truncations, systematic corruption,
          400000 random inputs, 400000 mutated inputs
  outcomes: accepted=27911 rejected=772961 truncated=402460 wrong_ether_type=281095
            wrong_hardware_type=8740 wrong_protocol_type=8040 wrong_hardware_length=3286
            wrong_protocol_length=4662 wrong_opcode=7609 mac_mismatch=48683 invalid_mac=9
            out_of_scope=6947 network_address=4 broadcast_address=4 own_address=7
            not_solicited=1415
  accepted-by-corruption (non-vacuity): 150
  result: OK — no panic path, no oracle violation
[exit 0 — 800,872 outcomes; every rejection reason observed at least once; the 27,911
accepted replies all satisfy the independent acceptance oracle]
```

- **Fuzz package gates** (not covered by the root commands, since §8.1 makes `fuzz/` a separate package): `cargo fmt` and `cargo clippy --locked --all-targets -- -D warnings` with the same denied lints as the root — both exit 0; `rustup run 1.89.0 cargo build --locked` (MSRV) — exit 0.
- **`--test-threads=1`** — full suite single-threaded: identical 128+9 pass result; no order dependence (the codec is pure and holds no state).
- **MSRV per CI**: `rustup run 1.89.0 cargo build --locked` at the root — exit 0 (the new module uses no API newer than 1.89; `let … else`, `TryInto` arrays and `matches!` are all older).
- **SPDX CI check** — the workflow's `find . -name '*.rs' -not -path './target/*'` first-line check passes for the whole tree, `fuzz/arp_frame.rs` included (no `fuzz/target` exists).
- **`--locked` discipline** — every dependency-resolving command above ran with `--locked` (deviation 1); `cargo fmt --check` runs without it (cargo-fmt rejects the flag), as in T-000…T-102.

**Test summary per type** (card §6 list):

| Type | Unit tests | Property tests | Key edge cases covered |
|---|---|---|---|
| Request builder | 2 | 0 | byte-exact golden vector (all 12 fields); totality across extreme/RFC 5737 targets; determinism; distinctness |
| Valid replies | 4 | 0 | golden vector; second solicited address from a locally-administered MAC; 60-byte zero and non-zero padding; target-field garbage accepted (unweighed) |
| Negative vectors | 12 | 0 | one per FR-DS-06 clause: EtherType/htype/ptype/hlen/plen/opcode; both MAC mismatch sites; zero/broadcast/multicast senders (with matching Ethernet source); out-of-scope ×3; network/broadcast/own (even when solicited); unsolicited (incl. empty set); every truncation length 0..41 |
| Scope edges & ordering | 3 | 0 | /31 lower address usable (RFC 3021), /31 own rejected, /32 host accepted/rejected; first-failing-condition-wins ×3; our own request → `WrongOpcode` then `OwnAddress` when forged |
| Counters | 2 | 0 | every reason tally independently (all 14 variants); mixed real-frame batch; `Display` format pinned |
| Context | 1 | 0 | getters, `is_solicited` both ways |
| Properties | 0 | 2 | 1,000 random byte strings never panic + invariant oracle + non-vacuity; 210 single-byte corruptions never panic, ≥50 stay accepted |

(Totals: 27 new test functions — 25 unit + 2 property — plus 3 new doctests.)

## 5. Deviations from the task card

1. **`cargo` commands run with `--locked`** (card §9 omits it; CI and T-000…T-102 use it) — same as T-002 deviation 2 / T-101 deviation 2 / T-102 deviation 1. `cargo fmt --check` runs without it (cargo-fmt rejects the flag).
2. **The fuzz target is a std-only deterministic harness, not a `cargo-fuzz` target.** SR-05 names `cargo-fuzz`, but wiring it in requires the `libfuzzer-sys` crate and the card's §8 forbids new dependencies without a Plan Question (§14.5); AC-16 explicitly allows a minimal stub. The harness re-proves the required property — no panic on any input — over 800,872 deterministic inputs plus compiler-enforced absence of panic paths (no asserts/`unwrap`/`expect`/indexing in the binary, the same lints denied as the root). Promotion to a real cargo-fuzz target with a committed corpus is follow-up 1.
3. **Frames longer than 42 bytes are accepted (padding ignored), not rejected.** The card describes the parser as "Ethernet header + ARP payload" without a maximum length; a real 28-byte ARP reply arrives padded to the 60-byte Ethernet minimum, so rejecting >42 would break every compliant responder. Only the first 42 bytes are read; `Truncated` covers <42. Tested both ways (`ethernet_padding_beyond_42_bytes_is_ignored`, `every_shorter_length_is_truncated`).
4. **The network/broadcast rejection is prefix-aware (≤/30), not unconditional.** The card's condition 11 lists "network address, broadcast address" unqualified, but FR-SC-05 — which the condition cites — says "/31 probes both addresses", and `Ipv4Net::host_range` (T-002) already models that. A literal reading would reject the legitimate lower address of every point-to-point link. Tested in `point_to_point_and_host_scopes_follow_fr_sc_05`.
5. **A second property test (single-byte corruptions) was added beyond the card's one**, with a non-vacuity assertion (≥50 corruptions must stay accepted). T-101/T-102 set the two-property precedent; both use the crate's deterministic `model::testing::Lcg` (no `proptest` — that would need a Plan Question).
6. **`InvalidReply` carries `found` payloads and a `MacMismatch` unifies conditions 7/8.** The card's §3 sketches `Err(InvalidReply { reason })` (a struct), but its R4 and AC-3…AC-14 require per-reason *variants* — the enum is the only reading that satisfies both. AC-9/AC-10 name the same variant (`MacMismatch`) for both Ethernet-header mismatches, so one variant serves both sites; AC-13 explicitly allows the distinct `NetworkAddress`/`BroadcastAddress`/`OwnAddress` variants I used instead of folding them into `OutOfScope`.
7. **The builder takes `our_mac`/`our_ip` as parameters, not an `InterfaceInfo`.** The card itself offers "from `InterfaceInfo` **or a parameter**"; §8.2 lets `discovery` depend only on `model` and `clock` (not `net`, where T-101's `InterfaceInfo` lives), so parameters are the only §8.2-clean option. T-104 bridges the two.
8. **`fuzz/` additionally contains `Cargo.toml`, `Cargo.lock` and `.cargo/config.toml`.** §8.1 prescribes `fuzz/arp_frame.rs` as "(separate package)" — a package needs a manifest and lockfile, and the config keeps artifacts in the git-ignored root `target/` so the CI SPDX `find` never scans build output. All three files are inside the card's allowed `fuzz/` scope.

## 6. Decisions and assumptions

**Decisions:**

- **D-1 Validation order = the FR-DS-06 clause order** (EtherType → htype → ptype → hlen → plen → opcode → Ethernet destination → Ethernet source → sender MAC validity → scope → network/broadcast/own → solicited). The first failing condition is the reported one; pinned by `the_first_fr_ds_06_condition_to_fail_wins` and the module table. This keeps counters attributable (a hostile frame is classified by its most fundamental defect) and matches the plan's listing.
- **D-2 The MAC boundary is enforced by construction**: the sender MAC only enters an `ArpReply` through `MacAddr::from_octets` (T-002), whose error becomes `InvalidReply::InvalidMac { reason }` — so an accepted reply *cannot* carry a §5.3-invalid MAC, and the reason (zero/broadcast/multicast) survives for the Details→debug view.
- **D-3 The Ethernet-header comparisons are octet comparisons, not `MacAddr` equality** — the frame's raw source/destination need not be valid MACs to be *compared*, and constructing `MacAddr`s for them would reject zero/broadcast destinations as `InvalidMac` instead of `MacMismatch`, misclassifying the common "not addressed to us" case.
- **D-4 `ArpReplyContext` borrows the solicited set** (`&'a HashSet<Ipv4Addr>`, card R7's "HashSet … or similar"): T-104 builds the set once per scan and the parser answers membership in O(1) — relevant at the 65,534-host FR-SC-06 ceiling. The context itself is deliberately unvalidated: it *describes* the scan; the validator re-derives every sender-IP rule from the scope on its own.
- **D-5 Counters are a side-table, not a parser output**: `ArpReplyCounters::record(&outcome)` keys on the variant, so the parser stays pure and total, and T-104/T-204 cannot get an uncounted rejection past the API (they must call `record` to see tallies, but a missed call cannot change any parse result). `Display` prints totals + nonzero reasons in FR-DS-06 order — a debug line, not UI prose (§5.4).
- **D-6 The reply's target MAC/IP (offsets 32..42) are not decoded at all.** FR-DS-06 assigns them no weight; the validator's `DecodedFrame` stops at the sender IP. This is also what makes the corruption property's non-vacuity assertion (≥50 accepted corruptions) a structural check: if a future change started weighing a target field, that test would fail.
- **D-7 Trailing padding is ignored, and `Truncated` reports `{needed: 42, found}`** (deviation 3). The length gate runs before any field decode, and the decode itself is total via `get` + `try_into` with checked offset arithmetic — the `Option` is the no-indexing discipline, not a second length opinion.
- **D-8 `thiserror` (already locked, already used by the model) derives `InvalidReply`'s `Display`/`Error`.** T-102 hand-rolled its single-variant error because that card demanded "std-only"; this card's §8 says "no new **crates**" and `thiserror` is not new, so the derive is the consistent choice with `MacAddrParseError`/`Ipv4NetError`.
- **D-9 The fuzz harness re-derives the frame layout locally** (its own `FRAME_LEN = 42` and inline field bytes) instead of importing the codec's constants, so a wrong constant in the code under test cannot make the fuzzer silently agree with it; and it duplicates the ~20-line Lcg because `model::testing::Lcg` is `#[cfg(test)]` and unreachable from another package. It exits 1 with the offending input in hex rather than asserting, so the target itself contains no panic path at all.
- **D-10 The fuzz package's lint set matches the root's**, including `print_stdout`/`print_stderr` denied, with the one narrowly scoped `#[allow]` on `fn main` — the same pattern the root `main.rs` uses for the CLI boundary (SR-03 governs TUI-reachable code; this binary has none).

**Assumptions** (per plan §0.2, written down):

- The `plan.md` at the repository root (commit `eea151e`, v1.3.0) is the authoritative plan; the card's "Plan version: 1.3.0" refers to it.
- "Transport-agnostic" (card §2, ADR-009 Pending) means: no socket types, no timing, no state — which the free-function + context-struct API provides; T-104's `ArpTransport` (§8.6) will feed `recv`'d byte vectors straight into `parse_arp_reply`.
- The counters' role ends at tallying: displaying them in Details→debug is T-204's rendering decision, and `Display` is a convenience, not a contract.
- `solicited` may legally contain out-of-scope or reserved addresses (the context is not validated, D-4); the parser still applies conditions 10–12 independently, so such entries can never produce an accepted reply (tested via the solicited-reserved-addresses test).

## 7. Dependencies

**None added or changed.** No crates.io crate was added, removed or re-versioned: the root `Cargo.toml`/`Cargo.lock` are untouched, and every root gate ran `--locked` against the committed lockfile. The `fuzz/` package (allowed by the card and prescribed by §8.1) depends only on the root crate **by path** and adds no external dependency; its `fuzz/Cargo.lock` was pinned to the root lockfile's exact versions (initially the fresh resolution drifted on 8 transitive crates — `js-sys`, `log`, `rustix`, `unicode-width` and the `wasm-bindgen` family — and was `cargo update --precise`'d back, so the two lockfiles now differ only by the `osza-netmon-fuzz` package entry itself). No §9.2 evaluation was therefore needed, and no Plan Question about `libfuzzer-sys` is *filed* — it is offered as follow-up 1 instead, because the card's AC-16 explicitly authorizes the std-only stub.

## 8. Plan Questions

None. Every ambiguity found (fuzzing infrastructure vs the no-new-deps rule, padding beyond 42 bytes, /31 network-address semantics, the `InvalidReply { reason }` sketch vs the per-variant ACs, builder parameterization vs §8.2) was resolvable from plan.md itself (§0.2 precedence, §6.3 FR-DS-06, §6.2 FR-SC-05, §8.1, §8.2) plus the card's own "or"-clauses and AC-16's stub allowance, and is documented in §5/§6 instead. None of them affects behavior beyond what the plan already decides.

## 9. Security and privacy notes

- **Untrusted input (SR-02/SR-04):** a received frame is hostile end to end. The parser is total — length-gated before any field read, every field accessed with `get`/`try_into` and checked offset arithmetic, no `unwrap`/`expect`/indexing/panic path in non-test code (denied lints + 1,000-input and 210-corruption property tests + the 800,872-input fuzz run re-prove it). Nothing is repaired or trimmed silently: every rejection names its reason.
- **Anti-forgery posture (plan §7.1):** all twelve FR-DS-06 conditions are enforced, notably solicited-only (an unsolicited reply is never an observation, however well-formed), Ethernet-source/sender-MAC consistency, and the sender-IP usability rules; the negative-vector suite covers each clause individually and in combination (first-failing-condition order).
- **No network I/O (§2.3):** the codec is pure byte manipulation; the builder produces a `Vec<u8>` and the parser consumes one. No socket exists in this task (R8/grep-verified; the first active-network code is T-104's, behind ADR-005).
- **Privileges:** none needed, none raised.
- **No `unsafe`, no printing (SR-01/SR-03):** grep-verified (§4); the crate-level `unsafe_code = "forbid"` build covers the new files; the fuzz binary's `main`-scoped print allow is documented in D-10.
- **Fixtures are synthetic** (plan §14.3 rule 8): RFC 5737 ranges only (`192.0.2.0/24` scope; `198.51.100.x`, `203.0.113.x` out of scope; `0.0.0.0`/`255.255.255.255` only as builder totality probes), documentation MACs (`aa:bb:cc:dd:ee:xx`, locally-administered `02:…`, the `01:00:5e:…` multicast class only as a rejection vector). No Owner-network identifiers are committed.
- **Secrets:** none stored; no credentials appear in the repository or this report.

## 10. Known issues and limitations

- **The fuzz harness is deterministic, not coverage-guided.** Fixed seeds, fixed counts (800,872 inputs, sub-second in release); it cannot discover the deep structured inputs a coverage-guided fuzzer would (e.g. multi-field coincidences), though every rejection reason is exercised and the acceptance oracle guards the `Ok` path. The `cargo-fuzz` promotion (follow-up 1) removes this limit.
- **VLAN tags are not handled.** An 802.1Q frame (EtherType `0x8101`/`0x88a8`, ARP at +4) is rejected as `WrongEtherType`. Whether T-104's transport strips tags before handing frames to the codec is an ADR-009/T-104 question; the codec per the card sees plain Ethernet.
- **`Truncated` conflates "short frame" with "short header"** — there is no variant for a frame that is long enough but internally inconsistent in lengths; with hlen/plen fixed at 6/4 by conditions 4/5, no such state exists today, so the variant would be dead.
- **The counters are u64 and unbounded in time** (no wrap handling): at the FR-SC-04 ceiling of 500 pps, a u64 bucket overflows after ~1.17 million years of continuous scanning; a per-scan reset (T-104) makes it moot.
- **`MacMismatch` does not say which of conditions 7/8 failed.** The ACs name one variant for both; a future split (`NotAddressedToUs` / `SourceMismatch`) is a compatible extension if the Details→debug view wants the split — noted as follow-up 4.
- **The property tests are deterministic** (fixed Lcg seeds), not cryptographically random — the same trade-off T-002/T-101/T-102 recorded.

## 11. Suggested follow-ups

1. Promote `fuzz/arp_frame.rs` to a real `cargo-fuzz` target (needs the `libfuzzer-sys` dependency approved per §9.2, a `fuzz/` corpus directory committed, and a CI smoke job) — the natural home is T-105's PoC hardening or a dedicated small task; SR-05's "corpus committed" clause is only fully satisfied then.
2. Add the fuzz package to the CI gates (fmt/clippy/build with the same pinned toolchain) so it cannot rot behind the root package's checks — a workflow-only change, out of this card's file scope.
3. Update the README status paragraph with the ARP codec, and `docs/reports/README.md`'s index if it tracks task reports — docs-only changes left out of this card's scope, same as T-101 follow-up 5 / T-102 follow-up 2.
4. When T-204 builds the Details→debug view, decide whether `MacMismatch` should split into its two underlying conditions (known issue 5) and whether `ArpReplyCounters`' `Display` line is the right rendering or the view should enumerate `rejected_with` per reason.
5. Carried from T-002/T-101/T-102: add a `Display` impl for `Ipv4Net` (CIDR form) when the first caller formats a scope — T-104's scan logging and the T-302 scope screen will want it.
