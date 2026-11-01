# Execution Report — T-102 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-01 · **Branch/commits:** `task/T-102-neighbor-table-reader` — `d39432e` (`src/discovery/` implementation), plus this report · **Plan version:** 1.3.0 (repository copy, commit `eea151e`)

## 1. Summary (≤ 5 lines)

The first FR-DS-01 discovery data source is implemented in `src/discovery/neighbor_table.rs`: the object-safe `NeighborSource` trait, `ProcNeighborTable` (bounded 64 KiB read of `/proc/net/arp` via `Read::take`, SR-10), a total parser for the six Appendix E columns (header skip, whitespace/CRLF tolerance, malformed lines skipped whole), and the FR-DS-02 filters (exact interface match, scope containment, `ATF_COM` completeness; the MAC boundary is the T-002 `MacAddr::from_octets`). Std-only, no new dependencies, no network I/O. 21 new unit tests + 3 doctests (fixtures for every AC, non-UTF-8 lines, an exact-count 64 KiB cap proof, object safety, live invariants, 2×1,000 hostile-input property tests); 101 unit + 6 doctest total, all gates green locally on the pinned toolchain.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1: complete entries (`0x2`) on the selected interface and scope → entries returned | Met | `parses_a_realistic_arp_table` (every field asserted: ip, hw_type, flags, mac, device, `is_complete`), `full_pipeline_keeps_exactly_the_fr_ds_02_entries` (the three keepers of `REALISTIC_TABLE` and nothing else), doctests `parse_arp_table` / `filter_neighbors` / `ProcNeighborTable`. |
| AC-2: incomplete entries (`0x0`) → all dropped | Met | `incomplete_entries_are_dropped` (the `0x0` row is dropped, the `0x2` row survives); parse-vs-filter split documented in `parses_a_realistic_arp_table` (an incomplete row still *parses*; completeness is a FR-DS-02 filter). |
| AC-3: permanent-only entries (`0x4` without `0x2`) → dropped | Met | `permanent_only_entries_are_dropped_and_combined_flags_kept` — `0x4` dropped; `0x6` (permanent + complete) and `0xA` kept with their raw flag values (R5); predicate table in `is_complete_reflects_the_atf_com_bit` (0x0/0x1/0x2/0x3/0x4/0x6/0xA). |
| AC-4: entries on a different interface → dropped | Met | `entries_on_other_interfaces_are_dropped` — `wlan0`, `eth1`, the prefix trap `eth0x` and the case trap `ETH0` all dropped; exact `eth0` match kept. |
| AC-5: IP outside scope → dropped | Met | `out_of_scope_entries_are_dropped` — TEST-NET-2 (`198.51.100.5`), TEST-NET-3 (`203.0.113.9`) and the adjacent `192.0.3.1` dropped; `192.0.2.1` kept; the /24 edges `.0`/`.255` kept (`Ipv4Net::contains` is inclusive, documented). |
| AC-6: zero, broadcast, multicast MACs → dropped | Met | `invalid_macs_are_rejected_at_the_boundary` — `00:00:00:00:00:00`, `ff:ff:ff:ff:ff:ff`, `01:00:5e:…` (IPv4 multicast), `33:33:…` (IPv6 multicast) produce no entry at all (parse-time boundary, R6); locally-administered `02:…` kept. |
| AC-7: garbage lines → valid lines still parsed, garbage skipped | Met | `malformed_lines_are_skipped_and_valid_lines_are_kept` (18 garbage forms: truncated 3-column, 5-column, non-hex flags, flags without `0x` prefix, u32-overflowing flags, octet-out-of-range IP, leading-zero IP, 3-field IP, 5-octet/non-hex/bare/mixed-separator MAC, non-hex HW type, invalid mask, `eth/0`, `eth:0`, 16-byte device, empty line, bare word — two anchors survive), `non_utf8_lines_are_skipped_whole` (0xff inside the MAC and the IP), `whitespace_runs_tabs_and_crlf_are_tolerated`, `columns_past_the_sixth_are_ignored`, `headerless_input_loses_only_its_first_line`, `empty_and_header_only_input_yield_no_entries`. |
| AC-8: size-bounded read (1 MB input, 64 KiB cap) | Met | `the_read_is_capped_at_64_kib` — a 1,280,048-byte temp file of fixed 64-byte lines returns **exactly** the 1,023 lines that fit in the first 64 KiB (arithmetic pinned by asserted fixture lengths and a cut-position guard); `Read::take(64 * 1024)` before `read_to_end`. |
| AC-9: property test — 1,000 random byte strings, never panics, output ≤ line count | Met | `property_parse_never_panics_on_hostile_input` (1,000 random-byte strings through lossy decode + parse + the full FR-DS-02 pipeline, output ≤ line count asserted), plus `property_parse_never_panics_on_token_soup` (1,000 column-shaped garbage lines, T-101 parity). |
| AC-10: all engineering gates pass | Met | §4: fmt, clippy (`-D warnings`), test (101 unit + 6 doctests), doc (plain and CI's `RUSTDOCFLAGS="-D warnings"` variant), audit (0 findings, 188 crates), deny (exit 0; the 4 warnings are byte-identical to the unmodified-`main` baseline, re-verified by stashing this changeset), MSRV build at 1.89.0. |
| AC-11: no `unsafe`, no `println!`/`eprintln!` in non-test code | Met | §4 greps: no `unsafe`, no `println!`/`eprintln!` anywhere in `src/discovery/`; every `unwrap`/`expect` match is inside `#[cfg(test)] mod tests` (24) or a doc-example (3) — clippy `allow-*-in-tests` is the authoritative enforcement and the non-test region has zero matches (cross-checked with `awk`). |
| AC-12: every new `.rs` file starts with the SPDX header | Met | §4: `find src/discovery -name "*.rs" -exec head -1 {} \; | sort | uniq -c` → 2 × `// SPDX-License-Identifier: GPL-3.0-only` (both new files). |

## 3. What changed

On `task/T-102-neighbor-table-reader` (base: `main` at `967db8d`):

- `d39432e` — the implementation:
  - `src/discovery/neighbor_table.rs` (1,127 lines incl. tests) — `NeighborEntry` (private fields + accessors, `is_complete()` on `ATF_COM`), `NeighborError` (std-only, path + `source`), the object-safe `NeighborSource` trait, `ProcNeighborTable` (`new`/`from_path`/`path`, bounded `read_table`, `Default`), `parse_arp_table` (total parser, all six columns validated), `filter_neighbors` (FR-DS-02 interface/scope/completeness), private helpers (`parse_line`, `parse_ipv4_decimal`, `parse_prefixed_hex`, `parse_mac_octets`, `is_valid_mask`, `is_kernel_device_name`, `hex_value`, `neighbors_from_bytes`); `#[cfg(test)] mod tests` with 21 tests.
  - `src/discovery/mod.rs` — module declaration and re-exports of the 6 public items (§8.1: discovery modules appear when their task arrives).
  - `src/lib.rs` — `pub mod discovery;` + doc note (the only change to existing code).
- report commit — `docs/reports/T-102/execution-01.md` (this file).

`plan.md`, `Cargo.toml`/`Cargo.lock`, the model/net sources, workflows and `deny.toml` are untouched. No ADR was added: ADR-010 stays Pending (decided by T-105), and this task made no architecture decision beyond interpreting the card.

## 4. Verification results

Card §9 commands, executed 2026-11-01 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from the CI-pinned, SHA-256-verified release tarballs):

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.29s
[exit 0]

$ cargo test --locked --all-features 2>&1 | grep -E "(test result|running)"
running 101 tests
test result: ok. 101 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[101 unit tests (21 new for T-102 + 80 pre-existing T-000/T-002/T-101) + 6 doctests (3 new: parse_arp_table, filter_neighbors, ProcNeighborTable; 3 pre-existing)]

$ cargo doc --no-deps
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.23s
    Generated /home/z/my-project/osza-netmon/target/doc/osza_netmon/index.html
[exit 0; CI variant with RUSTDOCFLAGS="-D warnings": also exit 0]

$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1395 security advisories (from /home/z/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (188 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings, no yanked crates]

$ cargo deny check
warning[duplicate]: found 2 duplicate entries for crate 'syn'
warning[license-not-encountered]: license was not encountered   (×3)
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — byte-identical to the unmodified main checkout (verified by stashing this changeset, re-running, diffing: identical; multiple-versions = "warn" is policy), so these are the known benign T-000 baseline warnings, not introduced here]

$ rustup run 1.89.0 cargo build --locked
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.37s
[exit 0 — MSRV per Cargo.toml; the new module uses no API newer than 1.89]

$ find src/discovery -name "*.rs" | sort
src/discovery/mod.rs
src/discovery/neighbor_table.rs

$ grep -rn "unsafe" src/discovery/ || echo "No unsafe found"
No unsafe found

$ grep -rn "println!\|eprintln!" src/discovery/ || echo "No println/eprintln found"
No println/eprintln found

$ grep -rn "unwrap\|expect" src/discovery/ --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" || echo "No unwrap/expect in non-test code"
[27 matches — 24 inside the #[cfg(test)] mod tests that opens at line 572 of src/discovery/neighbor_table.rs, plus 3 in `///` doc-example lines (220, 223, 384) that are doctest code, compiled only by rustdoc as separate test crates. The non-test region (lines 1–571) contains zero matches — cross-checked directly: awk 'NR<572 && /unwrap|expect/' src/discovery/neighbor_table.rs → 0 lines. Test-only unwrap/expect is permitted by clippy.toml (allow-*-in-tests); clippy is the authoritative enforcement and is green.]

$ find src/discovery -name "*.rs" -exec head -1 {} \; | sort | uniq -c
      2 // SPDX-License-Identifier: GPL-3.0-only
```

Additional task-specific verification:

- **`--test-threads=1`** — full suite single-threaded: identical 101+6 pass result; no order dependence (the only shared state, the live kernel table, is read-only — `live_kernel_table_satisfies_the_documented_invariants` asserts two reads agree).
- **`--locked` discipline** — every dependency-resolving command above ran with `--locked` (deviation 1); `cargo fmt --check` runs without it (cargo-fmt rejects the flag), as in T-000…T-101.
- **Live pipeline observation** (synthetic sandbox, not the Owner's network; the addresses below are the sandbox's cloud-fabric values, no Owner-network identifiers): `/proc/net/arp` (310 bytes) held three `eth0` rows, flags `0x6`; `read_neighbors(0.0.0.0/0, "eth0")` returned all three — `100.100.2.138 → fa:ff:ff:ff:ff:ff`, `100.100.100.200 → fa:ff:ff:ff:ff:ff`, `21.0.0.1 → ee:ff:ff:ff:ff:ff`, each `flags=0x06 hw_type=0x01 complete=true` (the cloud-style locally-administered unicast MACs pass the §5.3 boundary) — and `read_neighbors(192.0.2.0/24, "eth0")` returned zero entries (no real address inside TEST-NET-1). Collected with a temporary integration test that was deleted after the run (`git status` clean of it before committing).

**Test summary per type** (card §6 list):

| Type | Unit tests | Property tests | Key edge cases covered |
|---|---|---|---|
| Parsing | 9 | 2 | realistic 6-row table (every column incl. raw flags `0x6`, `hw_type`); empty/`\n`/header-only; 18 garbage forms; non-UTF-8 lines (0xff in MAC and IP); tabs/CRLF/multi-space/leading whitespace; dash-separated MAC (R4); dotted-netmask Mask; >6 columns ignored; headerless file; `is_complete` predicate table |
| FR-DS-02 filters | 5 | 0 | `0x0` dropped; `0x4` dropped, `0x6`/`0xA` kept raw; wrong interface (`wlan0`, `eth1`, prefix `eth0x`, case `ETH0`) dropped; TEST-NET-2/3 + adjacent /24 dropped, /24 edges kept; zero/broadcast/`01:00:5e:`/`33:33:` MACs produce no entry, `02:` kept |
| Source surface | 5 | 0 | 64 KiB cap (exact 1,023-of-20,000 count on a 1.28 MB fixture); constructors/`Default`/`path()`; missing file and directory are `NeighborError::Io` (Display names the path, `source()` chains); object safety (`&dyn NeighborSource`); live invariants (complete, device, scope, double-read equality) |

(Totals: 21 new test functions — 19 unit + 2 property — plus 3 new doctests; the live-invariants test runs on the host kernel and is deterministic on Linux CI runners, where `/proc/net/arp` always exists.)

## 5. Deviations from the task card

1. **`cargo` commands run with `--locked`** (card §9 omits it; CI and T-000…T-101 use it) — same as T-002 deviation 2 / T-101 deviation 2. `cargo fmt --check` runs without it (cargo-fmt rejects the flag).
2. **Lines with more than six columns keep their first six.** Appendix E says "ignore unknown columns" and plan §0.2 puts the plan above the card, so the card §6 garbage phrase "wrong number of columns" is implemented as *too few* columns (skipped) while extras are ignored — the exact behavior T-101 documented as its deviation 4, tested in `columns_past_the_sixth_are_ignored`.
3. **The Mask column is validated (`*` or dotted-quad) although the card's malformed list does not name it.** Card §2 requires "the same parsing discipline" as T-101, whose parser validates all eleven `/proc/net/route` columns including the five it does not store; one bad column marks the line non-kernel. Documented on `parse_arp_table`; tested (the `not-a-mask` line in the garbage suite).
4. **A second property test (token soup) was added beyond the card's one.** T-101 set the precedent of two 1,000-case hostile-input properties; both use the crate's deterministic `model::testing::Lcg` (no `proptest` — adding it would need a Plan Question per §14.5).
5. **The live test asserts `/proc/net/arp` exists and is readable.** Not in the card's §6 list; it makes the live smoke test deterministic on Linux (the plan's only supported platform) without asserting environment-specific values — the same pattern as T-101's `lo` invariant (its deviation 6).

## 6. Decisions and assumptions

**Decisions:**

- **D-1 Read pipeline = open → `Read::take(64 KiB)` → `read_to_end` → `from_utf8_lossy` → parse → filter.** The lossy decode is safe because *every* column is validated and U+FFFD passes no column validator, so a line containing bytes that are not valid UTF-8 is skipped whole (tested in `non_utf8_lines_are_skipped_whole`); this keeps one parser (`&str`-based, like `parse_routes`) instead of a parallel byte-level one. Unlike T-101's route read (any failure → empty `Vec`), I/O failures surface as `Err(NeighborError::Io)` because the card's own signature is `Result` — a caller can tell "no neighbors" from "table unreadable".
- **D-2 The MAC boundary is enforced at parse time, by construction.** `parse_line` builds entries through `MacAddr::from_octets` (card R6: "use it as the boundary"), so `NeighborEntry` exists only with a valid unicast sender MAC and the fourth FR-DS-02 filter cannot be forgotten by a future caller; the other three filters live in `filter_neighbors`, applied in the card's order (interface, scope, completeness).
- **D-3 "Unknown device" (card §3 malformed list) = a Device column that cannot be a kernel interface name.** Implemented as a mirror of the kernel's own `dev_valid_name()`: 1..=15 bytes (`IFNAMSIZ` − NUL), no `/` or `:`, neither `.` nor `..`. This never rejects a name the kernel could have created (no data loss), and any remaining weird token dies at the FR-DS-02 exact-match interface filter, so it can never reach a caller.
- **D-4 HW type and Flags require the `0x` prefix** (the kernel's format in this file); values are decoded with checked arithmetic, so `0x100000000` (u32 overflow) is rejected instead of wrapping.
- **D-5 The IP column uses a manual dotted-decimal parser** (card R3's preference): exactly four octets of 1–3 ASCII digits, no leading zeros (`%pI4` never emits them), each ≤ 255 via `u8::try_from`.
- **D-6 The HW address column accepts `:`- or `-`-separated six two-digit hex octets with a consistent separator** (card R4); the bare 12-digit form `MacAddr` also accepts is rejected here because `/proc/net/arp` never uses it, and mixed separators are rejected.
- **D-7 Line 0 is always the header** and skipped unconditionally (T-101 D-10 parity; a headerless file loses its first line — documented and tested).
- **D-8 Flags stay a raw `u32` with `is_complete()` (`ATF_COM`, bit 1)** per card R5; `hw_type` is kept raw too — classification (`LinkType`) lives in `net`, which `discovery` must not depend on (§8.2).
- **D-9 `NeighborError` is hand-rolled with `std` only** (manual `Display` + `Error`, `source()` chains to `io::Error`, the variant carries the offending path) because the card pins this task to "std-only (no new crates)". `thiserror` is already a locked direct dependency and would replace the two small impls if the Manager prefers consistency — noted as follow-up 5.
- **D-10 `parse_arp_table` and `filter_neighbors` are public and pure**, mirroring `parse_routes`: doctests and fixture suites exercise them directly, and the T-105 netlink source (if ADR-010 adopts one) can reuse the exact FR-DS-02 filter instead of reimplementing it.
- **D-11 Output preserves file order and does not deduplicate** (two rows for one IP both return); merging observations is the registry's job (T-201).
- **D-12 The live smoke test asserts invariants only** (complete, device, scope, read-twice equality) — values are host-specific.

**Assumptions** (per plan §0.2, written down):

- The `plan.md` at the repository root (commit `eea151e`, v1.3.0) is the authoritative plan; the card's "Plan version: 1.3.0" refers to it.
- "Complete entries only" (FR-DS-02) means the `ATF_COM` bit (`Flags & 0x2`), exactly as the card's §3 spells out; other bits never gate the filter.
- FR-DS-01's cycle timing (read before and after the sweep) is orchestration; this task delivers the reader the cycle will call (card §1).
- The scope filter is `Ipv4Net::contains` verbatim (card §3), whose model semantics include the network and broadcast addresses; the edge test documents this.

## 7. Dependencies

**None.** No crate was added, changed or removed; `Cargo.toml`/`Cargo.lock` are untouched and every gate ran `--locked` against the committed lockfile. The only crate-level choice was *not* using the already-present `thiserror` for `NeighborError`, to honor the card's "std-only" clause (D-9).

## 8. Plan Questions

None. Every ambiguity found (extra columns, mask validation, "unknown device") was resolvable from plan.md itself (Appendix E, §0.2 precedence, §14.3) plus the T-101 precedent the card explicitly points at, and is documented in §5/§6 instead.

## 9. Security and privacy notes

- **Untrusted input (SR-02/SR-04):** `/proc/net/arp` is treated as hostile end to end — the read is bounded at 64 KiB before any parsing (SR-10), every column is validated, malformed lines are skipped whole and never repaired, and there is no `unwrap`/`expect`/indexing/panic path reachable from file content (the denied clippy lints plus 2,000 hostile property inputs re-prove it).
- **No network I/O (§2.3):** the module opens exactly one file and sends nothing; the first active-network code remains T-104's, behind ADR-005. The card's R7 is grep- and code-verified.
- **Privileges:** none needed, none raised (ADR-005 unprivileged model unaffected).
- **No `unsafe`, no printing (SR-01, SR-03):** grep-verified (§4); the crate-level `unsafe_code = "forbid"` build covers the new files.
- **Fixtures are synthetic** (plan §14.3 rule 8): RFC 5737 ranges (`192.0.2.0/24` scope; `198.51.100.x`, `203.0.113.x` out-of-scope), documentation MACs (`aa:bb:cc:dd:ee:xx`, locally-administered `02:…`), and the documented flag values. The live observation in §4 records only the synthetic sandbox's cloud-fabric addresses — no Owner-network identifiers are committed.
- **Secrets:** none stored; no credentials appear in the repository or this report.

## 10. Known issues and limitations

- **No neighbor state.** `/proc/net/arp` exposes flags only; `reachable`/`stale`/`failed` semantics need the netlink source ADR-010 leaves Pending for T-105 (plan §4). `NeighborEntry::flags` keeps the raw value so a state mapping has data to work from.
- **I/O failures collapse into one `Io` variant** (path + `source`); distinguishing missing-file from permission-denied is the caller's choice via `io::ErrorKind` — the first caller that needs richer taxonomy is T-201/T-30x.
- **Duplicate rows are not merged** (D-11): a host with two rows for one IP returns two entries; deduplication is the registry's (T-201) job.
- **Content beyond 64 KiB is silently ignored** (by design, SR-10). A real table never approaches the bound (one short line per neighbor); the exact-count test documents the truncation behavior.
- **The property tests are deterministic** (fixed Lcg seeds), not cryptographically random — the same trade-off T-002/T-101 recorded; 2,000 hostile inputs per run still exercise the never-panic and count-bound properties.
- **The live test can flake** if the kernel's ARP table changes between its two reads (accepted, as in T-101's known issue 5; the double-read assertion would be the one to drop).
- **`interface_name` is matched exactly, not validated** by `read_neighbors`: a caller passing a name no interface has simply gets an empty vector, not an error (documented on the trait).

## 11. Suggested follow-ups

1. T-105: resolve ADR-010 (`/proc/net/arp` vs netlink `RTM_GETNEIGH`). The `NeighborSource` trait is object-safe and transport-free (R10), and `filter_neighbors` is public, so a `NetlinkNeighborSource` can slot in next to `ProcNeighborTable` and reuse the FR-DS-02 filter verbatim.
2. Update the README status paragraph ("No discovery … implemented yet") with the neighbor-table reader — a docs-only change left out of this card's scope, same as T-101's follow-up 5.
3. Carried from T-002/T-101: add a `Display` impl for `Ipv4Net` (CIDR form) when the first caller formats a scope — the T-105 PoC report and the T-302 scope screen will want it.
4. When T-201 consumes `NeighborEntry`, decide whether the registry wants the raw `flags`/`hw_type` exposed further (they are public accessors already) or wrapped into `Field::Known { source: Source::NeighborTable }` at the boundary as planned.
5. Manager discretion: replace the hand-rolled `NeighborError` impls with the already-locked `thiserror` derive for consistency with `MacAddrParseError`/`Ipv4NetError` (D-9) — a mechanical, behavior-preserving change.
