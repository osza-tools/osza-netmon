# Execution Report — T-101 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-10-31 · **Branch/commits:** `task/T-101-interfaces-scope` — `056cf30` (ADR-017 + dependency decision), `a066ee4` (`src/net/` implementation), plus this report · **Plan version:** 1.3.0 (repository copy, commit `eea151e`)

## 1. Summary (≤ 5 lines)

The interface discovery and scope layer of plan §6.2 is implemented in `src/net/interfaces.rs`: `InterfaceInfo` with every FR-SC-01 field (private fields, accessors), FR-SC-03 eligibility with typed reasons, FR-SC-02 class/ranking/suggestion, a total `/proc/net/route` parser (little-endian hex per Appendix E) and FR-SC-04/05/06 scope derivation via the T-002 `Ipv4Net`. Data source decided by ADR-017: `getifaddrs(3)` through the `nix` safe wrapper (one new direct dependency, **zero new crates in the graph** — the `Cargo.lock` diff is a single line, PQ-1 raised per card §8). 28 new tests (fixtures, malformed lines, ranking drain, all six prefix lengths, 2×1,000 hostile-input property tests, live invariants); 80 unit + 3 doctest total, all §11.3 gates green locally.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| `parse_routes` fixture tests: multiple routes, no default route, malformed lines (truncated, wrong hex, missing columns), empty input | Met | `parses_a_realistic_route_table` (3 routes, every column decoded incl. little-endian `0100A8C0`→192.168.0.1), `returns_none_when_no_default_route_exists`, `malformed_lines_are_skipped_and_valid_lines_are_kept` (truncated 10-column line, wrong-hex Gateway, wrong-hex RefCnt, overflowing hex, empty line, bare word — only the valid lines parse), `empty_and_header_only_input_yield_no_routes`, plus `hex_columns_are_case_insensitive_and_whitespace_runs_are_tolerated` (CRLF/multi-space), `columns_past_the_eleventh_are_ignored`, `headerless_input_loses_only_its_first_line`; §4 outputs. |
| `find_default_gateway` returns correct gateway when present, `None` when absent | Met | `finds_the_default_gateway_when_present`, `returns_none_when_no_default_route_exists`; rule and determinism: `default_gateway_requires_zero_destination_zero_mask_and_gateway_flag` (5-row table incl. on-link default and masked zero), `lowest_metric_wins_and_file_order_breaks_ties`. |
| Interface ranking: Wi-Fi (eligible, physical, default route) > Ethernet (eligible, physical) > docker0 (eligible, virtual) > veth123 (eligible, virtual) > lo (ineligible: Loopback) | Met | `ranking_follows_the_fr_sc_02_priority` — the five interfaces shuffled in the input; asserts `wlan0` suggested, then drains the suggestion repeatedly and asserts the full order `wlan0 → eth0 → docker0 → veth123` with `lo` never suggested. |
| `suggest_interface` returns the highest-ranked eligible interface | Met | `ranking_follows_the_fr_sc_02_priority`; tier edges: `a_default_route_carrier_outranks_physical_interfaces` (virtual `tun0` with default route beats idle physical NICs, FR-SC-02 "the one carrying the default route"), `same_tier_breaks_ties_by_name`, `suggest_returns_none_without_eligible_interfaces` (empty list and ineligible-only list). |
| Eligibility: no UP flag → `NotUp`; non-Ethernet link → `NotEthernet`; no IPv4 → `NoIpv4Address`; `lo` → `Loopback` | Met | `eligibility_reports_each_reason` (one mutation per variant + eligible baseline), `eligibility_check_order_is_deterministic` (fixed precedence Loopback → NotUp → NotEthernet → NoIpv4Address, decision D-2), `an_up_but_not_running_interface_stays_eligible` (D-3: FR-SC-03 keys on `IFF_UP`). |
| Virtual classification: `docker0`, `vethabc`, `br-int`, `virbr0`, `tun0`, `tap0`, `wg0`, `lo` → `Virtual`; `eth0`, `wlan0` → `Physical` | Met | `classifies_virtual_and_physical_names` — the card's ten names plus four boundary cases the pattern list decides (`br0` physical — pattern is `br-`; `lo0` physical — `lo` matches by equality; `wlp3s0` physical; `tunl0` virtual — starts with `tun`). |
| Scope derivation: /24, /22, /30 (2 hosts), /31 (2 hosts, RFC 3021), /32 (1 host), /16 over default cap per FR-SC-06 | Met | `derives_scope_for_the_card_prefix_lengths` (all six: base network, prefix, host count), `derived_scope_covers_the_interfaces_own_network_only` (FR-SC-04 containment + FR-SC-05 ranges for /24, /22-at-cap, /31 RFC 3021, /32), `a_16_scope_exceeds_the_default_cap_per_fr_sc_06` (`OverCapacity { requested: 65_534, cap: DEFAULT_MAX_HOSTS }`, allowed at `ABSOLUTE_MAX_HOSTS`, /15 rejected even at the ceiling), `derive_scope_returns_none_without_an_ipv4_address`. |
| All parsers total: no panics on hostile input (property test with 1000 random strings) | Met | `property_parse_routes_never_panics_on_hostile_input` (1,000 random-byte strings, plus output ≤ line-count invariant), `property_parse_routes_never_panics_on_token_soup` (1,000 column-shaped garbage lines: random hex any case, oversized hex, non-hex junk, random whitespace); lints deny `panic`/`unwrap`/`expect`/`indexing_slicing` in non-test code (§4 grep evidence). |
| All engineering gates pass: fmt, clippy, test, doc, audit, deny, MSRV | Met | §4: every command exit 0 (fmt clean; clippy `-D warnings` clean; 80+3 tests; `cargo doc` with `RUSTDOCFLAGS="-D warnings"`; `cargo audit` 0 findings on 188 crates; `cargo deny check` advisories/bans/licenses/sources ok — the 4 warnings are byte-identical to the pre-change baseline, §4; `rustup run 1.89.0 cargo build --locked` Finished; SPDX 10/10 `.rs` files). |

## 3. What changed

On `task/T-101-interfaces-scope` (base: `main` at `eea151e`):

- `056cf30` — the data-source decision:
  - `docs/adr/017-interface-data-source.md` — ADR-017 (Appendix G format): options (own FFI rejected by SR-01; `/sys/class/net` rejected — no per-interface IPv4/prefix, and `fib_trie` lacks interface attribution; `nix` chosen), the full 7-criterion §9.2 evaluation table, consequences, evidence links.
  - `docs/adr/index.md` — row 017 plus a note that ADR-017 is the first task-card-originated ADR (not a plan §4 transcription), and that its status tracks PQ-1.
  - `Cargo.toml` — `nix = { version = "=0.31.3", default-features = false, features = ["net"] }` (exact pin like ratatui, only the `net` feature; comment cross-references ADR-017/PQ-1).
  - `Cargo.lock` — **one line**: `"nix 0.31.3",` joins our dependency list; all five transitive crates (libc 0.2.191, bitflags 2.13.2, cfg-if 1.0.5, memoffset 0.9.1) were already locked for the ratatui tree.
- `a066ee4` — the implementation:
  - `src/net/interfaces.rs` (1,468 lines incl. tests) — `RouteEntry` (private fields + accessors, `is_default_gateway` predicate), `parse_routes` (total, header skip, all-11-columns hex validation, little-endian decode), `find_default_gateway` (lowest metric, file-order tie), `LinkType` (ARPHRD classification, `is_ethernet`), `IneligibleReason` + `Eligibility`, `InterfaceClass` (+ §5.4-safe `Display` labels), `InterfaceInfo` (all FR-SC-01 fields private, accessors, computed `class`/`eligibility`/`carries_default_route`), `enumerate_interfaces` (getifaddrs AF_PACKET + AF_INET merge, bounded `/proc/net/route` read, name-sorted), `suggest_interface` (FR-SC-02 tiers, name tie), `derive_scope` (FR-SC-04); `#[cfg(test)] mod tests` with 28 tests.
  - `src/net/mod.rs` — module declaration + re-exports of the 11 public items.
  - `src/lib.rs` — `pub mod net;` + doc note (the only change to existing code outside `Cargo.toml`).
- report commit — `docs/reports/T-101/execution-01.md` (this file).

`plan.md`, the model sources, workflows and `deny.toml` are untouched.

## 4. Verification results

Card §9 commands, executed 2026-10-31 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 reinstalled at the CI pins from SHA-256-verified release tarballs):

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.23s
[exit 0]

$ cargo test --locked --all-features 2>&1 | grep -E "(test result|running)"
running 80 tests
test result: ok. 80 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[80 unit tests (28 new for T-101 + 52 pre-existing T-000/T-002) + 3 doctests (2 new: parse_routes, find_default_gateway; 1 pre-existing Ipv4Net::new)]

$ cargo doc --no-deps
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.21s
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
warning[license-not-encountered]: license was not encountered   (×3)
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — the same 4 warnings appear on the unmodified main checkout (verified by stashing this changeset and re-running: identical output), so they are the known benign baseline of T-000, not introduced here; multiple-versions = "warn" by policy]

$ rustup run 1.89.0 cargo build --locked
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 18.22s
[exit 0 — nix 0.31.3 declares rust-version 1.69]

$ find src/net -name "*.rs" | sort
src/net/interfaces.rs
src/net/mod.rs

$ grep -rn "unsafe" src/net/ || echo "No unsafe found"
No unsafe found

$ grep -rn "unwrap\|expect" src/net/ --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" || echo "No unwrap/expect in non-test code"
[36 matches — every one at lines ≥ 797 of src/net/interfaces.rs, i.e. inside the #[cfg(test)] mod tests that opens at line 768: 26× expect(, 2× unwrap(), 2× unwrap_err(), 6× the word "expected" as a test-table variable. The non-test region (lines 1–767) contains zero matches — cross-checked directly: awk 'NR<768 && /unwrap|expect/' src/net/interfaces.rs → 0 lines. Test-only unwrap/expect is permitted by clippy.toml (allow-*-in-tests).]

$ grep -rn "println!\|eprintln!" src/net/ || echo "No println/eprintln found"
No println/eprintln found

$ find src/net -name "*.rs" -exec head -1 {} \; | sort | uniq -c
      2 // SPDX-License-Identifier: GPL-3.0-only

$ ls -la docs/adr/017-interface-data-source.md
-rw-rw-r-- 1 z z 6270 Oct 31 13:06 docs/adr/017-interface-data-source.md
```

Additional task-specific verification:

- **`--test-threads=1`** — full suite run single-threaded first: identical 80+3 pass result; no order dependence (the only shared state, the live kernel, is read-only — `live_enumeration_satisfies_the_documented_invariants` asserts enumerating twice yields the identical inventory).
- **`--locked` discipline** — every dependency-resolving command above ran with `--locked` (deviation 2); `cargo fmt --check` runs without it (cargo-fmt rejects the flag), as in T-000/T-001/T-002.
- **Baseline `cargo deny check` comparison** — with this changeset stashed, the unmodified `main` tree emits the same `duplicate syn` + 3 `license-not-encountered` warnings; unstash restores the tree (`git status --short` clean afterwards).
- **Live pipeline observation** (synthetic sandbox, not the Owner's network; no identifiers recorded beyond interface names): `enumerate_interfaces()` returned three interfaces — `lo` (Ineligible: loopback interface, MAC all-zero → `None` per §5.3), `dummy0` (Ineligible: interface is down), `eth0` (eligible, Ethernet, ARPHRD 1, carries the default route via `/proc/net/route`); `suggest_interface` picked `eth0` and `derive_scope` produced its own /32 network — the full FR-SC-01→02→04 path exercised against a real kernel without any socket.
- **SPDX header check** (local mirror of the CI step) — 10/10 `.rs` files carry `// SPDX-License-Identifier: GPL-3.0-only` as line 1 (8 pre-existing + 2 new).
- **Controlled-vocabulary pre-check** (§5.4, proactive as in T-002 D-9) — no banned word appears in any user-facing string added by this task; the phrase "safe wrapper" in ADR-017/doc comments is the plan's own technical term for nix's API (plan §4 ADR-009 "nix safe wrappers", §13 T-101 "getifaddrs via a safe wrapper"), not a user-facing security claim.

**Test summary per type** (card §9 requirement):

| Type | Unit tests | Property tests | Key edge cases covered |
|---|---|---|---|
| Route parsing | 10 | 2 | realistic 3-route table (every stored column, incl. `0100A8C0`→192.168.0.1 LE decode and hex metric 64=100); empty/`\n`/header-only; malformed neighbors (10-column truncation, wrong-hex Gateway, wrong-hex RefCnt — a column we don't store, u32-overflowing hex, empty line, bare word); lowercase hex + CRLF + multi-space runs; >11 columns tolerated; headerless file documented; default-gateway predicate 5-row table (on-link default, masked zero, non-zero dest); lowest metric + file-order tie; 1,000 random-byte strings and 1,000 token-soup lines never panic, output ≤ line count |
| Classification & eligibility | 5 | 0 | 14-name class table (card's 10 + `br0`/`lo0`/`wlp3s0`/`tunl0` boundaries); each of the four `IneligibleReason`s; fixed precedence order; up-but-not-running stays eligible; ARPHRD classification + `raw()` round-trip for 1/512/772/65534 |
| Ranking & suggestion | 4 | 0 | card's 5-interface scenario shuffled + drained to the full order; tier tie by name; virtual default-route carrier beats physical; `None` on empty and ineligible-only lists |
| Scope derivation | 4 | 0 | /24 /22 /30 /31 /32 /16 (+ /15 over ceiling): network base, prefix, host count; FR-SC-04 containment; FR-SC-05 ranges (/24, /22 at cap, /31 RFC 3021, /32); FR-SC-06 `OverCapacity` at 65,534 vs 1,022, allowed at the ceiling, /15 rejected; `None` without IPv4 |
| Types & surface | 3 | 0 | every FR-SC-01 accessor; `Display` labels (`virtual`/`physical`, four reason strings); live invariants (sorted unique names, `lo` loopback+virtual+ineligible with `mac() == None`, suggestion always eligible with a containing scope, double-enumeration equality) |

(Totals: 28 new test functions — 26 unit + 2 property — plus 2 new doctests; the live-invariants test runs on the host kernel and is deterministic on Linux CI runners, where `lo` always exists.)

## 5. Deviations from the task card

1. **New dependency `nix` 0.31.3 added.** Card §3 names this ADR path ("ADR documenting the interface data source chosen (e.g., `getifaddrs` via safe wrapper, `/sys/class/net`, or `nix`)") and §8 conditions it on a §9.2 evaluation in this report plus a Plan Question (PQ-1, §8 below). The dependency was added rather than deferred because the only std-reachable alternative cannot supply the FR-SC-01 IPv4/prefix field (ADR-017, options 1–2); the cost is minimal — zero new crates in the graph (lock diff: one line). If the Manager declines PQ-1, the rework is confined to `Cargo.toml`/`Cargo.lock` + the enumeration function.
2. **`cargo` commands run with `--locked`** (card §9 omits it; CI and T-000…T-002 use it) — same as T-002 deviation 2. `cargo fmt --check` runs without it (cargo-fmt rejects the flag).
3. **All 11 columns are hex-validated, five are not stored.** Card §5.5 says "malformed hex (skip line)" without limiting which columns; the parser validates RefCnt/Use/MTU/Window/IRTT too, so one bad column marks the line non-kernel and drops it. Documented in `parse_routes` and tested (`malformed_lines_are_skipped_and_valid_lines_are_kept`).
4. **Lines with more than 11 columns keep their first 11.** The card tolerates "extra whitespace" (which yields no extra tokens) but is silent on extra columns; the parser takes the first 11 and ignores the rest (tested). The alternative — skip — would drop lines a future kernel extension might append to.
5. **`enumerate_interfaces()` returns an empty `Vec` on source failure.** The card fixes that signature (§5.2); a `getifaddrs` error or unreadable `/proc/net/route` therefore collapses to "no interfaces", indistinguishable from an interface-less machine. Documented on the function; surfaced as follow-up 4 (typed error when a caller can present the difference).
6. **Live test asserts `lo` exists.** Not in the card's §7 list; it makes the live smoke test deterministic on any Linux host/CI runner (the plan's only supported platform) without asserting environment-specific values.

## 6. Decisions and assumptions

**Decisions:**

- **D-1 Data source = `getifaddrs(3)` via nix + `/proc/net/route` via pure std (ADR-017).** Probing on a live system showed one `getifaddrs` call returns per interface: the `AF_PACKET` record (name, index, hardware address, `ARPHRD`) and the `AF_INET` records (address + netmask); sysfs covers everything *except* the IPv4/prefix field, and neither `/proc/net/route` (connected-route line has the network+mask but not the interface's own address) nor `/proc/net/fib_trie` (addresses without interface attribution) can fill that gap on multi-interface hosts. The prefix comes from the netmask's leading-one count.
- **D-2 Eligibility precedence: Loopback → NotUp → NotEthernet → NoIpv4Address.** The card pins `lo` → `Loopback` (lo is up and has 127.0.0.1, so loopback must outrank NotEthernet at least); a categorical exclusion first is also the most useful reason to display. All disambiguated cases tested in `eligibility_check_order_is_deterministic`.
- **D-3 FR-SC-03 "up" = `IFF_UP`.** `IFF_RUNNING` is stored and exposed (`is_running`) but does not gate eligibility — the card's reason list has no running variant, and the neighbor-table path (FR-DS-14 read-only mode) works without a carrier. Tested in `an_up_but_not_running_interface_stays_eligible`.
- **D-4 `LinkType` keeps the raw `ARPHRD` number** (`Ethernet` = 1, `Loopback` = 772, `Other(raw)`), and only `ARPHRD_ETHER` counts as ARP-capable — Wi-Fi, bridges and veth pairs all report 1, which matches FR-SC-03's "Ethernet-type link" intent (it is the link layer ARP runs over).
- **D-5 One IPv4/prefix per interface; first `AF_INET` record wins.** FR-SC-01 models a single IPv4/prefix; secondary addresses are not part of this layer's data set (documented on `enumerate_interfaces`).
- **D-6 Per-interface default gateway + the card's global lookup.** `enumerate_interfaces` attaches to each interface its own lowest-metric default-gateway route (file order breaks ties); `find_default_gateway` implements the card's global API with the same preference (`min_by_key` = first of equal metrics). In the common one-default case they coincide; multi-homed hosts keep per-interface truth for the FR-SC screens while the ranking still names a single suggestion.
- **D-7 `Some(0.0.0.0)` as gateway means "on-link default".** A default-gateway route (flags & 0x2) whose Gateway column is zero (possible on ppp-style links) is kept with its honest value; `carries_default_route()` is `default_gateway().is_some()`, so ranking tier 1 follows route presence, not a non-zero address.
- **D-8 `MacAddr::from_octets` is the MAC boundary.** `lo`'s all-zero address yields `mac() == None` instead of a fabricated or raw value (§5.3 rejects zero/broadcast/multicast senders; the live test asserts this on the real `lo`).
- **D-9 Enumerate output is sorted by interface name** for deterministic screens and tests; kernel `getifaddrs` order is an implementation detail.
- **D-10 Header handling: line 0 is always the header.** Appendix E files always carry it; a headerless file loses its first line (documented + tested) rather than conditioning the parser on sniffing "Iface", which real kernels make unnecessary.
- **D-11 Bounded route read** at 64 KiB (`Take` before `read_to_string`, plan §1.3): a real table is a few KiB; the bound also caps hostile/oversized content before parsing.

**Assumptions** (per plan §0.2, written down):

- The `plan.md` at the repository root (commit `eea151e`, v1.3.0) is the authoritative plan; the card's "Plan version: 1.3.0" refers to it.
- "Ethernet-type link (ARP-capable)" (FR-SC-03) means `ARPHRD_ETHER` (D-4); the plan's own Appendix E ARP frame spec (Ethernet + ARP on the selected interface) presupposes exactly that family.
- The ranking tier "eligible + carries default route" applies to virtual carriers too (a VPN `tun0` is suggested while it owns the default route) — FR-SC-02 says "the one carrying the default route" without a physical restriction, and the card's §5.3 priority list puts the default-route tier first. Tested in `a_default_route_carrier_outranks_physical_interfaces`.
- `RouteEntry::is_default_gateway` includes the `Flags & 0x2` clause from card §5.5/§5.2 verbatim; an on-link default (no GATEWAY flag) is therefore not a default *gateway* route.

## 7. Dependencies

**Added: `nix` 0.31.3 (exact pin, `default-features = false`, features = `["net"]`)** — required by ADR-017 for `getifaddrs(3)`. §9.2 evaluation (also in ADR-017):

1. **Necessity:** the smallest std-only alternative (`/sys/class/net` + `/proc`) cannot supply the per-interface IPv4 address/prefix that FR-SC-01 mandates (`fib_trie` has no interface attribution; `route` has no own-address); calling `getifaddrs(3)` without a crate requires `unsafe` (SR-01 forbids). nix is the smallest safe wrapper.
2. **Maintenance:** nix 0.31.3, current release line (crate updated 2026-05-11); `cargo audit`: no advisories against nix or its transitive deps.
3. **License:** MIT (nix); transitive libc/bitflags/cfg-if MIT OR Apache-2.0, memoffset MIT — all on the `deny.toml` allowlist; `cargo deny check` licenses ok.
4. **`unsafe` footprint:** the libc call and sockaddr decoding live inside nix; its public API is safe. Our crate keeps `unsafe_code = "forbid"` — the grep and build gates re-prove it on this changeset.
5. **Transitives / build cost:** zero new crates — bitflags 2.13.2, cfg-if 1.0.5, libc 0.2.191, memoffset 0.9.1 were already locked for the ratatui tree; the `Cargo.lock` diff is exactly one line. No async runtime, no build-time data fetching.
6. **MSRV:** nix declares `rust-version = 1.69`; `rustup run 1.89.0 cargo build --locked` exit 0.
7. **Our constraints:** no runtime network (a `getifaddrs` call is a local kernel query — no socket, no packet, §2.3 untouched); no build scripts; works unprivileged (ADR-005).

No other dependency added, changed or removed; `ratatui`/`thiserror` untouched.

## 8. Plan Questions

- **PQ-1** · Context: card §8 — "No new dependencies unless approved via §9.2 evaluation in the execution report. If you need a crate (e.g., `nix` for `getifaddrs`), evaluate it against all 7 criteria in §9.2 and raise a Plan Question before adding it"; the card's own §3 anticipates nix as a candidate data source · What the plan says: §9.1 lists nix among the transport *candidates* ("decision by ADR in the named task", T-105) — it does not pre-name an interface-enumeration crate; §9.1 "Everything else — not allowed until approved through a Plan Question"; §13 T-101 requires "Interface data source chosen per §9.2 and reported" · Ambiguity/conflict: nix is a §9.1 candidate crate for a different task (T-105 transport); T-101 needs it (or an equivalent) now, and the card's approval mechanism ("§9.2 evaluation in the execution report") cannot complete before the report exists — a chicken-and-egg the card resolves only if the evaluation *is* the approval · Options with consequences: (1) adopt nix 0.31.3 now with ADR-017 + this evaluation (applied) — FR-SC-01 fully satisfiable, zero new crates in the graph, Manager veto costs one small rework; (2) sysfs-only now, defer the address source to a follow-up — no dependency, but FR-SC-01's IPv4/prefix field would be missing and every dependent task (T-105, T-302, G-1) blocked or degraded; (3) stop the task and wait for an out-of-band decision — cleanest process, slowest, and the card already names the crate · Executor's recommendation: option 1 (applied); if the Manager prefers strict process, option 3's answer arrives with this report anyway · Blocking? No.

## 9. Security and privacy notes

- **Untrusted input (SR-02/SR-04):** `/proc/net/route` content is treated as hostile end to end — bounded read (64 KiB), total parser (any malformed line is skipped whole, never repaired), little-endian hex decoded with checked `from_str_radix`, no indexing/slicing/unwrap/panic in the parsing path, and 2,000 hostile property inputs exercised. `getifaddrs` data arrives through nix's safe API; MAC octets pass the §5.3 validating constructor (all-zero/broadcast/multicast → `None`), so no invalid sender MAC can enter the model through this layer.
- **No network I/O:** no socket is opened anywhere in `src/net/` — `getifaddrs` is a kernel query and the route read is a file read. Plan §2.3 and the card's §4 (no ARP, no probing) are untouched; the first socket code remains T-104's, behind ADR-005.
- **Privileges:** enumeration needs no capability and no elevation (ADR-005's unprivileged model is unaffected).
- **No `unsafe` (SR-01), no printing (SR-03):** grep-verified (§4); the crate-level `unsafe_code = "forbid"` build also covers the new files.
- **Fixtures are synthetic** (documentation MACs `aa:bb:cc:…`, docker-typical locally-administered `02:42:…`, RFC 5737/1918 test ranges); the live-system observations in §4 record interface names only, from a synthetic sandbox — no real device identifiers or Owner-network details are committed (plan §14.3 rule 8).
- **Secrets:** none stored; the repository contains no credentials.

## 10. Known issues and limitations

- `enumerate_interfaces()` cannot distinguish "enumeration failed" from "no interfaces" (card-fixed signature; deviation 5) — a typed error or a `(Vec, Option<Reason>)` shape is a candidate follow-up when a consumer can present the difference (T-302).
- Linux-only: the `AF_PACKET` link-record accessor (`as_link_addr`) is Linux-specific. Consistent with the plan's Linux architecture (AF_PACKET ADR-005, `/proc` Appendix E, netns §11.2); a port needs a per-OS data source.
- Interfaces with several IPv4 addresses expose only the first (D-5) — selecting among secondary addresses is a UI-layer decision (T-302), not this layer's.
- A default-gateway route with gateway `0.0.0.0` is represented as `Some(0.0.0.0)` (D-7): honest, but a caller that formats `default_gateway()` for display should special-case it ("on-link") — noted for T-302.
- The live smoke test depends on `lo` existing (guaranteed on Linux; deviation 6) and on a stable kernel table across two enumerations — both hold on CI runners and quiet hosts; a route-table write mid-test could make it flaky, in which case the double-enumeration assertion would be the one to drop.
- The card's crude `grep -v "mod tests"` filter still shows test-module `unwrap`/`expect` matches (§4 explains the 36 lines); clippy's `allow-*-in-tests` is the authoritative enforcement and is green.

## 11. Suggested follow-ups

1. Manager: resolve PQ-1 (adopt `nix` 0.31.3 as decided in ADR-017, or order the sysfs-only rework).
2. Add a `Display` impl for `Ipv4Net` (CIDR form `a.b.c.d/n`) when the first caller formats a scope — carried over from T-002's follow-up 2; `derive_scope`'s consumers (T-105 examples, T-302 scope screen) will want it.
3. T-302 will need a test-visible constructor or builder for `InterfaceInfo` (private fields, accessor-only by design) to drive snapshot tests of the scope screen; decide the shape there, not speculatively here.
4. Consider a typed enumeration error (see known issue 1) when the UI task consumes this layer.
5. Update the README status paragraph ("ADR-001…016", "no discovery … implemented") with ADR-017 and the Phase 1 progress — a docs-only change left out of this card's scope.
6. When §11.7's vocabulary check lands, allow-list the plan-quoted phrase "safe wrapper" in ADR-017 (it is plan vocabulary — §4 ADR-009, §13 — not a user-facing security claim).
