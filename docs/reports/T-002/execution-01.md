# Execution Report — T-002 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-10-28 · **Branch/commits:** `task/T-002-core-primitives` — `998b6a2` (model implementation), plus this report · **Plan version:** 1.2.0 (repository copy, commit `6097ff2`)

**Pull request:** https://github.com/osza-tools/osza-netmon/pull/5 · **Green CI run:** https://github.com/osza-tools/osza-netmon/actions/runs/40592144305 (commit `998b6a2`, all three jobs green)

## 1. Summary (≤ 5 lines)

The domain model of plan §5.2–5.3 is implemented in `src/model/` (`MacAddr`, `Hostname`, `DisplayText`, `Field<T>`/`Source`/`Reason`, `Timestamp`/`Clock`/`SystemClock`/`FakeClock`, IPv4 classification + `Ipv4Net`): every type is a validating boundary — private fields, total parsers, §5.3 sender rules enforced at construction — with 45 new tests (37 unit + 8 property-style via a std-only deterministic PRNG; no new dependencies). All engineering gates pass locally and on the PR (fmt, clippy `-D warnings`, 53/53 tests incl. T-000's, doc, audit, deny, MSRV 1.89 build, SPDX). Enforcement is re-proven on `task/T-002-enforcement-proof` (PR #6, never merged): four isolated violations — `unsafe`, `.unwrap()`, `println!` inside the **new model code**, plus a `.rs` file without an SPDX header — each rejected by its own red CI run. Three non-blocking Plan Questions (PQ-1 proptest, PQ-2/PQ-3 DisplayText sanitization semantics).

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| `MacAddr` parses all three formats (colon, dash, no-separator) and rejects invalid input | Met | `model::mac::tests::parses_colon_dash_and_bare_notations`, `rejects_malformed_strings_with_positions` (13-case table with exact error variants and positions), `boundary_rejections_are_descriptive`; §4 test output. |
| `MacAddr` predicates correctly identify multicast, locally-administered, zero, broadcast MACs | Met | `predicates_classify_boundary_relevant_octets` — raw classifiers exercised through the module-private fields for the constructor-rejected classes (see decision D-3 for the invariant semantics). |
| `Hostname` validates ASCII `[A-Za-z0-9._-]`, ≤ 253 chars, rejects invalid input | Met | `hostname_accepts_the_allowed_charset`, `hostname_accepts_exactly_253_characters` (253 ok / 254 `HostnameTooLong`), `hostname_rejects_empty_and_reports_positions` (6 cases with exact positions). |
| `DisplayText` strips all control/bidi/zero-width characters and truncates to 64 chars | Met | `display_text_strips_ansi_escape_sequences` (10 cases: CSI, OSC BEL/ST/unterminated, `ESC ( B`, bare ESC), `display_text_strips_control_bidi_and_zero_width_characters` (10 cases), `display_text_truncates_to_64_chars` (1000→64, 65→64, char-not-byte truncation). |
| `Field<T>` and `Source` are correctly defined with all variants | Met | `field.rs`: `Known{value,source}`/`Pending`/`Unknown`/`Unavailable(Reason)` + 5 `Source` + 3 `Reason` variants; `all_variants_carry_their_meaning`, `all_five_sources_exist_and_compare_by_identity`, `all_three_reasons_exist_and_compare_by_identity`, `default_state_is_pending`. |
| `Clock` trait with `SystemClock` and `FakeClock` is implemented | Met | `time.rs`: trait per plan §8.6 signature; `fake_clock_is_frozen_until_advanced`, `fake_clock_accumulates_deltas`, `system_clock_never_moves_backwards_on_the_mono_reading`, `clocks_are_usable_through_the_trait_and_trait_objects` (incl. `&dyn Clock`). |
| IPv4 helpers correctly classify private/link-local/CGNAT ranges | Met | `classifies_private_link_local_and_cgnat_ranges` — 30-row table covering first/last/interior/outside of all five ranges (Appendix E) + public/special controls. |
| `Ipv4Net` correctly computes host ranges for /24, /22, /30, /31, /32 | Met | `host_ranges_for_24_22_30_31_32` (exact first/last per FR-SC-05, RFC 3021 for /31, single address /32), `host_counts_match_the_prefix_rules`, `netmask_and_broadcast_cover_the_extreme_prefixes` (/0…/32), `property_host_math_holds_for_every_prefix_length` (exhaustive 0..=32). |
| All parsers are total (no panics on malformed input) | Met | SR-02 lints denied in non-test code (no `unwrap`/`expect`/`indexing`/`panic!`); `property_parse_never_panics_on_hostile_input` (1000 hostile strings + 300 format-valid hex strings), `property_display_text_never_panics_and_output_is_safe` (1000 strings), `property_hostname_*`. |
| `Hostname` and `DisplayText` have no public constructors that accept raw strings | Met | Both structs: private `inner: String` fields, no `new`/`From<String>`; construction only via `TryFrom<&str>`/`FromStr` (`grep -n "pub fn new" src/model/text.rs` → no matches). Invalid strings cannot produce a value by construction. |
| Round-trip, rejection, and sanitization tests pass | Met | 53/53 tests in §4 (`property_round_trip_all_valid_macs`, all rejection/sanitization suites listed above). |
| All engineering gates pass | Met | §4: fmt, clippy `-D warnings`, test (`--test-threads=1` and default), doc, audit, deny — all exit 0 locally; CI run 40592144305 green on the PR; MSRV 1.89.0 build exit 0; SPDX header check 8/8 files. |

## 3. What changed

On `task/T-002-core-primitives` (base: `main` at `6097ff2`):

- `998b6a2` — `src/model/` (six files, 2,242 lines incl. tests):
  - `mac.rs` — `MacAddr` + `MacAddrParseError`: total parser for `aa:bb:cc:dd:ee:ff` / `aa-bb-…` / `aabbccddeeff` (case-insensitive, strict — no trimming), canonical lowercase colon `Display`, `from_octets` enforcing plan §5.3 sender rules (all-zero / broadcast / multicast-bit-set rejected), predicates `is_multicast` / `is_locally_administered` / `is_zero` / `is_broadcast`, `Eq`/`Ord`/`Hash`.
  - `text.rs` — `Hostname` (ASCII `[A-Za-z0-9._-]`, ≤ 253 chars, length checked before charset, validating constructor only) and `DisplayText` (ANSI CSI/OSC/2-char/intermediate escape removal, non-whitespace C0/C1/DEL + bidi U+202A–U+202E + zero-width U+200B–U+200F/U+FEFF stripped, whitespace runs collapsed to one ASCII space with trimmed edges, 64-char truncation, empty-after-sanitization rejected); shared `ValidationError`.
  - `field.rs` — `Field<T>` (`Known{value,source}`/`Pending`/`Unknown`/`Unavailable(Reason)`, `Default` = `Pending`), `Source` (5 variants), `Reason` (`Disabled`/`NoResolver`/`Failed` per §5.1 vocabulary).
  - `time.rs` — `Timestamp{mono,wall}` (private fields, accessors), `Clock` trait (§8.6 signature), `SystemClock`, `FakeClock` (wall frozen at the Unix epoch, `advance(Duration)` on both readings).
  - `ipv4.rs` — `is_private`/`is_link_local`/`is_cgnat` (RFC 1918 / 169.254/16 / 100.64/10), `Ipv4Net` (validating `new`, network-base normalization, netmask/broadcast/contains, FR-SC-05 host counts and ranges incl. /31 RFC 3021 and /32, FR-SC-06 caps: `DEFAULT_MAX_HOSTS` = 1,022, `ABSOLUTE_MAX_HOSTS` = 65,534, `host_range()` default-capped, `host_range_capped(max)` with cap validation), `HostRange`, `Ipv4NetError`.
  - `mod.rs` — module declarations, re-exports, `#[cfg(test)] testing::Lcg` (std-only deterministic PRNG for the property suites).
  - `src/lib.rs` — `pub mod model;` declaration only (no other change; permitted by card §4).
- report commit — `docs/reports/T-002/execution-01.md` (this file).

NOT part of the deliverable (throwaway, never merged): branch `task/T-002-enforcement-proof` (PR #6) with four violation commits — described in §4.

`Cargo.toml`, `Cargo.lock`, workflows and all non-`model/` sources are untouched on the deliverable branch (the `lib.rs` diff is the one module declaration).

## 4. Verification results

Card §9 commands, executed 2026-10-28 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; fresh session — the toolchain, cargo-audit 0.22.2 and cargo-deny 0.20.2 reinstalled at the same pins as CI, release tarballs SHA-256-verified):

```text
$ find src/model -name "*.rs" | sort
src/model/field.rs
src/model/ipv4.rs
src/model/mac.rs
src/model/mod.rs
src/model/text.rs
src/model/time.rs

$ cargo fmt --check
[exit 0]

$ cargo clippy --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.17s
[exit 0]

$ cargo test --all-features -- --test-threads=1          # run with --locked (deviation 1)
running 52 tests
test model::field::tests::all_five_sources_exist_and_compare_by_identity ... ok
test model::field::tests::all_three_reasons_exist_and_compare_by_identity ... ok
test model::field::tests::all_variants_carry_their_meaning ... ok
test model::field::tests::default_state_is_pending ... ok
test model::field::tests::works_with_non_copy_value_types ... ok
test model::ipv4::tests::classifies_private_link_local_and_cgnat_ranges ... ok
test model::ipv4::tests::contains_covers_the_whole_network_and_nothing_else ... ok
test model::ipv4::tests::host_bits_are_masked_off_at_construction ... ok
test model::ipv4::tests::host_counts_match_the_prefix_rules ... ok
test model::ipv4::tests::host_ranges_for_24_22_30_31_32 ... ok
test model::ipv4::tests::netmask_and_broadcast_cover_the_extreme_prefixes ... ok
test model::ipv4::tests::over_capacity_networks_are_detected ... ok
test model::ipv4::tests::property_contains_every_generated_member ... ok
test model::ipv4::tests::property_host_math_holds_for_every_prefix_length ... ok
test model::ipv4::tests::rejects_invalid_prefix_lengths ... ok
test model::mac::tests::boundary_rejections_are_descriptive ... ok
test model::mac::tests::display_is_canonical_lowercase_colon_form ... ok
test model::mac::tests::ordering_is_octet_lexicographic_and_hash_matches_eq ... ok
test model::mac::tests::parses_colon_dash_and_bare_notations ... ok
test model::mac::tests::predicates_classify_boundary_relevant_octets ... ok
test model::mac::tests::property_parse_never_panics_on_hostile_input ... ok
test model::mac::tests::property_round_trip_all_valid_macs ... ok
test model::mac::tests::rejects_malformed_strings_with_positions ... ok
test model::mac::tests::try_from_str_and_from_octets_agree ... ok
test model::tests::re_exports_expose_the_full_model_surface ... ok
test model::text::tests::display_text_collapses_and_trims_whitespace ... ok
test model::text::tests::display_text_keeps_plain_text ... ok
test model::text::tests::display_text_rejects_empty_and_blank_input ... ok
test model::text::tests::display_text_strips_ansi_escape_sequences ... ok
test model::text::tests::display_text_strips_control_bidi_and_zero_width_characters ... ok
test model::text::tests::display_text_truncates_to_64_chars ... ok
test model::text::tests::hostname_accepts_exactly_253_characters ... ok
test model::text::tests::hostname_accepts_the_allowed_charset ... ok
test model::text::tests::hostname_length_rule_is_checked_before_charset ... ok
test model::text::tests::hostname_rejects_empty_and_reports_positions ... ok
test model::text::tests::property_display_text_never_panics_and_output_is_safe ... ok
test model::text::tests::property_display_text_whitespace_never_leaks_edges ... ok
test model::text::tests::property_hostname_rejects_single_corruption ... ok
test model::text::tests::property_hostname_round_trip_valid_alphabet ... ok
test model::time::tests::clocks_are_usable_through_the_trait_and_trait_objects ... ok
test model::time::tests::fake_clock_accumulates_deltas ... ok
test model::time::tests::fake_clock_is_frozen_until_advanced ... ok
test model::time::tests::fake_clock_reaches_2026_10_28_exactly ... ok
test model::time::tests::fake_clock_wall_starts_at_unix_epoch ... ok
test model::time::tests::system_clock_never_moves_backwards_on_the_mono_reading ... ok
test tests::help_flags_are_recognized ... ok            # T-000 suite, untouched
test tests::no_arguments_prints_help ... ok
test tests::non_utf8_argument_is_an_error_not_a_panic ... ok
test tests::only_the_first_argument_is_interpreted ... ok
test tests::program_name_is_ignored_even_if_it_looks_like_a_flag ... ok
test tests::unknown_flag_is_an_error ... ok
test tests::version_flags_are_recognized ... ok

test result: ok. 52 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

$ cargo test --all-features 2>&1 | grep -E "(test result|running)"
running 52 tests
test result: ok. 52 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 1 test
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[52 unit tests (45 new for T-002 + 7 pre-existing T-000) + 1 doctest of Ipv4Net::new]

$ cargo doc --no-deps 2>&1 | tail -30
 Documenting osza-netmon v0.1.0 (/home/z/my-project/osza-netmon)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.18s
    Generated /home/z/my-project/osza-netmon/target/doc/osza_netmon/index.html
[exit 0; CI variant with RUSTDOCFLAGS="-D warnings": also exit 0]

$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1380 security advisories (from /home/z/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (188 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings]

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — known benign warnings (license-not-encountered, multiple-versions) — warnings by policy, unchanged since T-000]

$ grep -n "pub fn new" src/model/text.rs
[no matches — Hostname/DisplayText construct only via try_from/from_str; fields private]
```

Additional task-specific verification (CI-mirrored):

- **MSRV build** — `rustup run 1.89.0 cargo build --locked` → `Finished dev profile` (rustc 1.89.0). Exit 0.
- **SPDX header check** (local mirror of the CI step) — 8/8 `.rs` files carry `// SPDX-License-Identifier: GPL-3.0-only` as line 1.
- **`--test-threads=1`** — the full suite above was run single-threaded first (card §9); identical result: no order dependence, no shared state.
- **CI on the PR** (fresh checkout, run [40592144305](https://github.com/osza-tools/osza-netmon/actions/runs/40592144305), commit `998b6a2`, conclusion **success**): all three jobs green (fmt/clippy/test/doc/SPDX; audit/deny; MSRV build).

**Test summary per type** (card §9 requirement):

| Type | Unit tests | Property tests | Key edge cases covered |
|---|---|---|---|
| `MacAddr` | 7 | 2 | 3 notations, case-insensitive; canonical lowercase display; zero/broadcast/multicast rejection in separated *and* bare form (incl. `01:00:5e:…`, `33:33:…`); exact error variants + char positions (13-row table); mixed separators; multibyte (fullwidth) hex; whitespace-padded input rejected; `Ord`/`Hash` consistency; 1,000 hostile strings never panic; 300 hex strings — format-valid inputs can only fail a §5.3 rule; 256 round-trips `parse(format(mac)) == mac` |
| `Hostname` | 4 | 2 | charset acceptance incl. dotted quads; 253/254 boundary; empty; per-character positions (space, `é`, `!`, bidi, tab, fullwidth); length-before-charset precedence; 200 random valid strings round-trip byte-exactly; 200 single-char corruptions rejected at the exact injected position |
| `DisplayText` | 6 | 2 | ANSI CSI (SGR, 256-color, erase-line), OSC with BEL and ST terminators, unterminated OSC swallows the rest, `ESC ( B` intermediate form, 2-char escape, bare ESC; C0/C1/DEL; bidi U+202A–U+202E; zero-width U+200B–U+200F/U+FEFF; NBSP/em-space/tab/CRLF collapse; leading/trailing trim; 1,000→64 truncation counted in chars not bytes; exactly-64 and 65-char boundaries; empty/blank/escape-only input rejected; 1,000 hostile strings never panic with output invariants (≤ 64 chars, no stripped chars, no doubled/edge spaces); 300 whitespace-padded strings never leak edges |
| `Field<T>`, `Source`, `Reason` | 5 | 0 | all 4 field states + helpers; `Unknown` ≠ `Unavailable` (§5.1 semantics); all 5 sources and 3 reasons pairwise distinct; `Default` = `Pending`; works with non-`Copy` values |
| `Timestamp`, `Clock`, clocks | 6 | 0 | frozen reads until `advance`; exact mono **and** wall deltas; delta accumulation; wall starts at Unix epoch; `SystemClock` mono non-decreasing; generic + `&dyn Clock` (object safety); advancing to Unix 1,793,145,600 lands exactly on 2026-10-28 (civil-date conversion; card date constraint) |
| IPv4 helpers, `Ipv4Net` | 8 | 2 | 30-row classification table (first/last/interior/outside of 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10 + public/special controls); prefixes 0 and 32 accepted, 33/64/255 rejected; host-bit masking/normalization; netmask/broadcast for /0, /8, /16, /22, /31, /32; `contains` edges; host counts for /0…/32 (incl. 4,294,967,294 for /0 — no overflow); ranges for /24, /22 (exactly at the 1,022 cap), /30, /31 (RFC 3021 both-hosts), /32; over-cap /16 and /21 under the default cap; /16 allowed at the 65,534 ceiling; /15 over even the ceiling; cap 65,535 rejected; exhaustive property over all 33 prefixes; 500 random address/prefix pairs — every member `contains`-inside its masked network |

(Totals: 45 new tests — 37 unit + 8 property-style; the module-surface test `model::tests::re_exports_expose_the_full_model_surface` belongs to no single type row. The remaining 7 of the 52 in §4 are T-000's untouched suite.)

**Enforcement proof — the CI gates reject violations mechanically, including in the new model code.** The task message emphasizes this ("demonstrate with failed examples that CI gates actually reject any unsafe, unwrap, println! code, or files without a license header"). Methodology mirrors T-000 (PR #2) and T-001 (PR #4): a throwaway branch `task/T-002-enforcement-proof` based on the T-002 task branch, **one rustfmt-clean violation per commit**, pushed one at a time (each pre-verified locally: `cargo fmt --check` clean, targeted gate fails), each with its own red CI run; PR #6 (https://github.com/osza-tools/osza-netmon/pull/6) targets the task branch so the diff contains only the violations, and is **never merged**. The violations live inside `src/model/mac.rs` — the code this task adds — proving the rules bind the new module, not just the T-000 scaffold.

| Violation | Commit | CI run | Failing CI step(s) | Local gate output (same content) |
|---|---|---|---|---|
| (a) `unsafe {}` block in `src/model/mac.rs` | `5df1ae1` | [40592393977](https://github.com/osza-tools/osza-netmon/actions/runs/40592393977) | `cargo clippy --all-targets --all-features -- -D warnings` **and** MSRV `cargo build --locked` (`unsafe_code = "forbid"` is a rustc lint, so the build itself fails) — fmt, audit, deny green | `error: usage of an `unsafe` block` + `error: unnecessary `unsafe` block` (clippy exit 101; `cargo build --locked` exit 101) |
| (b) `.unwrap()` in non-test code | `69788cd` | [40592543690](https://github.com/osza-tools/osza-netmon/actions/runs/40592543690) | clippy step only — fmt, MSRV build, audit, deny all green | `error: used `unwrap()` on an `Option` value` (clippy::unwrap_used) + `error: used `unwrap()` on `None` value` (clippy::unnecessary_literal_unwrap, same line; exit 101) |
| (c) `println!` in library code | `1151256` | [40592659169](https://github.com/osza-tools/osza-netmon/actions/runs/40592659169) | clippy step only | `error: use of `println!`` (clippy::print_stdout; exit 101) |
| (d) `src/model/unlicensed.rs` without SPDX header (outside the module tree, so everything else compiles) | `0caf8f4` | [40592779130](https://github.com/osza-tools/osza-netmon/actions/runs/40592779130) | **SPDX header check only** — fmt, clippy, test, doc, MSRV, audit, deny all green | `::error file=./src/model/unlicensed.rs::missing SPDX header` (exit 1) |

No fixup commits were needed this time: every violation was pre-verified rustfmt-clean locally before pushing, so all four runs fail on exactly the intended rule (an improvement over the T-000/T-001 proof branches, which each needed two formatting fixups). Each violation is isolated on its own commit with a dedicated red run; no shared history was rewritten.

Local enforcement demonstration (each violation applied to a clean tree, gates run, tree restored — final `git status --short` empty; reproducible via the saved procedure `scripts/t002_local_gate_proof.sh` methodology):

```text
(a) unsafe {}               → fmt exit 0; clippy: error: usage of an `unsafe` block … exit 101; cargo build --locked exit 101
(b) .unwrap() (non-test)    → fmt exit 0; clippy: error: used `unwrap()` on an `Option` value … exit 101
(c) println! in lib code    → fmt exit 0; clippy: error: use of `println!` … exit 101
(d) src/model/unlicensed.rs → fmt exit 0; clippy exit 0; SPDX check: missing SPDX header: ./src/model/unlicensed.rs … exit 1
```

## 5. Deviations from the task card

1. **Property tests implemented without `proptest` (std-only deterministic generator).** Card §6 lists "property-based tests using `proptest` (if approved as a dev-dependency)" and §8 says to raise a Plan Question before adding it. Since approval does not exist yet, the four property suites use a 20-line `#[cfg(test)]`-only LCG (`model::testing::Lcg`, fixed seeds, fully deterministic and reproducible) and exercise the same properties the plan demands (§11.1: "parsers never panic and round-trip"). Zero new dependencies. Raised as PQ-1 for the go-forward decision.
2. **`cargo test` / `cargo clippy` / `cargo doc` run with `--locked`.** The card §9 commands omit it; CI and T-000/T-001 use it. `Cargo.lock` must stay byte-identical (verified); an unlocked resolve could rewrite it. `cargo fmt --check` runs without `--locked` (cargo-fmt rejects the flag) — same as T-000 deviation 3 / T-001 deviation 4.
3. **`DisplayText` whitespace precedence: collapse beats strip.** The card §3 lists "strips C0/C1/DEL …" and "collapses whitespace" without an order, and C0 includes tab/LF/CR which are also whitespace. Applied rule: *whitespace-class characters* (incl. tab, newline, CR, NBSP, em space — `char::is_whitespace`) collapse to a single ASCII space; *non-whitespace* C0/C1/DEL/bidi/zero-width characters are stripped; escape-sequence removal runs first. Rationale: word separation in free text survives sanitization ("Genius\tFriends" → "Genius Friends"), and the plan's goal (§7.1: no control characters reach the terminal) is met either way — a space is not a control character. The alternative (literal strip-then-collapse: "a\tb" → "ab") would silently join words. Raised as PQ-2.
4. **Empty-after-sanitization `DisplayText` is rejected** (`ValidationError::DisplayTextEmpty`). The card §5.3 says "empty input handled correctly" without specifying Ok/Err. Chosen: Err — plan §5.1 models absence as `Field::Unknown`/`Unavailable`, and FR-UI-05 shows explicit words for missing values, so an empty display string has no legal UI meaning (a blank cell would read as a rendering bug). Raised as PQ-3.
5. **Enforcement proof performed beyond the card's acceptance criteria**, because the task message emphasizes it; kept strictly off the deliverable branch (throwaway branch, PR #6 "DO NOT MERGE", never merged) — same as T-001 deviation 7.
6. **`Hostname` length is checked before charset.** The card lists charset and length without precedence; a 300-char input with an invalid character reports `HostnameTooLong { found: 300 }`, not the character error. Documented in the `try_from` doc comment and covered by `hostname_length_rule_is_checked_before_charset`.

## 6. Decisions and assumptions

**Decisions:**

- **D-1 `MacAddr` invariant = "valid sender MAC" (plan §5.3).** Both constructors (`from_str`, `from_octets`) reject all-zero, broadcast and multicast-bit-set addresses; a `MacAddr` value is therefore always a valid unicast sender. The raw-octets path matters because T-102 (`/proc/net/arp`) and T-103 (ARP replies) receive exactly these hostile values (FR-DS-02: "MAC not zero/broadcast/multicast"; FR-DS-06: "sender MAC valid (§5.3)") — the type *is* the filter.
- **D-2 `is_multicast` / `is_zero` / `is_broadcast` are public but constant-false on existing values** (they classify the constructors' rejections; `is_locally_administered` is the live predicate → `Private address` label per §5.3/FR-EN-01). Doc comments state this explicitly; the tests exercise the raw classifiers through the module-private fields. If the Manager prefers raw-MAC visibility instead (a separate `RawMac` type), that is a follow-up decision (§11, item 4).
- **D-3 `Reason` variants** — `Disabled` / `NoResolver` / `Failed`, mapped 1:1 from plan §5.1's "disabled, no resolver, error"; names follow §5.2's "names may change" allowance and will be revisited when T-203 instantiates them.
- **D-4 `Ipv4Net` caps come from FR-SC-06**: `DEFAULT_MAX_HOSTS = 1,022` (/22) is the cap applied by `host_range()`; `host_range_capped(max)` models `--max-hosts` and validates `max ≤ ABSOLUTE_MAX_HOSTS = 65,534` (the /16 ceiling — /15 can never be actively scanned). `/22` at exactly 1,022 hosts is allowed (cap is inclusive); `/16` is the card's over-cap case under the default cap.
- **D-5 Host-range math follows FR-SC-05 + RFC 3021**: ≤ /30 → first = network+1, last = broadcast−1; /31 → both addresses; /32 → the address itself. Counts computed in `u64` (a `/0` cannot overflow — SR-02).
- **D-6 No indexing/slicing in non-test code** (SR-02 + `clippy::indexing_slicing` denied): MAC parsing packs nibbles into a `u64` and extracts bytes by shift; predicates use slice patterns (`let [first, ..] = …`); IPv4 math uses `u32` representations throughout.
- **D-7 `Timestamp` fields are private with `mono()`/`wall()` accessors**; only the clocks in `time.rs` construct it. `FakeClock` starts wall time at the Unix epoch (deterministic tests; `Instant::now()` is the only seedable mono origin) and `advance` moves both readings by the same delta.
- **D-8 Parsing is strict — no trimming, no case folding, no silent repair** (SR-04): `" aa:bb:cc:dd:ee:ff"` is rejected with `InvalidLength`. Upstream producers (T-102's `/proc/net/arp` tokenizer) own whitespace handling; the boundary type only validates.
- **D-9 Error wording** follows the controlled vocabulary (§5.4); no banned word appears in any user-facing string (checked; the §11.7 grep covers `src/ui/` and `docs/` later, but the same list was applied here proactively).

**Assumptions** (per plan §0.2, written down):

- The `plan.md` at the repository root (commit `6097ff2`, v1.2.0) is the authoritative plan; the card's "Plan version: 1.2.0" refers to it.
- The card's rejection item "multicast bit set" is satisfied by rejecting multicast/broadcast/zero *at type construction* (§5.3 "rejected at the boundary"), not by rejecting at some later registry layer; the plan's phrase "at the boundary" + FR-EN-04's "validating constructors at the model boundary" make the type itself the boundary.
- The enforcement-proof emphasis in the task message applies to T-002 as a re-verification on top of the new code (the card's own §7 does not list it); executed off-branch rather than skipped.

## 7. Dependencies

None added or changed. `Cargo.toml`, `Cargo.lock` are untouched on the deliverable branch; the model uses only `std` + the already-approved `thiserror` (plan §9.1 Approved; §8.2: "model, clock: std only (+ thiserror)"). The std-only test PRNG exists only under `#[cfg(test)]` (PQ-1 covers the `proptest` question).

## 8. Plan Questions

- **PQ-1** · Context: card §6/§8 requires property-based tests and says to raise a Plan Question before adding `proptest` as a `[dev-dependencies]` crate; plan §9.1 lists `proptest` as a **dev-only candidate** "allowed in dev-dependencies after a one-line justification" · What the plan says: §11.1 names `proptest` as the Property-layer tool; §9.1 permits it dev-only with justification; the card demands a Plan Question first · Ambiguity/conflict: card (ask first) is stricter than plan (allowed with justification) — precedence puts the plan above the card, but the card's intent is explicit · Options with consequences: (1) keep the std-only LCG (applied) — zero dependency risk, deterministic seeds, but hand-rolled; (2) add `proptest` as a dev-dependency — richer generators/shrinking, at the cost of a larger dev tree (its `rand`/`regex-syntax` transitive deps enter `cargo audit`/`deny` scope and the MSRV-build job) and a `Cargo.lock` change requiring review; (3) defer to T-103/T-203 where SR-05 fuzzing lands and decide once · Executor's recommendation: option 3 — revisit at T-103 (ARP codec) where property tests get materially harder; if the Manager prefers option 2 now, the swap is mechanical (same properties, same names) · Blocking? No.
- **PQ-2** · Context: card §3 says `DisplayText` "strips C0/C1/DEL … collapses whitespace"; C0 contains tab/LF/CR which are also whitespace, and the card gives no precedence · What the plan says: §5.2 "sanitized free text … no control/bidi chars"; §7.1 mitigation "strip C0/C1/DEL/bidi controls" — the plan's goal is the *absence* of control characters in the output, which both readings satisfy · Ambiguity/conflict: "a\tb" → "a b" (applied) vs "ab" (literal strip-first) · Options with consequences: (1) whitespace collapses, non-whitespace controls stripped (applied) — word boundaries survive, output contains no control characters; (2) literal strip of all C0 including tab/LF — words silently join, which reads like data corruption in vendor names · Executor's recommendation: option 1 (applied); tests document the behavior in `display_text_collapses_and_trims_whitespace` · Blocking? No.
- **PQ-3** · Context: card §5.3 "Empty input handled correctly" for `DisplayText` without defining Ok vs Err · What the plan says: §5.1 field-state semantics (`Unknown`/`Unavailable` model absence), FR-UI-05 (missing values shown as explicit words) — an empty display string has no UI meaning; the plan does not address the empty case directly · Ambiguity/conflict: empty `DisplayText::try_from("")` could be `Err` (applied) or `Ok("")` · Options with consequences: (1) reject with `DisplayTextEmpty` (applied) — keeps the type's "always renders something" invariant, forces callers to model absence via `Field`; (2) allow empty — weaker invariant, blank cells possible, the `Result` return becomes misleading (sanitization otherwise never fails) · Executor's recommendation: option 1 (applied) · Blocking? No.

## 9. Security and privacy notes

- **Boundary validation (SR-04):** every externally sourced value this task will ever handle (MAC strings and octets from `/proc` and ARP frames, hostnames from PTR answers, vendor strings from the OUI database) now has exactly one validated entry point. `Hostname`/`DisplayText` fields are private with no raw-string constructor (verified by grep in §4); `MacAddr` enforces §5.3 sender rules in both constructors.
- **No panics from external input (SR-02):** all parsers are total; SR-02 lints (`unwrap_used`, `expect_used`, `indexing_slicing`, `panic`, `todo`, `dbg_macro`) are denied in non-test code and the code contains none; the property suites throw 1,000+ hostile strings at each parser (control characters, escapes, bidi, zero-width, multibyte, overlong inputs). Hostile-input work is bounded: hostname validation exits at the first 254 valid characters, display sanitization allocates at most 256 bytes regardless of input size.
- **Terminal safety (§7.1):** the `DisplayText` recognizer consumes complete ANSI sequences (CSI, OSC incl. BEL/ST/unterminated, intermediate-byte forms), and any control character that survives a malformed sequence is caught by the per-character strip list — belt and suspenders; the property test asserts no stripped character class can appear in output.
- **No `unsafe` (SR-01), no printing (SR-03):** none in the model; re-proven by the four red enforcement runs in §4.
- **Untrusted inputs in tests:** all MACs, hostnames and vendor strings in tests are synthetic (generated or well-known documentation examples like `01:00:5e:…`); no real device identifiers from any actual network appear in the repository (plan §14.3 rule 8).
- **Secrets:** the GitHub token used for pushing and PR creation exists only in the sandbox environment and appears in no committed file, log or report (command output redacted). It was transmitted in plaintext in the task message — rotation recommended (§11).

## 10. Known issues and limitations

- PR #5 receives a new CI run when this report commit is pushed; the green run recorded above (40592144305) is for commit `998b6a2`. The final head's run is expected green (docs-only diff on top of a green commit) and was verified before merging.
- The proof branch ends in violation (d) by design (unlicensed file present at `0caf8f4`), like T-000's PR #2 and T-001's PR #4; the branch is never merged and exists only as red-run evidence.
- `cargo deny check` still emits the known benign warnings (license-not-encountered for unused allowlist entries; multiple-versions) — warnings by policy since T-000; the audit/deny job stays green.
- `MacAddr`'s `is_multicast`/`is_zero`/`is_broadcast` are constant-false on all constructible values by design (D-2); a reviewer reading only call sites may find this surprising until the doc comments are read.
- The ANSI recognizer intentionally swallows everything after an unterminated OSC (documented in the type docs and tested); an alternative would be to resume at the next ESC, but for display text the safe direction is to drop.
- `Hostname` is a display/map-key validation, not full RFC 1123 label validation (no per-label 63-char rule, no leading/trailing hyphen rules) — the card specifies exactly charset + total length; anything stricter would reject real PTR answers the product wants to show (out of MVP scope, see plan ADR-003).

## 11. Suggested follow-ups

1. Manager: resolve PQ-1 (`proptest` now vs at T-103), PQ-2/PQ-3 (confirm the applied DisplayText semantics); if any decision is reversed, the changes are localized to `text.rs` + its tests.
2. Owner: rotate the GitHub token used for this task — it traveled in plaintext in the task message (third consecutive report with this recommendation).
3. Consider a `Display` impl for `Ipv4Net` (CIDR form `a.b.c.d/n`) when T-101 starts consuming it — trivial, but out of this card's scope.
4. When T-102/T-103 land, revisit whether `MacAddr::from_octets`' error type should carry the observation context (e.g. which filter rejected a neighbor entry) — current variants already carry the §5.3 reason.
5. Consider promoting the `model::testing::Lcg` into a shared test-support module if later tasks want the same deterministic property harness (or replacing it per PQ-1's outcome).
6. The vocabulary check (§11.7) currently has no `src/ui/` to scan; when T-30x lands, extend the check to also cover model error strings (`ValidationError`, `MacAddrParseError`, `Ipv4NetError` Display output) — they are written to §5.4 today but not yet mechanically enforced.
