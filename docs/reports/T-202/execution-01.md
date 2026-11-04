# Execution Report — T-202 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-04 · **Branch/commits:** `task/T-202-vendor-database`, based on `main` @ `ec746a8` — `12fc1e6` (enrichment::vendor module: loader, lookup, builder, 44 tests, the committed database image and the `src/lib.rs` wiring), `428b4a1` (`examples/gen_oui.rs`, `csv` dev-dependency, `data/oui/SOURCE.md`), plus this report and the `plan.md` Status Board edit · **Plan version:** 1.7.0 (repository copy)

## 1. Summary (≤ 5 lines)

The embedded vendor-name lookup of plan §6.5 FR-EN-01/FR-EN-02 is delivered in `src/enrichment/` (2,062 lines incl. tests; the module docs record the intended T-205 `Field` mapping): an embedded 1,514,769-byte database image (`data/oui/vendor-db.bin`, format `OZOUDB` v1, date 2026-11-03) holding 58,943 usable entries built from 58,946 IEEE source rows (3 dropped as D-3 duplicates), with longest-prefix match 36 → 28 → 24 bits, locally-administered MACs answered before any table access, and every name sanitized through `DisplayText` at load time (FR-EN-04, D-6). The loader is a total parser (typed `VendorDbError`, never a panic) and the builder is byte-deterministic (D-8: two independent runs → one SHA-256). `examples/gen_oui.rs` regenerates the image from the four IEEE registry CSVs (`csv` confined to `[dev-dependencies]`, used nowhere else); `data/oui/SOURCE.md` records the retrieval table, policies, the D-9 redistribution-terms finding (no explicit permission or prohibition found — raised as PQ-1) and the regeneration commands. 44 new library tests plus 9 example tests (two LCG property suites, a 2,000-case random-corruption suite, corrupt-input coverage beyond the R-9 list); every §11.3 gate green on the pinned 1.99.1 toolchain plus the MSRV 1.89.0 build; `plan.md` changed only in its Status Board row.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1 `src/enrichment/` exists; `cargo doc` clean; no `use crate::` import of registry/app/ui/net/discovery inside it (plan §8.2) | Met | §4: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` exit 0; `grep -rnE "use crate::(registry\|app\|ui\|net\|discovery)" src/enrichment/` → no matches (the only `crate::` imports are `crate::model`, printed in §4); the module uses std, `thiserror` and `crate::model` only. |
| AC-2 `VendorDb::embedded()` loads the committed DB; correct vendor for one real MA-L, MA-M, MA-S and IAB assignment | Met | `enrichment::vendor::tests::one_real_lookup_per_registry_class` — `28:6f:b9:00:00:01` → Nokia Shanghai Bell Co., Ltd. (MA-L); `c8:5c:e2:71:02:03` → SYNERGY SYSTEMS AND SOLUTIONS (MA-M, C85CE27); `8c:1f:64:af:a0:11` → DATA ELECTRONIC DEVICES, INC (MA-S, 8C1F64AFA); `40:d8:55:0d:70:01` → Avant Technologies (IAB, 40D8550D7); plus the sanity line of the measurement harness (§4.7). |
| AC-3 Locally-administered MAC → `PrivateAddress` before any table access (matching entry AND empty table) | Met | `locally_administered_macs_never_touch_the_tables` (the table *contains* the queried prefix `02AABB`, proving the check precedes lookup; the same MAC against an empty table also answers `PrivateAddress`); `locally_administered_real_mac_answers_private_address` on the committed DB; `property_lookup_never_panics_on_random_macs` asserts both branches are exercised. |
| AC-4 No entry → `VendorLookup::Unknown` | Met | `unknown_prefix_yields_unknown` (synthetic) and `unassigned_real_prefix_answers_unknown` (`ec:ec:ec:…` — ECECEC is unassigned at every length in the source data). |
| AC-5 Longest-prefix: synthetic overlap resolves to the longer entry; one real overlap pair tested both ways | Met | `longest_prefix_wins_and_falls_back_level_by_level` (36-bit hit; 7th-hex-digit miss falls to the 28-bit entry; a third MAC falls to the 24-bit parent); `the_real_overlap_pair_resolves_both_ways` (`c8:5c:e2:e0:aa:01` → Wonder Education Tech Limited, the MA-M holder of C85CE2E; `c8:5c:e2:f0:aa:01` → IEEE Registration Authority, the 24-bit fallback — C85CE2F is the one unassigned child of C85CE2 in this data). |
| AC-6 D-3 determinism on real data: `08:00:30:xx` → CERN, `00:01:C8:xx` → CONRAD CORP.; dropped names listed in `SOURCE.md` | Met | `duplicate_prefixes_resolve_to_the_current_holder` (both MACs, exact names); `duplicate_prefixes_resolve_to_the_last_row` reproduces both groups synthetically and asserts the kept/dropped name lists; `cross_registry_duplicates_in_the_36_bit_table_follow_merge_order` covers a same-length MA-S/IAB collision; `SOURCE.md` "Dropped duplicate prefixes" section lists all three dropped names. |
| AC-7 D-4 entity unescape incl. no-double-unescape; names otherwise verbatim | Met | `entity_unescaping_replaces_exactly_the_five_entities`, `entity_unescaping_is_a_single_pass` (`&amp;gt;` → `&gt;`, `&amp;amp;` → `&amp;`), `entity_unescaping_keeps_everything_else_verbatim` (case, padding and non-ASCII untouched), `unescaped_names_round_trip_through_the_database`. |
| AC-8 D-6 load-time sanitization: NBSP collapse, 64-char truncation, empty-after-sanitize skip + counter | Met | `nbsp_runs_collapse_at_load_time` ("A\u{00a0}\u{00a0}B" → "A B"); `long_names_truncate_to_exactly_64_characters` (70 → exactly `DISPLAY_TEXT_MAX_CHARS`, still a usable entry); `names_that_sanitize_to_empty_are_skipped_and_counted` (byte-patched image, `skipped_entries()` 1, `entry_count()` 0, lookup → `Unknown`). |
| AC-9 Corrupt-input suite (≥ the R-9 list) all `Err`, no panic | Met | `empty_and_short_inputs_are_truncated_errors`, `bad_magic_is_rejected`, `unsupported_versions_are_rejected`, `invalid_dates_in_the_header_are_rejected`, `total_length_mismatches_are_typed_errors`, `truncation_at_every_structural_region_is_an_error` (7 cut points across every region), `inconsistent_offsets_and_lengths_are_layout_errors`, `name_ranges_outside_the_region_are_rejected`, `invalid_utf8_in_the_name_region_is_rejected`, `name_slices_must_start_on_character_boundaries`, `unsorted_or_duplicated_keys_are_rejected`, `invalid_registry_tags_are_rejected`, `keys_outside_their_table_width_are_rejected`, `reserved_bytes_must_be_zero`, plus `property_random_corruption_never_panics` (2,000 random single-byte corruptions). |
| AC-10 `database_date()` equals the `--date` in `SOURCE.md`; calendar validation incl. leap years tested | Met | `the_embedded_database_is_self_consistent` asserts `2026-11-03`, matching `SOURCE.md` and the `--date 2026-11-03` invocation in §4.3; `database_date_accepts_real_calendar_dates` (2024/2000/1904 leap days) and `database_date_rejects_impossible_dates` (2023/1900 leap days, month 0/13, day 0/32, 31-in-30-days), `database_date_displays_zero_padded`. |
| AC-11 Determinism: two builds byte-identical (test + `sha256sum` evidence) | Met | `building_twice_from_identical_input_is_byte_identical` (bytes and stats equal); §4.4: two independent `gen_oui` runs → `b0e21c99036eda8db09daccfd1030eea52c858c4a7b3b01f939d468379b585f4` for both the committed file and the second output. |
| AC-12 `SOURCE.md` complete per R-8 | Met | `data/oui/SOURCE.md`: purpose, retrieval table (registry, URL, UTC date, SHA-256, entries), DB filename + SHA-256 + size, embedded date, dropped-duplicate list, D-1…D-6 summaries, D-9 quotes + URLs + check date + assessment, exact regeneration commands (incl. the invocation used), license statement. |
| AC-13 gen_oui runs end-to-end on the four real CSVs; report pastes invocation + stats; `csv::` only in `examples/gen_oui.rs`; `csv` only in `[dev-dependencies]` | Met | §4.3 (invocation + full stats block); §4.5/§4.6 greps: `csv::` occurrences outside `examples/gen_oui.rs` — none; `csv` appears in `[dev-dependencies]` only (Cargo.toml diff in the commit). |
| AC-14 All §11.3 gates green on the pinned toolchain; MSRV build passes; SPDX headers on every new `.rs`; report per Appendix B; plan.md diff is exactly the Status Board line | Met | §4.1 (fmt, clippy `-D warnings`, test, doc, audit, deny — all exit 0 on rustc/cargo 1.99.1, cargo-audit 0.22.2 / cargo-deny 0.20.2 from the CI pins); §4.1 MSRV `rustup run 1.89.0 cargo build --locked` exit 0; §4.5 SPDX grep — all new files carry the header; this report follows Appendix B; `git diff main -- plan.md` is one Status Board line (§4.8). |
| AC-15 Report states DB byte size, measured embedded-load time, in-memory size, and stripped release binary size vs NFR-10 | Met | §4.7: 1,514,769 bytes; embedded() load 13.6 ms first / 11.5–13.1 ms over 20 runs; resident footprint ≈ 16.6 MiB per database (composition explained); DB-inclusive stripped release reference binary 1,887,160 bytes ≈ 1.8 MB, far below the 10 MB NFR-10 budget (informational). |

## 3. What changed

On `task/T-202-vendor-database` (base: `main` @ `ec746a8`):

- `12fc1e6` — the library half and the committed artifact:
  - `src/enrichment/mod.rs` (16 lines) — module docs (enrichment scope, §8.2 dependency rule, T-202/T-203 split) and `pub mod vendor;`.
  - `src/enrichment/vendor.rs` (2,046 lines incl. tests) — `RegistryKind`, `VendorEntry` (+`VendorEntryError`), `normalize_organization_name` (D-4), `DatabaseDate` (D-7 calendar), `RegistryCounts`, `VendorLookup`, `VendorDbError`, `VendorDb` (`from_bytes` total loader with the D-6 sanitization, `embedded` via `include_bytes!`, `lookup` with the FR-EN-01 tiering, `database_date`/`entry_count`/`skipped_entries`/`registry_counts`), the builder (`build_db`/`build_db_detailed`, `BuiltDb`/`BuildStats`/`DroppedDuplicate` — D-2/D-3/D-5/D-8), and the 44 tests (synthetic, corrupt-input, two LCG property suites, vocabulary self-check, real-data expectations pinned to the committed image with the refresh note).
  - `data/oui/vendor-db.bin` — the committed database image (1,514,769 bytes; format spec in the module docs).
  - `src/lib.rs` — `pub mod enrichment;` plus one doc paragraph in the established style.
- `428b4a1` — the maintainer CLI and the provenance record:
  - `examples/gen_oui.rs` (518 lines) — thin CLI per R-7: flag parsing (`--mal/--mam/--mas/--iab/--date/--out`, exit codes 0/1/2, total error handling), CSV row extraction (D-1: header-name columns, BOM strip, skip-and-count), the ready-to-paste markdown stats block, and 9 tests (argument classification, date validation, BOM handling). File-scoped `#![forbid(unsafe_code)]` + the two print allows citing this task card §8, mirroring `poc_discover.rs`.
  - `Cargo.toml` — `csv = { version = "1.3", default-features = false }` in `[dev-dependencies]` with the one-line justification comment (§9.1 dev-only candidate, pre-approved by the card §8); `Cargo.lock` — resolved `csv 1.4.0` + `csv-core 0.1.13` (+ existing `memchr 2.8.3`), nothing else.
  - `data/oui/SOURCE.md` (162 lines) — the FR-EN-02 provenance record per R-8.
- this commit — `docs/reports/T-202/execution-01.md`, the `plan.md` Status Board row T-202 → DONE, and a §5.4 wording polish of the new module doc comments and one `SOURCE.md` sentence (the vocabulary self-check of §4.5 caught three banned words used in the network-status sense; the code semantics are unchanged).

`src/model/`, `src/registry/`, `src/net/`, `src/discovery/`, `src/main.rs`, `deny.toml`, workflows and docs other than this report are untouched.

## 4. Verification results

All commands ran 2026-11-03/04 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from the SHA-256-reproduced CI pins). Every dependency-resolving command used `--locked`; `cargo fmt --check` runs without it.

### 4.1 Engineering gates (§11.3)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.09s
[exit 0]

$ cargo test --locked --all-features
running 300 tests
test result: ok. 298 passed; 0 failed; 2 ignored; 0 measured   (lib)
test result: ok. 0 passed; 0 failed                             (bin)
netns suite: skipped (OSZA_NETMON_TESTS is not set; …)          (custom harness, as on main)
test result: ok. 9 passed; 0 failed                             (doctests)
[exit 0]   — 256 lib tests before T-202, 44 added; the 2 ignored are the pre-existing privileged T-104 tests
             (cargo test --locked --all-features --example gen_oui: 9 passed, 0 failed)

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Generated target/doc/osza_netmon/index.html
[exit 0]

$ cargo audit
    Scanning Cargo.lock for vulnerabilities (196 crate dependencies)
[exit 0]  — no vulnerabilities, no warnings

$ cargo deny --locked check
advisories ok, bans ok, licenses ok, sources ok
[exit 0]  — the same 3 pre-existing `license-not-encountered` warnings as on main
            (deny.toml allowances unused by the tree; byte-identical behavior on the base commit)

$ rustup run 1.89.0 cargo build --locked        (MSRV, §11.3)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 21.48s
[exit 0]
```

### 4.2 Data retrieval (re-measured on this download; recorded in SOURCE.md)

```text
$ sha256sum oui.csv mam.csv oui36.csv iab.csv
e8b6a42ff78ce6d28173513dbefb2620c50ff73780ae74b25472f89e6ec66b7a  oui.csv    (MA-L, 40,442 entries)
543c6ba58adfd1cf25e02464336179036a6f7e2709ed2fd16e584ae8d2e33331  mam.csv    (MA-M,  6,668 entries)
6afd58412964f615d8926e5be1200d651885da75fa066b5339f5441f488abcd7  oui36.csv  (MA-S,  7,261 entries)
6e71aa3d47f00f19d09cb3b31ce1038de1834703420f0ce4ce111da586f1a533  iab.csv    (IAB,  4,575 entries)
```

All four hashes match the Manager's baseline (task card §2.1), so this build consumes the identical data state. Re-measured quirks: 58,946 rows; 0 empty names; 239 `Private` names; 2 duplicate-prefix groups (the same 080030/0001C8 groups, same file order); 18,376 entries whose shorter prefix is also assigned (longest-prefix match is load-bearing); 456 non-ASCII names; 73 names over 64 characters; entities 13× `&amp;` and 6× `&quot;` (6 occurrences across 3 names).

### 4.3 End-to-end build of the committed database (card §9)

```text
$ cargo run --locked --example gen_oui -- \
    --mal /home/z/my-project/ieee-raw/oui.csv --mam /home/z/my-project/ieee-raw/mam.csv \
    --mas /home/z/my-project/ieee-raw/oui36.csv --iab /home/z/my-project/ieee-raw/iab.csv \
    --date 2026-11-03 --out data/oui/vendor-db.bin
## gen_oui statistics

| Registry | Input | Rows | Entries | Skipped rows |
| --- | --- | --- | ---: | ---: |
| MA-L | /home/z/my-project/ieee-raw/oui.csv | 40442 | 40442 | 0 |
| MA-M | /home/z/my-project/ieee-raw/mam.csv | 6668 | 6668 | 0 |
| MA-S | /home/z/my-project/ieee-raw/oui36.csv | 7261 | 7261 | 0 |
| IAB | /home/z/my-project/ieee-raw/iab.csv | 4575 | 4575 | 0 |

Skipped rows by reason: field count 0 · registry 0 · assignment 0 · empty name 0
Total entries: 58946 (skipped rows total: 0)
Database date: 2026-11-03
Usable entries after load-time sanitization (D-6): 58943 (MA-L 40439 · MA-M 6668 · MA-S 7261 · IAB 4575) · skipped at load: 0
Dropped duplicates (D-3, last row wins): 2
Output: data/oui/vendor-db.bin (1514769 bytes)
[exit 0]
```

### 4.4 Determinism evidence (D-8, card §9)

```text
$ cargo run --locked --example gen_oui -- <same four inputs> --date 2026-11-03 --out /tmp/db2
[exit 0]
$ sha256sum data/oui/vendor-db.bin /tmp/db2
b0e21c99036eda8db09daccfd1030eea52c858c4a7b3b01f939d468379b585f4  data/oui/vendor-db.bin
b0e21c99036eda8db09daccfd1030eea52c858c4a7b3b01f939d468379b585f4  /tmp/db2
```

### 4.5 Scope greps (card §9)

```text
$ grep -rn "csv::" --include="*.rs" src/ examples/ | grep -v "^examples/gen_oui.rs"
(no matches)

$ grep -rnE "use crate::(registry|app|ui|net|discovery)" src/enrichment/
(no matches)   — the only crate imports are: crate::model::{DisplayText, MacAddr} (vendor.rs:92)
                 and the two test-only imports crate::model::{DISPLAY_TEXT_MAX_CHARS, testing::Lcg}

$ grep -rLn "^// SPDX-License-Identifier: GPL-3.0-only$" src/enrichment/*.rs examples/gen_oui.rs
(no output — every new .rs file carries the header)

$ grep -rnE "println!|eprintln!|dbg!|todo!|unimplemented!" src/enrichment/   (SR-03)
(no matches)    $ grep -rn "sleep" src/enrichment/   (no matches)
```

### 4.6 Dependency placement

`git diff main..HEAD -- Cargo.toml`: one added block under `[dev-dependencies]` (`csv`, default features off, with the justification comment); no `[dependencies]` change. `git diff main..HEAD -- Cargo.lock`: `csv 1.4.0` and `csv-core 0.1.13` added (`memchr 2.8.3` was already in the tree); no other version moved.

### 4.7 Measurements (AC-15)

A reference binary outside the repository (path dependency on the crate; release profile with `strip=true`, thin LTO, one code unit — the same shape as the project's `[profile.release]`) loads the embedded database and exercises the lookup:

```text
sanity: 28:6f:b9:00:00:01 -> Nokia Shanghai Bell Co., Ltd.
entries: 58943 (skipped 0)
first embedded() load: 13.59 ms
rss: 1148 KiB -> 20824 KiB (delta 19676 KiB, allocator-inclusive in-memory estimate)
20 further loads: min 11.54 ms · median 11.65 ms · max 13.12 ms
live footprint: 16961 KiB per additional resident database (4 kept)
1,000,000 random lookups in 48 ms (48 ns each, 4842 hits)
size_of: DisplayText 24 B · VendorDb 120 B · estimated row storage 1.80 MiB
```

* DB byte size: **1,514,769 bytes** (~1.45 MiB, inside the expected 1–3 MB order).
* Measured `VendorDb::embedded()` load time: **13.6 ms first, 11.5–13.1 ms across 20 further loads** (single-threaded, release).
* In-memory size: **≈ 16.6 MiB resident per `VendorDb`** — composition: 58,943 rows × 32 B (`u64` key + 24 B `DisplayText` handle) ≈ 1.80 MiB of row storage, plus one `String` per name; the T-002 `DisplayText::try_from` constructor allocates `4 × 64 = 256` bytes of capacity per name, so 58,943 × 256 B ≈ 14.4 MiB is name-string capacity, plus allocator overhead. Comfortably inside the NFR-05 RSS budget (≤ 50 MB at 1,000 devices); a capacity-shrinking follow-up is noted in §11.
* Lookup latency (informational): ~48 ns per random lookup, dominated by the three binary searches.
* Stripped release binary size vs NFR-10 (≤ 10 MB, informational): the reference binary that calls `VendorDb::embedded()` — i.e. with the database actually linked in — is **1,887,160 bytes ≈ 1.8 MB**. For completeness: `cargo build --release` in the repository produces `target/release/osza-netmon` at 324,608 bytes and `target/release/examples/gen_oui` at 423,592 bytes — neither references `VendorDb::embedded()` yet (the app wiring is T-205), so the linker removes the unused static; the DB-inclusive reference binary is the honest NFR-10 figure at this stage. All sizes are far below the 10 MB budget.

### 4.8 plan.md diff

```text
$ git diff main..HEAD -- plan.md
-| T-202 | Vendor database | TODO | — |
+| T-202 | Vendor database | DONE | — (execution 01 submitted 2026-11-04, review pending) |
```

## 5. Deviations from the task card

None. Two notes, both anticipated by the card: the real MA-S name for `8C1F64AFA` is `DATA ELECTRONIC DEVICES, INC` (no trailing period — the card's §2.2 example carried one; R-9 says to use the exact names of this build, which the test does), and the card's R-4 sketch allowed adapted signatures — `build_db_detailed`/`BuiltDb`/`BuildStats`/`DroppedDuplicate` and `VendorEntryError` are additions in that spirit, documented in §6 (D-10/D-11).

## 6. Decisions and assumptions

Card policies applied as written: **D-1** (inputs, header-name columns, BOM, skip-and-count), **D-2** (merge order MA-L → MA-M → MA-S → IAB), **D-3** (same prefix and length → last row wins; both real groups reproduced in tests), **D-4** (single-pass entity unescape), **D-5** (`Private` verbatim, 239; empty names skipped, 0), **D-6** (load-time `DisplayText` sanitization with skip counting), **D-7** (retrieval date 2026-11-03 UTC, validated, embedded), **D-8** (byte-identical output, proven twice), **D-9** (terms check recorded in `SOURCE.md` and PQ-1 below). Additional decisions:

- **D-10 Binary format, not text.** The image is `header | table24 | table28 | table36 | names` (magic `OZOUDB`, version 1, 52-byte header, 12/12/16-byte entries, little-endian, per-length tables strictly ascending, deduplicated UTF-8 name region, date and per-registry counts in the header). Alternative considered: a sorted text format (prefix `NAME` lines per length class) — simpler to eyeball, but the loader would re-parse text on every load, name deduplication and O(log n) binary search would need an index anyway, and the total-parser obligations (field widths, offsets, UTF-8, truncation) are harder to check precisely on text. Binary with an explicit spec in the module docs keeps validation exact and the image compact (1.45 MiB vs ~2.5–3 MB text). The signature trade: `VendorDbError` gains `Layout`/`TooLarge` variants beyond the card's sketch (its "…" list anticipated exactly these categories).
- **D-11 CLI surface of `gen_oui`.** Flags `--mal/--mam/--mas/--iab/--date/--out`, each exactly once with one value; exit 0/1/2 per R-7, with a malformed or impossible `--date` classified as a *usage* error (2) — it is an argument defect, not a data defect; unreadable input, missing columns, encoding failures and an unwritable output are data errors (1). Usage text is printed with every 2.
- **D-12 Determinism mechanics.** The builder deduplicates names in the first-appearance order of the sorted tables (table24, then table28, then table36); the only `HashMap` is probed, never iterated, and the D-3 report is emitted from a `BTreeMap` walk, so no hash iteration order can reach the bytes (tested by the byte-equality test and proven by the two-run SHA-256).
- **D-13 Registry tag byte in every entry.** The 24/28-bit tables only admit their own tag (validated per entry) and the 36-bit table carries MA-S/IAB tags, which the loader cross-checks against the header counts (`CountMismatch`). The redundancy costs ~26 KB (~1.7% of the image) and buys a structural check plus the exact per-registry post-sanitization counts D-6 requires.
- **D-14 Eager in-memory sanitization and its footprint.** `from_bytes` sanitizes every name once at load and stores `DisplayText` per row, so lookups are allocation-light (one clone) and `entry_count`/`skipped_entries`/`registry_counts` describe the served state exactly. The measured ≈ 16.6 MiB resident footprint is dominated by the 256-byte-per-name capacity the T-002 `DisplayText` constructor allocates (§4.7) — a model-layer fact, deliberately left as is here (out of T-202 scope; follow-up in §11).
- **D-15 Registry class comes from the row's own `Registry` field** (not from the file it arrived in): a swapped `--mal/--mam` pair still yields a correct database, and any unrecognized label is a counted skip (D-1 "bad registry").
- **D-16 `gen_oui` re-loads the image it just wrote** and prints the post-sanitization totals from the loaded `VendorDb`, so the stats block describes what the runtime will serve and a self-inconsistency would surface as a data error at build time.
- **D-17 Example tests mirror the `poc_discover.rs` precedent** (a `#[cfg(test)]` module inside the example). Like that file's, they run under `cargo test --example gen_oui` (9 tests) rather than the plain §11.3 `cargo test` invocation; they are additionally exercised in this session (§4.1).

## 7. Dependencies

One addition, pre-approved by the task card §8 (plan §9.1 dev-only candidate): `csv = { version = "1.3", default-features = false }` in `[dev-dependencies]`, resolved to 1.4.0. §9.2 mini-evaluation:

1. **Necessity:** the alternative is ~80–120 lines of hand-rolled RFC 4180 quoting/unquoting over the four inputs — exactly the class of byte-level boundary code the plan prefers not to grow (T-103 kept its own codec only because no adequate crate existed for ARP frames); `csv` is confined to the example, so the library and its tests remain std-only (grep evidence in §4.5).
2. **Maintenance:** current release line (1.4.0, from the csv-core lineage maintained since 2016); no open advisories — `cargo audit` exit 0 with it in the tree.
3. **License:** MIT/UNLICENSE dual license — inside the `deny.toml` allowlist (`licenses ok`).
4. **`unsafe` footprint:** the parser is ordinary Rust over `csv-core`'s memchr-accelerated state machine; no `unsafe` reaches our code (`unsafe_code = "forbid"` still green).
5. **Transitive count and build cost:** with default features off, exactly `csv-core 0.1.13` (+ `memchr 2.8.3`, already in the tree); +2 lockfile entries; the example builds in ~2 s; no async runtime anywhere near the tree.
6. **MSRV:** builds under rustc 1.89.0 (`rustup run 1.89.0 cargo build --locked` exit 0, §4.1).
7. **Constraints:** pure library, no build scripts, no network at build or test time (the CSVs are maintainer-supplied paths; CI needs no network — the committed DB needs nothing).

## 8. Plan Questions

**PQ-1 · Redistribution terms of the IEEE registry data (D-9).** Context: T-202 embeds a derived compact form of the four public IEEE registry CSVs inside a GPL-3.0-only tool. What the plan says: §16 requires "data attribution in `data/oui/SOURCE.md`"; R-04 (risk register) says "check terms, record source and date"; ADR-014 fixes GPL-3.0-only. Ambiguity/conflict: the IEEE pages (the regauth page, its FAQ, the Document Notices & Disclaimers page — quotes, URLs and check date in `SOURCE.md`) publish **no explicit redistribution permission and no explicit prohibition** for the registry data; only a site-wide copyright footer. Options with consequences: (a) keep the derived DB with attribution as committed — matches long-standing practice of comparable open-source OUI tools, zero product impact, residual legal question unresolved; (b) obtain written permission from the IEEE Registration Authority — clean but slow, may impose conditions; (c) drop the embedded DB before 0.1.0 and resolve vendor names from an optional user-supplied file — removes the question at a large FR-EN-01 usability cost. Executor's recommendation: (a) now, actively pursue (b) in parallel before the 0.1.0 release (the card makes the question non-blocking for T-202). Blocking? **No.**

## 9. Security and privacy notes

Hostile inputs touched: the four maintainer-supplied CSVs (parsed only by the example; every malformed row is skipped and counted, never fatal) and the database image itself, which is hostile-input surface for the library — the loader validates magic, version, date, all offsets and lengths, table widths, sortedness, tag census, UTF-8 and character boundaries *before* sizing any allocation from the header counts, and every defect is a typed error (SR-02; the 2,000-case random-corruption property test and the 14 corrupt-input tests are the evidence). No network access at build, test or runtime; no `unsafe`; no `println!`/`eprintln!` in the library (SR-03; the example's two file-scoped allows are the card §8 pre-approval, mirroring `poc_discover.rs`). No real MAC addresses, hostnames or network details of the Owner's networks appear in the code, fixtures or this report: the real-data test vectors are public IEEE registry facts (Nokia Shanghai Bell, CERN, IEEE Registration Authority etc.), and all synthetic test data is invented (rule 8).

## 10. Known issues and limitations

* The resident footprint per `VendorDb` is ≈ 16.6 MiB, dominated by the 256-byte `String` capacity the T-002 `DisplayText` constructor allocates per name (§4.7). Within every current budget (NFR-05 ≤ 50 MB), but worth shrinking before release (see §11).
* The database is refreshed manually; a refresh changes entry counts and possibly legacy assignments, and `SOURCE.md` plus the real-data expectations in `vendor.rs` must be updated together (the NOTE at the real-data test block says so).
* `lookup` returns the *current holder* of a prefix per D-3; earlier holders are dropped by policy, so a very old device may show a newer vendor's name — inherent to the one-row-per-prefix data model, recorded in `SOURCE.md`.
* NFR-10 is measured with the DB-inclusive reference binary (§4.7) because `main.rs` does not reference `enrichment` yet (T-205 wires it); the repository's own release binary will cross the 10 MB check with real meaning at T-403.

## 11. Suggested follow-ups

1. `gen_oui --check <four CSVs> [--date …]`: compare a freshly downloaded CSV set against the committed image (counts + SHA-256 of a rebuild) and report drift without writing anything — the natural companion to a periodic refresh.
2. Shrink the in-memory footprint (e.g. intern the 34,044 distinct names and store row→name indices, or a short-inline-string type) once T-403's RSS measurements say it matters; alternatively propose a `DisplayText` capacity tweak to the model owner.
3. When PQ-1 is answered, record the outcome in `data/oui/SOURCE.md` and, if permission is obtained, cite it there verbatim.
4. A refresh task before the 0.1.0 release (re-run `gen_oui`, update `SOURCE.md`, the self-consistency numbers and the real-data expectations in one changeset).
