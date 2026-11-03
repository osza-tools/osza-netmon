# Execution Report — T-201 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-03 · **Branch/commits:** `task/T-201-device-registry`, based on `main` @ `1709cc6` — `a4701ca` (device-record, observation and config types), `b836c35` (registry engine + `src/lib.rs` wiring, incl. the full test suite), plus this report and the plan.md status-board edit · **Plan version:** 1.6.0 (repository copy)

## 1. Summary (≤ 5 lines)

The in-memory device registry of plan §6.4 FR-RG-01…07 is implemented in `src/registry/` (four modules, 3,358 lines incl. tests): `begin_cycle`/`observe`/`end_cycle` with strict `ScanId` discipline, ADR-007 cycle aging behind the age floor, ADR-008 identity `(interface_index, MAC)` with per-IP first/last seen and primary-IP tracking, the four factual tags with neutral structured notes, the shared-MAC threshold inside the idle window, the 4,096-key hard cap with persistent warning, and stable IP/hostname sorting with `DeviceKey`-bound selection. All time is injected (`&dyn Clock`); no test sleeps. 66 new unit tests (49 registry-engine + 9 device + 4 observation + 4 config), including two deterministic LCG property suites; every §11.3 gate green on the pinned toolchain plus the MSRV 1.89.0 build. No new dependencies; `Cargo.toml`/`Cargo.lock` untouched.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1 Idle only when both ADR-007 conditions hold (≥3 consecutive `Complete` misses AND ≥120 s) | Met | `three_missed_cycles_below_the_age_floor_keep_the_device_recent` (3 misses at 30 s → Recent; a 4th at 121 s → Idle), `the_age_floor_is_reached_exactly_at_120_seconds` (inclusive `≥` boundary at exactly 120 s; 119 s stays Recent), `two_missed_cycles_are_not_enough_even_after_an_hour`, `only_consecutive_complete_cycles_count`, `a_non_complete_cycle_does_not_interrupt_the_miss_streak`, `property_sessions_preserve_the_aging_and_identity_invariants` (both directions asserted after every cycle of 24 randomized sessions). |
| AC-2 `Partial`/`Failed`/`Cancelled` never increment `missed_cycles` or age | Met | `partial_failed_and_cancelled_cycles_never_age_devices` (20 cycles per outcome, 60 s apart — missed stays 0, status Recent), `a_non_complete_cycle_does_not_interrupt_the_miss_streak` (non-complete cycles neither age nor reset the streak), `cycle_summaries_report_the_aging_accounting` (`missed_advanced` accounting). |
| AC-3 Age floor defeats manual-refresh spam | Met | `manual_refresh_spam_does_not_idle_devices` (10 complete cycles 1 s apart, all missed — missed 10, status Recent), `the_age_floor_is_reached_exactly_at_120_seconds`. |
| AC-4 Any new observation returns an Idle device to Recent | Met | `any_new_observation_returns_an_idle_device_to_recent` (Idle → observe → Recent, `missed_cycles` 0, `last_seen` advanced; stays Recent at that cycle's end), `only_consecutive_complete_cycles_count` (observation resets the streak mid-sequence). |
| AC-5 Identity strictly `(interface_index, MAC)`; IPv4 changes never create devices | Met | `identity_is_interface_and_mac` (same MAC + two interfaces = 2 records; same key + two addresses = 1 record), `ipv4_changes_do_not_create_new_devices` (history keeps both addresses), `ip_history_tracks_first_and_last_seen_per_address`, `the_primary_ip_is_the_most_recently_observed_address` (incl. the equal-timestamp tie: last write wins), `one_address_under_two_macs_keeps_both_records_with_mirrored_notes` (never merged). |
| AC-6 Shared-MAC threshold (5 distinct IPs) applies the `Multiple IPs` tag | Met | `five_distinct_addresses_trigger_the_multiple_ips_tag_and_note` (4 → no tag, 5 → tag + neutral note), `four_addresses_do_not_trigger_the_tag_at_the_default_threshold`, `addresses_outside_the_idle_window_do_not_count_toward_the_threshold` (4 aged-out addresses + 1 recent → no tag; re-observation re-trips), `the_shared_mac_threshold_is_configurable`, `the_multiple_ips_note_count_only_rises`. |
| AC-7 Cap (4,096) drops new keys, updates existing ones, exposes a warning state | Met | `the_cap_drops_new_keys_but_keeps_updating_existing_ones` (full 4,096-record fill — every `Accepted{new_device:true}` — then `DroppedCapFull` for a new key, count stays 4,096, `cap_warning()` true, an existing key still updates), `a_small_cap_behaves_identically` (config 4), `the_cap_warning_is_persistent_once_raised`, `new_rejects_invalid_configs_and_default_matches_the_adrs` (default cap = `REGISTRY_CAP` = 4096). |
| AC-8 `ScanId` mismatch ignored; late arrivals do not corrupt state | Met | `observations_tagged_with_a_non_current_scan_are_ignored`, `observations_without_a_cycle_in_progress_are_ignored`, `end_cycle_with_a_mismatched_scan_id_is_ignored` (cycle continues; double-end ignored), `late_arrivals_from_an_old_scan_do_not_corrupt_the_current_cycle` (old-scan observation does not mark the device seen; aging proceeds correctly), `beginning_a_new_cycle_supersedes_an_unfinished_one`. |
| AC-9 Stable sorting; selection bound to `DeviceKey` survives sorting/refreshes | Met | `sorting_by_ip_is_numeric_not_lexicographic` (10 < 100 as numbers), `sorting_by_hostname_puts_known_first_and_unknown_last_by_ip` (ASCII case-insensitive; Pending/Unknown/Unavailable hostnames last, then by IP), `hostname_sort_ties_fall_back_to_the_ip`, `sorting_is_stable_for_equal_sort_keys` (equal primary IPs keep first-observation order, both modes), `a_primary_ip_change_re_sorts_the_list`, `selection_is_bound_to_the_device_key_not_the_row` (survives refresh + sort-mode flips), `select_next_and_previous_walk_the_order_and_stop_at_the_ends`, `property_sorted_keys_are_a_stable_permutation_of_the_records` (permutation + comparator + stability, 24 randomized rounds × both modes). |
| AC-10 All engineering gates pass | Met | §4: fmt, clippy `-D warnings`, test (254 passed + 2 ignored privileged, 9 doctests), doc (`-D warnings`), audit, deny — all exit 0 on the pinned 1.99.1; MSRV `rustup run 1.89.0 cargo build --locked` exit 0. |

## 3. What changed

On `task/T-201-device-registry` (base: `main` @ `1709cc6`):

- `a4701ca` — the registry's data model (not yet wired into the crate tree, so the intermediate tree is exactly `main` plus unreferenced files):
  - `src/registry/device.rs` (621 lines) — the record types: `DeviceKey` (`(iface_index, MacAddr)`, ADR-008 identity), `IpRecord` (per-IP first/last seen), `Status` (Recent/Idle, ADR-002 wording), `Tag`/`Tags` and `Note` (structured, neutral, `Display` forms in controlled vocabulary) and `SourceSet`; `Device` with the plan §5.2 fields, the private `last_observed_ip` (primary-IP tracking) and `seen_in_cycle` bookkeeping, and the public `primary_ip()`/`age()`/`has_ip()` accessors; 9 tests.
  - `src/registry/observation.rs` (237 lines) — `ScanId`, the four-variant `ScanOutcome` (Complete/Partial/Failed/Cancelled, no payloads — see D-2), `Observation` (scan-tagged, model-validated parts only); 4 tests.
  - `src/registry/config.rs` (225 lines) — `RegistryConfig` with the ADR defaults (3 / 120 s / 5 / 4,096), `try_new`/`validate`, `ConfigError` (thiserror); 4 tests.
- `b836c35` — `src/registry/mod.rs` (2,275 lines) and the `src/lib.rs` module registration (`pub mod registry;` + one doc paragraph):
  - production half — the `Registry`: `begin_cycle`/`observe`/`end_cycle` (ADR-007 aging, `CycleSummary` accounting), the single `absorb` write path (merge by key, IP history, sources, Recent reset, cap, `Private address`/`Gateway` tags, mirrored conflict notes, in-window shared-MAC threshold), `insert_local_device` (`This device`, source `LocalInterface`, aging exemption per PQ-1), `set_gateway_ip` (re-applies on route change), `set_hostname`/`set_vendor` (enrichment `Field` storage, FR-EN boundary), `iter`/`iter_sorted`/`sorted_keys` over the stable first-observation base order, `SortMode` (Ip / Hostname), and the `DeviceKey`-bound selection API (`select`, `select_next`/`select_previous`/`select_first`/`select_last`, `clear_selection`); the module doc maps every rule to FR-RG-01…07 and the ADRs.
  - test half — the 49 engine tests of §2 plus two LCG property suites (`property_sessions_preserve_the_aging_and_identity_invariants`, `property_sorted_keys_are_a_stable_permutation_of_the_records`) using the T-002 `model::testing::Lcg`.
- this commit — `docs/reports/T-201/execution-01.md` and the `plan.md` Status Board row T-201 → DONE.

`Cargo.toml`, `Cargo.lock`, `deny.toml`, `src/model/`, `src/net/`, `src/discovery/`, `src/main.rs`, workflows and docs other than this report are untouched. `src/lib.rs` changed only by the module registration and its doc paragraph.

## 4. Verification results

All commands ran 2026-11-03 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from the SHA-256-verified CI pins). Every dependency-resolving command used `--locked`; `cargo fmt --check` runs without it.

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.66s
[exit 0]

$ cargo test --locked --all-features
test result: ok. 254 passed; 0 failed; 2 ignored; 0 measured   (lib)
test result: ok. 0 passed; 0 failed                             (bin)
netns suite: skipped (OSZA_NETMON_TESTS is not set; …)          (custom harness, as on main)
test result: ok. 9 passed; 0 failed                             (doctests)
[exit 0]   — 190 lib tests before T-201, 66 added: 256 total, 254 run + 2 #[ignore]d privileged (T-104)

$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
    Generated target/doc/osza_netmon/index.html
[exit 0]

$ cargo audit
    Scanning Cargo.lock for vulnerabilities (194 crate dependencies)
[exit 0]  — no vulnerabilities, no warnings

$ cargo deny --locked check
advisories ok, bans ok, licenses ok, sources ok
[exit 0]  — 3 pre-existing `license-not-encountered` warnings (deny.toml allowances unused by the current tree); verified byte-identical on the base commit by stashing this branch's changes

$ rustup run 1.89.0 cargo build --locked        (MSRV, §11.3)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 22.59s
[exit 0]

Constraint greps (card §8):
$ grep -rnE "crate::(discovery|enrichment|app|ui)|use crate::net" src/registry/   → no matches
$ grep -rn "std::thread::sleep" src/registry/                                    → no matches (the word "sleep" appears only in comments stating the rule)
$ grep -rnE "unsafe|println|eprintln|dbg!|todo!|unimplemented!" src/registry/    → no matches (crate lint `unsafe_code = "forbid"` green)
$ grep -rni "stale" src/registry/                                                → 1 match: the "stale" string literal inside the §5.4 banned-word list the vocabulary test asserts against (see D-6)
$ head -1 src/registry/*.rs                                                      → all four files carry the SPDX header
$ git status --porcelain Cargo.toml Cargo.lock                                   → clean (no dependency change)
```

## 5. Deviations from the task card

None. The module is delivered as `src/registry/mod.rs` plus the three submodules the card explicitly allows ("and submodules if necessary") — `device.rs`, `observation.rs`, `config.rs` — to keep each file reviewable.

## 6. Decisions and assumptions

- **D-1 `ScanId`, `ScanOutcome` and `Observation` live in the registry, not `model`.** The card requires observations tagged with a `ScanId` but the registry may depend only on `model` and the clock (card §2, §8.2), while discovery (which already has its own `Observation`/`ScanOutcome`, T-103/T-104) must not depend on `registry`. Defining the registry's input types in `registry::observation` and letting T-205 map `discovery::DiscoveryEvent` → registry calls is exactly the boundary already agreed in PQ-3 of the T-104 execution report ("T-205 will map these onto `AppEvent`"). Alternative considered: shared types in `model` — rejected: `model` is the hostile-input boundary (T-002 scope), and scan bookkeeping is not a model primitive.
- **D-2 `ScanOutcome` carries no reason/error payloads** (unlike discovery's `Partial`/`Failed{reason}`). The registry's aging decision needs only Complete-vs-not; keeping the reasons out avoids pulling discovery's error strings across the module boundary (raw-string rule, card §8) and keeps `ScanOutcome` `Copy`. T-205 still has discovery's own event for logging. Assumption: the Manager agrees the mapping drops only information the registry never consumes.
- **D-3 `This device` records never age** (`end_cycle` skips them; `missed_cycles` stays 0). ADR-007 is silent about the local device, but plan §5.3 inserts it precisely because no scan can observe it ("nobody ARPs itself") — without the exemption the registry would eventually label the operator's own machine "not seen recently", contradicting the `This device` tag and FR-RG-07's honesty rule. Alternative: T-205 re-inserts the device every cycle. Raised as **PQ-1** (non-blocking).
- **D-4 "Distinct IPs seen within the idle window" (ADR-008) = addresses whose `last_seen` is within `idle_min_age` of `now`** — the same 120 s horizon that governs Idle, evaluated at every observation of the record; addresses that age out of the window stop counting, and re-observation brings them back (tested both ways). The tag, once applied, stays for the session (a factual session fact, like the IP history itself); the note's `distinct_ips` count only ever rises. Alternative readings (all IPs of the session; IPs since the last Idle→Recent transition) are recorded in **PQ-2** with this recommendation.
- **D-5 Conflict notes are mirrored on both records and name the other MAC**, per the ADR quote "also observed under MAC …". The same MAC on a different interface (same hardware, two records by ADR-008 identity) does **not** produce a note — the note text would be self-referential and confusing; this case is documented and tested (`the_same_mac_on_another_interface_is_not_a_conflict`). Notes are deduplicated and persist for the session (the IP stays in both histories, so the fact stays true).
- **D-6 The vocabulary self-check test contains the §5.4 banned words as string literals** (device.rs `status_and_tag_wording_follows_the_controlled_vocabulary`) — that is its function: asserting none of the user-facing `Display` output of `Status`/`Tag`/`Note` contains any of them. ADR-002's rule ("MUST NOT appear in our code identifiers or UI") is respected: no identifier or UI string carries the word; §11.7's future CI grep has an allow-listed "never use" table for exactly this pattern. All registry identifiers avoid the banned vocabulary (`IgnoredScanMismatch`, not "stale-scan").
- **D-7 `Registry::new` re-validates the config** even though `RegistryConfig::try_new` already does: the struct has public fields, so a field-assembled config must hit the same boundary (tested). Nothing is clamped silently (plan §8.7); violations are `ConfigError` values.
- **D-8 Sorting is recomputed on access** (`sorted_keys`/`iter_sorted`/selection) rather than cached with a dirty flag: no interior mutability, trivially correct invalidation. Cost is a stable sort over ≤ 4,096 keys per call — bounded and T-403-measurable; caching is a follow-up only if profiling demands it.
- **D-9 Hostname comparison is ASCII case-insensitive** (plan §5.2 hostnames are ASCII); known hostnames tie-break by primary IP, unknown hostnames order by primary IP, for full determinism regardless of arrival order.

## 7. Dependencies

None. `Cargo.toml` and `Cargo.lock` are untouched; the registry uses `std` + the already-approved `model` layer only (the "clock" of the §8.2 dependency table is `model::time` from T-002 — no separate top-level `clock` module exists).

## 8. Plan Questions

- **PQ-1 · This-device aging exemption.** Context: ADR-007 defines aging for observed devices; plan §5.3 inserts the local device from interface data because discovery cannot see it. What the plan says: ADR-007 lists no exemption; §5.3 gives no aging behavior for the local device. Ambiguity: without a rule, the local device idles after 3 cycles + 120 s, which contradicts the `This device` tag (FR-RG-07 honesty). Options: (a) registry-level exemption — `This device` records never age (implemented; self-contained, one tagged line of behavior); (b) T-205 re-inserts the local device every cycle (spreads the rule into the app layer; a missed insert regresses the UI); (c) no rule (local device eventually Idle — reads as "your own machine not seen recently"). Executor's recommendation: (a). Blocking? No — the change is one `end_cycle` branch, trivially swapped if the Manager prefers (b).
- **PQ-2 · "Distinct IPs seen within the idle window" (ADR-008).** Context: the shared-MAC threshold counts distinct IPs "seen within the idle window". What the plan says: ADR-008 gives no definition of the window. Ambiguity: which addresses count. Options: (a) addresses with `now − ip.last_seen < idle_min_age` (implemented; reuses the ADR-007 horizon, ages stale counts out, tested at the 121 s boundary); (b) every address of the session (DHCP churn eventually tags ordinary devices — the window qualifier would be meaningless); (c) addresses of the current Recent period (survives scan pauses but revives old counts on any return observation). Executor's recommendation: (a). Blocking? No — a one-line filter change in `absorb`.

## 9. Security and privacy notes

- The registry itself performs no I/O and touches no privileges; it is pure in-memory state on the main thread (FR-RG-01, ADR-012).
- All inputs are already boundary-validated model types (`MacAddr` refuses zero/broadcast/multicast; hostnames and vendor text arrive as validated `Field` values); the registry adds no raw-string surface (card §8, SR-04). Notes are structured values, so no external text ever enters a note.
- Untrusted-input bounds are enforced: the 4,096-key hard cap bounds state growth from hostile scans (AC-7), `missed_cycles` saturates instead of overflowing, per-record IP history is bounded by the cap × the scan scope, and `Instant` math is `checked_duration_since` with a zero fallback (no panicking path anywhere in the module — `panic = deny` green).
- Privacy: no data leaves the process (ADR-013, in-memory only); test data is TEST-NET-1 synthetic addresses (plan §2.3).

## 10. Known issues and limitations

- Aging is evaluated only at `end_cycle` (the card's API surface): if the scheduler stops producing complete cycles (T-204 failure backoff), statuses freeze at their last evaluation even as wall time advances. The strict ADR-007 reading requires completed cycles for the cycle condition, so this is faithful; T-205 may add a display-time re-evaluation if wanted (follow-up F-2).
- `CycleSummary.observed + absent` omits `This device` records by design (documented on the type); they are neither observed nor aged.
- The `Multiple IPs` tag, once applied, persists for the session even if the in-window count later falls below the threshold (D-4); the note count never falls.
- The full-cap test fills 4,096 records in ≈0.1 s (debug build); no T-403 performance measurements were taken in this task, by scope.

## 11. Suggested follow-ups

- **F-1 (T-205):** map `discovery::DiscoveryEvent` → `registry::{begin_cycle, observe, end_cycle}` including the `ScanOutcome` translation table (Complete→Complete; Partial/Failed{..}/Cancelled→Partial/Failed/Cancelled), and feed `Registry::insert_local_device`/`set_gateway_ip` from T-101's interface/route data at scope confirmation.
- **F-2 (T-205, optional):** a display-time `refresh_aging(now)`-style re-evaluation for long scheduler backoffs, if the Manager wants statuses to track wall time between cycles (ties into PQ-1/PQ-2).
- **F-3 (T-303/T-304):** the UI should render `Note::IpAlsoObservedUnder` and `Note::MultipleIps` via their `Display` forms (already in controlled vocabulary) and use `Registry::cap_warning()` for the persistent cap notice (FR-RG-04/§10.4).
- **F-4 (T-306/T-406, §11.7):** lift the banned-word list out of the registry's vocabulary test into the planned shared CI grep with its allow-listed table, instead of per-module copies.
- **F-5 (T-403):** measure `sorted_keys()`/`iter_sorted()` re-sort cost at 1,000/4,096 records under the NFR budgets; cache the order behind a dirty flag only if the numbers demand it (D-8).
