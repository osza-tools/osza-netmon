# Execution Report — T-205 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-09 · **Branch/commits:** `task/T-205-app-core`, based on `main` @ `4b94847` — Commit 0: `0e4bf18` (plan v1.10.0, Manager update); the T-205 work: `9a122a9` (privilege — the ADR-005 item 5 root check, §5.10), `b17d5fb` (app core — headless state machine, pure update, runtime, §5.1–5.9), `e2d959c` (this report), `bb10a37` (the AC-5 wait-condition hardening after the first CI run — §12) · **Plan version:** 1.10.0 (repository copy, written by Commit 0)

## 1. Summary (≤ 5 lines)

The headless application core of plan §13 T-205 is delivered in a new `src/app/` tree (eight modules, 5,518 lines incl. 59 tests) behind the §8.2 clarification of plan v1.10.0: the `AppState` screen machine (Notice → Scope → Dashboard ⇄ Details + help/too-small overlays), the terminal-agnostic `AppEvent` union feeding one 256-slot bounded queue, the pure `update(state, event, clock) -> effects` with the §5.6/§10.3 key map and the §5.9 enrichment rules, and the runtime wiring the reviewed T-203/T-204 workers (the §8.4 wait/drain/poll loop, the discovery forwarder thread under T-204's delivery policy, an inline hostname drain — deviation D-2 — and the bounded ≈ 1 s idempotent shutdown). The §5.10 privilege helper (`running_as_root` + the pure `parse_effective_uid`) lands in `discovery/privilege.rs` with four fixture tests. 63 new library tests (471 total: 469 pass + the 2 pre-existing privileged ignores) cover every AC headlessly — the full scenario script, the LCG key mash, FR-DS-12 end-to-end, the message log, resize, the runtime integration over real workers with fakes, and the NFR-03 benchmark (4,096 devices at the cap: burst mean 0.75 ms / max 6.31 ms debug, 94 µs / 0.67 ms release — every iteration asserted < 100 ms). All §9 gates green on the pinned 1.99.1 toolchain, MSRV 1.89.0 build green, netns 12/12 unchanged, the three fuzz harnesses byte-exact, `cargo audit` + `cargo deny` green. Two documented deviations (D-1: the app-side interface snapshot; D-2: the inline hostname drain) and two Plan Questions (PQ-1/PQ-2) are below.

## 2. Acceptance criteria

| AC | Status (Met / Partial / Not met) | Evidence (test name, command, file) |
|---|---|---|
| AC-0 Commit 0 exactly as §10 prescribes: pre-flight clean; the three plan.md edits byte-exact with in-band verification; the four local gates re-run immediately on the Commit-0 tree with the exact expected inventory (lib 408 = 406 pass + 2 pre-existing privileged ignores; bin 0; doctests 11; `--examples` gen_oui 9/9, poc_discover 7/7, poc_measure 11/11) | Met | Pre-flight: `git fetch origin` then `git rev-list --count main..origin/task/T-204-discovery-orchestrator` → `0`. Branch cut from updated main @ `4b94847`. The three edits applied by a scripted patch (`scripts` trail in §6) asserting each search string occurs exactly once before replacing; the 1.10.0 changelog row extracted **byte-exact from the task card file** (3,673 chars) to avoid transcription error. In-band verification (the T-106-RW1 hardened rule): `| **Plan version** | 1.10.0 |` ×1, `ACCEPT (after T-204-RW1; Manager-verified 2026-11-07)` ×1, `| **Plan version** | 1.9.0 |` ×0, `| T-204 | Discovery orchestrator and scheduler | TODO |` ×0, the 1.10.0 row begins on the line immediately after the 1.9.0 row's line (1063 → 1064), no blank line between. Committed as `0e4bf18` (plan.md only). Gates on the Commit-0 tree (§4.1): fmt exit 0 · clippy `-D warnings` exit 0 · test **lib 408: 406 passed + 2 ignored** (`discovery::privilege::tests::privileged_*`) + bin 0 + **11 doctests** · doc exit 0 · `--examples`: **gen_oui 9/9, poc_discover 7/7, poc_measure 11/11** — the inventory matches exactly. |
| AC-1 All §11.3 gates green on the final tree on the pinned 1.99.1 toolchain; MSRV 1.89.0 build green; SPDX header on every new `.rs`; `cargo audit` + `cargo deny check` green (cargo-audit 0.22.2 / cargo-deny 0.20.2, crates.io `--locked` provenance per T-203 PQ-2 — stated) | Met | §4.2/§4.3: fmt / clippy / test (471 = 469 + 2 ignores) / `RUSTDOCFLAGS="-D warnings"` doc all exit 0 on rustc/cargo 1.99.1; `rustup run 1.89.0 cargo build --locked` exit 0. §4.4 greps: `rg --files-without-match "^// SPDX-License-Identifier: GPL-3.0-only$" src/app/ src/discovery/privilege.rs` → no files. cargo-audit 0.22.2 and cargo-deny 0.20.2 installed **from crates.io with `--locked`** (the T-203 PQ-2 provenance resolution; CI re-runs its own sha256-verified release tarballs): audit exit 0 (196 crate dependencies, 0 vulnerabilities, advisory-db 1422 advisories); deny exit 0 (`advisories ok, bans ok, licenses ok, sources ok` + the pre-existing informational unmatched-license-allowance notes on ISC/BSD-3-Clause, present since T-000). |
| AC-2 Pure core: `update` performs no I/O; a thread-free, channel-free scenario suite with `FakeClock` drives notice `y` → scope `Enter` → dashboard (local device present, `This device` tagged) → `Enter` details → `Esc` → `?` help → `Esc` → `r` refresh → `s` sort toggle → `q` quit; every transition, message and effect asserted | Met | The signature is `pub fn update(state: &mut AppState, event: AppEvent, clock: &dyn Clock) -> Vec<Effect>` — no I/O, threads or channels are expressible through it beyond the injected clock. `app::update::tests::ac2_full_scenario_script_notice_to_quit` (update.rs): the whole script with zero threads/channels — local device present, `This device` tagged, vendor `Private address` (locally-administered MAC), confirmed scope facts, details open for the selected row (`j` first: the registry starts unselected — §6 decision 4), Esc back with the selection preserved, `?`/Esc overlay, `r` → exactly `Effect::StartScan { Manual, ScanParams { 2, DEFAULT_RATE_PPS, DEFAULT_LISTEN_WINDOW } }`, `s` toggles Ip↔Hostname with the selection surviving, `q` → `Effect::Quit` + the authoritative flag together. Companions: `ac2_confirm_effects_and_arming` (exactly `ResolveHostname { own_ip }`), `ac2_confirm_without_hostnames_queues_nothing`, `ac2_gateway_observed_in_a_cycle_gets_the_gateway_tag` (the `Gateway` tag lands on the observed holder). |
| AC-3 FR-ST-02: before `y` and scope confirmation no `StartScan` effect is ever emitted and the scheduler is never polled; a scripted key mash pre-confirmation produces zero discovery effects | Met | `app::update::tests::ac3_key_mash_before_confirmation_produces_zero_discovery_effects`: the LCG property-style mash the card suggests (`model::testing::Lcg`, **high-bit draws** `(next_u64() >> 32) % n`, the T-203 §11.1 form), 2,000 draws per phase, three phases each pre-confirmation **by construction** — (a) the Notice screen (every key except `y`/quit), (b) the Scope screen over an eligible list (every key except `Enter`/quit), (c) the Scope screen over an ineligible-only list (`Enter` included: it can only refuse) — asserting zero `StartScan` effects, no arming, and at the end that the scheduler's fresh `Immediately` slot is intact (`next_auto_in == Some(ZERO)`, `!is_running()`): proof it was never polled. The runtime half: `app::runtime::tests::ac3_runtime_never_polls_or_starts_discovery_before_confirmation` — the same mash through the real queue and `step`, the recording executor empty, the scheduler untouched. |
| AC-4 First scan: after confirmation the next loop iteration yields exactly `Effect::StartScan { trigger: Initial, params: ScanParams { passes: 2, rate_pps: DEFAULT_RATE_PPS, listen_window: DEFAULT_LISTEN_WINDOW } }`; local device inserted with `This device`; gateway IP tagged `Gateway` when present; `ResolveHostname { own_ip }` queued | Met | `app::runtime::tests::ac4_first_loop_iteration_starts_exactly_the_initial_two_pass_scan`: a confirmed state handed to the runtime, one `step(Duration::ZERO)`, the recording executor holds **exactly** the Initial start with the binding recipe (asserted field-by-field: passes 2, rate 100 pps, window 1.5 s), and the scheduler holds the one running cycle. The confirm-time facts are the AC-2 tests (local device + tag + `ResolveHostname { own_ip }`) plus `ac2_gateway_observed_in_a_cycle_gets_the_gateway_tag` (the tag applied to the observed gateway holder). |
| AC-5 Runtime integration: real read-only `DiscoveryWorker` over a scripted fake `NeighborSource` + real `HostnameWorker` over a fake `NameResolver` (shared `FakeClock`), driven via `AppEventSender` + `step`; cycle events flow, hostnames become `Known`, `last_scan` records the outcome, `next_auto_in` equals the interval from the finish, shutdown joins cleanly | Met (hardened in `bb10a37`, §12) | `app::runtime::tests::ac5_runtime_integration_read_only_cycle_with_real_workers`: `DiscoveryWorker::spawn_read_only` over a one-row fake neighbor source (built with the reviewed public `parse_arp_table`), the real `HostnameWorker` over a fixed-name fake resolver (the trait implemented in test code only, fully-qualified paths — the §2 ruling), one shared `SharedFakeClock` (the T-203 pattern), scope confirmation through the real queue. Bounded-poll loop (20 ms steps, 10 s deadline — no blind sleeps): after the flow, the registry holds the local device + the observed `.5` neighbor (source `NeighborTable`), the neighbor's hostname is `Known { "host-five.lan", ReverseDns }`, `last_scan` records ReadOnly/Complete/Initial, `next_auto_in(finished_at) == Some(60 s)` (the finish-anchored cadence), the counters snapshot is refreshed from the real workers (`cycles_started == 1`, `cycles_finished == 1`, `queries_issued >= 1`); quit through the queue, a second post-shutdown step (idempotence), clean drop. |
| AC-6 FR-DS-08/refresh/sort: `r` during a running cycle ⇒ `ScanAlreadyInProgress`, no effect, nothing queued; after the finish `r` starts a Manual 2-pass cycle; `s` toggles `SortMode`; the selection survives a re-sort and a refresh that changes row order | Met | `app::update::tests::ac6_refresh_during_a_running_cycle_is_already_in_progress_nothing_queued` (the typed message, zero effects, the scheduler still single-running); `ac6_after_the_finish_refresh_starts_a_manual_two_pass_cycle` (the exact Manual recipe); `ac6_selection_survives_re_sort_and_row_changing_refresh` (the selected key survives the Ip→Hostname toggle **and** a refresh whose re-observation moves the row by changing the primary IP to 192.0.2.5). |
| AC-7 FR-DS-12 end-to-end (scripted, pure): three `Failed` finishes ⇒ exactly one `AutoScansStopped` message, `auto_stopped` sticky (a later manual `Complete` does not resume; `poll` issues nothing), manual refresh still works while stopped; a `Failed` finish anchors the next auto at `max(interval, 30 s)`, a `Cancelled` finish at the plain interval | Met | `app::update::tests::ac7_three_failures_stop_auto_scans_sticky_and_manual_still_works`: three full Failed cycles through the event path (start decision → Started → Finished) ⇒ exactly one `AutoScansStopped` message and the state flag; the later manual Complete resets the streak at its finish (`failure_streak() == 0` asserted **after** the finish) while `auto_stopped` stays `true` (the PQ-1 ruling); `poll` returns `None` across repeated calls; the next `r` still starts a Manual cycle; still exactly one stop message. `ac7_failed_backoff_and_cancelled_plain_interval_anchoring`: at the 15 s minimum interval, the Failed finish anchors at 30 s (not-due at +29 s, due at exactly +30 s) and the Cancelled finish at 15 s. |
| AC-8 Enrichment rules: new device ⇒ vendor set per the §5.9 mapping (all three `VendorLookup` arms tested) and `ResolveHostname` queued; existing device re-observed ⇒ vendor not recomputed, hostname effect re-queued; `Resolved` applied to **every** record holding the IP; `hostnames_enabled = false` ⇒ zero hostname effects | Met | `app::update::tests::ac8_new_device_gets_vendor_and_hostname_effect_all_three_lookup_arms` — the T-202 pinned real fixtures: `28:6f:b9:00:00:01` → `Known("Nokia Shanghai Bell Co., Ltd.", VendorDb)`, `02:28:6f:b9:12:34` → `Known("Private address", VendorDb)`, `ec:ec:ec:11:22:33` → `Unknown`; each with the hostname effect queued. `ac8_existing_device_reobserved_vendor_not_recomputed_hostname_requeued` — a sentinel vendor field survives the re-observation (no recompute) while the hostname effect is re-queued. `ac8_resolved_applies_to_every_record_holding_the_ip` — the ADR-008 shared-IP case: both MAC records of 192.0.2.50 get the name, the local device stays `Pending`. `ac8_hostnames_disabled_emits_zero_hostname_effects_in_the_whole_script` — a full confirm+cycle script with zero `ResolveHostname` effects (the vendor fill still happens: it is not hostname-gated). |
| AC-9 Message log: every §5.7 kind produced by a scripted trigger; never exceeds 20 entries (oldest evicted); the dedup rule holds (100 cap-dropped observations ⇒ one `RegistryCapReached`) | Met | `app::update::tests::ac9_every_cycle_message_kind_is_produced_by_a_scripted_trigger` (ScanFailed/ScanDegraded with verbatim reasons; a plain Partial appends nothing); `ac9_hundred_cap_drops_produce_one_cap_message` (a 2-slot registry cap: 100 dropped observations ⇒ exactly one message, `cap_warning()` set); `ac9_repeated_identical_failures_dedup_while_present` (the identical repeat suppressed; a changed reason appends — §6 decision 8 records the reading). The per-kind log suite in `app::message::tests`: `capacity_is_twenty_and_the_oldest_is_evicted`, `identical_kinds_are_suppressed_while_present`, `eviction_re_allows_an_append_of_the_same_kind`, `every_kind_is_appendable_and_countable`, `a_fresh_log_is_empty`. The construction-time kinds (ReadOnlyMode/RootWarning/NoEligibleResolver) and ScopeUnavailable are covered in `app::state::tests` and `app::update::tests::scope_enter_on_ineligible_selection_reports_scope_unavailable`; AutoScansStopped in the AC-7 test. |
| AC-10 Resize: 79×24 and 80×23 ⇒ `too_small`; exactly 80×24 ⇒ not; recovery restores the underlying screen (state never reset); `q` quits while too small | Met | `app::update::tests::ac10_too_small_bounds_and_recovery`: the three too-small boundaries, exactly-80×24 and 100×30 not too small, a hard 10×4 shrink grown back to 120×40 with the screen, the selection, `last_scan` and the message log intact (FR-ST-04: never a reset), and `q` quitting while too small. Companion: `ac10_tick_marks_dirty_and_shutdown_ack_changes_nothing` (Tick marks dirty; ShutdownAck changes nothing). |
| AC-11 NFR-03 benchmark: 4,096 synthetic devices, a burst of Started + 128 × Observations(32) + Finished + Tick + 5 Input through loop iterations (drain ≤ 16); **every** iteration < 100 ms (assert; report mean and max); a sort-toggle iteration at 4,096 devices also < 100 ms | Met | `app::runtime::tests::ac11_nfr03_no_iteration_blocks_at_4096_devices`: the registry pre-filled through the real `update` path (128 × 32 batches inside one cycle; the entry is MAC-less so the registry holds **exactly 4,096** records at the ADR-008 cap — the local device would otherwise take a slot), then the card's exact burst (136 events) through 16 measured `step` iterations. Debug build (the gate configuration): **mean 751.674 µs, max 6.310898 ms — every iteration asserted < 100 ms (15.8× headroom at the max)**; sort toggle 914 ns. Release build (additional evidence): mean 94.136 µs, max 670.842 µs; sort toggle 522 ns. The whole burst was processed (the finish landed, all 4,096 re-observations merged, `cap_warning()` false). T-403 re-measures on the reference machine. |
| AC-12 Scope & hygiene: `rg "ratatui\|crossterm" src/app/` ⇒ no matches; the §8.2 import grep ⇒ no matches; `rg "use crate::ui" src/` ⇒ no matches; the diff touches only the allowed paths | Met | §4.4: all three greps exit 1 (no matches — including doc comments, which avoid naming the terminal frameworks). `git diff --stat main..HEAD`: `plan.md` (+3/−2, Commit 0 only), `src/app/**` (8 new files), `src/lib.rs` (+13: the registration + doc paragraph), `src/discovery/privilege.rs` (+153: the §5.10 helper, parser and tests only), `docs/reports/T-205/**` (this file). Nothing else; `Cargo.toml`/`Cargo.lock`/`fuzz/**`/`tests/**`/`.github/**` untouched. |
| AC-13 No regressions: the netns suite 12/12 behind `OSZA_NETMON_TESTS=1` with `tests/netns/**` unmodified; the three fuzz harnesses reproduce their recorded summaries byte-exact | Met | §4.3: netns run inside `unshare --user --map-root-user --net` — verbatim `netns suite: 12 scenario(s), 0 failure(s), 38.0s total`, exit 0, no edits to `tests/netns/**` (the AC-12 diff proves it). Fuzz: `arp_frame` `accepted=27911 …` (every counter byte-identical to the recorded line); `dns_response` `known-name 3299, no-name 5018, malformed 491403, server-failure 1367, truncated 784`; `resolv_conf` `401141 inputs, 864209 entries, 579386 skipped, 142287 selected / 258855 no-resolver`. |
| AC-14 Report per Appendix B, complete (§5 deviations and §6 decisions filled in) | Met | This file; the two deviations and the decisions are below; §8 carries the two Plan Questions this card's execution surfaced. |

## 3. What changed

- **Commit 0 (Manager-ordered, §10):** `0e4bf18` — plan.md v1.9.0 → v1.10.0 (header, Status Board T-204 row, the verbatim 1.10.0 changelog row after the 1.9.0 row), applied by a scripted patch and verified in-band per the T-106-RW1 hardened rule; the four local gates re-run immediately (§4.1).
- **`src/discovery/privilege.rs`** (+153 lines, the §5.10 exception): `running_as_root()` — one bounded (64 KiB, SR-10) read of `/proc/self/status` behind the pure, total `parse_effective_uid` (the `Uid:` line's second of four fields, decimal, last-line-wins mirroring `parse_thread_status`); an unreadable/unparsable file yields `false` (the warning is suppressed when the value cannot be determined); **not** `nix::unistd::geteuid` (the crate's "user" feature is off; no Cargo.toml change is authorized). Four new tests (realistic/root, whitespace/last-line, total-over-garbage including missing line/one-field/negative/overflow/empty/u32::MAX, and the totality smoke test). Module docs updated; no existing line of the reviewed tests changed.
- **`src/app/` (new, 8 files, 5,518 lines incl. 59 tests)** — `mod.rs` (67): module map + re-exports; `event.rs` (130): `AppEvent`/`InputEvent`/`Key` (terminal-agnostic §10.3 vocabulary); `action.rs` (295): `Effect` (StartScan/ResolveHostname/Quit — no CancelScan, documented), `EffectError` (the workers' typed errors verbatim), `EffectsExecutor` (execute + worker_stats + hostname_events + shutdown), `WorkerExecutor`; `message.rs` (359): `MessageKind` (9 typed kinds), `Message`, `MessageLog` (capacity 20, the FR-ER dedup rule); `config.rs` (169): `SessionParams`, `AppMode`, `AppInitError`; `state.rs` (812): `AppState` (screens, overlays, registry, scheduler, counters, `PAGE_STEP` 8, NFR-08 bounds), `ScopeEntry` (deviation D-1), `ConfirmedScope`, `LastScan`, `CountersSnapshot`; `update.rs` (2,434): the pure `update` with the §5.5 event semantics, the §5.6 key map, scope confirmation, the §5.9 enrichment rules and the §2 recipe helper; `runtime.rs` (1,252): the §8.4 loop, the 256-slot bounded queue, `AppEventSender`, the discovery forwarder (T-204's delivery policy), the inline hostname drain (deviation D-2), the counters refresh, the bounded idempotent shutdown, `RecordingExecutor` (pub for T-301).
- **`src/lib.rs`** (+13): `pub mod app;` + the house-style doc paragraph.

## 4. Verification results

### 4.1 The four local gates on the Commit-0 tree (§10, run immediately after `0e4bf18`)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 22.22s
[exit 0]

$ cargo test --locked --all-features
running 408 tests
test result: ok. 406 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.12s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored 0 measured; 0 filtered out; finished in 0.00s
netns suite: skipped (OSZA_NETMON_TESTS is not set; ...)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s   (doctests)
[exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Generated …/target/doc/osza_netmon/index.html        [exit 0]

$ cargo test --locked --all-features --examples
test result: ok. 9 passed; … (gen_oui)
test result: ok. 7 passed; … (poc_discover)
test result: ok. 11 passed; … (poc_measure)
[exit 0]
```

The inventory matches the card's expected counts exactly (408 = 406 + the two pre-existing privileged ignores; bin 0; 11 doctests; 9/7/11 examples).

### 4.2 The gates on the final tree (pinned 1.99.1)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.10s
[exit 0]

$ cargo test --locked --all-features
running 471 tests
test result: ok. 469 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 10.41s
running 0 tests        (bin)
test result: ok. 0 passed; 0 failed; 0 ignored; …
running 11 tests       (doctests)
test result: ok. 11 passed; 0 failed; 0 ignored; …
[exit 0]   — 63 new tests (59 in src/app/, 4 in privilege.rs); the 2 ignores are the
             pre-existing discovery::privilege::tests::privileged_* pair

$ cargo test --locked --all-features --examples
test result: ok. 9 passed; … / ok. 7 passed; … / ok. 11 passed; …      [exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Generated …/target/doc/osza_netmon/index.html                       [exit 0]

$ rustup run 1.89.0 cargo build --locked
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 23.84s  [exit 0]

$ cargo audit          # cargo-audit 0.22.2, installed from crates.io --locked
    Fetching advisory database …
      Loaded 1422 security advisories
    Scanning Cargo.lock for vulnerabilities (196 crate dependencies)
[exit 0, 0 vulnerabilities]   (provenance: crates.io `--locked` at the CI-pinned
                              version — the T-203 PQ-2 resolution; CI re-runs its
                              own sha256-verified release tarballs)

$ cargo deny check     # cargo-deny 0.20.2, installed from crates.io --locked
advisories ok, bans ok, licenses ok, sources ok
[exit 0]   (+ the pre-existing informational unmatched-license-allowance notes on
            ISC/BSD-3-Clause, present since T-000)
```

### 4.3 The task-specific §9 commands

```text
$ cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame --target-dir target
  outcomes: accepted=27911 rejected=772961 truncated=402460 wrong_ether_type=281095
    wrong_hardware_type=8740 wrong_protocol_type=8040 wrong_hardware_length=3286
    wrong_protocol_length=4662 wrong_opcode=7609 mac_mismatch=48683 invalid_mac=9
    out_of_scope=6947 network_address=4 broadcast_address=4 own_address=7 not_solicited=1415
  accepted-by-corruption (non-vacuity): 150
  result: OK — no panic path, no oracle violation          [byte-exact]

$ cargo run --manifest-path fuzz/Cargo.toml --bin dns_response --target-dir target
  outcomes: known-name 3299, no-name 5018, malformed 491403, server-failure 1367,
    truncated 784, timeout/transport 0
  accepted-by-corruption (non-vacuity): 676
  result: OK — no panic path, no oracle violation          [byte-exact]

$ cargo run --manifest-path fuzz/Cargo.toml --bin resolv_conf --target-dir target
  parse results: 401141 inputs, 864209 entries, 579386 skipped malformed lines
  selections: 142287 selected, 258855 no-resolver (141749 selected on random inputs)
  accepted-by-corruption (non-vacuity): 488
  result: OK — no panic path, no invariant violation       [byte-exact]

$ unshare --user --map-root-user --net env HOME=$HOME RUSTUP_HOME=$HOME/.rustup \
    CARGO_HOME=$HOME/.cargo PATH="$HOME/.cargo/bin:$PATH" OSZA_NETMON_TESTS=1 \
    cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture
netns suite: 12 scenario(s), 0 failure(s), 38.0s total     [exit 0]

$ cargo test --locked --all-features -- app::runtime::tests::ac11_nfr03… --nocapture
NFR-03 burst: 16 iterations, mean 751.674µs, max 6.310898ms      (debug build)
NFR-03 sort toggle: 914ns
$ cargo test --locked --all-features --release -- app::runtime::tests::ac11_nfr03… --nocapture
NFR-03 burst: 16 iterations, mean 94.136µs, max 670.842µs        (release build)
NFR-03 sort toggle: 522ns
```

### 4.4 The hygiene greps (AC-12)

```text
$ rg -n "ratatui|crossterm" src/app/                      → no matches [exit 1]
$ rg -n "use crate::(discovery::arp::(codec|scanner|transport)|discovery::neighbor_table|enrichment::dns)" src/app/
                                                          → no matches [exit 1]
$ rg -n "use crate::ui" src/                              → no matches [exit 1]
$ rg --files-without-match "^// SPDX-License-Identifier: GPL-3.0-only$" src/app/ src/discovery/privilege.rs
                                                          → no files  [exit 1]
$ git diff --stat main..HEAD
 plan.md                    |    5 +-     (Commit 0 only)
 src/app/action.rs          |  295 +++    (new)
 src/app/config.rs          |  169 +++    (new)
 src/app/event.rs           |  130 +++    (new)
 src/app/message.rs         |  359 +++    (new)
 src/app/mod.rs             |   67 ++     (new)
 src/app/runtime.rs         | 1252 ++++   (new)
 src/app/state.rs           |  812 ++++   (new)
 src/app/update.rs          | 2434 ++++   (new)
 src/discovery/privilege.rs |  153 ++     (the §5.10 helper, parser and tests only)
 src/lib.rs                 |   13 +      (registration + doc paragraph)
 docs/reports/T-205/execution-01.md (this file)
```

### 4.5 The exact new test inventory (63 tests)

- `app::action::tests` (2): `effect_error_displays_the_worker_reasons_verbatim`, `quit_is_a_no_op_and_shutdown_is_idempotent_for_any_executor`.
- `app::config::tests` (2): `defaults_are_the_plan_values`, `an_invalid_registry_config_is_a_typed_init_error`.
- `app::event::tests` (2): `the_full_key_vocabulary_constructs_and_compares`, `events_wrap_their_payloads_losslessly`.
- `app::message::tests` (5): `capacity_is_twenty_and_the_oldest_is_evicted`, `identical_kinds_are_suppressed_while_present`, `eviction_re_allows_an_append_of_the_same_kind`, `every_kind_is_appendable_and_countable`, `a_fresh_log_is_empty`.
- `app::state::tests` (12): `fresh_state_starts_on_the_notice_screen_unacknowledged`, `an_acknowledged_notice_starts_on_the_scope_screen`, `startup_messages_fire_exactly_when_their_condition_holds`, `read_only_mode_appends_its_reason_verbatim`, `no_resolver_message_only_when_hostnames_are_enabled`, `all_startup_messages_together_deduplicate_to_three`, `selection_starts_at_the_first_eligible_entry`, `selection_is_row_zero_when_nothing_is_eligible`, `the_vendor_database_date_is_exposed`, `the_entry_snapshot_mirrors_the_interface_accessors_exactly`, `production_construction_from_kernel_data_selects_the_suggestion`, `a_minute_of_nothing_leaves_the_state_untouched`.
- `app::update::tests` (31): `ac2_full_scenario_script_notice_to_quit`, `ac2_confirm_effects_and_arming`, `ac2_confirm_without_hostnames_queues_nothing`, `ac2_gateway_observed_in_a_cycle_gets_the_gateway_tag`, `ac3_key_mash_before_confirmation_produces_zero_discovery_effects`, `scope_navigation_skips_ineligible_rows_and_wraps`, `scope_navigation_without_eligible_rows_is_a_no_op`, `scope_enter_on_ineligible_selection_reports_scope_unavailable`, `unknown_keys_are_ignored_without_marking_dirty`, `ctrl_c_quits_from_every_screen_and_overlay`, `page_keys_move_by_eight_rows_and_clamp`, `details_navigation_moves_the_selection`, `ac6_refresh_during_a_running_cycle_is_already_in_progress_nothing_queued`, `ac6_after_the_finish_refresh_starts_a_manual_two_pass_cycle`, `ac6_selection_survives_re_sort_and_row_changing_refresh`, `ac7_three_failures_stop_auto_scans_sticky_and_manual_still_works`, `ac7_failed_backoff_and_cancelled_plain_interval_anchoring`, `ac8_new_device_gets_vendor_and_hostname_effect_all_three_lookup_arms`, `ac8_existing_device_reobserved_vendor_not_recomputed_hostname_requeued`, `ac8_resolved_applies_to_every_record_holding_the_ip`, `ac8_hostnames_disabled_emits_zero_hostname_effects_in_the_whole_script`, `ac9_every_cycle_message_kind_is_produced_by_a_scripted_trigger`, `ac9_hundred_cap_drops_produce_one_cap_message`, `ac9_repeated_identical_failures_dedup_while_present`, `ac10_too_small_bounds_and_recovery`, `ac10_tick_marks_dirty_and_shutdown_ack_changes_nothing`, `observations_before_confirmation_are_ignored`, `stale_scan_batches_are_ignored_by_the_registry`, `finished_reanchors_the_scheduler_even_when_the_registry_guard_ignores`, `last_scan_records_the_cycle_facts`, `aging_happens_exactly_per_the_outcome_class`.
- `app::runtime::tests` (5): `ac3_runtime_never_polls_or_starts_discovery_before_confirmation`, `ac4_first_loop_iteration_starts_exactly_the_initial_two_pass_scan`, `a_failed_start_appends_one_scan_failed_message_and_never_resilences`, `ac5_runtime_integration_read_only_cycle_with_real_workers`, `ac11_nfr03_no_iteration_blocks_at_4096_devices`.
- `discovery::privilege::tests` (4 new): `parses_effective_uid_from_a_realistic_status`, `effective_uid_parse_tolerates_whitespace_and_unknown_lines`, `effective_uid_parse_is_total_over_garbage`, `running_as_root_is_total_and_stable`.

## 5. Deviations from the task card

1. **D-1 — the scope-screen list is an app-side snapshot (`ScopeEntry`), not `Vec<InterfaceInfo>`.** The card's §5.4 names `interfaces: Vec<InterfaceInfo>`, and AC-2/AC-5 require a *fake/synthetic* interface list driving the whole flow deterministically. `InterfaceInfo`'s fields are private to `net::interfaces` — the only production constructor is `enumerate_interfaces()` — so **no deterministic fake list can exist** for `src/app/` tests under the card's own constraint that `src/net/**` must not change (AC-12's allowed paths; §4 "no changes to reviewed modules other than the one privilege helper"). Resolution: `AppState::new(params, interfaces: Vec<InterfaceInfo>, …)` — the card-faithful production signature — snapshots each interface into `ScopeEntry` (a plain projection of the net layer's public accessors, including the derived eligibility/class views and the mirrored `derive_scope` construction); the pub `AppState::with_scope_entries(params, entries: Vec<ScopeEntry>, …)` accepts synthetic entries (the scenario suites; any future in-crate consumer). The snapshot is proven honest by `the_entry_snapshot_mirrors_the_interface_accessors_exactly` — a relational test over whatever `enumerate_interfaces()` returns on the running machine (deterministic on any machine, including one with no interfaces), asserting every snapshot field equals the corresponding accessor output and that the mirrored scope derivation equals `net::derive_scope` on the same interface. The alternative (a `#[cfg(test)]` constructor inside `net::interfaces`) would have violated the card's explicit path constraint; PQ-1 asks the Manager to rule.
2. **D-2 — the hostname events are drained inline, not by a second forwarder thread.** The card's §5.8 mandates "two owned threads, one per worker event receiver". The discovery side is exactly that (the T-204 spawn hands over an owned `Receiver<CycleEvent>`). The hostname side cannot be: T-203's `HostnameWorker::events()` returns `&Receiver<HostnameEvent>` — the handle keeps the receiver, by design ("drained by the application's main loop") — and no owned extraction API exists, so no `'static` thread can hold it (the alternatives — `Arc<Mutex<HostnameWorker>>` sharing or per-step scoped threads — either change the card's `WorkerExecutor { discovery, hostname }` shape and add lock contention on the NFR-03 path, or add spawn churn for the same borrow gymnastics). The runtime instead drains the receiver through the executor's `hostname_events()` accessor at every step boundary (≤ `DRAIN_MAX` events, each run through `update` directly): no extra bounded hop exists, so the forwarder-side drop policy is moot — T-203's own bounded `emit` already counts its drops in `events_dropped` (visible as `counters.hostname.events_dropped`). Worst-case added latency is one wait slice (≤ 1 s); lookups take seconds. The `forwarder_dropped_hostnames` counter is kept for shape compatibility and is structurally zero, documented as such. PQ-2 asks the Manager to rule.

## 6. Decisions and assumptions

1. **Scope navigation wraps** (the card's "wrap or clamp — pick one, test it"): the selection cycles through the eligible rows; tested both directions, plus the no-eligible no-op and the ineligible-row snap-to-first-eligible.
2. **Details navigation is implemented** (the card's "Up/Down may move the selection — house choice"): `Up/k/Down/j` follow the plan §10.3 selection keys while Details is open; tested.
3. **Help is modal**: while the overlay is open only `Esc`/`?` (close) and `q`/`Ctrl+C` (quit, FR-UI-06) act; everything else is ignored (not dirty). Tested.
4. **`Enter` on Dashboard opens Details only when a row is selected**; the registry starts unselected (a confirm inserts the local device but selects nothing), so the first navigation key selects the first row — the AC-2 script presses `j` before `Enter`, matching §5.6's "selection is the registry's `selected_key`".
5. **A `Some(0.0.0.0)` default gateway is on-link, not a gateway address** (the net layer's documented encoding): `set_gateway_ip` is called only for a specified address; the raw `default_gateway` is still stored verbatim in `ConfirmedScope` for the header.
6. **An eligible interface without a valid MAC skips the local-device insertion** at confirm (no `(iface, MAC)` identity exists, ADR-008); the scope still confirms and arms. This is also the AC-11 fixture choice (the benchmark registry then holds exactly 4,096 synthetic devices at the cap).
7. **`update` never calls `scheduler.cycle_started()`**: the scheduler's *running* state is set by its own start decisions (`poll`/`manual_refresh`), and the app is the single commander, so every `Started` event follows a decision the scheduler already made (§5.5 lists no such call; the redundancy would be dead code).
8. **The "once per finished cycle" reading of §5.7 for `ScanFailed`/`ScanDegraded`**: the paragraph's first sentence is the normative dedup rule ("while a kind is already present in the log **and unchanged in its reason string**, a repeat append is suppressed"), so two consecutive failures with the *same* reason keep one entry while present; a changed reason appends; eviction re-allows. Pinned by `ac9_repeated_identical_failures_dedup_while_present`. One line to change if the Manager reads it the other way.
9. **A refused start leaves the scheduler holding *running*** (the poll's decision already transitioned it): no further start is issued and a manual refresh is answered `AlreadyInProgress` — the honest reflection of T-204's "the orchestrator never silently respawns it" (an application restart is the remedy). Pinned by `a_failed_start_appends_one_scan_failed_message_and_never_resilences`.
10. **`next_auto_in` shapes the wait only while discovery is armed**: pre-confirmation a fresh scheduler reports "due now", which would otherwise make every step a zero-wait busy spin while the poll it feeds is gated (FR-ST-02). Documented in `Runtime::step`.
11. **The runtime's hostname drain is bounded at `DRAIN_MAX`** per iteration (16), mirroring the queue drain's starvation bound.
12. **`PAGE_STEP = 8`** is the documented provisional constant (T-303 replaces it with the real visible-row count); with no selection both page keys select the first row (consistent with the registry's own `select_next`/`select_previous`).
13. **`RecordingExecutor` is pub** (the card's "your choice, documented"): T-301's input-thread tests can reuse it.
14. **`dirty` starts `true`** at construction (the first frame has something to draw); every non-suppressed message append sets it.
15. **`hostnames_enabled` (the app-level flag) is taken from `SessionParams.hostnames_enabled`**; the assembly keeps it consistent with `HostnameConfig.enabled` (a mismatch is harmless: the worker answers `Disabled` honestly).
16. **`parse_effective_uid` is last-`Uid:`-line-wins** (the kernel writes one; hostile input may write more — the same overwrite discipline as `parse_thread_status`), and `running_as_root()`'s unreadable-file answer is `false` (suppressed warning), exactly as the card's §5.10 doc comment prescribes.
17. **A forwarder spawn failure (an OOM-class event) degrades the T-204 way** — the handle is absent, discovery events stop flowing, shutdown joins what exists — never a panic (the `panic`/`expect` lints are denied in production code).
18. **Commit 0's patch was scripted and extracted from the task card file** (the 1.10.0 changelog row read programmatically, 3,673 chars) with each search string asserted to occur exactly once before replacing — the T-204 Commit-0 pattern; the verification is in-band (§4.1/AC-0), never by displayed output.

## 7. Dependencies

None. No new crates, no `Cargo.toml`/`Cargo.lock` changes (the AC-12 diff proves it); everything is std + the already-approved in-tree crates, and §5.10 explicitly avoids the `nix` "user" feature.

## 8. Plan Questions

1. **PQ-1 — the interface-list test seam (deviation D-1).** `InterfaceInfo` is constructible only inside `net::interfaces` (private fields; `enumerate_interfaces()` is the sole production constructor), so the card's AC-2 script and AC-5 "fake interface list" cannot exist with a literal `Vec<InterfaceInfo>` state field under the card's own no-touch constraint on `src/net/**`. This card resolves it with the app-side `ScopeEntry` snapshot (`AppState::new` converts; `with_scope_entries` accepts synthetic entries; the snapshot is proven field-equivalent relationally). **Ruling requested:** ratify the snapshot, or authorize a follow-up card adding a `#[cfg(test)]`-gated constructor (or an `InterfaceInfo::new(…)` API) to `net::interfaces` so a future refactor can hold the card's literal field type — in which case `ScopeEntry` would collapse back into it.
2. **PQ-2 — the hostname forwarder (deviation D-2).** The card's §5.8 mandates two forwarder threads, but T-203's reviewed handle lends its event receiver (`events() -> &Receiver<HostnameEvent>`; no owned extraction), so the second thread cannot exist as specified. This card resolves it with the inline main-thread drain through the executor (≤ 16 events per step; T-203's own bounded `emit` remains the drop policy; latency ≤ one wait slice). **Ruling requested:** ratify the inline drain, or authorize a small T-203 follow-up exposing an owned receiver (e.g. `fn into_events(self) -> Receiver<HostnameEvent>` on a spawn variant) so the card's two-thread shape can be restored in a later card.

## 9. Security and privacy notes

No new network egress: the app layer opens nothing (the §5.10 helper reads `/proc/self/status` once, bounded at 64 KiB, informationally). No `unsafe`, no credentials, no telemetry. The `reason` strings stored in the message log are the reviewed workers' own one-line outputs and the net layer's reviewed eligibility words — stored and compared, never rendered by this layer (T-401 words them). The `too_small` overlay never clears state (FR-ST-04), so a hostile resize cannot be used to hide information from the user.

## 10. Known issues and limitations

- `CountersSnapshot::forwarder_dropped_hostnames` is structurally zero under deviation D-2; the authoritative hostname-drop counter is the worker's `events_dropped` (`counters.hostname.events_dropped`). If PQ-2 is ruled toward the two-thread shape, the counter becomes live again.
- The NFR-03 numbers were measured on the executor's sandbox (debug and release), not the reference machine; T-403 re-measures per §11.5.
- Pre-confirmation, the scope facts are `None` (`ConfirmedScope` exists only after the Scope screen's `Enter`); the card listed the five facts as flat fields — the grouping is the honest shape for "from the confirmed interface" (decision, not deviation: the card's own "(from the confirmed interface)" qualifier).
- The scope screen's list is a snapshot taken at construction; interfaces that appear or change during a session are not re-enumerated (one scope per session is the MVP model; plan §6.2 defers re-selection).

## 11. Suggested follow-ups

1. **T-301** — attach the terminal: map the input library onto `Key`, drive resizes into `AppEvent::Resize`, hold the `AppEventSender` with the bounded-retry pattern documented on it, and render from `Runtime::state()` (the recording executor is available for its input-thread tests).
2. **T-302** — the notice-ack persistence and the large-scope/public-range confirmation dialogs feed `SessionParams.notice_acknowledged` and the confirm path; the scope screen renders `AppState::interfaces()` (the D-1 snapshot carries name/class/eligibility/gateway).
3. **T-303** — replace `PAGE_STEP` with the real visible-row count (one constant + its two tests).
4. **T-401** — word the nine `MessageKind`s (the reasons are stored verbatim; `ScopeUnavailable`'s reason uses the net layer's reviewed eligibility words).
5. **T-403** — re-measure NFR-03 on the reference machine (the benchmark test prints mean/max under `--nocapture`).
6. **T-404** — the shared `model::testing::Lcg` low-bit migration noted in T-203's follow-ups: this card's mash already uses high-bit draws locally; the shared helper can adopt them then.
7. If PQ-1/PQ-2 are ruled toward the card's literal shapes, the two deviations each collapse in a small dedicated card (§8).

## 12. Attempt 01 addendum — the first CI run and the AC-5 hardening

The first CI run on the delivered branch (**run #58**, head `e2d959c`) failed one job (`cargo test --all-features`): `app::runtime::tests::ac5_runtime_integration_read_only_cycle_with_real_workers` — the observed `.5` neighbor's hostname field was still `Pending` when the bounded-poll loop exited. Root cause (a test race, not a production defect): the loop's wait condition accepted **any** device's hostname becoming `Known`, and the local device's own confirm-time lookup (queued before the cycle even starts) can resolve first; the loop then broke one step before the neighbor's answer landed — a window the executor sandbox never hit across dozens of runs but the GitHub runner's scheduling did. Fix (`bb10a37`, test-only): the wait condition now requires the **observed device's** hostname specifically (plus the cycle finish) — exactly what the subsequent assertions check. Verification: eight consecutive full `app::` suite runs green locally, then three full-suite runs (471 tests each) green; CI **run #59** on `bb10a37` is green on all four jobs (fmt/clippy/test/doc/SPDX, audit/deny, netns, MSRV). The in-band evidence of §4 is from the pre-fix tree except where noted; the only code difference between the two heads is the ten-line test-condition change above (no production line changed — `git diff e2d959c..bb10a37` touches `src/app/runtime.rs` tests only).
