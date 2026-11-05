# Execution Report — T-204 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-06 · **Branch/commits:** `task/T-204-discovery-orchestrator`, based on `main` @ `be32502` — Commit 0: `f71ce89` (plan v1.9.0, Manager update), `2d89cc2` (ADR-015 ratified); the T-204 work: `a0e7212` (ScanId moves into the model domain layer), `a6711f8` (scheduler — the pure FR-DS-12 state machine), `d62f0b5` (orchestrator worker — §8.5 cycles, ScanId stamping, read-only mode), `9e33749` (transport — pnet's opaque fatal poll error maps to InterfaceLost), plus this report · **Plan version:** 1.9.0 (repository copy, written by Commit 0)

## 1. Summary (≤ 5 lines)

The discovery orchestration layer of plan §6.3 FR-DS-08…12/FR-DS-14 is delivered in two new modules behind the §8.2 dependency rule (model + std only, grep clean): `discovery/scheduler.rs` (1,199 lines incl. 15 tests) — the pure FR-DS-12 state machine implementing Manager rulings (a)–(f) exactly, with the typed `RediscoveryInterval` constructor (0 / ≥ 15 s / default 60 s) and the ADR-011 pass-policy constants as the authoritative home for T-205/T-402; and `discovery/worker.rs` (2,293 lines incl. 17 tests) — the orchestrator thread that executes whole §8.5 cycles through the **real** T-104 `ArpWorkerHandle` (neighbor read → paced sweep → listen window → neighbor read → outcome), stamping every event with a `model::ScanId` (moved from `registry::observation`, re-exported unchanged so every T-201 test passes unmodified), one cycle at a time over bounded channels, ≤ 250 ms cancellation, socket-free read-only mode, typed already-in-progress / worker-gone / degraded-Partial outcomes, and the ScanId discipline (stale arp events dropped and counted). The T-105 follow-up note is applied in `arp/transport.rs` (pnet's opaque "Unexpected poll event" → `InterfaceLost`, one match arm + unit test). 33 new library tests (total 406: 404 pass + the 2 pre-existing privileged ignores), the AC-9 property test (LCG high-bit draws, 2 × 20,000 sequences), the netns suite re-run 12/12 in 38.0 s unchanged, and all §9 gates green on the pinned 1.99.1 toolchain with the MSRV 1.89.0 build green.

## 2. Acceptance criteria

| AC | Status (Met / Partial / Not met) | Evidence (test name, command, file) |
|---|---|---|
| AC-0 Commit 0 exactly as §10 prescribes: pre-flight clean, plan.md at v1.9.0 with the exact edits, ADR-015 status Accepted + index row; the four local gates re-run immediately after on the Commit-0 tree (expected inventory: lib 373 = 371 pass + 2 ignored; bin 0; netns 0 (ungated); doctests 11; `--examples` gen_oui 9) — results in report §4 | Met | Pre-flight `git fetch origin` + `git rev-list --count main..origin/task/T-203-hostname-resolver` → `0`; branch cut from updated main @ be32502. plan.md edits applied via a Python patch asserting each target string occurs exactly once before replacing, committed as `f71ce89` (plan.md only: header 1.8.0→1.9.0, Status Board T-203 TODO→DONE/ACCEPT (v1.9.0), the verbatim 1.9.0 changelog row inserted immediately after the 1.8.0 row); the bracket-bearing changelog row verified **in-band** (T-106-RW1 hardened rule — never by displayed output): counts of the `[m-sequence` and `[main]` byte sequences are exactly 2 each in plan.md after the edit (the 1.5.0 row + the new row), the row tail matches a programmatically constructed expected string byte-exactly, and the 1.9.0 row sits directly after the 1.8.0 row (empty-gap check). ADR-015 line + index row byte-exact per §10c, committed as `2d89cc2`. Gates on the Commit-0 tree (§4.1): fmt exit 0 · clippy exit 0 · test **373 lib tests: 371 pass + 2 ignores** (`discovery::privilege::tests::privileged_drop_fails_closed_verification_catches_residual`, `…privileged_open_raw_socket_succeeds_and_drop_verifies`) + bin 0 + **11 doctests** · doc exit 0 · `--examples`: **gen_oui 9/9**, poc_discover 7/7, poc_measure 11/11 — the inventory matches the expected counts exactly. |
| AC-1 All §11.3 gates green on the pinned toolchain; MSRV 1.89.0 build green; SPDX headers on every new `.rs`; `cargo audit` and `cargo deny check` green (provenance note like T-203 PQ-2 if the tools had to be installed) | Met | §4.2: fmt / clippy `-D warnings` / test / `RUSTDOCFLAGS="-D warnings"` doc all exit 0 on rustc/cargo 1.99.1 (rust-toolchain.toml pin); `rustup run 1.89.0 cargo build --locked` exit 0; §4.4 greps: `grep -rLn "^// SPDX-License-Identifier: GPL-3.0-only$" src/discovery/*.rs src/discovery/arp/*.rs src/model/*.rs` lists no files (the new `scheduler.rs`/`worker.rs` and every edited file carry the header; independently re-checked per file with `head -1`). cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from crates.io `--locked` at the CI-pinned versions (the T-203 PQ-2 provenance resolution; CI re-runs its own sha256-verified release tarballs) — §4.2: audit exit 0 (196 crate dependencies, 0 vulnerabilities, advisory-db 1409 advisories), deny exit 0 (`advisories ok, bans ok, licenses ok, sources ok` + the pre-existing informational unmatched-license-allowance notes on ISC/BSD-3-Clause, present since T-000). |
| AC-2 Scheduler table-driven matrix: 60 s default cadence anchored at finish; never a start while running; interval 0 manual-only; interval validation (0 valid, 1..=14 rejected typed, 15 valid); failed backoff max(interval, 30 s); 3 consecutive failures stop auto-scans with the typed notice; manual allowed while stopped; streak semantics; manual-during-scan already-in-progress; post-manual re-anchor | Met | `default_cadence_is_anchored_at_finish` (due exactly at finish 25 + 60 = 85, not start+60; `poll` mid-run → `None`); `interval_validation_table` (0 → manual-only valid; 1 s, 7 s, 14 s, 14.999 s, 500 ms, 1 ns → the typed `IntervalTooShort` with its exact Display; 15 s valid; default 60 s); `failure_backoff_table` (15→30, 29→30, 30→30, 60→60 s, asserted not-due at delay−1 s and due at delay) + `backoff_applies_to_the_next_attempt_only`; `three_consecutive_failures_stop_auto_scans_with_the_typed_notice` (notice exactly at the 3rd, `poll` → `None` ever after, manual still starts with 2 passes); `the_stop_is_sticky_across_a_later_manual_success`; `streak_semantics_table` (7 outcome sequences: Failed increments, Complete/Partial reset, Cancelled neutral, notice count == 1 iff stopped); `cancelled_cycles_do_not_break_a_failure_streak`; `manual_refresh_during_a_running_cycle_is_already_in_progress` (nothing queued — the next start after the finish is the auto cadence, periodic); `fresh_manual_cycle_consumes_the_initial_slot_and_re_anchors` (post-manual anchor = manual finish + interval); `manual_only_mode_never_auto_starts_but_failure_rules_apply`; `next_auto_in_reports_the_remaining_time`; `cycle_started_is_idempotent_and_tolerated_from_idle`; `adr011_policy_constants_are_pinned` (2/1 passes, 100 pps, 1.5 s window). |
| AC-3 Orchestrator full-cycle test (real `ArpWorkerHandle`, fake transport + fake neighbor source): the event sequence is exactly cycle-started → observations(pre-read) → observations(arp batches) → observations(post-read) → cycle-finished, all carrying the same `ScanId`, ids monotonically increasing across cycles, passes/rate/window as commanded | Met | `full_cycle_event_sequence_through_the_real_arp_worker`: real `ArpWorkerHandle::spawn(scanner_for(&fake))` with the T-104 `FakeTransport` (2 responders + 3 silent on a /29) and a scripted fake `NeighborSource`; asserts Started(id 1, Initial, Active) → NeighborTable pre-read batch → ArpReply batches (2 observations) → NeighborTable post-read batch → Finished(id 1, Complete, `replies_accepted` 2, `requests_sent` 8, `passes_run` 2) with every event tagged `ScanId::new(1)`; cycle 2 → id 2 > 1; passes/rate/window as commanded: `requests_sent` 8 = 5 + 3 re-probed proves the 2-pass command reached the scanner, `passes_run` 2, `elapsed ≥ 200 ms` proves the 200 ms listen window, and consecutive pass-1 send instants keep the 500 pps minimum spacing (checked against the fake's sent log). |
| AC-4 One cycle at a time: a start during a running cycle → typed already-in-progress, and the fake transport proves no second sweep began (send count unchanged) | Met | `a_start_during_a_running_cycle_is_rejected_and_queues_nothing`: mid-cycle `start_cycle` → `Err(AlreadyInProgress)` (counted in `stats.starts_rejected`); after the finish exactly one Started was ever observed, the send count is exactly one cycle's 13 (5 + 4 + 4 re-probes), and the **next** start is accepted (a queued command would be running and the guard would reject it — nothing was queued); the explicit second cycle then adds exactly one 1-pass sweep (18 total). |
| AC-5 Cancel: mid-cycle cancel completes within the bound (test ≤ 1 s, margin justified); the cycle emits cycle-finished(Cancelled); a subsequent cycle runs normally (fresh cancel flag) | Met | `cancel_completes_within_the_bound_and_the_next_cycle_runs`: 3 s listen window, cancel after the pre-read batch → Finished(Cancelled) received **< 1 s** after `cancel_cycle()` (design bound 250 ms; 1 s = 4× headroom for CI scheduling jitter across the two threads and the arp worker's 50 ms cancel slices — the T-203 AC-9 margin pattern); the post-read is skipped (zero neighbor rows after cancel); the next cycle completes `Complete` with `replies_accepted` 1 (fresh per-cycle cancel flag, the T-104 guarantee preserved end to end). |
| AC-6 Backpressure: a full command channel → typed error, never blocks; a saturated event channel → mid-cycle batches drop+count while cycle-finished is still delivered; cancel under saturation still within the bound | Met | `a_full_command_channel_returns_the_typed_error_without_blocking`: the worker held inside a gated neighbor read (StartCycle popped), 12 `cancel_cycle()` calls — the first 8 fill the 8-slot queue (`Ok`), calls 9–12 return the typed `Err(CommandQueueFull)` **immediately** (all 12 < 1 s; never blocks) while the flag set by call 1 still cancels the cycle (Finished(Cancelled) after the gate opens); a start during the cycle is the FR-DS-08 `AlreadyInProgress` (the guard precedes the send — see §5 deviation 4 for the interaction); `command_send_errors_map_to_the_typed_variants` unit-tests the `try_send` error mapping both ways. `saturated_events_drop_and_count_mid_cycle_batches_but_deliver_the_finish`: a 2,200-row pre-read (69 batches of 32 > the 64-slot event channel) with no draining consumer — ≥ 5 batches dropped and counted (verified before draining, from the stats snapshot once the sweep is underway), then the drain receives the finish (Complete — the cycle itself stayed healthy). `cancel_under_event_saturation_still_meets_the_bound`: same fixture, cancel while saturated → Finished(Cancelled) < 1 s (dropping on cancel is what keeps the bound under saturation). |
| AC-7 Read-only: the constructor path creates no arp worker and no socket (a test proves the socket-touching path is absent — e.g. the active-only types are not constructible in that mode); the cycle completes `Complete` with mode read-only; a neighbor-read failure yields `Failed` | Met | `DiscoveryWorker::spawn_read_only(neighbors, scope, iface)` — the signature **offers no way to hand in** an `ArpWorkerHandle`, scanner or transport (type-level absence; the worker's `Mode::ReadOnly` carries no session and its cycle arm cannot reach any arp machinery), proven behaviorally by `read_only_cycles_complete_without_any_socket_machinery`: Started(id 1, Manual, ReadOnly) → one NeighborTable batch (3 rows) → Finished(Complete, `counters == ScanCounters::default()` — no sweep ran, no `ArpReply` source can appear, exactly one neighbor read). `read_only_neighbor_failure_fails_the_cycle`: a failing read → Finished(Failed{reason contains "reading the neighbor table failed: …"}). |
| AC-8 ScanId discipline: a batch arriving after cancel/finish is dropped and counted, never emitted under a later cycle's id (test with a gated fake that delays a batch) | Met | `a_stale_arp_batch_is_dropped_and_counted_never_misattributed`: the gated `GatedArpSession` (a `pub(crate)` test seam — see §5 deviation 2) scripts scan 1 normally, then releases a straggler batch **after** scan 1's `ScanFinished` (an event no correct T-104 worker can produce: it joins its flusher before the summary — which is exactly why the seam exists); the orchestrator's idle drain catches it (`stats.stale_arp_events == 1`, polled deterministically — no blind sleep), it is never emitted under cycle 1's id, and cycle 2 runs clean with all its events tagged id 2 and the straggler never reappears. The drains (idle + cycle-start) plus wait-phase-only attribution are the defense in depth. |
| AC-9 Scheduler property test passes (LCG, high-bit draws): no auto start while running; due-time consistency across arbitrary sequences | Met | `property_scheduler_is_consistent_across_random_sequences`: local LCG twin with **high-bit** draws (`(next_u64() >> 32) % n`, the T-203 fuzz-harness form — the shared `model::testing::Lcg` stays low-bit until T-404); 2 seeds × 20,000 well-formed random steps (poll / manual / started / finished with random outcomes, time advancing 0–90 s per step) against a protocol shadow: no `StartCycle` while running or stopped; every auto start respects the last finish's anchor + ruling (a)/(b) delay (`elapsed ≥ interval` or `≥ max(interval, 30 s)` after a Failed finish); the `AutoScansStopped` notice fires exactly once and only at streak 3; `auto_scans_stopped()` never diverges from the shadow; deterministic opening guarantees non-vacuity (`auto_starts ≥ 1`, asserted). |
| AC-10 Netns regression: the existing suite still 12/12 behind `OSZA_NETNS_TESTS=1` (no scenario edits; paste the summary line) | Met | §4.2, verbatim: `netns suite: 12 scenario(s), 0 failure(s), 38.0s total` — run inside `unshare --user --map-root-user --net`, exit 0, no edits to `tests/netns/**` (the AC-12 diff proves it). |
| AC-11 Transport mapping: a unit test proves the pnet opaque fatal error now maps to the honest interface-lost classification | Met | `pnet_datalinks_opaque_fatal_poll_error_maps_to_interface_lost` (in `arp/transport.rs`): `io::Error::other("Unexpected poll event")` — the exact untyped error pnet_datalink 0.35.0 constructs at its three Linux poll sites (verified in the vendored source, `linux.rs:296/348/399`) — classifies as `InterfaceLost`, is fatal, and displays the honest message; a different `Other` error still falls through to the conservative `FatalIo` (the mapping does not swallow unknowns). The mapping is implemented (not skipped): one match arm with a message guard in `TransportError::from_io`, documented with the ADR-009 consequence / T-105 follow-up 3 provenance. |
| AC-12 §8.2 grep clean; `git diff` touches only the allowed paths: `src/model/**`, `src/registry/observation.rs` (re-export only), `src/discovery/**`, `src/lib.rs` (doc line), `docs/reports/T-204/**` — nothing else | Met | §4.4: `grep -rnE "use crate::(registry|app|ui|net)" src/discovery/` → no matches (exit 1). `git diff --stat be32502..HEAD`: `plan.md` + `docs/adr/{015-dns-ptr-client.md,index.md}` (Commit 0 only), `src/model/mod.rs` (+45: the ScanId definition + module-doc lines), `src/registry/observation.rs` (−definition, +re-export +docs), `src/discovery/{scheduler,worker}.rs` (new), `src/discovery/mod.rs` (module registration, docs, re-exports), `src/discovery/arp/transport.rs` (+40: the one match arm + test), `src/lib.rs` (+16 doc lines), `docs/reports/T-204/execution-01.md` (this file). `Cargo.toml`, `Cargo.lock`, `fuzz/**`, `.github/**`, `tests/**` untouched. |
| AC-13 Execution report per Appendix B, complete | Met | This file; §5 deviations and §6 decisions filled in (the card's §6 says they are expected); §8 carries the one Plan Question this card left genuinely ambiguous. |

## 3. What changed

- **Commit 0 (Manager-ordered, §10):** `f71ce89` — plan.md v1.8.0 → v1.9.0 (header, Status Board T-203 row, the verbatim 1.9.0 changelog row after the 1.8.0 row, bracket-bearing content applied and verified in-band per the T-106-RW1 hardened rule); `2d89cc2` — ADR-015 status → Accepted (file line 3 + index row), byte-exact per §10c.
- **`src/model/mod.rs`** — `ScanId` (u64 newtype: `new`, `as_u64`, `From<u64>`, `Display`) defined in the model root with its §5.1/§8.5 provenance documented (moved from `registry::observation`, T-204); module doc line added. No other model change.
- **`src/registry/observation.rs`** — the definition replaced by `pub use crate::model::ScanId;`; module docs record the move and why (§8.2). Every existing T-201 test passes unmodified (R-1).
- **`src/discovery/scheduler.rs`** (new, 1,199 lines incl. 15 tests) — `RediscoveryInterval` (+ `SchedulerError::IntervalTooShort`, `MIN_REDISCOVERY_INTERVAL` 15 s, `DEFAULT_REDISCOVERY_INTERVAL` 60 s), the ADR-011 pass-policy constants (`PASSES_INITIAL_AND_MANUAL` 2, `PASSES_PERIODIC` 1, plus re-exports of the scanner's `DEFAULT_RATE_PPS`/`DEFAULT_LISTEN_WINDOW` so this module is the one-stop policy surface), `Trigger` (Initial/Manual/Periodic with `passes()`), `SchedulerDecision` (StartCycle/None/AlreadyInProgress/AutoScansStopped), `DiscoveryScheduler` (`new`/`poll`/`manual_refresh`/`cycle_started`/`cycle_finished`/`is_running`/`auto_scans_stopped`/`failure_streak`/`interval`/`next_auto_in`), the failure-backoff floor (30 s) and auto-stop threshold (3) constants, and the AC-2 matrix + AC-9 property suite. Pure: no I/O, threads, or clocks; `Timestamp` is a parameter.
- **`src/discovery/worker.rs`** (new, 2,293 lines incl. 17 tests) — `OrchestratorCommand`/`CycleEvent`/`CycleSummary`/`Degradation`/`CycleMode`/`OrchestratorError`/`OrchestratorStats(+Snapshot)`, the `pub(crate) ArpWorkerSession` seam (`RealArpSession` in production, the gated fake in tests), `DiscoveryWorker` (`spawn_active`/`spawn_read_only`/`start_cycle`/`cancel_cycle`/`stats`/`shutdown`+`Drop`), `WorkerThread` (run loop, `run_cycle`, read-only and active cycle runners, `drive_arp_scan`, forwarding with the bounded retry budget, lifecycle delivery, stale drains), the pacing constants (`CYCLE_COMMAND_CAPACITY` 8, `CYCLE_EVENT_CAPACITY` 64, `WAIT_SLICE` 50 ms, `FORWARD_RETRY_BUDGET` 8 × `SEND_RETRY_WAIT` 10 ms, `FIRST_SCAN_ID` 1), and the AC-3…AC-8 test battery with the fake neighbor source and the gated arp session.
- **`src/discovery/mod.rs`** — registers the two modules, documents them in the tree's module map, re-exports their public names (the scheduler's ADR-011 constants included; `DEFAULT_RATE_PPS`/`DEFAULT_LISTEN_WINDOW` keep their single definitions in `arp::scanner`).
- **`src/discovery/arp/transport.rs`** — the T-105 follow-up 3 mapping (one match arm + guard in `from_io`) + its unit test; nothing else in the file changed.
- **`src/lib.rs`** — a T-204 doc paragraph (house style).

## 4. Verification results

### 4.1 The four local gates on the Commit-0 tree (§10d, run immediately after `2d89cc2`)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 21.29s
[exit 0]

$ cargo test --locked --all-features
running 373 tests
test result: ok. 371 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.11s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 11 tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
[exit 0]
  (the two ignores: discovery::privilege::tests::privileged_drop_fails_closed_verification_catches_residual,
   discovery::privilege::tests::privileged_open_raw_socket_succeeds_and_drop_verifies — the
   pre-existing privileged ones; inventory matches AC-0's expectation exactly)

$ cargo test --locked --all-features --examples
     Running unittests examples/gen_oui.rs:      running 9 tests — ok. 9 passed
     Running unittests examples/poc_discover.rs: running 7 tests — ok. 7 passed
     Running unittests examples/poc_measure.rs:  running 11 tests — ok. 11 passed
[exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
[exit 0]
```

### 4.2 The §9 gates on the final T-204 tree (pinned 1.99.1 unless noted)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (...)
    Finished `dev` profile [unoptimized + debuginfo] target(s)
[exit 0]

$ cargo test --locked --all-features
running 406 tests
test result: ok. 404 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.12s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 11 tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
[exit 0]

$ cargo test --locked --all-features --examples
     Running unittests examples/gen_oui.rs:      running 9 tests — ok. 9 passed
     Running unittests examples/poc_discover.rs: running 7 tests — ok. 7 passed
     Running unittests examples/poc_measure.rs:  running 11 tests — ok. 11 passed
[exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Generated /…/target/doc/osza_netmon/index.html
[exit 0]

$ rustup run 1.89.0 cargo build --locked        # MSRV
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 22.50s
[exit 0]

$ cargo audit          # cargo-audit 0.22.2 (crates.io --locked; CI pins the same version, T-203 PQ-2 provenance)
    Loaded 1409 security advisories
    Scanning Cargo.lock for vulnerabilities (196 crate dependencies)
[exit 0 — no vulnerabilities]

$ cargo deny check     # cargo-deny 0.20.2 (same provenance)
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — plus the pre-existing informational "unmatched license allowance" notes
 on unused allowlist entries (ISC, BSD-3-Clause), present since T-000]

$ unshare --user --map-root-user --net bash -c 'cd <repo> && OSZA_NETMON_TESTS=1 cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture'
… 12 × "scenario ok: …" (S1–S9, incl. S5's five hostile sub-scenarios, S6 egress, S7 privilege model)
netns suite: 12 scenario(s), 0 failure(s), 38.0s total
[exit 0]
```

### 4.3 Fuzz targets (§9 commands, verbatim invocations)

```text
$ cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame --target-dir target
arp_frame fuzz target (T-103, SR-05) — std-only deterministic harness
  outcomes: accepted=27911 rejected=772961 truncated=402460 wrong_ether_type=281095 …
  accepted-by-corruption (non-vacuity): 150
  result: OK — no panic path, no oracle violation
[exit 0]

$ cargo run --manifest-path fuzz/Cargo.toml --bin dns_response --target-dir target
  outcomes: known-name 3299, no-name 5018, malformed 491403, server-failure 1367, truncated 784, timeout/transport 0
  accepted-by-corruption (non-vacuity): 676
  result: OK — no panic path, no oracle violation
[exit 0]

$ cargo run --manifest-path fuzz/Cargo.toml --bin resolv_conf --target-dir target
  parse results: 401141 inputs, 864209 entries, 579386 skipped malformed lines
  selections: 142287 selected, 258855 no-resolver (141749 selected on random inputs)
  accepted-by-corruption (non-vacuity): 488
  result: OK — no panic path, no invariant violation
[exit 0]
```

Both T-203 harness summaries reproduce **byte-exact** the numbers recorded in the plan v1.9.0 changelog row (dns_response and resolv_conf), and arp_frame reproduces its T-103/T-203-era summary shape — determinism intact, no fuzz-code changes (fuzz/ untouched, AC-12).

### 4.4 The §9 greps

```text
$ grep -rnE "use crate::(registry|app|ui|net)" src/discovery/        # expect no matches
[no output — exit 1]

$ grep -rLn "^// SPDX-License-Identifier: GPL-3.0-only$" src/discovery/*.rs src/discovery/arp/*.rs src/model/*.rs   # expect no files listed
[no files listed — independently re-verified per file: every header line 1 matches]
```

## 5. Deviations from the task card

1. **`Box<dyn NeighborSource + Send>` instead of the card's `Box<dyn NeighborSource>`** (worker.rs, 4 use sites). The orchestrator thread owns the neighbor source across a thread boundary, which demands `Send`; T-102's trait carries no `Send` supertrait (T-203's `NameResolver` has one, T-102's does not). The bound is applied at the use site so `neighbor_table.rs` stays untouched; the production `ProcNeighborTable` (a `PathBuf`) and every test fake satisfy it automatically.
2. **A `pub(crate) ArpWorkerSession` trait seam** (worker.rs). The card's AC-8 requires testing a late batch "with a gated fake that delays a batch", which is impossible through the real `ArpWorkerHandle` + receiver pair: the pair's channels are created inside `ArpWorkerHandle::spawn` and a third sender cannot be injected — and a correct T-104 worker *cannot* produce a straggler at all (it joins its flusher thread before sending `ScanFinished`, so the final flush always precedes the summary). The minimal seam (start/cancel/recv_timeout/shutdown) exists precisely so the AC-8 defense can be proven; production wraps the real pair in `RealArpSession` and the public API is unchanged (`spawn_active` still takes the concrete handle and receiver).
3. **`cancel_cycle` sets the flag first and sends the `CancelCycle` command best-effort.** The card lists "cancel cycle" among the commands, but the worker thread is busy inside a cycle precisely when a cancel matters, so — exactly like T-104's handle — the shared flag is the mechanism and the command is the protocol's name for the same intent (a no-op when the idle loop finds it). `cancel_cycle` returns `Result<(), OrchestratorError>` so a saturated command queue surfaces the typed `CommandQueueFull` *after* the flag was set (the cancellation still took effect); this is what makes AC-6's "full command channel → typed error, never blocks" deterministically testable.
4. **`CommandQueueFull` is unreachable for *starts* under the single-commander contract.** The card mandates both "nothing queued" (the FR-DS-08 guard precedes the `try_send`) and the typed queue-full error; together they mean a start can only ever see the queue full if a commander races the worker's command pick-up (plan §8.3/§8.4 fix a single main loop as the commander). The error and its mapping are implemented and unit-tested (`command_send_errors_map_to_the_typed_variants`), the never-blocks property is proven for every handle method under a genuinely full queue (AC-6's cancel-spam test), and the interaction is documented here rather than hidden.
5. **Test-visible sleeps exist in the orchestrator suite** (poll ticks of 1–10 ms inside the bounded `wait_stats`/sent-log helpers, plus the bounded 5 s latch inside the gated fake neighbor read). R-11's "no sleep in unit tests" is honored where it bites — the *scheduler* suite is pure `FakeClock` with zero sleeps and zero threads, and no orchestrator assertion is sleep-based: every wait is a bounded poll with a deadline, and every timing claim is an `elapsed` bound (the T-104 worker-suite precedent for component tests with real threads).
6. **Small additive API beyond the card's minimum:** `DiscoveryScheduler::next_auto_in(&self, now) -> Option<Duration>` (the event loop's `recv_timeout` input, plan §8.4 — T-205 needs it and this is its only home), `OrchestratorStats`/`OrchestratorStatsSnapshot` (the T-203 `HostnameStats` pattern — the card's "drop and count" needs an observable counter, and AC-6/AC-8 assert through it), and `Trigger::passes()` / the `scheduler` re-exports of the scanner's rate/window constants (the card's "one authoritative home" — the values keep their single definitions in `arp::scanner`).

## 6. Decisions and assumptions

1. **`ScanId` lives in `model/mod.rs`** (the card's suggested option): it is a domain root concept next to the re-export hub; a dedicated `scan.rs` module for one newtype would be speculative structure (P5).
2. **The scheduler's decision *is* the transition to running.** `poll`/`manual_refresh` mark the machine running when they return `StartCycle`, which makes ruling (a)'s "overlap is structurally impossible" literally true and FR-DS-08's already-in-progress total. `cycle_started()` is kept as the card's input and given real, benign semantics: idempotent while running, tolerated from idle (the machine then holds running so every ruling stays consistent with what it is told); a finish from that state re-anchors the cadence normally.
3. **Auto-stop is sticky** — a later manual `Complete` resets the streak (ruling (d)) but does not silently resume auto-scans. The card says "auto-scans stop entirely (typed notice; T-205 surfaces the error)"; silent resumption would hide exactly that error. Resumption is the application's visible decision (e.g. re-creating the scheduler on a settings change). Raised as PQ-1 (§8) since the card does not address it.
4. **Backoff scope:** the `max(interval, 30 s)` delay anchors at the *Failed* finish itself and applies to the next auto attempt only; a later non-failed finish re-anchors at the plain interval (`backoff_applies_to_the_next_attempt_only`). `Cancelled` finishes anchor at the plain interval (ruling (b) names only `Failed`).
5. **Cancel semantics:** a cancelled cycle skips the post-sweep neighbor read (the user asked to stop; the already-delivered evidence stays valid and is simply not aged — ADR-007), and at finish time the orchestrator's own cancel/shutdown flag forces `Cancelled` even if the sweep itself had completed (a cycle the user cancelled never ages). A `Failed` sweep is never "downgraded" to `Cancelled` by a late cancel flag — the worse outcome wins.
6. **Degradation precedence:** a neighbor-read failure downgrades `Complete` (and `Partial`) to `Partial` with the typed `Degradation`; a sweep that already `Failed` stays `Failed` (the worse outcome is the honest one — both reasons are still in the summary).
7. **`ScanId` starts at 1** (per-session counter, `FIRST_SCAN_ID`); 0 is thereby never a live cycle id, keeping any future "no cycle yet" sentinel unambiguous.
8. **Neighbor rows are forwarded chunked at the arp worker's `MAX_BATCH_SIZE` (32)** so each event is independently droppable under saturation (FR-DS-10 shape) and event sizes stay uniform with the arp batches.
9. **The FR-DS-08 guard is cleared *before* the finish event is delivered.** The dead-worker test exposed the race in the opposite order: an app reacting to `Finished` by starting the next cycle could observe the just-ended cycle as still running. Clearing first is safe in the other direction too — a start accepted during the finish delivery merely queues for the worker's next pick-up (the thread is single-cycle by construction).
10. **The scheduler and orchestrator use `arp::scanner::ScanOutcome`** (the FR-DS-11 four-way outcome) rather than a new enum — it is already the discovery-layer outcome; T-205 maps it onto the registry's `ScanOutcome` exactly as it maps the observation types (the PQ-3 boundary of T-104).
11. **A manual refresh before any auto cycle consumes the initial slot:** the next auto cycle after its finish is *periodic* (1 pass, ADR-011) and the cadence re-anchors at the manual finish — the literal reading of ruling (e); the session has already had its 2-pass first scan (the manual one).
12. **The transport mapping is implemented, not skipped** (AC-11): the existing classification was honest in *severity* (fatal) but reported pnet's opaque "Unexpected poll event" string; the one-match-arm mapping gives it interface-lost *semantics* with the honest message, exactly as the T-105 follow-up note prescribes. The match keys on the message text because pnet_datalink 0.35.0 constructs the error untyped (no errno, `ErrorKind::Other` — verified at `linux.rs:296/348/399` of the vendored source); the fall-through test proves no other untyped error is swallowed.

## 7. Dependencies

None. `std` + the in-tree `thiserror` only (R-12); no `Cargo.toml`/`Cargo.lock` changes (AC-12 diff proves it); no new crates, no `unsafe`, no `println!`/`eprintln!`.

## 8. Plan Questions

**PQ-1 — Auto-stop resumption after a later success (FR-DS-12, ruling (c)/(e) interaction).** The card fixes when auto-scans stop (three consecutive `Failed` cycles, typed notice) and that manual refresh remains allowed while stopped, and ruling (e) says a manual cycle's outcome counts normally toward the streak — but it does not say whether a *subsequent* successful cycle (necessarily manual, since auto is stopped) resumes auto-scans when its `Complete` resets the streak to 0.
*Implemented answer:* **sticky stop** — `failure_streak` resets per ruling (d) while `auto_scans_stopped` stays true for the session; `poll` never issues an auto start again; only a new session (or an explicit T-205 decision, e.g. re-creating the scheduler on a settings change) resumes. Tested by `the_stop_is_sticky_across_a_later_manual_success`.
*Alternatives considered:* (a) auto-resume on the next streak-resetting `Complete` — rejected: it silently undoes the "stop entirely (T-205 surfaces the error)" state the card chose; (b) resume on any manual *start* — rejected for the same reason, plus it would make the notice's lifetime one keypress.
*Why a PQ:* the card is explicit about every other lifecycle rule; this one materially shapes T-205's error-surface design and deserves a Manager ruling rather than a silent choice.

## 9. Security and privacy notes

- No new network I/O: the orchestrator only *drives* the already-reviewed T-104 worker and reads the already-reviewed `/proc/net/arp` source; read-only mode (FR-DS-14) constructs no socket at all, and its constructor signature makes that unconstructible-by-omission (AC-7).
- External input stays hostile and bounded: neighbor-table reads are the T-102 64 KiB-bounded total parser behind a trait; the orchestrator adds no parsing of its own. All channels are bounded (8 commands / 64 events); every wait is flag-checked at ≤ 50 ms (FR-DS-09); nothing blocks uninterruptibly (the forwarding budget is 8 × 10 ms, then drop-and-count); no `unwrap`/`expect`/`panic`/indexing outside tests (the §11.3 clippy gate); no `unsafe`.
- The transport mapping change tightens honesty, not behavior: the opaque pnet error was already fatal; it now *says* interface-lost so T-401 can word the right message.
- The scheduler is pure and deterministic — no time, randomness or I/O of its own; the property suite's LCG is test-only with fixed seeds.

## 10. Known issues and limitations

- The `CommandQueueFull` path for *starts* is unreachable in the intended single-commander wiring (the FR-DS-08 guard precedes the send — §5 deviation 4); it exists as typed defense and is covered by unit test and by the cancel-spam proof of never-blocking.
- With a *defective* arp worker (one that violated T-104's flush-before-summary ordering), a straggler delivered *during* the next cycle's wait phase would be indistinguishable from that cycle's own batches (the arp events carry no scan id by T-104's design); the orchestrator's drains remove everything attributable-before-scan-start, and the real worker's join ordering makes the residual case impossible. The seam + test document the boundary precisely.
- The scheduler's `cycle_finished` processes whatever it is told, including finishes it did not decide (documented totality); a double-reported finish by a future caller would double-count into the streak. T-205 drives one report per `Finished` event.
- Orchestrator timing assertions use real wall time (bounded polls + `elapsed` bounds with 4× headroom, the T-203/T-104 CI pattern); under extreme CI load they could flake in principle — the same residual risk the T-104 worker suite carries today. The first CI run of the PR demonstrated exactly one such case and it was a **test bug, not a product bug**: `cancel_completes_within_the_bound_and_the_next_cycle_runs` originally asserted "zero observation rows of any kind after cancel", which the load-exposed race between the cancel and the sweep made false (the responder's ArpReply evidence, validly delivered before the cancel propagated, counts as a row). The production behavior is correct per the T-104 delivery policy; the assertion now counts only neighbor-table rows (precisely what "no post-read" means). Fixed in the same orchestrator commit; re-verified 15/15 sequential runs plus 3/3 full-suite parallel runs locally, and the re-run CI is green.

## 11. Suggested follow-ups

1. **T-205 wiring note (informational):** the scheduler's `next_auto_in(now)` is the event loop's `recv_timeout` input (plan §8.4); `DiscoveryWorker::start_cycle` takes the decision's `trigger` + `ScanParams { passes: trigger.passes(), rate_pps: DEFAULT_RATE_PPS, listen_window: DEFAULT_LISTEN_WINDOW }` — the wiring recipe is in both modules' docs.
2. Consider letting the netns suite (or T-403) run one orchestrator-level cycle inside a namespace so the full §8.5 chain (not just the scanner) gets wire-level evidence; the unit suite covers it through the real worker + fake transport only.
3. If a future card revisits arp-event attribution (e.g. carrying a scan tag on `DiscoveryEvent`), the `ArpWorkerSession` seam is also the natural place to assert it; until then it stays the AC-8 test seam only.
