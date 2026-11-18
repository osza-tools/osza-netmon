# Execution Report — T-302-FU1 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-18 · **Branch/commits:** `task/T-302-FU1-resolver-rescope`, based on `main` @ `52da775` (PR #21 fully merged — pre-flight `git rev-list --count main..origin/task/T-302-notice-scope-screens` → 0) — Commit 0: `34ed519` (plan v1.13.0, Manager update); the T-302-FU1 work: this branch's subsequent commits (the pure decision, the gate + swap surface, the wiring, the pty evidence) · **Plan version:** 1.13.0 (repository copy, written by Commit 0)

## 1. Summary (≤ 5 lines)

The PQ-2 divergence closes in the ruled shape: at the attach, the wiring re-runs the resolver selection over the **confirmed** scope through a pure decision (`Keep`/`Swap`/`Drop`), and the hostname worker is swapped unless the startup resolver lies inside the confirmed subnet. Two runtime mechanisms carry it: the **deferred-hostname-effects gate** (while detached, `ResolveHostname` effects are held — the confirm-time own-address lookup can no longer execute against the startup worker) and the **hostname swap surface** (`Runtime::attach_hostname` + `EffectsExecutor::attach_hostname`, the E-2c option-(i) mirror). Post-attach, `AppState.resolver_selected` tells the truth. The pty suite grows 14 → 15 scenarios (`flow_resolver_scope_swap`: a non-suggested confirmation **Drops** — the retired resolver serves zero queries; a suggested confirmation **Keeps** — the own-address lookup is served first by the kept resolver); every §11.3 gate green, the two-interface egress proof unchanged (506/0/0, CapEff/CapPrm = 0), netns 12/12, the three fuzz harnesses byte-exact.

## 2. Acceptance criteria

| AC | Status | Evidence |
|---|---|---|
| AC-0 Commit 0 exactly per §0 | Met | Pre-flight clean: `git rev-list --count main..origin/task/T-302-notice-scope-screens` → **0**; the branch created from `main` @ `52da775` (the PR #21 merge, verified by `git rev-parse HEAD` on the fresh branch). The eight edits applied by a scripted patch (`/home/z/my-project/scripts/commit0_patch.py`): each of the seven search strings asserted to occur **exactly once** before replacing, and every insertion extracted **byte-exact from the card file's fenced blocks** (never retyped — the script parses `TASK-T-302-FU1-resolver-reselection.md` and splices its four code blocks). In-band verification counts, all asserted by the script and re-checked with `rg -cF`: `\| **Plan version** \| 1.13.0 \|` ×1 (and `1.12.0` ×0 — no match), the §12.1 dependency row ×1, the G-3 graph row ×1, the G-3 criteria tail ×1, the §13 catalog header ×1, both §21 status rows ×1, the 1.13.0 changelog row ×1 and directly after the 1.12.0 row (adjacency asserted). Gates on the Commit-0 tree (code untouched): fmt exit 0; clippy exit 0; `cargo test --locked --all-features` — lib **525 = 523 pass + 2 pre-existing privileged ignores**, bin 0, 11 doctests, pty **14/14 in 145.2 s**; doc with `RUSTDOCFLAGS="-D warnings"` exit 0 — exactly the accepted T-302 inventory, so the patch touched nothing it should not have. |
| AC-1 All §11.3 gates green on the final tree | Met | §4.1: fmt exit 0; clippy `--locked --all-targets --all-features -- -D warnings` exit 0; `cargo test --locked --all-features` — lib **528 = 523 pass + 5 new tests + the 2 pre-existing privileged ignores** (530 total), bin 0, 11 doctests, pty **15/15 in 155.9 s** (14 existing unchanged + 1 new); doc with `RUSTDOCFLAGS="-D warnings"` exit 0; `--examples` gen_oui 9/9, poc_discover 7/7, poc_measure 11/11; MSRV 1.89.0 `cargo build --locked` green; `cargo audit` 0 vulnerabilities (1 **allowed informational warning**, pre-existing — see §10); `cargo deny check` all ok. `git diff main -- Cargo.lock Cargo.toml fuzz/ src/net/ src/discovery/ src/enrichment/ src/registry/ src/model/ tests/netns/ docs/adr/ src/main.rs` — **empty** (asserted, §4.4). |
| AC-2 The pure decision table, every row | Met | `app::update::tests::fu1_the_resolver_scope_decision_table_is_exactly_the_cards_semantics` — all six rows: `(Some(a), None)` → **Keep**; `(Some(a), Some(Selected))` → **Swap** (port 53 via `resolver_socket()`); `(None, Some(Selected))` → **Swap** (the startup-`None` + reselect-`Some` row); `(Some(a), Some(NoResolver))` → **Drop**; `(None, Some(NoResolver))` → **Keep** (stay `None`, a no-op, not an error); the degenerate `(None, None)` → **Keep** (unreachable from the wiring, total anyway). `fu1_the_keep_row_provably_re_reads_nothing` pins the shape proof: the re-selection is an *input* and the function has no I/O at all, so the in-scope Keep row (the wiring's pure `Ipv4Net::contains` check passes, no re-selection value computed) cannot have called `select_from_system` — the AC's "provable by the pure function's shape". |
| AC-3 Runtime-level swap tests (fakes, the E-2c pattern) | Met | `app::runtime::tests::fu1_a_non_suggested_confirmation_swaps_and_the_own_lookup_follows_the_swap` — a two-interface state (eth9 suggested, wlan9 confirmed through the real queue with the FR-SC-07 dialog), the wiring's recipe applied verbatim (containment check → re-selection → pure decision → `Swap`), the replacement spawned by the fake spawner over a second recording resolver: hostname events flow through the swapped stream (the own device's field becomes `Known("swapped.lan", ReverseDns)`). `fu1_a_suggested_confirmation_swaps_nothing` — the Keep arm calls `attach_hostname(None, …)`: the discovery attach counter reads 1, the **hostname swap counter reads 0** (`RecordingExecutor::hostname_attach_count`, the new no-op proof), and the deferred own-address lookup is released over the kept worker. `fu1_the_drop_case_installs_a_none_resolver_worker_and_no_datagram_is_ever_sent` — the Drop arm installs a `None`-resolver replacement (the fake spawner's drop shape). |
| AC-4 The ordering proof (R-3) | Met | The swap test's recording resolvers: the **retired** resolver serves **zero** queries after the confirming keypress (indeed zero ever — asserted before and after the swap), and the **swapped** resolver serves exactly `[198.51.100.129]` (the confirm-time own-address lookup) — the lookup provably executes against the post-swap resolver; the at-most-one invariant is asserted pre-attach (`runtime.deferred_hostname == [ResolveHostname { own_ip }]`, the private-field view from the child test module). The Drop test: **zero queries ever** (no datagram on either resolver's behalf — the replacement has no resolver) and the own device's hostname field honestly `Field::Unavailable(Reason::NoResolver)` (ADR-003 item 3, no silent retry loop). The wiring-level reproduction: the pty `flow_resolver_scope_swap` (AC-5). |
| AC-5 Wiring-level: the fake-session flow drives the real loop's attach | Met | `tests/pty/main.rs::flow_resolver_scope_swap` (the 15th scenario): the fake session's **injected** decision inputs (`OSZA_PTY_RESOLVER_SEAM`, R-5's pure-data seam) drive the real `run_loop` attach — phase `drop`: startup resolver `192.0.2.6` (inside the suggested eth9's /29) + injected re-selection `NoResolver`, the non-suggested wlan9 confirmed (exact count 2 backstops the PQ-3 attach) → the served-query evidence shows **zero** queries on the retired resolver (pre-fix, the confirm-time own-address lookup `198.51.100.129` leaked onto it — the first run of this scenario caught exactly that class of defect live, §6 decision 6); phase `keep`: the same adversarial injection confirmed **inside** eth9's scope (exact count 4) → the evidence's **first** served query is `192.0.2.1` (the confirm-time own-address lookup, released at the attach and served by the kept resolver before the scan's observation lookups). |
| AC-6 Regressions: the 14 pty scenarios, netns, fuzz — unchanged and green | Met | The existing 14 scenario functions are byte-unchanged (the diff adds only the 15th entry, its helpers, and the doc lines); pty **15/15 in 155.9 s**, including `netns_two_interface_egress` with its exact counts reproduced live — **506 ARP requests on the confirmed wire, 0 on the suggested interface's, 0 pre-confirm, CapEff/CapPrm = 0 while the TUI runs** — and NFR-04 idle 0.200% of one core, 40.9 wake-ups/s. netns **12/12 in 38.0 s** under `unshare --user --map-root-user --net` with `tests/netns/**` untouched. The three fuzz harnesses **byte-exact** against the T-302 record (§4.3: every counter identical — the empty `fuzz/` diff asserted). |
| AC-7 Hygiene | Met | §4.4: `rg "ratatui\|crossterm" src/app/` → 0 matches; `rg "ui::" src/app/` → 0 matches; no `println!`/`eprintln!`/`dbg!` in `src/ui/` (grep exit 1); SPDX headers on every touched `.rs` (no new `.rs` files — all touched files carry the crate's existing header). `git diff main --stat` touches only `plan.md` (Commit 0), `src/app/{action,mod,runtime,state,update}.rs` (F-mapped hunks only — §5.1; `config.rs` needed no change), `src/ui/assembly.rs`, `tests/pty/{fakes,main}.rs`, and this report. |
| AC-8 Report per Appendix B | Met | This file — §3 one line per file, §5 the F-letter hunk mapping (§5.1) and the deviation list, §8 the PQ list, §9 the R-3 proof and the in-subnet/egress argument. |

## 3. What changed

- `plan.md` (Commit 0, +11/−4) — the eight v1.13.0 edits: version bump, the §12.1 dependency row + G-3 row, the §12.2 G-3 criteria tail, the §13 T-302-FU1 catalog entry, the §21 status rows (T-302 → DONE ACCEPT + FOLLOW-UPS; T-302-FU1 ISSUED), the §22 1.13.0 changelog row (byte-exact from the card).
- `src/app/update.rs` (+167) — **F-1**: `ResolverScopeDecision` (`Keep`/`Swap(SocketAddr)`/`Drop`) and the pure `resolver_scope_decision(startup, reselection)` beside the other pure helpers (module docs included), + the two AC-2 table tests. Production `update` itself is untouched (the gate lives in the runtime; the confirm still emits exactly the one own-address effect).
- `src/app/runtime.rs` (+566) — **F-2**: the `deferred_hostname`/`hostname_attached` fields (the deferred-hostname-effects gate; `Runtime::new` open-by-default and unchanged), the gate arm in `execute_effect`, `Runtime::attach_hostname` (install-or-keep, the F-3 truth re-record, the gate release), `RecordingExecutor`'s `hostname_attaches` counter + `hostname_attach_count()` + the trait impl; the three FU1 tests with the `RecordingResolver` fake (the fake spawner), the `wlan9_entry` two-interface fixture, and the `confirm_wlan9` queue drive.
- `src/app/action.rs` (+39) — **F-2**: `EffectsExecutor::attach_hostname` (the total default arm — the stray handle is shut down, never leaked — mirroring `attach_discovery`'s) + `WorkerExecutor`'s swap impl (retire via the worker's own stop flag — the T-203 bound; install the replacement).
- `src/app/state.rs` (+24) — **F-3**: `AppState.resolver_selected` (`pub(crate)`; set from `SessionParams` at construction, re-recorded by the runtime's hostname attach — `Some` only for a confirmed-scope resolver), + the mirror asserts in the fresh-state test.
- `src/app/mod.rs` (+3/−1) — **F-1**: the `resolver_scope_decision`/`ResolverScopeDecision` re-exports.
- `src/ui/assembly.rs` (+214/−35) — the wiring: step 4's known-residual comment replaced by the provisional-selection contract; `ResolverScope`/`ResolverReselect` (R-5's seam); `run_with`'s signature grows the seam (`clock` + `resolver` — pre-authorized D-3/R-5 pattern); `lifecycle`/`run_loop` thread them; the attach block calls `attach_resolver_scope` (the pure containment check first — no re-read on the in-scope path; `select_from_system` only when the startup resolver lies outside; the pure decision applied) and `spawn_hostname_worker` (the fresh stop flag shared by worker and resolver — the T-203 contract; step 4's honest degradation on a bind failure); `AssembledExecutor`'s `attach_hostname` delegation (§6 decision 6 — the interceptor owns no workers of its own).
- `tests/pty/fakes.rs` (+132) — R-5: the recording `FakeResolver` (every served query recorded), `resolver_seam_from_env` (the `OSZA_PTY_RESOLVER_SEAM` knob: `drop`/`keep` armed phases with the realistic startup address `192.0.2.6` — inside the suggested scope — and the adversarial `NoResolver` injection; unset = the pre-FU1 shape, no evidence written), `write_resolver_evidence` (the served-query record under the isolated config directory, after the session ends), and the `run_with` call grown by the seam.
- `tests/pty/main.rs` (+115) — the 15th scenario `flow_resolver_scope_swap` (both phases, the evidence assertions, the exact-count backstops) + the `resolver_evidence`/`armed_fake_session` helpers + the doc list; the existing 14 scenario functions unchanged.
- `src/main.rs`, `Cargo.toml`, `Cargo.lock`, `fuzz/**`, `src/net|discovery|enrichment|registry|model/**`, `tests/netns/**`, `docs/adr/**`, `src/app/config.rs` — **untouched** (diff-verified, §4.4).

## 4. Verification results

### 4.1 The gates (pinned 1.99.1 toolchain)

```text
$ cargo fmt --check                                                     [exit 0]
$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile …                                            [exit 0]
$ cargo test --locked --all-features
     Running unittests src/lib.rs
test result: ok. 528 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed; 0 measured; 0 filtered out
     Running tests/pty/main.rs
    idle 60s: utime+stime 12 ticks (0.200% of one core), 2457 voluntary
              wake-ups (40.9/s) over 60.0s
    egress: 506 ARP requests on the confirmed wire, 0 on the suggested
            interface's wire
pty suite: 15 scenario(s), 0 failure(s), 155.9s total
   Doc-tests osza_netmon
test result: ok. 11 passed; 0 failed; 0 measured; 0 filtered out
$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps                [exit 0]
$ cargo test --locked --all-features --examples
  9 passed (gen_oui); 7 passed (poc_discover); 11 passed (poc_measure)   [exit 0]
$ rustup run 1.89.0 cargo build --locked
    Finished `dev` profile …                                            [exit 0]
$ cargo audit     # 0 vulnerabilities; 1 allowed warning (rustix 1.1.5,
  RUSTSEC-2026-0486 "unsound", informational — pre-existing lock content,
  see §10)                                                              [exit 0]
$ cargo deny check    # advisories ok, bans ok, licenses ok, sources ok  [exit 0]
```

### 4.2 The new test inventory (+5 lib; the pty suite 14 → 15)

- `app::update::tests` (2): `fu1_the_resolver_scope_decision_table_is_exactly_the_cards_semantics`, `fu1_the_keep_row_provably_re_reads_nothing` (AC-2).
- `app::runtime::tests` (3): `fu1_a_non_suggested_confirmation_swaps_and_the_own_lookup_follows_the_swap` (AC-3 swap + AC-4 ordering + the at-most-one invariant + the F-3 truth), `fu1_a_suggested_confirmation_swaps_nothing` (AC-3's counter no-op proof + the gate release), `fu1_the_drop_case_installs_a_none_resolver_worker_and_no_datagram_is_ever_sent` (AC-4's Drop half).
- `app::state::tests` (extended): `fresh_state_starts_on_the_notice_screen_unacknowledged` gains the `resolver_selected` mirror asserts (F-3).
- `tests/pty` (15 scenarios = 14 kept unchanged + 1 new): `flow_resolver_scope_swap` (AC-5, both phases).

### 4.3 The task-specific commands

```text
$ unshare --user --map-root-user --net env HOME=$HOME RUSTUP_HOME=$HOME/.rustup \
    CARGO_HOME=$HOME/.cargo PATH="$HOME/.cargo/bin:$PATH" OSZA_NETMON_TESTS=1 \
    cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture
netns suite: 12 scenario(s), 0 failure(s), 38.0s total                  [exit 0]

$ cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame --target-dir target
  outcomes: accepted=27911 rejected=772961 truncated=402460 wrong_ether_type=281095
    wrong_hardware_type=8740 wrong_protocol_type=8040 wrong_hardware_length=3286
    wrong_protocol_length=4662 wrong_opcode=7609 mac_mismatch=48683 invalid_mac=9
    out_of_scope=6947 network_address=4 broadcast_address=4 own_address=7 not_solicited=1415
  accepted-by-corruption (non-vacuity): 150
  result: OK — no panic path, no oracle violation                [byte-exact]

$ cargo run --manifest-path fuzz/Cargo.toml --bin dns_response --target-dir target
  outcomes: known-name 3299, no-name 5018, malformed 491403, server-failure 1367,
    truncated 784, timeout/transport 0
  accepted-by-corruption (non-vacuity): 676
  result: OK — no panic path, no oracle violation                [byte-exact]

$ cargo run --manifest-path fuzz/Cargo.toml --bin resolv_conf --target-dir target
  parse results: 401141 inputs, 864209 entries, 579386 skipped malformed lines
  selections: 142287 selected, 258855 no-resolver (141749 selected on random inputs)
  accepted-by-corruption (non-vacuity): 488
  result: OK — no panic path, no invariant violation              [byte-exact]
```

Every counter identical to the T-302 record (`docs/reports/T-302/execution-01.md` §4.3) — the harnesses are untouched (the empty `fuzz/` diff asserted below).

### 4.4 The scope and hygiene assertions

```text
$ git diff main -- Cargo.lock Cargo.toml fuzz/ src/net/ src/discovery/ \
    src/enrichment/ src/registry/ src/model/ tests/netns/ docs/adr/ src/main.rs
                                                                        → empty [0 lines]
$ git diff main --stat
 plan.md | 15 +-   src/app/action.rs | 39+   src/app/mod.rs | 3+-   src/app/runtime.rs | 566+
 src/app/state.rs | 24+   src/app/update.rs | 167+   src/ui/assembly.rs | 214+/35-
 tests/pty/fakes.rs | 132+   tests/pty/main.rs | 115+   (+ this report)
$ rg "ratatui|crossterm" src/app/                                       → no matches [exit 1]
$ rg "ui::" src/app/                                                    → no matches [exit 1]
$ rg "println!|eprintln!|dbg!" src/ui/                                  → no matches [exit 1]
```

## 5. Deviations from the task card

1. **D-1 — the executor trait method takes the spawned worker, not the resolver box.** The card's §3 sketched the swap surface as "spawns/installs the replacement (a fresh stop flag; `Option<Box<dyn NameResolver>>` built by the wiring …)". As implemented, the **wiring** builds the whole replacement (`spawn_hostname_worker` in `src/ui/assembly.rs`: it mints the fresh stop flag, passes the very same `Arc` into `UdpResolver::new`, and spawns the worker — the T-203 construction contract requires the worker and its resolver to share one flag, so the flag cannot be minted by an executor that only receives the resolver) and `EffectsExecutor::attach_hostname(worker: HostnameWorker)` installs it. This is exactly `attach_discovery`'s ratified E-2c shape (the wiring builds the worker; the Runtime/executor swaps it), stays total through the default arm, and keeps every I/O act in the wiring (R-1). Recorded as a deviation because the letter of §3 named the resolver box as the parameter.
2. **D-2 — `Runtime::attach_hostname` also re-records the state truth.** The card's F-3 owns "the post-attach `resolver_selected` truth" but names no vehicle; the runtime owns the state (the wiring holds only `&mut Runtime`), so the method takes `(replacement, effective_resolver)` and writes `state.resolver_selected = effective_resolver` — `Some` only for the decision's Keep/Swap target inside the confirmed scope, `None` for Drop (and for a Swap whose socket could not be bound). The wiring computes both from the pure decision; the runtime stays decision-free.
3. **D-3 — `run_with`'s signature grows again** (`clock` now threaded + `resolver: ResolverScope`), and the fake session grew the `OSZA_PTY_RESOLVER_SEAM` knob, the recording `FakeResolver`, and the post-session evidence file. R-5 pre-authorized the decision-inputs growth ("startup address + an injectable re-selection result — pure data, mirroring the pending map"); the knob and the evidence file are the harness-side halves of that seam (the fake session cannot print — its stdio is the pty — so the served-query record rides the isolated `XDG_CONFIG_HOME` exactly like the ack flows' record assertions; no production code is involved, and the unset knob leaves the default session byte-identical in behavior to the pre-FU1 fake).
4. **D-4 — the pty suite grows to 15 scenarios.** AC-6 requires the existing 14 "unchanged and green" — they are (byte-unchanged functions, all green, the egress counts identical) — and AC-1 requires "the scenario count stated": **15** (14 kept + `flow_resolver_scope_swap`).

### 5.1 The F-letter hunk mapping (AC-8; every `src/app/**` hunk of the 5-file diff)

| Letter | Hunks |
|---|---|
| **F-1** | `update.rs`: the `ResolverSelection` + `SocketAddr` imports; `ResolverScopeDecision` (the `Keep`/`Swap(SocketAddr)`/`Drop` enum with its docs) and `resolver_scope_decision` (the pure decision, its table documented; no I/O anywhere in it) beside `scan_params_for`; the two table tests. `mod.rs`: the `resolver_scope_decision`/`ResolverScopeDecision` re-exports. |
| **F-2** | `runtime.rs`: the `deferred_hostname`/`hostname_attached` fields (+docs), the `build` initialization (attached → open-by-default, unchanged semantics for `Runtime::new`), the gate arm in `execute_effect`, `Runtime::attach_hostname`, `RecordingExecutor`'s `hostname_attaches` counter + accessor + trait arm, and the three `fu1_*` tests with their fixtures (`wlan9_entry`, `RecordingResolver`, `recording_worker`, `confirm_wlan9`). `action.rs`: `EffectsExecutor::attach_hostname` (doc + the total default arm) and `WorkerExecutor`'s impl (retire via the stop flag — the T-203 bound — then install). |
| **F-3** | `state.rs`: the `SocketAddr` import, `AppState.resolver_selected` (`pub(crate)`, documented — `Some` only for a confirmed-scope resolver; T-304 renders it), the `build` mirror from `SessionParams`, and the mirror asserts in `fresh_state_starts_on_the_notice_screen_unacknowledged`. The gate's own fields live in `Runtime` (F-2's "Runtime fields"); the state carries exactly the one truth field. |

Nothing else in `src/app/**` changed; `config.rs` needed no change (`SessionParams.resolver_selected` already existed — T-205's field, now told the truth post-attach).

## 6. Decisions and assumptions

1. **The gate keys on its own flag, not `discovery_attached`.** The wiring attaches the confirmed discovery worker **before** applying the resolver-scope decision (the card's own loop-point wording), and the deferred lookups must not run between the two — so a `hostname_attached` flag (opened only by `attach_hostname`) governs the gate, initialized from the same construction bool (`Runtime::new` → open, `new_detached` → held). `Runtime::new` (attached, all T-205 tests) is open-by-default and unchanged in behavior: its vec stays empty.
2. **The hold is a `Vec`, the invariant is asserted by tests, not by a runtime assert.** Pre-attach, only `complete_confirm`'s own-address effect can exist (the placeholder worker never runs a cycle — the suppressed poll — so no observation lookups; nothing else observes before the first cycle). The swap test asserts the held vec is exactly `[ResolveHostname { own_ip }]` and the Drop test asserts its length is 1; a `debug_assert` would violate the no-panics discipline, so the invariant lives as tested documentation.
3. **Keep is a real `attach_hostname(None, …)` call, not a skipped step** — R-4's uniformity: the decision runs on every confirmation path (active, read-only, the no-eligible fallback), and the gate must open on every path too (the own-address lookup was emitted on every path). The executor sees no swap request (the counter proof); the state truth is re-recorded to the same value.
4. **The degraded Swap is honest.** A `Swap(address)` whose `UdpResolver::new` fails (bind/connect refused) installs a `None`-resolver replacement and records `resolver_selected = None` — step 4's own degradation shape ("honestly no resolver, not a silent Some-that-never-answers"); a `HostnameWorker::spawn` failure (OOM-class) fails closed with `AssemblyError::WorkerSpawn` through the same restore-everything path as step 4 — never a panic, never a silent half-swap.
5. **The real-binary Swap path.** The real assembly's `Swap` arm builds a real `UdpResolver` over the re-selected in-scope resolver (`spawn_hostname_worker` — the same construction step 4 uses, T-203-tested). End-to-end, the sandbox's netns scenarios exercise the `Keep`-on-`None` row (no resolver exists inside a fresh network namespace: startup `None` → re-select `NoResolver` → keep the honest `None`-resolver worker — the egress counts are unchanged); the `Swap` install itself is driven end-to-end by the pty `drop` phase (a real replacement worker install through the real loop) and at the runtime level by the fake-spawner tests. No netns host inside this sandbox carries an in-subnet resolver, so the real-socket `Swap` cannot be reproduced live here — stated honestly rather than simulated.
6. **The pty scenario is discriminating, not vacuous.** Its first run failed exactly as the pre-fix behavior would — the wiring's `AssembledExecutor` (the production interceptor) initially inherited the trait's default `attach_hostname` arm (shut the replacement down, keep the startup worker), and the evidence immediately showed the leaked own-address lookup `[198.51.100.129, 198.51.100.130]` on the retired resolver. The delegation (`AssembledExecutor::attach_hostname` → `WorkerExecutor`) fixed it; the assertion caught a real wiring gap that every unit suite had missed (the runtime tests drive `WorkerExecutor` directly). This is the strongest evidence in the report that AC-5's assertion bites.
7. **The adversarial `keep` injection.** The `keep` phase injects the same `NoResolver` re-selection answer as the `drop` phase: a bug that re-reads on the in-scope path (violating AC-2's no-re-read shape) would Drop and serve nothing, so the phase's first-served-query assertion fails — the Keep phase tests the containment check, not just the happy path.
8. **The evidence order is deterministic.** The deferred own-address lookup is released inside `attach_hostname` — before the next step's scheduler poll can issue the first scan — so it is enqueued to the worker's bounded command channel ahead of any observation lookups (FIFO), and the `keep` phase's "first served query is the own address" holds structurally, not by timing.
9. **The state truth is `pub(crate)` without a public accessor** — the T-205 PQ-2 ruling's pattern (no view surface before its screen exists); T-304's card shapes the public "reverse DNS via `<addr>`" view; the in-crate tests read the field directly.

## 7. Dependencies

None. `Cargo.toml`, `Cargo.lock` and `fuzz/` are byte-identical to `main` (asserted in §4.4) — everything new is std, the already-approved direct deps, and the crate's own public APIs (`enrichment::hostname::ResolverSelection` joins the app layer's already-ratified hostname-public-API surface, exactly as `HostnameConfig` already does in `config.rs`).

## 8. Plan Questions

None. The deferred-effects gate was implementable additively (no reordering of frozen `Runtime::step` semantics — the gate sits in `execute_effect`, downstream of `update`), no enrichment-layer change was required, and every `src/app/**` hunk maps to exactly one F-letter (§5.1). The one letter-level divergence from §3's sketch (the trait method's parameter — D-1) is a shape detail inside the authorized surface, not a scope question.

## 9. Security and privacy notes

**How R-3's zero-out-of-scope-datagram property is proven.** Structurally, in three layers. (1) *The hold*: while the runtime is detached, every `ResolveHostname` effect is held in `deferred_hostname` (the gate arm in `execute_effect`) — the confirming step's own-address lookup cannot reach the startup worker (the runtime tests assert the held vec is exactly that one effect and that the startup resolver has served nothing). (2) *The order*: `attach_hostname` swaps the executor's worker **first** and releases the gate **after**, so the first executed lookup reaches the post-swap executor — `fu1_a_non_suggested_confirmation_swaps…` proves it with recording resolvers (the swapped resolver serves exactly `[own_ip]`; the retired serves zero after the confirming keypress, indeed zero ever), and `fu1_the_drop_case…` proves the Drop half (zero queries ever; the own hostname field honestly `Unavailable (NoResolver)`). (3) *The wiring*: the pty `flow_resolver_scope_swap` reproduces both properties through the real loop with injected inputs — the evidence file (the startup resolver's served-query record) is empty on the non-suggested confirmation and begins with the own-address lookup on the suggested one. From the confirmation moment onward, every executed lookup therefore targets either a resolver inside the confirmed subnet (Keep/Swap) or no resolver at all (Drop) — and no lookup executes before that moment (the pre-confirm wires stay quiet, unchanged from the accepted T-302 evidence: zero egress pre-confirm).

**Why the in-subnet rule implies confirmed-interface egress.** `UdpResolver::new` binds an ephemeral local socket and `connect()`s it to the resolver; the kernel then routes the datagram to that connected destination per the routing table. The confirmed subnet is the confirmed interface's own on-link prefix (it is `derive_scope` of the interface's very address — the same fact the confirmation authorizes), so a resolver address inside that subnet has a directly-connected route through the confirmed interface: its datagrams egress the confirmed interface, inside the confirmation's authorization and inside §2.3's allowance (ADR-003's "selected subnet"). A resolver *outside* the confirmed subnet enjoys no such guarantee — its connected route follows whatever the routing table says (typically the default route, egressing the suggested interface), which is precisely the PQ-2 divergence this task closes.

No new untrusted input is parsed (the re-selection re-uses the T-203/SR-10-bounded reads and the reviewed pure selector); no privileges change (ADR-005's order untouched; the egress scenario's `CapEff`/`CapPrm` = 0 read reproduced); no new file is written by production code (the evidence file is a pty-harness test artifact under the isolated per-scenario `XDG_CONFIG_HOME`); no `unsafe`; no new crates; SPDX complete.

## 10. Known issues and limitations

- **The more-specific-route residual (card-mandated documentation, for `docs/limitations.md`, T-405):** the in-subnet rule is ADR-003's letter and the practical scope discipline, but an operator's more-specific route (or policy routing) could still pull an in-subnet resolver's traffic off the confirmed interface. The rule guarantees the *destination* is inside the authorized subnet; the *egress interface* is the kernel's to decide. Not fixed here (no interface binding exists on the frozen T-203 socket shape); this line is the input T-405 needs.
- The real-socket `Swap` arm is not reproducible end-to-end in this sandbox (no netns host carries an in-subnet resolver — §6 decision 5); its construction is step 4's own (T-203-tested) and its install is driven by the pty `drop` phase and the runtime fake-spawner tests.
- A detached runtime whose wiring never calls `attach_hostname` holds its deferred lookups until drop (they die with the runtime — no lookup, no datagram). The real wiring always pairs the two attaches (R-4); the shape is the safe direction (holding is quieter than leaking) and is documented on the field.
- The audit database carries one *allowed informational warning* against `rustix` 1.1.5 (RUSTSEC-2026-0486, "unsound") — pre-existing lock content, unchanged by this task; reported per AGENTS.md rule 10 rather than "fixed".

## 11. Suggested follow-ups

1. **T-303** — the dashboard replaces the placeholder; nothing in this task added render surface (by design).
2. **T-304** — the details/help screens render `resolver_selected` as "reverse DNS via `<addr>`" (the state truth is in place; the view surface belongs to its card, per the T-205 PQ-2 ruling's pattern).
3. **T-405 / `docs/limitations.md`** — carry §10's more-specific-route line into the limitations catalog verbatim.
4. **Post-MVP** — if hostname-event latency ever matters, revisit the per-worker event-stream shape (the T-205 D-2 deferral, unchanged by this task: the swap makes the drain follow the current worker's receiver automatically).
