# Execution Report — T-301 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-10 · **Branch/commits:** `task/T-301-terminal-lifecycle`, based on `main` @ `94769ba` — Commit 0: `7e21317` (plan v1.11.0, Manager update); the T-301 work: `a6cd9d5` (terminal lifecycle — ui layer, input thread, signals, loop, assembly, §5.1–5.7), `d5ca381` (pty harness — restore/resize/smoke/idle evidence, §6), this report · **Plan version:** 1.11.0 (repository copy, written by Commit 0)

## 1. Summary (≤ 5 lines)

The terminal is attached to the T-205 headless core: a new `src/ui/` tree (six modules, 1,815 lines incl. 16 tests) owns the §8.8 lifecycle (earlier panic hook → `ratatui::try_init` → explicit mouse capture → RAII restore on every path), one input thread translating crossterm events through the pure §10.3 map, the ADR-018 SIGTERM/SIGHUP bridge quitting through the app's normal quit path, the §8.4 loop (tick-through-the-sender, dirty-flag rendering over the E-1 accessor), and the §5.6 assembly wiring the reviewed workers under the ADR-005 privilege order with the read-only fallback. `signal-hook =0.3.18` lands as the pre-authorized exact pin — zero new crates (the lock diff is one edge). A new `tests/pty` harness drives the real binary over `script(1)` ptys: terminal restored after all five exit paths, the resize toggle, two end-to-end smokes (fake-source and real active discovery inside a veth netns), and NFR-04 idle CPU at 0.183% of one core over 60 s. All §7 gates green; netns 12/12 and the three fuzz harnesses byte-exact; the diff touches only card-allowed paths with the E-1 accessor plus its one-line reach path (D-1) inside `src/app/**`.

## 2. Acceptance criteria

| AC | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-0 Commit 0 exactly per §9 | Met | Pre-flight: `git rev-list --count origin/main..origin/task/T-205-app-core` → 0 (PR #18 fully merged; branch cut from updated `main` @ `94769ba`). Byte-exact edits with each search string asserted to occur exactly once before replacing (scripted, §4.1); in-band verification counts: `\| **Plan version** \| 1.11.0 \|` ×1, `1.10.0` version row ×0, `\| T-205 \| Application core (headless) \| DONE \|` ×1, `G-2 ☑` ×1, the 1.11.0 row directly after the 1.10.0 row. The four local gates on the Commit-0 tree: lib 471 = 469 pass + 2 pre-existing privileged ignores; bin 0; doctests 11; `--examples` gen_oui 9/9, poc_discover 7/7, poc_measure 11/11 — exactly the expected inventory. |
| AC-1 All §7 gates green, MSRV, SPDX, audit/deny | Met | §4 below: fmt, clippy `--locked --all-targets --all-features -- -D warnings`, `cargo test --locked --all-features` (lib 489 = 487 pass + 2 ignored; bin 0; doctests 11; pty 9/9), doc with `RUSTDOCFLAGS="-D warnings"`, `--examples` 9/7/11, MSRV 1.89.0 `cargo build --locked` green, `cargo audit` 0 vulnerabilities (196 crates), `cargo deny check` all ok (crates.io `--locked` provenance per T-203 PQ-2). SPDX header on every new `.rs` (§4.4). |
| AC-2 Terminal restored after normal/error/panic/SIGTERM/SIGHUP | Met | `tests/pty`: `restore_normal_q` (exit 0), `restore_error_exit` (exit 1, the forced-fault seam), `restore_panic` (exit 101, the forced-panic seam), `restore_sigterm`, `restore_sighup` (exit 0 each) — every one asserts raw mode off (the echo probe: one byte must come back with ECHO restored, during the wrapper's trailing pty-lifetime sleep), mouse capture off and the alternate screen left (the last capture sequence in the stream is the disable), plus the exit code. |
| AC-3 The full §10.3 map as pure translation | Met | `ui::input::tests::the_full_10_3_map_translates_exactly` (every key, plus `y`; shifted glyphs), `unknown_keys_and_modifiers_are_ignored_without_error` (unknown letters/specials, Ctrl+J/Alt+Q/shift-arrows, Release kind), `resizes_translate_and_everything_else_is_consumed_or_ignored` (resize → `AppEvent::Resize`; mouse/focus/paste → `None`). Mouse events are consumed as no-ops at the input thread while capture is on (AC-2's capture assertions prove capture is on). |
| AC-4 No busy spin; tick drop tolerance; render only on dirty/tick | Met | `ui::assembly::tests::loop_wait_caps_at_the_tick_deadline_and_max_wait` and `…admits_no_discovery_state_so_it_cannot_spin_pre_confirmation` (the wait function's signature admits no discovery state — the type is the proof; a scripted idle minute shows only tick-shaped blocks); the tick's bounded send and drop tolerance are the loop's documented `try_send` + re-anchor (a dropped tick is retried by the next second; the runtime's synthesized tick is the safety net — `AppEvent::Tick` docs); `ui::render::tests::renders_are_counted_over_a_scripted_event_sequence` drives the **real** `update` over a scripted sequence and counts 8 renders of 10 events (only the changing ones; unknown keys and consumed mouse events render nothing); `ui::input::tests::the_poll_timeout_is_nonzero_and_bounded` pins the 100 ms poll slice. |
| AC-5 End-to-end smoke | Met | `tests/pty::smoke_fake_source` — the T-205 AC-5 fake-source variant under the pty (real workers over the reviewed fakes, real terminal): notice → `y` → scope → `Enter` → a nonzero live device count visible (the count cell's cursor-addressed write) → `q` → exit 0, terminal restored. `tests/pty::smoke_netns_real` — the **real binary, active mode**, inside a veth network namespace (§14.3.7): the same flow with real ARP discovery finding the peer, nonzero count visible, clean exit. Both ran and passed in this environment. |
| AC-6 Idle CPU | Met | `tests/pty::idle_cpu`: 60 s at the notice screen — utime+stime from `/proc/<pid>/stat` = **0.183% of one core** (11 ticks / CLK_TCK 100 / 60.0 s; an earlier run measured 0.167%), 2,457 voluntary wake-ups (40.9/s, all timer-shaped: the input thread's 100 ms poll slice, the reviewed T-203/T-204 workers' own poll slices, the 1 Hz tick; the signal thread contributes zero — it blocks, woken only by `Handle::close`). The CI variant (10 s under `CI=1`) measured 0.100–0.200%. Evidence pasted in §4.3. |
| AC-7 The signals ADR | Met | `docs/adr/018-signal-handling.md` (the next free number — confirmed in `docs/adr/index.md`; 017 was the highest), with the §9.2 criteria copied in and answered, the honest evaluation against the `nix` `signalfd` alternative (and the prohibited std-only `unsafe` path), and the choice matching the pre-authorized change exactly: `signal-hook = "=0.3.18"` (§5.3 option (a)). Index updated. |
| AC-8 E-1 discipline | Met | The search: `rg "dirty" src/app/` on the pre-change tree shows only the `pub(crate)` field, the read-only `dirty()` accessor, the construction-time `true`, and internal writes — **no observe-and-clear API exists** (the full grep in §4.4). Exactly one accessor added to `state.rs` (`take_dirty`, with its test), plus deviation D-1: the one-line `Runtime::take_dirty` delegation without which the accessor is unreachable (the runtime owns the state privately; no `&mut AppState` path exists — §5 below). Nothing else in `src/app/**` changed (the diff is those two hunks). |
| AC-9 Hygiene | Met | §4.4: `rg "ratatui\|crossterm" src/app/` empty; `ui::`-references in `src/app/` empty; the render path (`render.rs`) imports app + model only; no `unsafe` anywhere new (`#![forbid(unsafe_code)]` also added to the harness files); no `println!`/`eprintln!` in `src/ui/` (the assembly reports through `AssemblyError`; only `main.rs` prints, pre-init/post-restore with the T-000 scoped allows). |
| AC-10 No regressions | Met | Full inventory stated (§4.2): lib 489 = 487 pass + 2 pre-existing privileged ignores (471 + 18 new), bin 0, doctests 11, pty target 9/9 scenarios; `--examples` gen_oui 9/9, poc_discover 7/7, poc_measure 11/11; netns 12/12 in 37.9 s with `tests/netns/**` untouched; the three fuzz harnesses reproduce their T-205-reported summaries byte-exact (§4.3). |
| AC-11 Report per Appendix B | Met | This file (§5 deviations, §6 decisions, §8 PQs). |

## 3. What changed

- `src/ui/mod.rs` (new) — module layout + the §8.2 discipline docs (the render path vs. the wiring role).
- `src/ui/lifecycle.rs` (new) — the §8.8 guard: earlier panic hook, `try_init`, explicit mouse capture, idempotent restore, `Drop` safety net.
- `src/ui/input.rs` (new) — the input thread (100 ms poll slices, stop flag, error budget), the pure `map_event`/`map_key` §10.3 translation, the bounded-retry send; 5 tests.
- `src/ui/signals.rs` (new) — the ADR-018 bridge: the signal thread, the Ctrl+C-event delivery under the lifecycle retry policy, `close`-woken bounded shutdown; 3 tests.
- `src/ui/render.rs` (new) — the placeholder frame (screen name, live device count, marker line — generic over the backend, drawn against `TestBackend` in tests) and the pure `should_render` decision; 5 tests.
- `src/ui/assembly.rs` (new) — `run` (§5.6: interfaces → session facts → the privilege-ordered workers → state → runtime → lifecycle), `run_with` (the injection seam), the loop (`loop_wait`, tick-through-the-sender, dirty-consume), `Threads` teardown with `Drop` safety nets, the fault seam; 3 tests.
- `src/app/state.rs` — E-1: `take_dirty` + its test (the only pre-authorized accessor).
- `src/app/runtime.rs` — D-1: the one-line `take_dirty` delegation + its test.
- `src/main.rs` — the interactive default (no arguments runs the assembled TUI); the post-restore error report.
- `src/lib.rs` — `pub mod ui;` + the doc paragraph (registration only).
- `Cargo.toml` / `Cargo.lock` / `fuzz/Cargo.lock` — `signal-hook = "=0.3.18"` (§5.3 option (a)) and the `[[test]]` registration for the pty target; the lock diffs are the single `signal-hook` edge under `osza-netmon` (the fuzz lock mirrors it — the fuzz package depends on the root by path).
- `docs/adr/018-signal-handling.md` + `docs/adr/index.md` — the signals ADR and its row.
- `tests/pty/{main,drive,fakes}.rs` (new) — the harness (§6) + its registration.
- `docs/reports/T-301/execution-01.md` — this file.

## 4. Verification results

### 4.1 The four local gates (pinned 1.99.1 toolchain)

```text
$ cargo fmt --check                                            [exit 0]
$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile …                                    [exit 0]
$ cargo test --locked --all-features
     Running unittests src/lib.rs
test result: ok. 487 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running tests/netns/main.rs        (gated: 0 scenarios without OSZA_NETMON_TESTS)
     Running tests/pty/main.rs
pty scenario restore_normal_q         … ok
pty scenario restore_error_exit       … ok
pty scenario restore_panic            … ok
pty scenario restore_sigterm          … ok
pty scenario restore_sighup           … ok
pty scenario resize_too_small_toggle  … ok
pty scenario smoke_fake_source        … ok
pty scenario smoke_netns_real         … ok
pty scenario idle_cpu                 … ok
    idle 60s: utime+stime 11 ticks (0.183% of one core), 2457 voluntary
              wake-ups (40.9/s) over 60.0s
pty suite: 9 scenario(s), 0 failure(s), 102.5s total
   Doc-tests osza_netmon
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps          [exit 0]
$ cargo test --locked --all-features --examples
  9 passed; 7 passed; 11 passed      (gen_oui, poc_discover, poc_measure)
$ rustup run 1.89.0 cargo build --locked                           [exit 0]
$ cargo audit
  Loaded 1430 security advisories; Scanning Cargo.lock (196 crate
  dependencies); 0 vulnerabilities                       [exit 0]
$ cargo deny check
  advisories ok, bans ok, licenses ok, sources ok      [exit 0]
```

### 4.2 The new test inventory (18 lib tests + 9 pty scenarios)

- `app::state::tests` (1 new): `take_dirty_observes_and_clears_the_flag_once_per_change`.
- `app::runtime::tests` (1 new): `take_dirty_surfaces_and_clears_the_render_due_flag`.
- `ui::input::tests` (5): `the_full_10_3_map_translates_exactly`, `unknown_keys_and_modifiers_are_ignored_without_error`, `resizes_translate_and_everything_else_is_consumed_or_ignored`, `the_poll_timeout_is_nonzero_and_bounded`, `the_input_thread_stops_within_a_bounded_time`.
- `ui::signals::tests` (3): `shutdown_closes_and_joins_without_any_signal`, `a_delivered_quit_is_exactly_the_ctrl_c_event`, `stop_flag_interrupts_a_delivery_retry_loop`.
- `ui::render::tests` (5): `the_placeholder_shows_screen_count_and_marker`, `every_screen_state_names_itself`, `the_too_small_overlay_hides_the_screen_without_resetting_state`, `the_render_decision_renders_only_on_dirty_or_tick`, `renders_are_counted_over_a_scripted_event_sequence`.
- `ui::assembly::tests` (3): `loop_wait_caps_at_the_tick_deadline_and_max_wait`, `loop_wait_admits_no_discovery_state_so_it_cannot_spin_pre_confirmation`, `the_fault_seam_is_inert_for_garbage_and_armed_only_by_the_exact_values`.
- `tests/pty` (9 scenarios): the five restore cases, the resize toggle, the two smokes, the idle measurement (harness=false, custom main — the netns target's precedent).

### 4.3 The task-specific §6 commands

```text
$ unshare --user --map-root-user --net env HOME=$HOME RUSTUP_HOME=$HOME/.rustup \
    CARGO_HOME=$HOME/.cargo PATH="$HOME/.cargo/bin:$PATH" OSZA_NETMON_TESTS=1 \
    cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture
netns suite: 12 scenario(s), 0 failure(s), 37.9s total           [exit 0]

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
```

### 4.4 The hygiene greps (AC-8/AC-9)

```text
$ rg -n "ratatui|crossterm" src/app/                       → no matches [exit 1]
$ rg -n "ui::" src/app/                                    → no matches [exit 1]
$ rg -n "^use crate::" src/ui/render.rs
    use crate::app::AppState;  use crate::app::Screen;     (app + model only)
$ rg -n "unsafe" src/ui/ tests/pty/          → only the three #![forbid] headers
$ rg -n "println!|eprintln!|print!|dbg!" src/ui/           → no matches [exit 1]
$ rg --files-without-match "^// SPDX-License-Identifier: GPL-3.0-only$" src/ tests/
                                                            → no files
$ rg -n "dirty" src/app/     (the E-1 search, on the pre-change tree)
  state.rs:  the pub(crate) field, the construction-time true,
             the read-only dirty() accessor
  runtime.rs: one |= write      update.rs: the state writes
  → no observe-and-clear API exists (take_dirty is the minimal addition)
$ git diff --stat main..HEAD
 Cargo.lock | 1 +   Cargo.toml | 21 +-   fuzz/Cargo.lock | 1 +
 docs/adr/018-signal-handling.md | 131 ++   docs/adr/index.md | 3 +-
 src/app/runtime.rs | 57 ++   src/app/state.rs | 53 ++   src/lib.rs | 15 +
 src/main.rs | 56 +-   src/ui/* | 1865 +++ (six new files)
 tests/pty/* | 1053 +++ (three new files)   docs/reports/T-301/execution-01.md
```

## 5. Deviations from the task card

1. **D-1 — one line in `src/app/runtime.rs`: `Runtime::take_dirty`.** E-1 authorizes exactly one additive accessor on `state.rs` (the dirty observe-and-clear), and §5.4 mandates consuming the flag from the loop. But the state is owned **privately** by the runtime (`state: AppState`, no `&mut` API exists — `state()` returns `&AppState` only), so the authorized accessor is unreachable from `src/ui/**`: the card's two requirements cannot both hold on the frozen surface. The one-line delegation (calling the E-1 accessor, nothing else) is the minimal reach path; it is additive, documented at both sites, and tested (`take_dirty_surfaces_and_clears_the_render_due_flag`). PQ-1 requests ratification (or the Manager's preferred shape for T-302/T-303).
2. **D-2 — the fault seam `OSZA_NETMON_TEST_FAULT` (`panic`/`error`).** AC-2b/c require a *deterministic* error exit and a forced panic *in the real binary, after init* — and no production path can deliver either on demand: the lints deny `panic!`/`unwrap`/`expect` outright (that is the point of this codebase), and no reachable code path fails on command. The seam is one env-var check at one point (after init, before the loop), inert for every other value (unit-tested), with a narrowly scoped `#[allow(clippy::panic)]` mirroring `main.rs`'s print allows. No CLI parsing happens (the card's "you parse nothing" is about flags; an env probe for the pty tests is the netns suite's own `OSZA_NETMON_TESTS` pattern).
3. **D-3 — the `[[test]]` registration of the pty target in `Cargo.toml`.** §10 allows "tests/** (a new pty harness)" but confines `Cargo.toml` to the §5.3 additions. With `autotests = false`, an unregistered `tests/pty/main.rs` is dead code — it would never compile or run; the repository's own `Cargo.toml` comment prescribes exactly this registration for future targets ("future test targets must be added here"). The three-line row is the mechanical companion of the allowed path, not a dependency change.
4. **D-4 — `main.rs`'s bare-invocation dispatch.** With no arguments the assembled TUI must run, but `classify_args` (frozen in `lib.rs`, which this card may touch only for registration) answers `PrintHelp` for both `--help` and the empty command line. `main` distinguishes them with the raw argument count (`std::env::args_os().count() == 1`) — two lines of wiring dispatch, no business logic, no parsing of flags.
5. **D-5 — `fuzz/Cargo.lock` carries the same one-edge diff.** The fuzz package depends on the root by path, so its lock mirrors the root's dependency edge; the change is the authorized `signal-hook` edge and nothing else (the paste in §7). Reverting it would dirty the tree on every fuzz run (the house gate command updates it).

## 6. Decisions and assumptions

1. **The ratatui 0.30.2 rules verified against the pinned source** (§5.1's mandate): `init.rs`'s `set_panic_hook` wraps the hook current at init time and calls it **after** `restore()` — so the earlier hook (ours) must be installed **before** `try_init`, exactly as the module docs say ("Ensure that this method is called *after* your app installs any other panic hooks"); `try_restore` = raw mode off then leave the alternate screen; mouse capture is never touched by init/restore (it is ours). All cited in `lifecycle.rs`'s docs.
2. **The earlier panic hook disables capture, then chains.** It also covers the case no guard can: a panic on a *non-main* thread (no unwind through the loop, no guard `Drop`) still leaves a clean, capture-free terminal — the conservative price is that such a panic breaks the TUI visually (ratatui's own hook is process-global). The reviewed workers are panic-free by lint; accepted and documented.
3. **The map's modifier discipline** (§5.2): plain presses for the §10.3 specials (a shifted arrow is a different key, outside the map); `Shift` accepted only for the letter glyphs whose shifted forms are in the map (`G`, `?`); `Ctrl+C` both spellings; `Release` events ignored; `Repeat` acts like `Press` (holding an arrow keeps moving).
4. **The input thread's error budget**: eight consecutive poll/read failures end the thread (a gone pty never busy-spins on errors; the exit itself is owned by the signal path and the loop). The stop-flag responsiveness is unit-tested.
5. **The tick flows through the sender** (§5.4), bounded: a dropped tick is harmless — the next second retries and the runtime's synthesized tick is the safety net. Steady state is one tick per second (the queued tick resets the runtime's tick anchor, so the synthesis stays dormant); at startup the two may race once, costing at most one extra render.
6. **The render decision is the dirty consume**: a processed tick always marks the state dirty (T-205's tested `update`), so `should_render(dirty, tick)` collapses to the consume in the loop while the pure function documents the FR-UI-07 rule for any future core change; AC-4's counting test drives the real `update`.
7. **The discovery worker binds at startup to the suggested interface** (ADR-005 item 2 — the socket opens "before the TUI starts" bound to *the selected* interface; the scope screen's selection starts on the same suggestion; `drop_capabilities` runs before any worker thread spawns, the T-104/poc order). The frozen T-204/T-205 surface fixes the worker's scope at spawn, so **confirming a different eligible interface would leave the scan scope on the suggested one** — a known limitation of the frozen surface (PQ-3), invisible in the placeholder, owned by T-302/T-303's real scope UX.
8. **No eligible interface → a dormant read-only worker** over the real neighbor table filtered by a name that matches nothing and the reserved 0.0.0.0/0 (nothing is confirmable, discovery never arms, no scan ever starts) — an honest idle handle so the runtime's shape is constant.
9. **An eligible interface without a valid MAC → the read-only fallback** (no honest active session without an identity to announce — ADR-008); the socket is dropped unused, no packet is ever sent.
10. **The placeholder reads the live device count through the crate-visible `registry` field's public `device_count()`** — `AppState` exposes no count accessor and E-1's one-accessor budget went to the dirty flag, so the placeholder (in-crate, read-only, zero app changes) takes the crate-visible path; PQ-2 proposes the clean accessor for the real screens.
11. **`script(1)` is the pty driver** (§6's sanctioned fallback — the pinned `nix` features do not include `term`): the techniques are documented in `drive.rs`: `-qefc` + a pidfile wrapper for the exit code and `/proc/<pid>/task/<pid>/children` for the app's pid; `stty -F /proc/<app>/fd/0` for `TIOCSWINSZ`; the **echo probe** for "raw mode off" (ECHO restored); the capture sequences for "capture off".
12. **Word-level pty sentinels**: ratatui renders by cell diff — unchanged spaces split lines into word runs, so multi-word literals never appear contiguously in the stream; sentinels are single words, and the device count is matched by its cursor-addressed write (`ESC[2;10H` + a nonzero digit).
13. **The idle variant ladder**: 60 s by default, 10 s under `CI=1` (the card's documented CI variant), `OSZA_PTY_IDLE_SECS` override for reproduction; the wake-up count is process-wide (the sum over every task's status — the plain file counts only the main thread).
14. **Signal-initiated quits exit 0**: the card routes them through the app's *normal* quit path, and a clean, restored shutdown is a success, not a 128+n termination (asserted per scenario).
15. **The resize scenario runs on the fake session** (a deterministic confirmable interface on any runner); the real binary's resize path is the same input-thread → `AppEvent::Resize` code, and the netns smoke exercises the real binary end to end.
16. **`assembly.rs` is the §8.1 "main" wiring role hosted under `src/ui`** (the card's own suggested layout): it touches the terminal, the workers' public construction APIs and the process environment by definition, while the *render* path keeps the §8.2 discipline (app + model only — the greps in §4.4 target exactly that split, as `src/app`'s greps target its imports).
17. **The read-only reason strings are provisional** (`"no CAP_NET_RAW: read-only mode (neighbor table only)"`, `"the interface reports no valid hardware address"`) — honest and actionable-shaped; T-401 owns the final §6.8 wording.
18. **`TerminalGuard::Drop` is best-effort and quiet by design**: at teardown time stdout may be the broken thing, so there is no useful §8.7 surface left (the same choice ratatui's own `restore` error path makes); the explicit restore on the normal/error paths still propagates failures.

## 7. Dependencies

One pre-authorized addition (§5.3 option (a)): **`signal-hook = "=0.3.18"`** as a direct exact pin. It is already in `Cargo.lock` as the pinned crossterm's dependency (its SIGWINCH source — verified in the locked source: `crossterm-0.29.0/src/event/source/unix/mio.rs` uses `signal_hook_mio`/`signal_hook`), and crossterm consumes the default feature set (`channel`, `iterator`), so the direct pin adds **zero new crates and compiles no new code**. The entire lock diff:

```text
 $ git diff main..HEAD -- Cargo.lock fuzz/Cargo.lock
  dependencies = [            (package osza-netmon, both files)
   "nix 0.31.3",  "pnet_datalink",  "ratatui",
+  "signal-hook",
   "thiserror 2.0.21", … ]
```

The full §9.2 evaluation (all seven criteria, copied verbatim and answered) is in `docs/adr/018-signal-handling.md`, with the honest comparison against the `nix` `signalfd` alternative (option (b): a feature-flag addition plus ~30 lines of fd plumbing we would own) and the prohibited std-only path (`unsafe`, §14.3.4). No version bumps anywhere; no dev-dependencies added.

## 8. Plan Questions

1. **PQ-1 — the E-1 reach path (deviation D-1).** §5.4 mandates that the ui loop consumes the dirty flag; E-1 authorizes exactly one accessor on `state.rs`; but the runtime owns the state privately and lends no `&mut`, so the accessor is dead code without a path. This card resolves it with the one-line `Runtime::take_dirty` delegation (additive, tested, nothing else in the module changed). **Ruling requested:** ratify the delegation, or prescribe the preferred exposure for T-302/T-303 (e.g. a `Runtime` method pair, or an E-2-style authorization for a broader state-view API when the real screens land).
2. **PQ-2 — the device-count reach (decision 10).** The placeholder needs the live device count (§5.5/AC-5); `AppState` has no count accessor and E-1's budget is spent. The placeholder reads the crate-visible `registry` field's public `device_count()` — zero app changes, in-crate, read-only. **Ruling requested:** ratify the placeholder's reach, or authorize a one-line `pub fn device_count(&self) -> usize` on `AppState` for T-302/T-303 (the placeholder file is replaced wholesale then anyway).
3. **PQ-3 — the worker-scope timing (decision 7).** ADR-005 item 2 binds the raw socket "before the TUI starts" to the selected interface, and the T-204/T-205 surface fixes the discovery worker's scope at spawn (`Runtime::new` consumes the event receiver; there is no late-attachment API), while the scope screen lets the user confirm a different eligible interface — the two can diverge. This card follows the ADR (spawn at startup, at the suggestion) and documents the divergence as a known limitation. **Ruling requested:** confirm the startup-time binding for the placeholder phase, and decide the vehicle for the real fix (a runtime API accepting a worker + receiver post-confirm, or a worker re-spawn path — both need app changes and belong to T-302/T-303's cards, which own the real scope UX).

## 9. Security and privacy notes

No new network egress: the assembly opens exactly the reviewed sockets (the ADR-005 raw socket when privileged, the resolver's UDP socket per the ADR-003 selection) and nothing else; the pty smokes probe only inside a synthetic network namespace (§14.3.7 — `unshare --user --map-root-user --net` with a veth pair; RFC 5737 documentation addresses; no real network is touched). The capability discipline is ADR-005's: the socket opens while privileges are held, everything drops before any other thread spawns, and a failed verification fails closed before the terminal exists. No `unsafe` anywhere (`#![forbid(unsafe_code)]` repeated in the harness files). The fault seam is inert without the exact env value and adds no parsing of untrusted input. The harness reads only its own children's `/proc` entries. No real MACs, hostnames or addresses enter the repository: the fixtures are the T-205 synthetic set (192.0.2.0/29, `02:00:…`, `host-five.lan`).

## 10. Known issues and limitations

- **The scope divergence (PQ-3):** confirming an interface other than the suggested one leaves the scan scope on the suggested interface's network — honest placeholder-phase behavior on the frozen surface; the UI never claims otherwise (the placeholder shows no scope text).
- **The placeholder hides navigation state**: `j/k/g/G/PgUp/…` are translated, delivered and processed (AC-3's unit tests prove the map; the core's T-205 tests prove the semantics), but the placeholder draws only the screen name, the count and the marker — the selection is not visible until T-302/T-303.
- **The idle wake-up floor is the reviewed workers' poll slices** (~41/s total: the input thread's 100 ms slice, the T-203/T-204 threads' own slices, the 1 Hz tick; the signal thread contributes zero). NFR-04 is met with a 5× margin on CPU; T-403 re-measures on the reference machine and owns any tightening of the wake-up budget.
- **The pty harness depends on `script(1)`, `stty -F`, `kill(1)` and `/proc`** (all standard on the CI image and the sandbox); the netns smoke additionally needs `unshare` and `ip` (both verified present; the scenario skips with a note where they are not, and the fake-source smoke is the fallback evidence — the card's own provision).
- **`AppState::dirty()` (read-only) remains alongside `take_dirty`**: the read accessor is used by the app's own tests; removing it would be a second app change beyond E-1.

## 11. Suggested follow-ups

1. **T-302** — the notice/scope/too-small screens: the real scope UX is the natural vehicle for PQ-3's ruling (the ack persistence feeds `SessionParams.notice_acknowledged`; the scope list renders `AppState::interfaces()`).
2. **T-303** — the dashboard: replaces `render.rs` wholesale (PQ-2's accessor, if authorized, lands there), and the real `PAGE_STEP`.
3. **T-305** — the mouse: `InputEvent` gains mouse variants; the input thread's `Event::Mouse(_) => None` arm is the seam.
4. **T-401** — words the provisional reason strings (decision 17) and the §6.8 messages.
5. **T-402** — the CLI: `--no-mouse` rides `AssemblyParams::mouse_enabled`; the flags feed `run`'s construction.
6. **T-403** — re-measures NFR-04 (and the wake-up rate) on the reference machine.
7. If PQ-1/PQ-2/PQ-3 are ruled toward different shapes, each is a small dedicated change (§8).
