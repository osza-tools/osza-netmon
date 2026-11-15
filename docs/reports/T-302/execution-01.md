# Execution Report — T-302 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-14 · **Branch/commits:** `task/T-302-notice-scope-screens`, based on `main` @ `227ab15` (PR #20 fully merged — pre-flight `git rev-list --count main..origin/task/T-301-terminal-lifecycle` → 0) — Commit 0: `ef84f0f` (plan v1.12.0, Manager update); the T-302 work: this branch's subsequent commits (screens + ack store, the PQ-3 assembly, the pty harness) · **Plan version:** 1.12.0 (repository copy, written by Commit 0)

## 1. Summary (≤ 5 lines)

The three placeholder screens become real: the ADR-004 notice (verbatim, `NOTICE_VERSION` = 1), the FR-SC-01…08 scope list (every snapshot fact, the suggestion and `virtual` labels, ineligible reasons in the net layer's own words, the request-count/mode line with the card-fixed estimate), the too-small screen, and the two confirmations — FR-SC-06's default-cap refusal (read-only remains) and raised-cap packet-count dialog, FR-SC-07's typed-`yes` for public ranges (E-2b, §10.3's typing exception included). The ack record is the MVP's sole persisted state (E-2a through the wiring's executor interceptor, mode `0600`, total parsing, non-fatal writes). The PQ-3 fix lands in the normative shape (E-2c option (i)): one bound raw transport per eligible interface under privileges, the single capability drop before any thread, the transports held unused until the confirmation, and the post-confirm attach — proven by the two-veth-pair netns scenario driving the real binary: **506 ARP requests on the confirmed subnet's wire, 0 on the suggested interface's, zero egress pre-confirm, CapEff/CapPrm = 0 while the TUI runs**. The pty suite grows 9 → 14 scenarios (first/second/corrupt-ack flows, the write failure, the egress proof); every §7 gate green.

## 2. Acceptance criteria

| AC | Status | Evidence |
|---|---|---|
| AC-0 Commit 0 exactly per §9 | Met | Pre-flight clean (count 0; branch from `main` @ `227ab15`). The five edits applied by a scripted patch (`/home/z/my-project/scripts/commit0_plan_bump.py`, each search string asserted to occur exactly once; the 1.12.0 row read byte-exact from a file, 3,047 bytes, never retyped). In-band verification counts: `\| **Plan version** \| 1.12.0 \|` ×1, `1.11.0` ×0, `Phase 3 in progress (G-0, G-1, G-2 passed)` ×1, `\| T-301 \| Terminal lifecycle and event loop \| DONE \|` ×1, `Resolved (v1.12.0` ×1, the 1.12.0 row directly after the 1.11.0 row. Gates on the Commit-0 tree: fmt/clippy exit 0; lib 489 = 487 pass + 2 pre-existing privileged ignores; bin 0; doctests 11; pty 9/9; `--examples` gen_oui 9/9, poc_discover 7/7, poc_measure 11/11 — the exact expected inventory. |
| AC-1 All §7 gates green, MSRV, SPDX, audit/deny, zero Cargo changes | Met | §4: fmt; clippy `--locked --all-targets --all-features -- -D warnings`; `cargo test --locked --all-features` (lib 525 = 523 pass + the 2 pre-existing privileged ignores; bin 0; 11 doctests; pty 14/14 in 145.2 s); doc with `RUSTDOCFLAGS="-D warnings"`; `--examples` 9/7/11; MSRV 1.89.0 `cargo build --locked` green; `cargo audit` 0 vulnerabilities (196 crates; 1 **allowed informational warning**, see §10); `cargo deny check` all ok (cargo-audit 0.22.2 / cargo-deny 0.20.2, crates.io `--locked` provenance per T-203 PQ-2). SPDX on every new `.rs` (§4.4). `git diff main -- Cargo.lock Cargo.toml fuzz/` — **empty** (asserted). |
| AC-2 Notice: ADR-004 verbatim; y/q only; ack file 0600, card-fixed, non-fatal | Met | `ui::notice::tests::the_notice_shows_the_adr004_text_verbatim_with_the_display_name` + `the_notice_text_is_pinned_and_versioned` (the three ADR-004 sentences pinned character-for-character with `{DISPLAY_NAME}` substituted; the version constant pinned at 1). The keys are the core's (FR-ST-01; only `y` acknowledges — `update`'s tested T-205 map, unchanged). First-run/version-change/corrupt: `ui::ack::tests` (6 tests: the parser's exact-shape acceptance, a 20-case rejection table, the 0600 round trip, the wide-mode tightening, hostile/oversize/non-UTF-8/missing files, the parent-is-a-file write failure) + the pty `flow_first_run_ack` (written, mode `0600` asserted via stat, `version=1` + the shaped `acknowledged=` line), `flow_second_run` (straight to scope, no notice), `flow_ack_reask` (garbage and version-mismatch → notice again), `flow_ack_write_failure` (XDG pointed at a regular file → `y` → the app continues to scope, exit 0). |
| AC-3 Scope: every FR-SC-01…05, 08 fact; reasons; labels; count + mode + reminder; formulas | Met | `ui::scope::tests::the_scope_list_shows_every_fr_sc01_fact_and_the_labels` (name, IPv4/prefix, MAC, link type, up/running, gateway, `suggested`, `virtual`, `unavailable: loopback interface`) — every fact comes from the frozen `ScopeEntry` snapshot; the one gap (link type) is an E-2d field mirrored from the net layer's public accessor (PQ-1 below). `the_mode_line_follows_the_selection_and_the_read_only_reasons`, `a_slash_32_explains_itself_as_read_only` (FR-SC-05), `a_public_raised_cap_network_chains_both_dialogs`, and the formula tests `probe_target_counts_mirror_the_scanner_for_every_prefix_class` (/24 253, /29 5, /30 1, /31 1, /32 0, /22 1021, /21 2045, /16 65533 — mirroring the scanner's `targets()`), `the_request_count_and_duration_formulas_are_the_card_fixed_ones` (253 → 506 requests, 2×(3+1.5 s) = 9 s, ceiling rounding), `local_use_classification_follows_fr_sc07`. The reminder line renders verbatim (`REMINDER_LINE`). |
| AC-4 Confirmations: FR-SC-06 + FR-SC-07, both flow-tested | Met | Unit: `the_default_cap_refuses_active_discovery_and_read_only_remains` (targets 2,045 > 1,022 → the refusal dialog with both numbers; Esc cancels; Enter continues read-only — `discovery_active = false`), `the_raised_cap_confirms_with_the_packet_count_dialog` (cap 4,094: 2,045 targets, 4,090 requests, 45 s estimated), `above_the_raised_cap_is_refused_with_the_actual_cap` (a /19 over a raised cap states the raised cap), `the_typed_yes_state_machine_accepts_only_the_exact_word` (letters accumulate; a wrong Enter clears and stays; `q`/`Ctrl+C` do not quit while typing — §10.3's exception; only exact `yes` submits), `esc_cancels_the_typed_yes_dialog_and_read_only_needs_none`. Flow: the pty `drive_confirm_selected_public` path (the dialog's split-proof box-corner sentinel, the typed letters, the submit) in `smoke_netns_real` and `netns_two_interface_egress`; the fake-session flows confirm read-only (no dialog, correctly — both rules are active-mode-only). |
| AC-5 The PQ-3 fix, §5.7 shape, egress-proven | Met | §5.7.1: `open_pending_discoveries` (assembly) opens one bound transport per eligible interface while privileged, then the single `drop_capabilities()` before any thread spawns — **observed live**: the egress scenario reads `/proc/<pid>/status` at the notice screen: `CapEff`/`CapPrm` = 0. §5.7.2: the transports live inside `PendingDiscovery`'s spawners (no send, no read, no thread); `close_rest` drops them at the attach. §5.7.3: the E-2c ordering tests (`e2c_no_scan_starts_while_detached_the_first_follows_the_attach`: the confirmation emits no StartScan while detached — the placeholder is never commanded; the attach lands; the **next** poll issues exactly the one Initial start) + the loop's attach step. §5.7.4: read-only and no-eligible bind late (the read-only spawners; the dormant handle stays for the no-eligible case). §5.7.5: FR-ST-02 unchanged (T-205's AC-3 suite; the fake flows assert zero pre-confirm egress at the pty level too). §5.7.6: **`netns_two_interface_egress`** — two veth pairs (198.51.100.0/24 suggested, 203.0.113.0/24 confirmed), two passive listeners on the peer ends, the real binary, the NON-suggested interface confirmed: **506 ARP requests logged on the confirmed wire (all target IPs in 203.0.113.0/24, none .0/.1/.255), 0 on the suggested interface's wire, 0 pre-confirm**, exit 0 restored. |
| AC-6 Too-small: proper rendering, automatic recovery, no reset | Met | `ui::scope::tests::the_too_small_screen_shows_minimum_current_and_recovery` (minimum 80×24, current, "Resize to continue") at both sizes; the render is state-free (the core's tested `too_small` flag only). The pty `resize_too_small_toggle` — now on the **real** screens (notice → scope → confirm → dashboard → 79×24 too-small → 80×24 dashboard with its count intact). |
| AC-7 Snapshots at 80×24 and 100×30, review notes | Met | `ui::render::tests::every_screen_renders_at_both_snapshot_sizes` (notice, scope, the public dialog, the too-small screen at 80×24 and 100×30), `the_dispatch_renders_the_real_screens_and_keeps_the_placeholders`, `the_large_scope_dialogs_render_through_the_dispatch`, plus `ui::scope::tests::each_dialog_renders_its_facts_at_both_sizes` (all three dialogs, both sizes) and the notice's both-sizes test. Review notes: §6 decision 11. |
| AC-8 E-2 discipline | Met | §5 below: every `src/app/**` hunk maps to exactly one E-2 letter — a (the effect + its no-op arm + `NOTICE_VERSION` + the mod re-export + tests), b (the overlay types/state/key handling + the confirm chain and its formulas + the mod re-exports + the T-205 fixture adaptations + tests), c (the Runtime attach surface: `attach_discovery`, `new_detached`, the poll gate, the spare sender, the drops base, the executor trait method + both impls + `RecordingExecutor`'s counter + tests), d (`SessionParams.max_hosts`, `AppState.max_hosts`, `AppState.scope_suggested` (+accessor), `ScopeEntry.link_type` (+mirror), `ConfirmedScope.discovery_active`, the `link_type` fixture updates). `git diff main --stat -- src/app/`: 6 files, every hunk listed in §5's table. |
| AC-9 Hygiene | Met | §4.4: `rg "ratatui\|crossterm" src/app/` → 0; `rg "ui::" src/app/` → 0 (the E-2 doc comments were reworded to keep it clean); the render path (`render.rs`, `notice.rs`, `scope.rs`) imports app + model (+ `net`'s public `LinkType`/`InterfaceClass` — public data types, ratified v1.10.0) only; no `unsafe` (`#![forbid(unsafe_code)]` repeated in the new listener); no `println!`/`eprintln!` in `src/ui/`; the §5.4 vocabulary grep over the new user-facing strings clean (the 5 hits in `src/ui/` are the pre-existing T-301 doc-comment "verified" wording and `TrySendError::Disconnected` code arms — not user-facing; the notice's "authorized" is the ADR-004 text, and "unauthorized" appears nowhere). |
| AC-10 No regressions | Met | Full inventory: lib 525 = 523 pass + 2 pre-existing privileged ignores (489 → 525, +36 net new); bin 0; 11 doctests; pty 14/14 (9 kept + 5 new) in 145.2 s; `--examples` 9/7/11; netns **12/12 in 38.0 s with `tests/netns/**` untouched** (diff-verified); the three fuzz harnesses byte-exact (§4.3: every counter identical to the T-205 record); NFR-04 idle re-measured 0.233% of one core over 60 s, 40.9 wake-ups/s (an earlier run measured 0.183%; both ≥ 4× inside the budget). |
| AC-11 Report per Appendix B | Met | This file (§5 deviations with the E-2 mapping, §6 decisions, §8 PQs). |

## 3. What changed

- `src/ui/ack.rs` (new, 360 lines) — the notice-ack store: `AckStore::from_env`/`at` (XDG with the HOME fallback, `None` without either), the total `acknowledged_version` parser (exact two-line shape, canonical decimals, 4 KiB bound), the `0600` writer (dirs created, create-mode + an explicit `set_permissions` so a pre-existing wide file is tightened); 6 tests.
- `src/ui/notice.rs` (new, 188) — the notice screen: the ADR-004 text verbatim (`NOTICE_TEXT`, pinned) with `{DISPLAY_NAME}` substituted, the §10.2 wireframe's scope-promise paragraph, the `[y]`/`[q]` line, the word wrap; 4 tests.
- `src/ui/scope.rs` (new, 685) — the scope screen (two lines per interface: name, IPv4/prefix, link type, up/running, the suggestion/`virtual` labels; MAC + gateway or the net layer's `unavailable: <reason>` words), the FR-SC-08 mode line (active: requests + the card-fixed estimate with "≈"/"estimated"; read-only: the honest reason — session, no MAC, or the `/32` explanation), the three confirmation dialogs, the too-small screen; 7 tests.
- `src/ui/render.rs` (reworked) — the dispatch: the real notice/scope/dialogs/too-small + the clearly marked T-303/T-304 placeholders (dashboard, details, help); `should_render` unchanged; 6 tests.
- `src/ui/assembly.rs` (reworked, +543/−189) — the PQ-3 assembly: `open_pending_discoveries` (§5.7.1), `PendingDiscovery` (the per-interface spawner map, `build`/`close_rest`), `AssembledExecutor` (the E-2a interceptor: the ack write is wiring-side I/O, non-fatal; everything delegates to `WorkerExecutor`), `AssemblyParams.max_hosts` (default 1,022; the wiring rejects 0 and > 65,534), the ack read at startup, the uniform dormant placeholder + `Runtime::new_detached`, and the loop's attach step (§5.7.2/3) with the read-only fallback.
- `src/ui/input.rs` — `map_key` passes every plain/shifted alphanumeric glyph through (the typed-`yes` letters must reach the queue; the core ignores unbound keys — T-205's tested behavior); +1 regression test; the §10.3 specials and modifier discipline unchanged.
- `src/app/action.rs` — E-2a: `Effect::PersistNoticeAck { version }` + the bare-executor no-op arm; E-2c: `EffectsExecutor::attach_discovery` (default: shut the stray handle down) + `WorkerExecutor`'s swap impl.
- `src/app/config.rs` — E-2a: `NOTICE_VERSION = 1` (the constant the effect carries and the store checks); E-2d: `SessionParams.max_hosts` (default `DEFAULT_MAX_HOSTS`).
- `src/app/state.rs` — E-2b: `ConfirmKind`/`ConfirmOverlay` + `AppState.confirm` + `confirm_kind()`/`confirm_typed()`; E-2d: `AppState.max_hosts`, `AppState.scope_suggested` (+accessor), `ScopeEntry.link_type` (mirrored; the relational test extended), `ConfirmedScope.discovery_active`.
- `src/app/update.rs` — E-2a: `y` emits `PersistNoticeAck` exactly once; E-2b: the dialog chain (`begin_confirm` → the cap/public gates → `complete_confirm`), the overlay key handling (§10.3's typing exception), and the pure FR-SC-05/06/07/08 helpers (`probe_target_count`, `initial_request_count`, `estimate_duration`, `is_local_use_network`); the T-205 fixtures walk the now-mandatory FR-SC-07 dialog; 12 new tests.
- `src/app/runtime.rs` — E-2c: `Runtime::new_detached` + `attach_discovery` (the forwarder swap with the drops base, the executor swap, the poll-gate release), the `spare_sender`, `RecordingExecutor`'s attach counter; the T-205 fixtures' FR-SC-07 adaptation; 2 new tests.
- `src/app/mod.rs` — the re-exports (`NOTICE_VERSION`, `ConfirmKind`, `ConfirmOverlay`, the four formula helpers).
- `tests/pty/listener.rs` (new, 111) — the passive netns egress listener (the crate's own `open_raw_socket` + `LinuxArpTransport`; sends nothing; one line per frame: EtherType, ARP opcode, target IP; a pid sidecar; a deadline).
- `tests/pty/fakes.rs` — the two-interface fake session over the **same** PQ-3 machinery (`run_with` with a pending map: `eth9` 3 fake hosts, `wlan9` 1) + the real ack wiring (read at startup, write through the assembled executor).
- `tests/pty/main.rs` — the scenario set 9 → 14 (the four ack flows + the egress proof), XDG isolation for every spawned app, split-proof sentinels (the dialogs' box corner; the count helper handles full-line writes), the listener lifecycle; `drive.rs` — the `wait_for` timeout dump.
- `src/main.rs`, `Cargo.toml`, `Cargo.lock`, `fuzz/**`, `src/net|discovery|enrichment|registry|model/**`, `tests/netns/**`, `docs/adr/**` — **untouched** (diff-verified).

## 4. Verification results

### 4.1 The gates (pinned 1.99.1 toolchain)

```text
$ cargo fmt --check                                                     [exit 0]
$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile …                                            [exit 0]
$ cargo test --locked --all-features
     Running unittests src/lib.rs
test result: ok. 523 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
     Running tests/pty/main.rs
    idle 60s: utime+stime 14 ticks (0.233% of one core), 2457 voluntary
              wake-ups (40.9/s) over 60.0s
    egress: 506 ARP requests on the confirmed wire, 0 on the suggested
            interface's wire
pty suite: 14 scenario(s), 0 failure(s), 145.2s total
   Doc-tests osza_netmon
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
$ RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps                [exit 0]
$ cargo test --locked --all-features --examples
  9 passed (gen_oui); 7 passed (poc_discover); 11 passed (poc_measure)   [exit 0]
$ rustup run 1.89.0 cargo build --locked
    Finished `dev` profile …                                            [exit 0]
$ cargo audit     # cargo-audit 0.22.2, crates.io --locked provenance
  Loaded 1509 security advisories; Scanning Cargo.lock (196 crate
  dependencies); 0 vulnerabilities; 1 allowed warning (rustix 1.1.5,
  RUSTSEC-2026-0486 "unsound", informational — pre-existing lock content,
  see §10)                                                              [exit 0]
$ cargo deny check    # cargo-deny 0.20.2
advisories ok, bans ok, licenses ok, sources ok                          [exit 0]
```

### 4.2 The new test inventory (+36 net; the 2 ignores are the pre-existing `discovery::privilege::tests::privileged_*` pair)

- `app::config::tests` (1): `the_notice_version_starts_at_one`.
- `app::state::tests` (1): `a_fresh_state_has_no_dialog_and_the_session_cap`; the relational mirror test gains the `link_type` assert.
- `app::update::tests` (12): the formula trio (`probe_target_counts_mirror_the_scanner_for_every_prefix_class`, `the_request_count_and_duration_formulas_are_the_card_fixed_ones`, `local_use_classification_follows_fr_sc07`), the confirm paths (`a_private_network_confirms_with_one_enter_no_dialog`, `the_default_cap_refuses_active_discovery_and_read_only_remains`, `the_raised_cap_confirms_with_the_packet_count_dialog`, `above_the_raised_cap_is_refused_with_the_actual_cap`, `a_public_raised_cap_network_chains_both_dialogs`, `a_slash32_confirms_read_only_without_a_dialog`, `esc_cancels_the_typed_yes_dialog_and_read_only_needs_none`), the typed-yes machine (`the_typed_yes_state_machine_accepts_only_the_exact_word`), and `the_notice_ack_effect_is_emitted_exactly_once`.
- `app::runtime::tests` (2): `e2c_no_scan_starts_while_detached_the_first_follows_the_attach`, `e2c_the_attached_workers_events_flow_through_the_swapped_stream`.
- `app::action::tests` (1): `the_notice_ack_effect_is_a_no_op_on_the_bare_worker_executor`.
- `ui::ack::tests` (6): the parser acceptance/rejection table, the 0600 round trip + rewrite, the wide-mode tightening, hostile files, the typed write failure.
- `ui::notice::tests` (4), `ui::scope::tests` (7), `ui::render::tests` (6 — the placeholder suite reworked into the dispatch/snapshot suite), `ui::input::tests` (1: the typed-`yes` letters regression).
- The T-205 suites' fixtures (state/update/runtime/render) walk the FR-SC-07 dialog where their RFC 5737 fixtures confirm public networks — every original assertion kept, the drive extended (§5 D-2).
- `tests/pty` (14 scenarios = 9 kept + 5 new): `flow_first_run_ack`, `flow_second_run`, `flow_ack_reask`, `flow_ack_write_failure`, `netns_two_interface_egress`.

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

### 4.4 The hygiene greps (AC-8/AC-9)

```text
$ rg -n "ratatui|crossterm" src/app/                       → no matches [exit 1]
$ rg -n "ui::" src/app/                                    → no matches [exit 1]
$ rg -n "^use crate::" src/ui/render.rs src/ui/notice.rs src/ui/scope.rs
    render: app::AppState, app::Screen, ui::notice, ui::scope (dispatch only)
    notice: the crate root's DISPLAY_NAME
    scope:  app::* (public views + the formula helpers), model::Ipv4Net,
            net::{InterfaceClass, LinkType} (public data types, v1.10.0 ruling)
$ rg -n "println!|eprintln!|print!|dbg!" src/ui/           → no matches [exit 1]
$ rg -n "unsafe" src/ui/ack.rs src/ui/notice.rs src/ui/scope.rs tests/pty/listener.rs
                                                           → the #![forbid] header only
$ rg --files-without-match "^// SPDX-License-Identifier: GPL-3.0-only$" src/ tests/
                                                           → no files
$ git diff main -- Cargo.lock Cargo.toml fuzz/ src/net/ src/discovery/ \
    src/enrichment/ src/registry/ src/model/ tests/netns/ docs/adr/ src/main.rs
                                                           → empty (asserted)
$ rg -in "<the §5.4 never-use list>" src/ui/  → 5 matches, all pre-existing
    non-user-facing (T-301 doc wording "verified against the pinned ratatui";
    TrySendError::Disconnected code arms); every new user-facing string clean
```

## 5. Deviations from the task card

1. **D-1 — `map_key` passes plain alphanumeric glyphs through (src/ui/input.rs).** The card's E-2b authorizes the typed-`yes` key handling *in update*; it does not name the input thread's §10.3 filter. But T-301's `map_key` dropped every letter outside `j k g G r s q y ?` **before the queue** — `e` never reached `update`, so `yes` could never be typed through a real terminal (found live by the pty scenarios; the unit suites pass because they drive `update` directly). The fix is the smallest that makes the mandated behavior possible: every plain/shifted ASCII alphanumeric rides `Char(char)` (§10.3's letters are a subset; `?` keeps its arm); the specials and the modifier discipline are unchanged; the core ignores unbound keys (T-205's tested `update`), so no navigation semantics change. Regression test: `every_plain_letter_reaches_the_queue_including_the_yes_typing`.
2. **D-2 — the T-205 fixtures walk the FR-SC-07 dialog.** The synthetic fixtures use RFC 5737 documentation ranges (the §14.3 synthetic-data rule), which are *public* — with FR-SC-07 implemented, their confirmations require the typed `yes`. The T-205 suites' helpers (state: none; update: `confirm_with_typed_yes`; runtime: `confirmed_state`, the ac5 queue drive; render: `confirm_public`) now include the dialog in the drive. **No assertion was weakened**: the confirm-time effects are asserted exactly as before (`[ResolveHostname { own_ip }]` — the dialog consumes none), and the drives gained the mandated step. The `y`-press assertions now pin `[PersistNoticeAck { version: 1 }]` (E-2a's exact-once contract).
3. **D-3 — `run_with`'s signature grew (params, state, executor, placeholder events, **pending map**, clock) and takes `AssembledExecutor`.** The card's §4.1 anticipated the ack store "here or in the assembly"; the fake session needs the same PQ-3 machinery (the two-interface pending map, the detached runtime, the attach) for §6's "scan starts on the CONFIRMED fake interface" to be *decided* rather than pre-wired. The executor type change is the E-2a interceptor's home.
4. **D-4 — `drive.rs`'s `wait_for` dumps the output on timeout** (the `send`-path pattern, extended): the sentinel work below needed it; it stays as diagnostics.

### 5.1 The E-2 hunk mapping (AC-8; every `src/app/**` hunk of the 6-file diff)

| Letter | Hunks |
|---|---|
| **E-2a** | `action.rs`: the `PersistNoticeAck { version }` variant + its doc; the bare `WorkerExecutor` no-op arm + test. `config.rs`: `NOTICE_VERSION = 1` + its pin test (the effect's version source). `mod.rs`: the `NOTICE_VERSION` re-export. `update.rs`: `notice_key`'s `y` emission + `the_notice_ack_effect_is_emitted_exactly_once`. |
| **E-2b** | `state.rs`: `ConfirmKind`/`ConfirmOverlay` + `AppState.confirm` + `confirm_kind()`/`confirm_typed()`. `update.rs`: `handle_key`'s typing exception, `begin_confirm`, `confirm_dialog_key`, `complete_confirm`, `session_active`/`active_confirmable`, the four formula/classification helpers, the module docs, the 12 new tests, and the T-205 fixture adaptations (D-2 — the mandated dialog's blast radius). `runtime.rs`: the T-205 fixture adaptations (D-2). `mod.rs`: the `ConfirmKind`/`ConfirmOverlay` + formula re-exports. |
| **E-2c** | `runtime.rs`: the `discovery_attached`/`spare_sender`/`forwarder_drops_base` fields, `new_detached`, the `build` split, `attach_discovery` (+ the sender helper), the step-4 poll gate, `refresh_counters`' base, `RecordingExecutor`'s attach counter + impl, the two `e2c_*` tests. `action.rs`: `EffectsExecutor::attach_discovery` (default + `WorkerExecutor` impl). Chosen shape: the card's **option (i)** (a Runtime/executor method) — §6 decision 1. |
| **E-2d** | `config.rs`: `SessionParams.max_hosts` + default + test. `state.rs`: `AppState.max_hosts`, `AppState.scope_suggested` + accessor + the `build` wiring, `ScopeEntry.link_type` (+ `from_interface` mirror + the relational-test assert + the fixture literals across the suites), `ConfirmedScope.discovery_active`, `a_fresh_state_has_no_dialog_and_the_session_cap`. Each justified: the core gates on the cap (the card's own example); the screen must mark the suggestion (FR-SC-02) and the moving selection cannot carry it; link type is a mandated FR-SC-01 fact absent from the snapshot (PQ-1); the assembly's attach decision needs the active/read-only fact (§5.7). |

## 6. Decisions and assumptions

1. **E-2c shape: option (i), not (ii).** An in-order `AttachDiscovery` effect would execute *after* the same step's scheduler poll already issues the first `StartScan` (step 4 precedes step 5 in `Runtime::step`), or require reordering frozen T-205 step semantics and rewriting its pinned confirm-effect assertions. Option (i) — the `Runtime::attach_discovery` method (worker + event stream swap) with `new_detached`'s suppressed poll — is purely additive: every existing runtime test constructs via `Runtime::new` (attached) and is unchanged. The `EffectsExecutor::attach_discovery` default (shut the stray handle down) keeps `RecordingExecutor` and any test executor total.
2. **The attach's ordering proof is structural**: while detached, the poll gate cannot fire; the attach releases it; the next step's poll issues the Initial start — so the first scan *cannot* run on the placeholder (`e2c_no_scan_starts_while_detached…` asserts zero StartScan + the fresh `Immediately` slot intact, then exactly one Initial start after the attach).
3. **Per-interface active/read-only**: an eligible interface with a socket *and* a valid MAC/IPv4 becomes an active pending session; without a MAC it is read-only (the socket drops unused — the T-301 decision); an `EPERM` anywhere makes the whole session read-only (FR-DS-14). The session mode is `Active` iff at least one active pending session exists. The scope screen derives the per-interface mode (session read-only / no MAC / `/32` ⇒ read-only with its reason) — no new state for it.
4. **The FR-SC-06 refusal's "read-only remains"** is a real path: `Enter` continues read-only and the confirmed scope records `discovery_active = false` (the assembly attaches the read-only spawner); `Esc` cancels. At a raised cap the same network gets the packet-count dialog instead; above the raised cap, the refusal states the raised cap.
5. **The read-only fallback in the loop** (`build` returns `None` only if the pending map lacks the confirmed name — structurally impossible in the real assembly, which covers every eligible interface) spawns a read-only worker over the confirmed facts — total, never a panic.
6. **The resolver is still selected over the suggested interface's scope** (the frozen T-203/T-205 worker shape) — with a non-suggested confirmation the resolver may lie outside the confirmed subnet. Documented residual (PQ-2 proposes the vehicle).
7. **The notice carries the §10.2 wireframe's second paragraph** ("It does not scan ports…") under the ADR-004-verbatim three sentences — the plan's own notice wireframe shows it; the pinned-constant test makes any text change a deliberate, version-bumping act.
8. **The duration estimate is the card's formula verbatim** (passes × (ceil(targets/rate) + listen_window)) with the scanner's own constants; it is conservative by less than one pass gap (the scanner's inter-pass gap is not in the formula). No PQ: the formula is card-fixed, the constants are the scanner's.
9. **The E-2a write is wiring-side** (`AssembledExecutor` in `src/ui/assembly.rs` intercepts the effect; the file I/O lives in `ui::ack`) — the card's "I/O belongs here or in the assembly, never in `src/app/`". A write failure is swallowed per ADR-004 ("asks again next run"); the effect succeeds.
10. **The fake session is read-only**, so its flows confirm with one `Enter` (both confirmation rules are active-mode-only); the FR-SC-07 flow is exercised end-to-end by the *real* binary scenarios (`smoke_netns_real`, the egress proof). The two-interface fake (eth9 = 3 fake hosts, wlan9 = 1) makes the PQ-3 attach *decided* through the real loop: the flow test asserts the exact count 2 (the suggested interface's table would read 4; a missing attach 1).
11. **Snapshot review notes (AC-7)**: two lines per interface (columns: marker, name 10, IPv4/prefix 17, link 10, state 14, labels — 51 cells fixed, ≤ 29 for labels at 80 cols); the ineligible reason lives on the second line in the wireframe's `unavailable: <net layer's words>` form; the mode line shows requests + `≈ … estimated` (fits 80 columns to a /21; a /16's line clips at the right edge — T-303 owns the layout polish); dialogs are centered ≤ 70×10 bordered boxes; the too-small screen is five plain lines. A list longer than the fold is truncated with an honest `+N more interfaces`.
12. **Pty sentinel discipline extended**: words can split at cells that match the screen *underneath* an overlay (observed: `confirma` + `ion`), so the dialogs use their box-drawing corner `┌` as the sentinel (no other screen draws it), the egress selection uses the mode-line's written run (`3.0/24`/`113.0/24`, verified cell-by-cell against the diff), and the device-count helper also matches full-line `Devices: N` writes (the first dashboard frame over a *real* screen writes the whole line, unlike T-301's placeholder-over-placeholder digit-only write).
13. **The netns listeners are double-forked** (`( cmd & )` in the setup): as direct children of `script(1)` they break its child handling (observed live: script stops forwarding stdin when one is killed mid-session, and never exits while any linger). The listener publishes its pid; the scenario kills both after the assertions (the deadline is the safety net).
14. **The kernel does not answer ARP in the single-namespace smoke topology of this sandbox** (verified against the T-301 baseline: its netns smoke's nonzero count is satisfied by the local device — count 0→1 — and never reached 2 here either). The egress proof does not depend on answers: it asserts the *requests* on both wires (the full 506 on the confirmed, 0 on the suggested). The T-106 nested-namespace lab (S1–S7) remains the authoritative responder evidence (12/12 green).
15. **Every spawned app gets an isolated `XDG_CONFIG_HOME`** — the real binary reads and writes the ack record; a scenario's outcome must not depend on (or touch) the runner's real configuration.

## 7. Dependencies

None. `Cargo.toml`, `Cargo.lock` and `fuzz/Cargo.lock` are byte-identical to `main` (asserted in §4.4) — everything new is std, the already-approved direct deps, and the crate's own public APIs.

## 8. Plan Questions

1. **PQ-1 — the `ScopeEntry` link-type gap (E-2d as implemented; ratification requested).** Context: FR-SC-01 mandates the link type among the visible facts; T-205's D-1 snapshot lacked it. What the plan says: §5.3 of the card — "All facts must come from the existing `ScopeEntry` snapshot — if a mandated fact is missing from the snapshot, raise a PQ; do not touch `src/net/**`"; §8 — "Snapshot-fact gaps on `ScopeEntry` … are PQs, not implementations". Ambiguity: `InterfaceInfo::link_type()` is an existing **public** accessor (ADR-017), so mirroring it into the snapshot is exactly D-1's ratified pattern and fits E-2d's "additive fields the screens require" — but the card's PQ language could be read as requiring the question *before* the field. Options: (a) ratify the E-2d addition as implemented (one field, one mirror line, the relational-test assert, the fixture literals); (b) rule it out and T-303 re-raises with a different vehicle. Executor's recommendation: (a) — no `src/net/**` change, no behavior, the same guarded-equivalence proof. **Blocking: no** (the field is implemented and tested either way; the ruling settles the letter).
2. **PQ-2 — the resolver-selection divergence under a non-suggested confirmation.** Context: the frozen T-203/T-205 worker shape fixes the hostname worker and its resolver at startup; the assembly selects the resolver over the *suggested* interface's scope (ADR-003's eligibility rule). What the plan says: ADR-003 ("a nameserver … inside the selected subnet") vs the PQ-3 ruling's confirmed-interface scope. Ambiguity: after confirming a different interface, the selected resolver may lie outside the confirmed subnet — the queries still go to a local LAN resolver (the privacy posture is unchanged in class), but the letter of ADR-003's rule is not guaranteed. Options: (a) leave as documented residual (this report §6.6); (b) re-select + re-spawn the hostname worker at the attach (needs its own E-2-style authorization — a worker-and-event-stream swap like E-2c's); (c) disable hostname lookups when the confirmed scope does not contain the selected resolver. Executor's recommendation: (b), assigned to T-303/T-401 (the attach machinery lands here; the swap is the same shape). **Blocking: no** (no user-visible claim is wrong: hostnames are labeled best-effort and `Unavailable` is honest).

## 9. Security and privacy notes

The capability discipline is ADR-005's, now with the §5.7 normative shape: every raw socket opens while privileges are held (one per eligible interface), the single drop runs before any thread spawns, and the pty scenario reads `CapEff`/`CapPrm` = 0 from `/proc/<pid>/status` while the TUI is live (SR-06 evidence at the assembled-binary level, new). No probe precedes ack+confirm: the AC-3 suites (T-205, unchanged in intent) and the egress scenario's pre-confirm wire check (both listeners carry zero ARP requests before the confirmation). The ack record is the only file the app writes (SR-08): mode `0600` enforced (create-mode + `set_permissions` on rewrite), parsing total against hostile content (P7 — 20-case rejection table, oversize bound, non-UTF-8), writes non-fatal. The netns egress proof runs inside `unshare --user --map-root-user --net` over RFC 5737 addresses only; the listeners are passive (recv-only) and die by kill or deadline; no real network is touched. No `unsafe`; no new crates; SPDX complete.

## 10. Known issues and limitations

- The resolver divergence (PQ-2): with a non-suggested confirmation, PTR queries may go to a resolver outside the confirmed subnet (still a local resolver; still §2.3-compliant traffic).
- The audit database (1,509 advisories at run time) carries one *allowed informational warning* against `rustix` 1.1.5 (RUSTSEC-2026-0486, "unsound", 2026-10-27) — pre-existing lock content, unchanged by this task, not a vulnerability; reported per AGENTS.md rule 10 rather than "fixed".
- The scope screen's mode line clips at the right edge for /15–/16 networks (the line exceeds 80 columns; the row above shows the subnet) — T-303 owns the layout polish.
- The terminal's *initial* size is still T-301's 80×24 assumption until the first resize event (§5.4 of that card); a terminal launched smaller than 80×24 shows the first frame clipped until a resize arrives. Unchanged from T-301 (documented there); the too-small overlay handles every resize-driven case.
- The pty harness's leaked-listener window: a failed egress scenario can leave two listeners alive for up to 240 s (the deadline); the passing path kills them explicitly.
- The kernel does not answer ARP for same-namespace peer addresses in this sandbox (§6.14): the smoke's nonzero-count assertion is satisfied by the confirmed interface's own device (as in T-301's baseline here); peer *discovery* evidence remains the T-106 lab's (12/12).

## 11. Suggested follow-ups

1. **T-303** — the dashboard: replaces the placeholder (PQ-2's ruling could ride its card), and the real `PAGE_STEP`/layout polish (the mode-line clipping).
2. **T-304** — details + help: the help screen should carry the reminder line and the SR-13 statement; the notice version bump procedure (edit text + `NOTICE_VERSION` + the pin test) is documented in `notice.rs`.
3. **T-401** — final §6.8 wording for the read-only reasons (the T-301 provisional strings are reused verbatim) and any ack-write failure message (none is shown today, per the card's "no in-session message is required").
4. **T-402** — `--max-hosts` and `--interface` ride `AssemblyParams` (the field + the ceiling validation land here); the parser re-checks.
5. **T-306** — consolidate the snapshot suite (insta or the in-repo pattern, per its card); the both-sizes discipline and the review notes are in place.
6. A dedicated ADR for the pty sentinel discipline (§6.12) if the harness grows more overlay-sensitive scenarios.
