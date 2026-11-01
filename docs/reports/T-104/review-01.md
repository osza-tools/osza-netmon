# Review Report — T-104 (review of attempt 01)

**Reviewer:** R-Lance (independent reviewer, plan §14.1 — findings only, no code edits, no merge) · **Date:** 2026-11-01 · **Commit reviewed:** `7c734561c54c23da0a3bb400b33e47ac5d1846a9` (branch `task/T-104-arp-scanner-privileges`, PR #10; base `60de97b` = open PR #9, task T-103) · **Plan version:** 1.3.0 (repository copy)

**Diff reviewed:** `60de97b..7c73456` — 10 files, +4,942/−28: `Cargo.toml`/`Cargo.lock`, `src/discovery/{mod.rs,privilege.rs}`, `src/discovery/arp/{mod.rs,transport.rs,scanner.rs,worker.rs}`, `examples/poc_discover.rs`, `docs/reports/T-104/execution-01.md`.

## Verdict: APPROVE WITH FOLLOW-UPS

All gates re-run green, all re-checkable acceptance criteria independently verified, the live lab evidence reproduces, and the three Plan Questions are well-founded. The follow-ups are docs/dependency-hygiene items (F-1…F-4) plus two PQ ratifications (§9); none requires code rework of the scanner, privilege, transport or worker modules.

## 1. Independent verification

Environment: Debian 13 sandbox, rustc/cargo **1.99.1** (the `rust-toolchain.toml` pin), cargo-audit **0.22.2**, cargo-deny **0.20.2** (installed at the executor's stated CI pins). No host root/`sudo` available; privileged verification ran inside a user+network namespace (`unshare --user --map-root-user --net`), which grants `CAP_NET_RAW` in that namespace — the same adaptation the executor documented (deviation 12) and the task card's own alternative recipe.

| Command (re-run) | Result |
|---|---|
| `cargo fmt --check` | exit 0 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | exit 0 |
| `cargo test --locked --all-features` | exit 0 — **188 passed, 0 failed, 2 ignored** (lib) + 0 (bin) + **9 doctests**; identical to the report |
| `cargo test --locked --all-features --all-targets` | exit 0 — additionally **7 example tests** (`poc_discover`) |
| `unshare --user --map-root-user --net cargo test --locked --all-features -- --ignored` | exit 0 — **2 passed**: `privileged_open_raw_socket_succeeds_and_drop_verifies`, `privileged_drop_fails_closed_verification_catches_residual` |
| `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked` | exit 0 |
| `cargo audit` (0.22.2) | exit 0 — 1,395 advisories loaded, 194 crates scanned, no findings |
| `cargo deny check` (0.20.2) | exit 0 — advisories/bans/licenses/sources ok; only the pre-existing `ISC unmatched license allowance` warning (T-000 baseline, unchanged) |
| `rustup run 1.89.0 cargo build --locked` (MSRV, CI parity) | exit 0 |
| `cargo clippy --locked --lib --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout -D clippy::print_stderr -D clippy::panic` | exit 0 (AC-21 evidence re-confirmed) |
| `cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame` | exit 0 — ~800k inputs (400k random + 400k mutated), `result: OK — no panic path, no oracle violation`; the T-103 target is green **with the new T-104 code compiled in** |

### 1.1 Code hygiene greps (re-run)

- `grep -rnw "unsafe" src/ examples/` → 3 hits, **all in doc comments** describing the *absence* of `unsafe` (`model/text.rs`, `model/mod.rs`, `net/interfaces.rs` — pre-existing). Zero `unsafe` code. `#![forbid(unsafe_code)]` crate-wide + `#![forbid(unsafe_code)]` in the example.
- `grep -rnE "println!|eprintln!|dbg!" src/discovery/ src/net/ src/model/` → exactly **2 hits**, both `eprintln!` skip-notices inside `#[cfg(test)]` code of `privilege.rs` (lines 686, 711), permitted by `clippy.toml` (`allow-print-in-tests`) and by the card's "non-test, non-example" wording (report AC-17).
- SPDX: `find . -name '*.rs' -not -path './target/*'` | xargs grep -L "SPDX-License-Identifier: GPL-3.0-only" → **0 files missing** (whole repository, matching the CI mirror).
- §5.4 forbidden-vocabulary grep over the new files: only `mpsc::TrySendError::Disconnected`/internal `Delivery::Disconnected` — std API identifiers, not user-facing device vocabulary. User-facing strings observed: `complete`, `partial`, `failed: {reason}`, `cancelled`, `arp reply`, `neighbor table` — factual, §5.4-compliant, no verdicts.
- Markers (`TODO|FIXME|XXX|HACK|todo!|unimplemented!`) in the new files: none.

### 1.2 Architecture check (§8.2)

`grep -rhoE "crate::[a-z_]+" src/discovery/` → only `crate::discovery` (internal) and `crate::model`. **No** `crate::registry`/`crate::app`/`crate::ui` — and, stricter than the review brief allowed, **no** `crate::net` and no `crate::clock` either (`clock` does not exist yet; the scanner takes `Instant`/`Duration` parameters). The `FakeTransport` test-support module lives behind `#[cfg(test)]` in `arp/mod.rs`. External imports in `discovery`: `std`, `thiserror`, `pnet_datalink` (only in `privilege.rs` + `arp/transport.rs`), `nix` (only `prctl::set_no_new_privs` in `privilege.rs`), `caps` (only in `privilege.rs`). Compliant with §8.2 as written (`discovery`: `model`, `clock` only) and with the single-registry-owner/bounded-channel rules (worker: `sync_channel(8)` commands, `sync_channel(64)` events, both bounded constants tested).

### 1.3 Privilege verification (SR-06, AC-3/AC-4 of the card)

- The `#[ignore]` privileged test asserts, in a dedicated thread, **after** `open_raw_socket("lo")`: `CapEff == 0`, `CapPrm == 0`, `CapInh == 0`, `CapAmb == 0`, `NoNewPrivs == 1` — read back from `/proc/thread-self/status` via the module's own parser. Passed under the user namespace.
- Independently reproduced live (§1.4): the example prints its own post-drop `ThreadCapsStatus` line; in my runs: `CapInh=0000000000000000 CapPrm=0000000000000000 CapEff=0000000000000000 CapBnd=0000000000000000 CapAmb=0000000000000000 NoNewPrivs=1` (user-namespace root: `CAP_SETPCAP` held, so the bounding set was narrowed too — deviation 7's opportunistic path, exactly as documented).
- Unprivileged read-only run: `CapBnd` keeps the residual mask (`00000000a80425fb`) while `NoNewPrivs=1` — the documented compensating-control behavior (ADR-005's verification deliberately excludes `CapBnd`).

### 1.4 Live PoC (AC-13/AC-19-class) — independent two-namespace lab

Replicated the executor's §4.1 lab myself (veth pair, RFC 5737 `192.0.2.0/24`, kernel responder on `.2`/`.3` + Python helper responder with synthetic MACs `02:00:00:00:00:0X` on `.5`/`.7`; everything inside throwaway namespaces; nothing outside probed). Scripted under `/scripts` of the review workspace, not committed.

Run 1 (responder namespace still configuring during the first ~100 ms of pass 1): `targets=506 sent=506 accepted=4 outcome=complete` — pass 2 legitimately re-probed **all** 253 targets because *nothing had answered at the pass-2 snapshot* (the responders only came up after pass 1's early requests were lost on the not-yet-up peer link). This is the snapshot semantics working as specified, not a defect (see §6 note on pass semantics).

Run 2 (1 s readiness delay before starting the binary) — **exact reproduction of the executor's evidence**:

```text
privileges after drop: CapInh=0000000000000000 CapPrm=0000000000000000 CapEff=0000000000000000 CapBnd=0000000000000000 CapAmb=0000000000000000 NoNewPrivs=1
192.0.2.2 … (arp reply) · 192.0.2.3 … (arp reply, same MAC as .2 — kernel multi-address case)
192.0.2.5 02:00:00:00:00:05 (arp reply) · 192.0.2.7 02:00:00:00:00:07 (arp reply)
summary: outcome=complete
summary: targets=502 sent=502 send_errors=0 (transient=0 fatal=0) accepted=4 rejected=0 duplicates=0 cap_dropped=0 passes=2
elapsed 7.565302174s · exit 0
```

`targets` invariant of D-7 holds: 502 = 253 (pass 1) + 249 (pass 2 non-responders); 253 + 249 = 502 = requests_sent + transient + fatal. Elapsed matches the ADR-011 decomposition (2 × 2.53 s paced sending + 1 s pass gap + 1.5 s listen window).

Run 3 (/29 differential, kernel responder on `.2` + helper on `.5`): `targets=8 sent=8` = 5 (pass 1: `.2…​.6`) + 3 (pass 2: `.3, .4, .6` only — **`.2` and `.5` were skipped**). Proves the pass-2 non-responder filter and the pass gap in the live path with the production transport.

Read-only fallback (unprivileged host user, no capabilities): `no CAP_NET_RAW: starting in read-only mode…`, neighbor-table path only, `mode: read-only (no ARP sweep)`, exit 0; residual `CapBnd` observed as documented. Error paths re-run: missing interface → exit 2; missing argument → exit 2 with usage.

### 1.5 Dependency claims verified against the vendored sources

The §9.2 necessity argument for `pnet_datalink` (PQ-1) was checked in the registry sources, not taken from the report:

- `nix 0.31.3`: `SockProtocol` is `#[non_exhaustive]` with `EthAll` (`ETH_P_ALL`) as the only Ethernet variant — **no `ETH_P_ARP` variant**; `LinkAddr(pub(in super::super) libc::sockaddr_ll)` — the field is crate-private, so **no safe `sockaddr_ll` construction from outside nix**. Claim confirmed.
- `socket2 0.6.3`: `SockAddr` safe constructors cover unix/inet/inet6 only; raw storage constructors (`new`, `try_init`) are `unsafe`. Cannot bind an `AF_PACKET` socket safely. Claim confirmed. (`socket2` is not in this project's `Cargo.lock`.)
- `pnet_datalink 0.35.0/src/linux.rs`: `ChannelType::Layer2 => (SOCK_RAW, ETH_P_ALL)` and binds via `sockaddr_ll` with `sll_ifindex` — the `ETH_P_ALL`-only limitation and the bind mechanics are exactly as the report describes.
- `caps 0.5.6`: sole transitive dependency `libc` (already locked); `Cargo.lock` diff = **6 added packages** (`caps`, `pnet_datalink`, `pnet_base`, `pnet_sys`, `ipnetwork`, `no-std-net`), **0 removed, 0 version-changed**; `serde`/`serde_core` were already locked pre-T-104. `deny.toml` and `plan.md` untouched; `src/net/`, `src/model/`, `src/lib.rs`, `src/main.rs` untouched — all as the report claims.

### 1.6 Environment limitations (declared, per review rule 10)

- No host `sudo`/`ip netns`: privileged paths verified in a user namespace (equivalent for these ACs; the card itself documents this recipe).
- A live prctl/capset **failure** could not be provoked in any sandbox I have either — the fail-closed exit-1 path of the example is evidenced by code reading and unit tests (`verify_dropped_catches_every_residual` + the `#[ignore]` residual test), same limitation the executor declared (report §10). Not countable against the task.
- T-106's scripted netns harness (S1–S9) does not exist yet (future task); the live evidence above is the manual-lab equivalent the card asked for.
- The fuzz target is the std-only deterministic harness T-103 delivered (not libFuzzer); I re-ran its full default campaign, green.

## 2. Acceptance criteria re-check

Numbering follows the review commissioning brief (§4 of the review instructions). Note: the execution report numbers the card's ACs 1–23, a different (finer) list; the mapping is given where useful. The card itself is not in the repository; the plan (§6.3 FR-DS-03…11, §13 T-104 entry, ADR-005/009/011/012) is the authority used.

| AC (brief) | Met? | Reviewer evidence |
|---|---|---|
| AC-1 `ArpTransport` object-safe, `send`/`recv`/`cancel` | **Met, with a note** | Object-safe, `Send + Sync` supertraits, `&self` methods (`transport.rs`); compile-time proof test (`trait_objects_are_object_safe_and_shareable`). **There is no `cancel` method on the trait** — cancellation is scanner-level (`Arc<AtomicBool>` checked in ≤ 50 ms slices) and every transport wait is bounded (`recv(timeout)`, 50 ms send timeout), so a transport-level cancel is unnecessary for FR-DS-09; plan §8.6's illustrative trait has no `cancel` either. If the card literally required a `cancel` method, the executor should have raised it as a deviation; as the plan's own trait sketch omits it, I judge the shape plan-conformant. |
| AC-2 AF_PACKET bound to interface + `ETH_P_ARP` (or `ETH_P_ALL` + filter, per deviation) | **Met (via documented deviation)** | `pnet_datalink` opens `SOCK_RAW`/`ETH_P_ALL` (verified in the library source — no `ETH_P_ARP` option exists there), bound to the interface index; promiscuous **off** (`Config::promiscuous = false`, FR-DS-07). Software EtherType filter in the receive loop (`has_arp_ethertype`, offsets 12..14) drops non-ARP frames before the validator and does not count them as rejected replies; `parse_arp_reply` still enforces FR-DS-06 condition 1. Deviation 5 documented with a clear input note for T-105/ADR-009. |
| AC-3 CapEff/CapPrm = 0 after socket open | **Met** | `drop_capabilities` clears all four sets and **verifies** via `/proc/thread-self/status` (fail closed); `#[ignore]` privileged test asserts all four zero post-open; live reproduction in §1.3/§1.4. Exceeds ADR-005's minimum (CapEff/CapPrm only). |
| AC-4 `no_new_privs` via `prctl` | **Met** | `nix::sys::prctl::set_no_new_privs()` as step 1 of the drop; `NoNewPrivs=1` asserted by tests and observed live in every run. |
| AC-5 `EPERM` → typed error → read-only mode | **Met** | `PrivilegeError::PermissionDenied` from `ErrorKind::PermissionDenied` (EPERM/EACCES); the example maps it to read-only mode with an actionable message; unit test (`open_raw_socket_maps_eperm_to_permission_denied`, self-skipping on privileged runners) + live read-only run. |
| AC-6 pacing at configured rate (default 100 pps, no burst) | **Met** | Deadline math `max(prev, now) + interval` (a late wakeup never bursts — pure-function test); interval from clamped rate (1..=500, 0→1); slice waits cancel-checked. Tests: every gap ≥ 9 ms at 100 pps, span ≥ 108 ms for 13 sends. Live: 502 requests in 7.565 s incl. gap/window, matching the pacing model. |
| AC-7 pass 2 sends only to non-responders | **Met** | Pass-start snapshot of the responder set; skip before pacing; pre-gap all-responded skip. Unit test parses pass-2 frames from the send log; live /29 differential: 5 + 3 sends, responders skipped (§1.4 run 3). |
| AC-8 replies validated via `parse_arp_reply` (T-103) | **Met** | Every received frame (after the EtherType pre-filter) goes through `parse_arp_reply` with `ArpReplyContext` (own MAC/IP, scope, solicited set) in `receive_loop`; rejection tallies land in `ArpReplyCounters`. |
| AC-9 observations streamed, batched ≤ 50 ms | **Met** | Worker flusher thread with a 50 ms age deadline independent of arrivals (10 ms tick), 32-observation max batch; tests: single observation flushed < 200 ms in a 600 ms scan (timer, not scan-end, delivered it); batches ≤ 32 asserted over 254 observations. |
| AC-10 `ScanOutcome` classification (`Complete`/`Partial`/`Failed`/`Cancelled`) | **Met** | Four variants; first-terminal-event-wins via check-and-set `Mutex<Option<Terminal>>`; tests cover fatal send/receive → `Failed`+reason, transient → `Partial`, all-failed-sends → `Failed`, cancel → `Cancelled`, clean → `Complete`. |
| AC-11 cancellation ≤ 250 ms | **Met** | All waits sliced at `CANCEL_SLICE` = 50 ms with flag checks; cancel works while sending, in the pass gap, in the listen window, and while blocked in `recv` (all tested with real waits, < 280 ms wall including ~15 ms flag delay). Note F-5 on the test bound's looseness. |
| AC-12 fake-transport tests cover rate, passes, cancellation, outcomes | **Met** | 34 scanner tests + 8 worker tests + 8 transport tests + 12 privilege tests, all against the deterministic `FakeTransport` (scripted responders, delays, send failures, recv parking, send log); clamps, dedup, cap, listen window, stale-cancel, backpressure-cancel, shutdown-join all present. |
| AC-13 `poc_discover` runs and prints observations | **Met** | Re-run live three times (two /24, one /29): observations print progressively, counters and outcome summary print, exit 0; capability line printed in every run. |
| AC-14 ADR-018 documents transport decision per §9.2 (all 7 criteria) | **Substance met; see F-3** | **No `docs/adr/018-*.md` exists** (the ADR index ends at 017). The executor routed the transport decision through ADR-009 (Pending, decided by T-105) with the full 7-criteria §9.2 evaluation in execution report §7 — which I verified criterion-by-criterion, and whose factual claims I re-verified against the vendored sources (§1.5). The plan explicitly permits an interim choice "behind the trait" (§13, T-104) and assigns the ADR-009 decision to T-105, so a new ADR would duplicate ADR-009's subject. If the card did require a standalone ADR-018, this must be clarified — hence F-3, not a code defect. |
| AC-15 all gates pass | **Met** | Every gate re-run exit 0 (§1), plus MSRV build and the strict lib-only clippy variant. |
| AC-16 no `unsafe` in our code | **Met** | `forbid(unsafe_code)` crate-wide and in the example; grep clean (§1.1); dependency-internal `unsafe` (pnet/caps/nix libc wrappers) assessed in report §7 per §9.2 criterion 4. |
| AC-17 no `println!`/`eprintln!` in library code | **Met (with documented exemption)** | 2 `eprintln!` hits, both inside `#[cfg(test)]` skip-notices in `privilege.rs` — test code, exempt per the card's "non-test, non-example" wording, `clippy.toml`, and the strict lib-only clippy run (exit 0). The example's `print_*` use is narrowly allowed in that one file (deviation 10, mirroring `src/main.rs`). |
| AC-18 SPDX headers on all new files | **Met** | 0 of the repository's `.rs` files miss the header (§1.1); all 6 new/modified source files carry it. |

Card-ACs 19–23 of the execution report (lab run, worker, no-unwrap/expect/panic, no upward deps, dependency PQ) were also re-verified: live lab §1.4; worker tests §2/AC-9/AC-11; strict clippy §1; §8.2 grep §1.2; Cargo.lock diff §1.5.

## 3. Checklist (§14.8)

| # | Item | Pass / Fail / N/A | Notes |
|---|---|---|---|
| 1 | Scope: only what the card asked; none of §2.2; no probe types outside §2.3 | **Pass** | Diff confined to the card's file set (+ report). No persistence (§2.2) work. The only traffic originated is paced, scoped ARP requests; promiscuous mode never enabled (FR-DS-07); no UDP/TCP probing (ADR-005 item 8 respected). |
| 2 | Acceptance criteria re-verified independently | **Pass** | §2 above; commands re-run, not trusted (§1). |
| 3 | Gates all pass | **Pass** | fmt/clippy/test/ignored/doc/audit/deny + MSRV, all exit 0 (§1). |
| 4 | Security: no `unsafe`; no panics on external input (SR-02); boundary validation (SR-04); privilege handling per ADR-005; no real identifiers in fixtures | **Pass** | `forbid(unsafe)`; strict clippy (unwrap/expect/panic/print) green on the lib; total parser for frames (T-103) and for `/proc` text (hostile-input tests); bounded 64 KiB read; ADR-005 ordering (open → NNP → ambient → bounding-if-possible → sets → verify fail-closed); fixtures fully synthetic (RFC 5737 + `02:…` MACs). One report-prose hygiene item: F-2 (host identifiers in the execution report's read-only run evidence). |
| 5 | Architecture: §8.2 rules; single registry owner; bounded channels; cancellable waits | **Pass** | §1.2. No registry exists yet (T-201); the worker exposes no registry coupling; channels bounded and their constants tested; every wait sliced/bounded (FR-DS-09). |
| 6 | Honesty: §5.4 vocabulary; no completeness claims | **Pass** | §1.1 grep; outcome/source labels factual; the report's limitations section is candid (known issues §10); "verified" appears only as the technical term for capability verification, not a device verdict. |
| 7 | Tests: meaningful, deterministic, not weakened; edge cases present | **Pass** | §6 below. |
| 8 | Dependencies: no unapproved additions; `Cargo.lock` diff reviewed | **Pass, with pending ratification** | +2 crates and one `nix` feature, exact-pinned, consolidated under PQ-1 raised **before** the addition (card §2.1 mechanism, T-101 precedent); lock diff = 6 leaf additions, nothing else moved (§1.5). Manager ratification is exactly PQ-1 — recommend ratifying (§9). |
| 9 | Docs/ADR updated where behavior or decisions changed | **Pass, with a follow-up** | The decision record lives in the execution report §7 by design (PQ-1 chicken-and-egg, ADR-017 precedent: ADR update follows the Manager's decision); ADR-005's "chosen by T-104 (Pending)" line and ADR-009 stay correctly Pending until then. Follow-ups: F-3 (ADR vehicle clarification), F-4 (ADR-005 item 5 unowned). |
| 10 | Report accuracy: Execution Report matches the diff | **Pass** | §8 below — verified claim-by-claim; lab evidence reproduces (§1.4). |

## 4. Findings

| ID | Severity | Location | Description | Recommendation |
|---|---|---|---|---|
| F-1 | Low | `fuzz/Cargo.lock` (committed at `7c73456`) | **Stale after the dependency additions.** The fuzz package depends on the root crate, so T-104's 6 new crates must appear in its lockfile too; T-103 had established lockfile parity ("same 179 versions"). Consequence verified: `cargo run --manifest-path fuzz/Cargo.toml --locked` fails ("cannot update the lock file … --locked was passed"); without `--locked` every fuzz run silently rewrites the file (+58 lines) and dirties the tree. Dev-workflow and CI-reproducibility impact only; the shipped crate is unaffected. | Regenerate and commit: `cargo update --manifest-path fuzz/Cargo.toml --lockfile-only` (or one plain fuzz run) in a follow-up commit before/with merge. |
| F-2 | Low | `docs/reports/T-104/execution-01.md` §4.1 (read-only run output) | **Host identifiers in committed evidence.** The unprivileged read-only run records the sandbox host's real interface MAC and IP (a /32 on the sandbox's egress interface). Fixtures are clean (§14.3 rule 8); this is report-prose hygiene — but rule 8's intent ("no real identifiers") covers committed run evidence, and the file ships in the repository. | Docs-only follow-up: redact the MAC/IP in that block (keep the `CapBnd` residual and mode lines, which are the evidence). No history rewrite required. |
| F-3 | Info | `docs/adr/` (absence), execution report §7 | The review brief's AC-14 expects `ADR-018` documenting the transport decision; the repository's plan instead assigns the transport-library decision to **ADR-009 (Pending, T-105)** and permits an interim choice behind the trait. The 7-criteria evaluation exists in full (report §7, source-verified). Creating an ADR-018 would duplicate ADR-009's subject; not creating one leaves the brief's AC-14 formally unmet. | Manager: confirm the intended vehicle. Recommended: record the PQ-1 ratification as evidence in ADR-009 (or a short ADR-018 that explicitly supersedes/feeds ADR-009) when ratifying — one-document change, no code. |
| F-4 | Info | ADR-005 item 5 vs `src/`, `examples/` | "If started with euid 0, the app warns once ('running as root is not required…') and still drops capabilities" is implemented nowhere yet — and is not part of the T-104 card's enumerated privilege items (open/EPERM/drop/verify), so this is not a T-104 scope violation. Risk: the requirement has no owner and can be lost. | Assign explicitly to the app-assembly task (T-205) or the CLI task (T-402) in the next card batch; one-line note in the plan's task list suffices. |
| F-5 | Info | `scanner.rs` test `cancelling_while_sending_returns_promptly` | The cancellation test bounds total elapsed at 280 ms with the flag set at ~15 ms, i.e. ≈265 ms from flag — slightly looser than FR-DS-09's 250 ms budget (the implementation's real bound is `CANCEL_SLICE` = 50 ms). Smoke-bound, not wrong; a CI hiccup could in principle pass a regression that FR-DS-09 would fail. | Optional: assert `elapsed - flag_delay <= 250 ms` (flag delay is known to the test). Not blocking. |
| F-6 | Info | `scanner.rs` pass logic | Pass-2 targets are snapshotted **at pass start** (per ADR-011's "as of" wording). An address that answers between the snapshot and its pass-2 probe is re-probed once: harmless (solicited set still covers it; no false observation; dedup holds), and the mirror-image pre-gap race is already documented (deviation 13). | None. Optionally note the snapshot semantics next to deviation 13 in the report for T-105's experiment design. |

## 5. Scope check

- Files touched = exactly the card's allowed set: `Cargo.toml`/`Cargo.lock` (PQ-1), `src/discovery/privilege.rs`, `src/discovery/arp/{mod,transport,scanner,worker}.rs`, `src/discovery/mod.rs` (registration/re-exports only), `examples/poc_discover.rs`, the execution report. Read-only for this task: codec, net, model, neighbor_table, lib, main, `deny.toml`, workflows, `plan.md` — verified untouched against the base.
- No §2.2 (persistence) behavior; no new probe types (§2.3: active ARP only, in-scope, paced, capped); no DNS/TCP/UDP probing; promiscuous collection explicitly disabled.
- The lab runs (executor's and mine) stayed inside throwaway namespaces with RFC 5737 addresses and locally-administered MACs; nothing outside was probed (§14.3 rule 7/8 respected).
- Nothing was merged and no code was modified by this review (the only tree mutation during verification — the fuzz lockfile rewrite — was reverted; §1 gate table reflects the committed tree).

## 6. Test quality assessment

- **Volume/scope:** 62 new lib tests (60 run + 2 privileged `#[ignore]`) + 7 example tests, on top of T-103's suite; every card behavior has at least one test named after it (target generation /31·/32/laziness, clamps, pacing lower bound, pass-2 filtering, solicited-only, cap, dedup, listen window, all four outcomes, five cancellation phases, batching deadline/size/backpressure-cancel, stale cancel, shutdown-join, command-queue bound, `/proc` parser totality).
- **Determinism:** the `FakeTransport` gives scripted responders, reply delays, send failures (indexed or total), fatal receive errors, and `recv` parking; `send_lag` makes the pre-gap race deterministic; no wall-clock-only assertions without generous margins (the one loose bound is F-5). The two privileged tests are correctly `#[ignore]`d with the exact invocation documented in the source.
- **Not weakened:** assertions check real properties (gap ≥ 9 ms at 100 pps; `targets == sent + errors` invariant; pass-2 frames parsed from the send log; batch sizes; flush deadline delivered by the timer in a still-running scan; cancel works with a **full** event channel). Edge cases from the card are present: rate 0/`u32::MAX`, /31 (RFC 3021), /32, hostile `/proc` text (garbled, missing, wrong-typed, 10 kB lines), non-UTF-8 argv, poisoned-lock recovery.
- **Gaps (non-blocking):** no test exercises a real `EPERM`-during-active-scan (transport `PermissionLost`) end-to-end — covered only by classification tests (`from_io` table) — acceptable for this phase; T-106's harness is the planned home for S-level impairment scenarios.

## 7. Security assessment

- **Privilege handling (ADR-005/SR-06):** ordering is correct and minimal — the socket is opened before the drop (`RawSocket` owns the handles; nothing later needs privilege), `no_new_privs` first, ambient cleared before the capset-managed sets, bounding set narrowed only when `CAP_SETPCAP` is held (with `NoNewPrivs` as the compensating control — sound reasoning, verified live in both the cleared and residual-mask cases), and the drop **fails closed** on verification. Per-thread semantics are documented (drop on the main thread before spawning) and the example follows it.
- **Untrusted input (SR-02/SR-04):** all frame bytes pass T-103's total validator against the solicited set; non-ARP frames are filtered before counting; the `/proc` reader is size-bounded with a total parser (hostile-text tests); argv is total (non-UTF-8 → usage error). No indexing/unwrap/expect/panic outside tests (strict clippy green); mutex poisoning recovered, never propagated as a panic.
- **Abuse bounds:** response cap (1,024) drops excess valid replies without failing the scan; unknown I/O errors classify fatal (fail-closed, deviation 8 — the conservative direction); send path bounded (50 ms); receive path never blocks past the caller's timeout + 1 ms.
- **Supply chain (SR-11):** 6 new lockfile leaves, all exact-pinned at the requirement level; `cargo audit` clean at the pinned toolchain; `cargo deny` green against the unchanged allowlist; MSRV build green. `pnet_datalink`'s slow maintenance cadence is accepted **provisionally behind the trait** — the right containment given ADR-009-Pending (risk R-02).
- **Privacy:** fixtures and lab identities synthetic; one report-prose item (F-2). No secrets or tokens anywhere in the diff.

## 8. Report accuracy

Verified claim-by-claim against the diff and re-runs; the Execution Report **matches**:

- Gate outputs (test counts 188+2/9/7, fmt/clippy/doc/audit/deny results, the 2 `eprintln` locations, the "no upward dependencies" grep, MSRV note) — identical to my re-runs.
- `Cargo.lock` accounting ("+58 lines, 6 new crates; serde already locked") — exact (§1.5).
- Dependency evaluation facts (nix/socket2/pnet mechanics, caps transitives, licenses) — source-verified (§1.5).
- Lab evidence (502 targets, 4 devices with the same-MAC kernel case and distinct-MAC helper case, 7.56 s, caps lines) — reproduced exactly under equivalent conditions (§1.4, run 2). My run 1 (506) is explained by responder-side startup timing, consistent with — and additional evidence for — the snapshot semantics the report documents (deviation 13); it is a lab artifact, not a report inaccuracy.
- The 14 deviations and 13 decisions/assumptions were each checked against the code; all are real, implemented as described, and none hides a scope expansion. Deviations 5/6/7 (the ones the review brief singled out) hold up under source-level scrutiny (§1.5, §1.3).
- One accuracy-adjacent hygiene item: F-2 (real host identifiers in the read-only evidence block).

## 9. Recommendation to the Manager

**Verdict: APPROVE WITH FOLLOW-UPS.** The implementation is plan-conformant, honestly reported, and its evidence reproduces. Recommend:

1. **Merge PR #10 after PR #9** (this branch is based on it), with the two docs-level follow-ups folded in or ticketed: F-1 (refresh `fuzz/Cargo.lock`), F-2 (redact host identifiers in the execution report). No code rework required.
2. **PQ-1 — recommend RATIFY**: `pnet_datalink =0.35.0` (provisional per ADR-009-Pending, fully behind `ArpTransport`), `caps =0.5.6`, and the `nix` `process` feature. I verified the necessity argument at source level: neither `nix` nor `socket2` can open+bind `AF_PACKET` without `unsafe`; `caps` adds exactly one already-locked transitive; audit/deny/MSRV green. Record the decision in ADR-009's evidence (and resolve F-3's vehicle question at the same time).
3. **PQ-2 — recommend ACCEPT**: `MAX_PASSES = 3` is grounded in the plan's own experiment space ("passes 1/2/3", Appendix D line "Experiments"); ADR-011 states no maximum; the clamp is tested. Re-pin at T-105 if the data says so.
4. **PQ-3 — recommend ACCEPT (option 1)**: `Observation { ip, mac, source }` in `discovery::arp::scanner` + `DiscoveryEvent` in `discovery::arp::worker` (re-exported at `discovery`). No duplicate type existed; §8.2 stays clean (verified: `discovery` imports `model` + self only); T-205 gets one stable import point to map onto `AppEvent`.
5. **Follow-ups to ticket**: F-4 (assign ADR-005 item 5's euid-0 warning to T-205/T-402), F-5 (optional test-bound tightening), F-6 (none — note only).
6. **Inputs for T-105** (already well-prepared by this task): measure the `ETH_P_ALL` + software-filter cost through the trait; carry the "no safe `sockaddr_ll` outside pnet" finding; use the §4.1 netns recipe (works without `sudo`) as the T-106 harness seed.
7. **For the record:** privileged verification in this review used a user namespace (no host root available); a live prctl-failure demonstration remains impossible in these sandboxes and stays a documented evidence gap (code + unit tests only), not a defect.
