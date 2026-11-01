# Execution Report — T-104-FU1 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-02 · **Branch/commits:** `task/T-104-arp-scanner-privileges`, appended on `7c73456` (T-104 attempt 01, PR #10) — `6c81e4a` (F-1 fuzz lockfile), `c6bf94d` (F-2 redaction), `fa60c42` (review-01 verbatim), `621378a` (ADR-005/009 + index), `991b42d` (Manager plan v1.4.0), plus this report · **Plan version:** 1.4.0 (repository copy — applied by this task per card §3; the card was issued against 1.3.0)

## 1. Summary (≤ 5 lines)

Both blocking review findings are closed and the Manager's decisions are recorded: `fuzz/Cargo.lock` regenerated with the six T-104 dependency leaves and the `--locked` fuzz campaign green (F-1); the sandbox host's real interface MAC and IPv4 address redacted from the T-104 execution report with the dictated note added (F-2); the PQ-1 interim ratification recorded in ADR-009 (still Pending, final decision at T-105) and the implemented mechanism, `caps =0.5.6` and T-205's ownership of item 5 recorded in ADR-005; the reviewer's report committed verbatim; the Manager's `plan.md` v1.3.0 → v1.4.0 edit applied exactly as dictated. **No production code changed**; all gates re-run green on the committed tree.

## 2. Acceptance criteria

| AC (card §5) | Status | Evidence (command, file, commit) |
|---|---|---|
| AC-1 locked fuzz run + lockfile leaves | Met | §4: `cargo run --manifest-path fuzz/Cargo.toml --locked --bin arp_frame` — exit 0, `result: OK — no panic path, no oracle violation`. `fuzz/Cargo.lock` committed in `6c81e4a` (+58 lines) with all six T-104 leaves: `caps 0.5.6`, `pnet_datalink 0.35.0`, `pnet_base 0.35.0`, `pnet_sys 0.35.0`, `ipnetwork 0.20.0`, `no-std-net 0.6.0`; §4.1 parity check: 194 shared packages with the root `Cargo.lock`, all versions identical, the only fuzz-only entry being `osza-netmon-fuzz` itself. (Regeneration used the reviewer's sanctioned alternative to the non-existent `--lockfile-only` flag — deviation D-1.) |
| AC-2 clean tree after an unlocked fuzz run | Met | §4: post-commit plain `cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame` — exit 0, `git diff fuzz/Cargo.lock` empty (no rewrite), `git status --short` empty. |
| AC-3 redaction | Met | §4.3 greps: the real MAC (`46:c0:…`) and routable IP (`21.0.19.91/32`) appear nowhere; every remaining MAC/IP hit is synthetic lab data, justified one by one in the hit-list; the `CapBnd` residual mask, `NoNewPrivs`, the mode lines and the exit code are intact; the dictated redaction note sits immediately under the block. |
| AC-4 ADR-009 ratification record | Met | `docs/adr/009-discovery-transport-library.md`: status still `Pending`, now `Pending (interim selection ratified by the Manager, T-104; final decision T-105)`; `## Evidence` gained `### Interim selection — T-104 (ratified 2026-11-02)` with the approved requirements, the source-verified necessity argument (citing `docs/reports/T-104/review-01.md` §1.5), the `ArpTransport` containment (risk R-02) and the `ETH_P_ALL` limitation to measure at T-105; `docs/adr/index.md` row 009 matches. |
| AC-5 ADR-005 implementation record | Met | Items 3, 5 and 7 carry clearly marked `(T-104-FU1 note)` annotations (implemented mechanism covering both `CAP_SETPCAP` cases with evidence links; `**Owner: T-205** (Manager assignment, T-104-FU1) — the euid-0 warning is not implemented yet.`; `caps =0.5.6` ratified, `capctl` not used); the status qualifier is now `Accepted (mechanism implemented T-104; PoC confirmation T-105)`; the quoted decision text is unchanged (decision D-E). |
| AC-6 review report verbatim | Met | `docs/reports/T-104/review-01.md` committed in `fa60c42` byte-identical to the reviewer's delivered file (`cmp` clean; 182 lines / 31,834 bytes; provenance in decision D-A); no `review_lab*.sh` was committed — none exists in this checkout (the reviewer kept the lab scripts out of the repository; they are referenced by name only). |
| AC-7 plan.md exact | Met | §4.2 embeds the full `git diff plan.md`: exactly the nine dictated edits (version row; §0 status row; §4 rows 005/009 + appended row 017; the ADR-011 clamp sentence; the T-105 ×2 / T-205 ×1 / T-403 ×1 bullets; the §21 five rows + gates line; the §22 1.4.0 row) and nothing else. |
| AC-8 gates still green | Met | §4: fmt, clippy, both test invocations, doc, audit and deny all exit 0; test counts identical to the T-104/review baseline (188 passed + 2 `#[ignore]` lib, 9 doctests, 7 example tests). |
| AC-9 changeset scope | Met | `git diff --stat 7c73456..HEAD` (§4) touches exactly the allowed files: the seven listed there plus this report, which is added by the commit carrying it (the eighth AC-9 file). No file outside the AC-9 list differs from `7c73456`. |

## 3. What changed

On `task/T-104-arp-scanner-privileges`, appended on `7c73456` (no rebase, no force-push, no new branch):

- `6c81e4a` — `fuzz/Cargo.lock` (F-1): +58 lines — the six T-104 dependency leaves at the same resolved versions as the root `Cargo.lock` (which took the identical +58-line delta in T-104); no existing entry changed.
- `c6bf94d` — `docs/reports/T-104/execution-01.md` (F-2): in the §4.1 read-only run block, `mac 46:c0:77:1a:2b:b2` → `mac REDACTED-MAC` and `ip 21.0.19.91/32` / `scope 21.0.19.91/32` → `REDACTED-IP/32` (both fields); the dictated note added immediately under the block. One line modified, one line added; the capability, mode and exit-code evidence lines are untouched (the redaction hunk is reproduced in §4.3).
- `fa60c42` — `docs/reports/T-104/review-01.md`: the reviewer's report, verbatim as delivered.
- `621378a` — `docs/adr/009-discovery-transport-library.md` (status parenthetical + the `### Interim selection — T-104 (ratified 2026-11-02)` evidence subsection), `docs/adr/005-privilege-model.md` (status qualifier + item 3/5/7 annotations + evidence links), `docs/adr/index.md` (rows 005 and 009 updated to match the ADR files).
- `991b42d` — `plan.md`: the Manager's v1.4.0 edit, applied verbatim (nine edits; full diff in §4.2).
- this commit — `docs/reports/T-104-FU1/execution-01.md`.

**Explicit statement: no production code changed.** `src/**` and `examples/**` are byte-identical to `7c73456`; `Cargo.toml`, the root `Cargo.lock`, `deny.toml`, `clippy.toml`, `rust-toolchain.toml` and `.github/**` are untouched — mechanically proven by the AC-9 diff stat. No new `.rs` file exists (the SPDX-header constraint is vacuously met); no `unsafe`, no new dependency, no test assertion changed.

## 4. Verification results

All commands ran 2026-11-02 with the pinned toolchain (rustc/cargo **1.99.1**, x86_64-unknown-linux-gnu; cargo-audit **0.22.2** and cargo-deny **0.20.2** installed at the CI pins). Every dependency-resolving command used `--locked`, except the single F-1 regeneration run that is its subject. Absolute sandbox paths and long compile logs are elided (`…`, bracketed notes); results and exit codes are unaltered.

```text
$ cargo fmt --check
[exit 0 — no output]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Checking osza-netmon v0.1.0 (…)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 16.36s
[exit 0]

$ cargo test --locked --all-features
running 190 tests
test result: ok. 188 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.09s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 measured; 0 filtered out; finished in 0.00s
running 9 tests
test result: ok. 9 passed; 0 failed; 0 measured; 0 filtered out; finished in 0.00s
[exit 0 — lib: 188 passed + 2 #[ignore] privileged; bin: 0; doctests: 9; every individual
 test line reports ok; counts identical to the T-104 report and the review re-run]

$ cargo test --locked --all-targets --all-features
running 190 tests
test result: ok. 188 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.05s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 measured; 0 filtered out; finished in 0.00s
running 7 tests
test result: ok. 7 passed; 0 failed; 0 measured; 0 filtered out; finished in 0.00s
[exit 0 — adds the 7 example-embedded tests of poc_discover; doctests are not an
 --all-targets target — the asymmetry T-104 documented as deviation 11]

$ cargo doc --no-deps
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.33s
   Generated …/target/doc/osza_netmon/index.html
[exit 0]

$ cargo audit
    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`
      Loaded 1395 security advisories (from …/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (194 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings, no yanked crates; same advisory
 count (1395) and crate count (194) as the T-104 and review runs]

$ cargo deny check
warning[duplicate]: found 2 duplicate entries for crate 'syn' (syn 2.0.119, syn 3.0.9 — the ratatui tree; dependency tree elided)
warning[license-not-encountered]: "BSD-2-Clause" — unmatched license allowance (deny.toml:20)
warning[license-not-encountered]: "BSD-3-Clause" — unmatched license allowance (deny.toml:21)
warning[license-not-encountered]: "ISC" — unmatched license allowance (deny.toml:22)
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — only the pre-existing T-000-baseline warnings (duplicate syn; the three
 unmatched allowances), unchanged relative to the T-103/T-104/review runs]

$ cargo update --manifest-path fuzz/Cargo.toml --lockfile-only
error: unexpected argument '--lockfile-only' found

  tip: a similar argument exists: '--locked'

Usage: cargo update --manifest-path <PATH> --locked [SPEC]...

For more information, try '--help'.
[exit 1 — the flag does not exist on the pinned cargo 1.99.1 (cargo update --help lists
 no such option); deviation D-1. The lockfile was regenerated with the independent
 reviewer's sanctioned alternative, stated in review-01.md F-1 ("or one plain fuzz run"):]

$ cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame      (F-1 regeneration run, unlocked)
    Updating crates.io index
     Locking 6 packages to highest Rust 1.89 compatible versions
      Adding caps v0.5.6
      Adding ipnetwork v0.20.0
      Adding no-std-net v0.6.0
      Adding pnet_base v0.35.0
      Adding pnet_datalink v0.35.0
      Adding pnet_sys v0.35.0
[compile log elided — Finished `dev` profile [unoptimized + debuginfo] target(s) in 23.33s]
arp_frame fuzz target (T-103, SR-05) — std-only deterministic harness
  stages: known answers, truncations, systematic corruption,
          400000 random inputs, 400000 mutated inputs
  outcomes: accepted=27911 rejected=772961 truncated=402460 wrong_ether_type=281095 wrong_hardware_type=8740 wrong_protocol_type=8040 wrong_hardware_length=3286 wrong_protocol_length=4662 wrong_opcode=7609 mac_mismatch=48683 invalid_mac=9 out_of_scope=6947 network_address=4 broadcast_address=4 own_address=7 not_solicited=1415
  accepted-by-corruption (non-vacuity): 150
  result: OK — no panic path, no oracle violation
[exit 0 — git diff fuzz/Cargo.lock: exactly +58 lines, no other change; parity check in §4.1]

$ cargo run --manifest-path fuzz/Cargo.toml --locked --bin arp_frame
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 18.82s
     Running `fuzz/target/debug/arp_frame`
  [campaign output identical to the regeneration run — same counters, same result]
  result: OK — no panic path, no oracle violation
[exit 0 — AC-1; run twice, once immediately after the regeneration and once on the
 committed tree; both green]

$ cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame      (AC-2: post-commit unlocked run)
  [campaign output identical — deterministic harness]
  result: OK — no panic path, no oracle violation
[exit 0 — git diff fuzz/Cargo.lock: empty (the lockfile no longer rewrites);
 git status --short: empty (clean tree)]

$ git status --short
[empty — the working tree is clean; the root-CWD fuzz invocations leave build artifacts
 in fuzz/target/ (not gitignored), which were removed after each run — deviation D-2]

$ git diff --stat 7c73456..HEAD
 docs/adr/005-privilege-model.md             |  12 +-
 docs/adr/009-discovery-transport-library.md |  10 +-
 docs/adr/index.md                           |   4 +-
 docs/reports/T-104/execution-01.md          |   3 +-
 docs/reports/T-104/review-01.md             | 182 ++++++++++++++++++++++++++++
 fuzz/Cargo.lock                             |  58 +++++++++
 plan.md                                     |  24 ++--
 7 files changed, 279 insertions(+), 14 deletions(-)
[plus this report — docs/reports/T-104-FU1/execution-01.md — added by its own commit,
 the eighth and final AC-9 file]

$ git diff plan.md
[empty — the edit is committed; the full diff of the Manager's edit is reproduced in §4.2]
```

### 4.1 Lockfile parity check (F-1)

```text
$ python3 … lock_parity.py Cargo.lock fuzz/Cargo.lock
root lock: 194 packages, fuzz lock: 195 packages, shared: 194
only in root (0): []
only in fuzz (1): ['osza-netmon-fuzz 0.1.0']
PARITY OK: fuzz lock = root lock packages + the additions listed above, all shared versions identical
```

The fuzz package again carries "its own lockfile with the same resolved versions" (its `Cargo.toml` header) — the T-103 lockfile parity that F-1 flagged as broken is restored, and the additions are exactly the six T-104 leaves.

### 4.2 Full `git diff plan.md` (AC-7 — the Manager's v1.4.0 edit, verbatim)

Captured against the working tree immediately before the plan commit (`991b42d`); the committed diff is identical. All nine dictated edits are present; nothing else changed.

```diff
diff --git a/plan.md b/plan.md
index 11bc163..ab7ae8d 100644
--- a/plan.md
+++ b/plan.md
@@ -3,9 +3,9 @@
 | | |
 |---|---|
 | **Document** | `plan.md` — the single source of truth for this project |
-| **Plan version** | 1.3.0 |
+| **Plan version** | 1.4.0 |
 | **Targets product version** | 0.1.0 (MVP) |
-| **Status** | Approved for execution — Phase 0 may start |
+| **Status** | Approved for execution — Phase 1 in progress (G-0 passed) |
 | **Ecosystem** | osza-tools |
 | **Product name** | `osza-netmon` (confirmed, ADR-001) |
 | **Repository** | https://github.com/osza-tools/osza-netmon |
@@ -143,11 +143,11 @@ Decisions are recorded as ADRs in `docs/adr/` (task T-001). Status: **Accepted**
 | 002 | Status vocabulary (Recent / Idle) | Accepted |
 | 003 | Hostname resolution policy | Accepted |
 | 004 | Authorization notice policy | Accepted |
-| 005 | Privilege model | Accepted (mechanism details Pending T-104/T-105) |
+| 005 | Privilege model | Accepted (mechanism implemented T-104; PoC confirmation T-105) |
 | 006 | Single-package repository (lib + bin) | Accepted |
 | 007 | Aging model (scan-cycle based) | Accepted |
 | 008 | Device identity and shared-MAC handling | Accepted |
-| 009 | Discovery transport library | Pending (T-105) |
+| 009 | Discovery transport library | Pending (T-105); interim selection ratified T-104 |
 | 010 | Neighbor-table source (`/proc/net/arp` vs netlink) | Pending (T-105) |
 | 011 | Probe strategy (passes, rate, sender IP, unicast refresh) | Pending (T-105), defaults below |
 | 012 | Concurrency: std threads, no async runtime | Accepted |
@@ -155,6 +155,7 @@ Decisions are recorded as ADRs in `docs/adr/` (task T-001). Status: **Accepted**
 | 014 | Project license | Accepted (variant to confirm, O-7) |
 | 015 | DNS PTR client implementation | Pending (T-203) |
 | 016 | CI provider: GitHub Actions | Accepted |
+| 017 | Interface data source (`getifaddrs` via `nix`) | Accepted (T-101) |
 
 ### ADR-001 Naming — Accepted
 The source brief mixes `osza-tools` and `veex-tools`. Names: ecosystem `osza-tools`; crate and binary `osza-netmon`; display name "osza Network Monitor". The name MUST live in exactly one place in code (`pub const APP_NAME`/`DISPLAY_NAME`) plus `Cargo.toml`, so a rename is a one-commit change. The Owner confirmed the name and created the repository at https://github.com/osza-tools/osza-netmon.
@@ -208,7 +209,7 @@ Only cycles with outcome `Complete` age devices; `Partial`, `Failed` and `Cancel
 ### ADR-009/010/011 Pending, with provisional defaults for implementation
 - **ADR-009 transport.** Candidates: `pnet_datalink` (its latest release, 0.35.0, dates from May 2024 — slow cadence; do not assume it), `nix` safe wrappers, `socket2`. Criteria in §9.2; also the transport is hidden behind the `ArpTransport` trait so replacing it costs one module.
 - **ADR-010 neighbor source.** `/proc/net/arp` (simple; no state) vs netlink `RTM_GETNEIGH` (state: reachable/stale/failed). T-102 implements `/proc/net/arp`; T-105 decides whether netlink is worth the dependency.
-- **ADR-011 probe strategy.** Provisional defaults: sender IP = interface IP; **100 packets/s**; initial scan and manual refresh use **2 passes** (second pass only to addresses that did not answer, after ≥ 1 s); periodic rediscovery uses **1 pass**; listen window **1.5 s** after the last send. T-105 also evaluates sender `0.0.0.0` (RFC 5227 style probes) and unicast ARP refresh of known devices.
+- **ADR-011 probe strategy.** Provisional defaults: sender IP = interface IP; **100 packets/s**; initial scan and manual refresh use **2 passes** (second pass only to addresses that did not answer, after ≥ 1 s); periodic rediscovery uses **1 pass**; listen window **1.5 s** after the last send. T-105 also evaluates sender `0.0.0.0` (RFC 5227 style probes) and unicast ARP refresh of known devices. Implementation clamp (T-104, ratified): passes are clamped to 1..=3; the default stays 2. T-105 re-pins this from data.
 
 ### ADR-012 / 013
 - **012:** `std::thread` + bounded channels. No tokio or other async runtime in the MVP.
@@ -763,6 +764,8 @@ Authoritative scope summaries. The Manager issues a full task card (Appendix A)
 **T-105 PoC measurement campaign and decision report** · M · *Mostly agent-run in netns; one human-run observation on the Owner's isolated network; protocol in Appendix D*
 - Run the protocol on the synthetic networks (netns profiles P0–P3) and on the Owner's isolated Wi-Fi (observation only); compare transports (criteria §9.2), neighbor sources, probe strategies (rate, passes, sender IP `0.0.0.0` vs interface IP, unicast refresh of known devices).
 - Deliver `docs/poc/poc-report.md` with raw data, recall per cycle, timings, packet counts, failure cases; proposed ADR-009/010/011; limitation catalog; go / adjust / stop recommendation against G-1.
+- Measure the cost of the interim transport's `ETH_P_ALL` binding plus software EtherType filter, and evaluate an `ETH_P_ARP`-binding alternative (T-104 deviation 5).
+- Account for pass-2 snapshot semantics in the experiment design: the non-responder set is snapshotted at pass start, so a late answer can be re-probed once (T-104 review F-6).
 - **Acceptance:** every Appendix D metric reported with method; recommendations justified by data, not preference.
 
 **T-106 Network-namespace integration harness** · M · *Implements: §11.2*
@@ -789,6 +792,7 @@ Authoritative scope summaries. The Manager issues a full task card (Appendix A)
 
 **T-205 Application core (headless)** · L · *Implements: §8.4*
 - `AppState`, `Action`, `AppEvent`, pure `update()`, effects executor in `main`/app wiring, screen state machine (Notice → Scope → Dashboard/Details/Help), message log (last 20), counters; hostname/vendor enrichment integration.
+- ADR-005 item 5: if euid is 0, warn once ("running as root is not required; use file capabilities") and still drop capabilities (assigned by the Manager, T-104-FU1).
 - **Acceptance:** scenario scripts drive the whole flow headlessly (including errors, read-only, resize events, quit); NFR-03 benchmark with 4,096 devices and event bursts.
 
 ### Phase 3 — TUI
@@ -829,6 +833,7 @@ Authoritative scope summaries. The Manager issues a full task card (Appendix A)
 
 **T-403 Performance and resource verification** · M · *Implements: NFR-01…07, NFR-10*
 - Measure per §11.5; fix regressions found.
+- Tighten the cancellation smoke-test bound to `elapsed − flag_delay ≤ 250 ms` (T-104 review F-5), with CI-jitter margin justified in the report.
 - **Acceptance:** all budgets met or deviations accepted by the Manager in writing.
 
 **T-404 Security hardening pass** · M · *Implements: SR-01…13*
@@ -1014,9 +1019,9 @@ Entry rule: a feature must serve one of the four questions (§1.2) and receive i
 | T-001 | ADR records | DONE | ACCEPT |
 | T-002 | Core primitives | DONE | ACCEPT |
 | T-101 | Interfaces, scope, default route | DONE | ACCEPT |
-| T-102 | Neighbor table reader | TODO | — |
-| T-103 | ARP codec | TODO | — |
-| T-104 | ARP scanner and privilege handling | TODO | — |
+| T-102 | Neighbor table reader | DONE | ACCEPT |
+| T-103 | ARP codec | DONE | ACCEPT |
+| T-104 | ARP scanner and privilege handling | DONE | ACCEPT + FOLLOW-UPS (T-104-FU1) |
 | T-105 | PoC measurement and decision report | TODO | — |
 | T-106 | netns integration harness | TODO | — |
 | T-201 | Device registry | TODO | — |
@@ -1037,7 +1042,7 @@ Entry rule: a feature must serve one of the four questions (§1.2) and receive i
 | T-405 | Documentation and packaging | TODO | — |
 | T-406 | Acceptance campaign | TODO | — |
 
-Gates: G-0 ☐ · G-1 ☐ · G-2 ☐ · G-3 ☐ · G-4 ☐
+Gates: G-0 ☑ · G-1 ☐ · G-2 ☐ · G-3 ☐ · G-4 ☐
 
 ---
 
@@ -1049,6 +1054,7 @@ Gates: G-0 ☐ · G-1 ☐ · G-2 ☐ · G-3 ☐ · G-4 ☐
 | 1.1.0 | 2026-10-26 | Owner answers: name confirmed (ADR-001), GPL-3.0 (ADR-014), GitHub Actions (ADR-016), repository URL. The Owner's real network cannot provide ground truth, so G-1 and AC-13 are re-scoped to synthetic netns validation with impairment profiles P0–P3, scenarios S8/S9 added, risk R-15 added, T-105/T-106 updated, open items O-7/O-8 added. |
 | 1.2.0 | 2026-10-28 | T-001 accepted: `docs/adr/` directory created with 16 ADR files transcribed from §4; `index.md` master index added; `AGENTS.md` updated with decision-log reference; PQ-1 resolved (v1.1.0 statuses authoritative per §0.2 precedence); mechanical fidelity check confirms 87 verbatim quoted sentences. |
 | 1.3.0 | 2026-10-28 | T-002 accepted: `src/model/` primitives delivered (MacAddr, Hostname, DisplayText, Field/Source/Reason, Clock/FakeClock, IPv4 helpers + Ipv4Net caps); 45 tests including std-only LCG property suites. Plan Questions resolved: PQ-1 — `proptest` deferred to T-103, std LCG retained; PQ-2 — `DisplayText` collapses whitespace before stripping non-whitespace controls so word boundaries survive; PQ-3 — empty-after-sanitization rejected (`ValidationError::DisplayTextEmpty`), absence modeled via `Field`. PR #5 merged; PR #6 retained as enforcement proof (never merged). |
+| 1.4.0 | 2026-11-02 | Phase 0 closed: T-000/T-001/T-002 accepted, **G-0 passed**. Phase 1 progress: T-101 (ADR-017), T-102, T-103 accepted; T-104 accepted with follow-ups after independent review (all gates re-run, privileged tests in a user namespace, live two-namespace lab reproduced, /29 differential proved the pass-2 filter). PQ-1 ratified: `pnet_datalink =0.35.0` + `caps =0.5.6` + `nix/process`, interim and contained behind `ArpTransport`; ADR-009 stays Pending for T-105. PQ-2 (`MAX_PASSES=3`) and PQ-3 (event-type placement) accepted. Manager card defects corrected on the record: the transport ADR vehicle is ADR-009 (not a new ADR-018), the `ArpTransport` trait needs no `cancel` method, and `discovery` must not depend on `net`. ADR-005 item 5 assigned to T-205; review F-5 to T-403; F-6 and the `ETH_P_ALL` cost to T-105. |
 
 ---
 
```

### 4.3 Redaction greps and hit-list (AC-3)

```text
$ grep -nE '([0-9a-f]{2}:){5}[0-9a-f]{2}' docs/reports/T-104/execution-01.md
168:interface: veth-a (mac 22:c7:5a:17:47:c2, ip 192.0.2.1/24, scope 192.0.2.0/24)
172:192.0.2.2 2e:ef:d3:bb:25:ad (arp reply)
173:192.0.2.3 2e:ef:d3:bb:25:ad (arp reply)
174:192.0.2.5 02:00:00:00:00:05 (arp reply)
175:192.0.2.7 02:00:00:00:00:07 (arp reply)

$ grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' docs/reports/T-104/execution-01.md
25:| AC-13 example runs and prints | Met | Lab run in §4: observations (`192.0.2.2 … (arp reply)`) plus a counters/outcome summary, exit 0. |
31:| AC-19 manual lab run | Met | §4: two-namespace synthetic lab (veth pair, `192.0.2.0/24`), 4 devices discovered — `.2`/`.3` by the responder namespace's kernel (same MAC, the documented multi-address case) and `.5`/`.7` by a helper responder with distinct synthetic MACs; `outcome=complete`, exit 0. No real network was probed (plan §14.3 rule 7). |
136:ip addr add 192.0.2.1/24 dev veth-a && ip link set veth-a up
138:    ip link set lo up; ip addr add 192.0.2.2/24 dev veth-b; ip addr add 192.0.2.3/24 dev veth-b;
145:`arp_responder.py` (helper, synthetic MACs, answers requests for `192.0.2.5`/`192.0.2.7`):
168:interface: veth-a (mac 22:c7:5a:17:47:c2, ip 192.0.2.1/24, scope 192.0.2.0/24)
172:192.0.2.2 2e:ef:d3:bb:25:ad (arp reply)
173:192.0.2.3 2e:ef:d3:bb:25:ad (arp reply)
174:192.0.2.5 02:00:00:00:00:05 (arp reply)
175:192.0.2.7 02:00:00:00:00:07 (arp reply)
183:Reading of the numbers: 253 probe targets (254 hosts minus our own address) → pass 1 sends 253, pass 2 sends the 249 non-responders → 502 requests; elapsed 7.56 s ≈ 2 × 2.5 s of paced sending + the 1 s pass gap + the 1.5 s listen window (the ADR-011 defaults exercised end to end). `192.0.2.2`/`.3` are answered by the responder namespace's kernel with veth-b's MAC (the card's "several addresses on one interface answer with the same MAC" case); `.5`/`.7` come from the helper responder with distinct synthetic MACs. The capability lines prove SR-06 live: full capability sets before, all-zero `CapEff`/`CapPrm`/`CapInh`/`CapAmb` (and `CapBnd`, cleared because user-namespace root holds `CAP_SETPCAP`) and `NoNewPrivs=1` after.
212:**Error paths (exit codes):** missing interface → exit 2 (`no interface named "osza-no-such-iface" exists`); no argument → exit 2 (usage); scope `/15` → exit 2 (`scope 192.0.0.0/15 is too large for this example: network has 131070 usable hosts, above the cap of 65534`).
```

Hit-list — every remaining hit, with its justification:

| Hit (line) | Justification |
|---|---|
| `22:c7:5a:17:47:c2` (168, `veth-a`) | Kernel-generated, locally-administered (bit 1 of `0x22` set) MAC of the **throwaway veth interface inside the lab network namespace** — synthetic lab data, not an identifier of the sandbox host or of any Owner network; `veth-a` itself is one of the card's whitelisted generic lab names. |
| `2e:ef:d3:bb:25:ad` (172–173, `veth-b`) | Same class — the responder namespace's kernel-assigned veth MAC. It also *is* the evidence for the documented "two addresses, one MAC" multi-address case that the reviewer independently reproduced; redacting it would destroy that evidence. |
| `02:00:00:00:00:05`, `02:00:00:00:00:07` (174–175) | Helper-responder synthetic MACs — the card's explicit `02:…` whitelist. |
| `192.0.2.x` (25, 31, 136, 138, 145, 168, 172–175, 183) | RFC 5737 documentation range — the synthetic lab's `/24` and its members. |
| `192.0.0.0/15` (212) | Documentation-range supernet of the lab scope, quoted by the example's too-large-scope error message. |

Hostname/interface scan of the whole report: **no hostname of the sandbox host appears anywhere**; the only interface names are `lo`, `veth-a`, `veth-b`, `eth0` (generic lab names, all whitelisted) and the synthetic `osza-no-such-iface`. The host's real identifiers (`46:c0:77:1a:2b:b2`, `21.0.19.91/32`) appear nowhere (`rg '46:c0:77|21\.0\.19'` → no matches). The redacted §4.1 block, for the record:

```diff
-interface: eth0 (mac 46:c0:77:1a:2b:b2, ip 21.0.19.91/32, scope 21.0.19.91/32)
+interface: eth0 (mac REDACTED-MAC, ip REDACTED-IP/32, scope REDACTED-IP/32)
```

with, immediately under the block: `> Host identifiers redacted per plan §14.3 rule 8 (Manager order T-104-FU1); the capability and mode lines are the evidence.`

## 5. Deviations from the task card

1. **D-1 — `cargo update --lockfile-only` does not exist on the pinned toolchain.** Cargo 1.99.1 rejects the flag (`error: unexpected argument '--lockfile-only' found`; `cargo update --help` lists no such option), so the card's §2.1/§6 command cannot run as written. Substituted the independent reviewer's own sanctioned alternative, stated in `review-01.md` F-1 — "or one plain fuzz run": one unlocked `cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame`. The substitution added **exactly** the six missing leaves (+58 lines — the identical delta the root `Cargo.lock` took in T-104) and touched no existing entry (§4.1 parity check); the card's subsequent `--locked` command then ran green (AC-1). Non-blocking: every AC-1 property is satisfied.
2. **D-2 — fuzz build artifacts during root-CWD invocations.** Cargo discovers `.cargo/config.toml` by working directory, not by `--manifest-path`, so the card's root-CWD fuzz commands bypass `fuzz/.cargo/config.toml`'s `target-dir = "../target"` redirect (T-103's mechanism that keeps artifacts in the gitignored root `/target`) and leave artifacts in `fuzz/target/`, which `.gitignore` (only `/target`) does not cover. The artifact directory was removed after each run and before every `git status --short` check; nothing outside the eight AC-9 files was ever staged or committed (the §4 diff stat proves it). Root cause and fix recorded as suggested follow-up 1.
3. **D-3 — placement of the appended §13 bullets.** The Manager's edit dictates "append" bullets to the T-105, T-205 and T-403 lists. The new work-item bullets were inserted immediately **before** each task's `- **Acceptance:**` bullet instead of after it, preserving the task catalog's structural invariant that every entry ends with its Acceptance bullet (a literal end-append would leave work items trailing the acceptance criterion in all three entries). The dictated bullet text is character-for-character unchanged; only this positional interpretation is the executor's. If the literal end-of-entry position was intended, the correction is a three-line reorder.

## 6. Decisions and assumptions

**Decisions:**

- **D-A review-01.md provenance (card §2.5).** The card says the file is "currently untracked in the working tree" and instructs the executor to stop if it is not present in the checkout. This executor's checkout is a fresh clone of the branch — untracked files do not survive cloning — but the Owner delivered the reviewer's file **with this task card**, and that delivered copy was committed verbatim (`cmp` byte-identical; 31,834 bytes / 182 lines; commit `fa60c42`). Nothing was reconstructed; the stop-condition targets the no-copy scenario, which did not occur.
- **D-B scope of §2.2 "of the sandbox host".** Only the host's real interface identifiers (the `eth0` MAC and the `21.0.19.91/32` address) were redacted. The kernel-generated veth MACs of the throwaway lab namespaces remain, as synthetic lab data (hit-list in §4.3): they identify neither the sandbox host nor any Owner network, they carry the multi-address-case evidence, and this scope matches the independent reviewer's F-2 finding, which flagged only the §4.1 host identifiers. If the Manager intends the stricter reading (only `02:…` MACs may remain), follow-up 3 redacts the two veth MACs identically in a one-line change.
- **D-C ADR-009 status-line rendering.** "Status stays `Pending` and gains `(interim selection ratified by the Manager, T-104; final decision T-105)`" was rendered as `Pending (interim selection ratified by the Manager, T-104; final decision T-105)` — the dictated parenthetical replaces the now-redundant `(T-105)` suffix, mirroring the Manager's own §4 row style (`Pending (T-105); interim selection ratified T-104`).
- **D-D `docs/adr/index.md` row 005.** Updated to ADR-005's new status qualifier alongside the card-ordered row 009 update: the index's own header requires it to stay consistent with the ADR files, and AC-9 already lists `docs/adr/index.md` among the allowed files. No other index row changed.
- **D-E ADR annotation convention.** ADR-005's items are verbatim plan quotations; every T-104-FU1 addition is a separate, prefixed `(T-104-FU1 note)` line — the file's established non-plan-text convention (it already carries `(T-001 …)` cross-references) — so the decision text itself remains unchanged, as §2.4 requires.
- **D-F §21 rows T-000 and T-101.** Both already matched the dictated text exactly in plan v1.3.0, so no edit was needed ("set these rows exactly" is satisfied by inspection); every other status-board row is untouched, as dictated.

**Assumptions** (per plan §0.2, written down):

- "The SAME branch as PR #10" means the branch tip `7c73456` as reviewed; the observed fact that `main` already contains the PR #10 merge commit (`4381efc`) does not change the card's instructions (append to the branch, no new branch, no rebase, no force-push, no merging) — recorded in §10, not acted on.
- The card's §3 anchors were all verified present in `plan.md` v1.3.0 before any edit; none was missing, so no Plan Question arose.

## 7. Dependencies

None added, changed or removed. The regenerated `fuzz/Cargo.lock` only mirrors into the fuzz package the six crates the root `Cargo.lock` already locked and the Manager ratified under PQ-1 (`caps 0.5.6`; `pnet_datalink 0.35.0` with its `pnet_base`/`pnet_sys`/`ipnetwork`/`no-std-net` transitives) — same versions, verified by the §4.1 parity check. `Cargo.toml`, the root `Cargo.lock` and `deny.toml` are untouched; `cargo audit` and `cargo deny check` are green on the committed tree.

## 8. Plan Questions

None. (The `--lockfile-only` flag absence is a card-vs-toolchain defect with a reviewer-sanctioned resolution, recorded as deviation D-1 — not an ambiguity or conflict in `plan.md`.)

## 9. Security and privacy notes

- **Privacy (F-2):** the only real host identifiers in the shipped evidence are redacted; §4.3 justifies every remaining MAC/IP hit as synthetic lab data (RFC 5737 ranges; kernel- or helper-generated MACs of throwaway namespace interfaces). No hostname of the sandbox host exists in the report. The evidence lines the card names (residual `CapBnd` mask, `NoNewPrivs`, mode lines, exit code) are intact.
- **No secrets:** no token, key or credential appears in any committed file; the reviewer's report was received from the Owner and committed unmodified (its own §7 states "No secrets or tokens anywhere in the diff").
- **No code change:** the T-104 security posture (privilege-drop ordering, total parsers, `#![forbid(unsafe_code)]`, bounded channels and waits) is untouched; all gates re-ran green on the exact committed tree, and the AC-9 diff stat proves no production file differs from the reviewed `7c73456`.

## 10. Known issues and limitations

- **PR #10 is already merged.** `main` contains the PR #10 merge (`4381efc`), observed at execution time; the card's premise "After this task PR #10 is mergeable" was already satisfied before this task ran. These follow-up commits extend `task/T-104-arp-scanner-privileges` beyond that merge point; bringing them into `main` is a Manager/Owner action (follow-up 2).
- **`fuzz/target/` is unignored** while the package's artifact redirect only applies to in-directory cargo invocations (D-2's root cause) — pre-existing since T-103 and outside this card's file scope.
- **The card's regeneration command is not runnable** on the pinned toolchain (D-1); future cards should use the plain-run form or `--precise`-style updates that exist on stable cargo.
- The two `#[ignore]` privileged tests were **not** re-run: §6's command list omits them and no code changed; the review's user-namespace runs of 2026-11-01 remain the live privileged evidence for T-104.

## 11. Suggested follow-ups

1. Close the fuzz-artifact gap: add `fuzz/target/` to `.gitignore`, or state in `AGENTS.md` / `fuzz/Cargo.toml` that fuzz commands must run from inside `fuzz/` (where `.cargo/config.toml` redirects artifacts to the gitignored root `target`).
2. Manager: route the T-104-FU1 commits into `main` (PR #10 is already merged, so a small follow-up PR from `task/T-104-arp-scanner-privileges` would carry exactly the eight AC-9 files).
3. If the stricter §2.2 reading is intended (only `02:…` synthetic MACs may remain in committed evidence), redact the two kernel-generated veth MACs in `docs/reports/T-104/execution-01.md` identically — a one-line change, at the cost of the same-MAC multi-address evidence.
4. When review F-1's regeneration recipe is next quoted in a card, use the plain-run form (the `--lockfile-only` flag does not exist on stable cargo).
