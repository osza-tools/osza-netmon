# Execution Report — T-106 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-03 · **Branch/commits:** `task/T-106-netns-harness`, based on `main` at `1351c2b` (merge of PR #11, T-104-FU1) — see §3 for the commit list · **Plan version:** 1.4.0 (repository copy)

## 1. Summary (≤ 5 lines)

Plan §11.2's scenarios S1–S7 are now a reproducible, opt-in integration suite behind `OSZA_NETMON_TESTS=1` in `tests/netns/` (one custom test binary), built on the T-104 §4.1 unprivileged user-namespace recipe (nested `unshare --net` device side, veth ends moved by PID, RFC 5737 addresses, `02:…` synthetic MACs) with a dev-only responder implemented as a self-reexec of the test binary (option (a)) that carries the Appendix D impairment profiles P0–P3 plus the S9 sleepy parameters, a receive log that backs the S2 rate and S6 egress assertions, and a `--measure` entry point that produced the S8/S9 tables (S1/S2/S4 × P0–P3 + three S9 variants, 3 cycles each, JSON + Markdown, two runs, zero recall variance). 12/12 scenarios green inside the wrapper in 38 s; without the gate variable the tree behaves exactly as before (188 passed / 0 failed / 2 ignored + 9 doctests; netns skipped; no namespace tooling touched); CI gained a `netns` job plus the two pre-approved hygiene fixes; zero production `src/` changes.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1 no env var: baseline unchanged, netns skipped | **Met** | `cargo test --locked --all-features` → `188 passed; 0 failed; 2 ignored` (lib) + `9 passed` (doctests) + `netns suite: skipped (OSZA_NETMON_TESTS is not set; …)`; the netns target is a custom binary (`harness = false`), so it adds no libtest counts and needs no namespaces — §4.3 |
| AC-2 inside wrapper + gate: S1–S7 pass, no interference | **Met** | Suite run of §4.4: 12 scenarios, 0 failures, 37.9 s (serialization enforced by the runner + per-scenario interface names/subnets — §6) |
| AC-3 S1 20/20, 0 dup, 0 extras, Complete | **Met** | `S1: 20/20 discovered (10 kernel + 10 helper), 0 duplicates, 0 extras, outcome Complete, elapsed 7.395s`; driven through the live worker (§4.4) |
| AC-4 S2 NFR-02, counter identities, rate | **Met** | `S2: 250/250 in 5.080s (NFR-02 budget 10 s, CI margin 49%); targets=256 sent=256 window-max=100 min-gap=Some(9)ms`; `targets == requests_sent + send_errors_transient + send_errors_fatal` asserted; pass-2 re-probes exactly `.252–.254` (the only addresses requested exactly twice in the log), 253+3 targets — §4.4 |
| AC-5 S3 completes, no hang, zero accepted | **Met** | `S3: 13 silent targets, complete in 2.749s, zero accepted`; outcome Complete asserted; no-hang bound 6 s asserted |
| AC-6 S4 one MAC, many IPs, none merged/dropped | **Met** | `S4: 12 distinct IPs behind one MAC (02:00:00:00:00:99), none merged or dropped`; 12 distinct (ip, mac) pairs asserted |
| AC-7 S5 every hostile mode rejected by reason, no hang, cap respected | **Met** | one rejection each with the correct tally (`NotSolicited`, `Truncated {needed: 42, found: 20}`, `InvalidMac {MulticastAddress}`, `OutOfScope {198.51.100.99}`); flood: `1500 hostile replies, accepted 8 ≤ cap 8, cap_dropped 10, duplicates 89, complete in 2.67s` (cap lowered to 8 via the public `with_response_cap` hook for this scenario) — §4.4 |
| AC-8 S6 egress 100% ARP requests, in scope, within margin | **Met** | `S6: 22 ARP requests out (all in-scope), 0 non-ARP frames, window-max 13 ≤ 110`; every logged scanner frame asserted `et=0x0806 op=1 tip ∈ targets`; count == `requests_sent`; NFR-06 total-margin asserted; lab-internal kernel frames (other sources) counted separately (2) — §6 |
| AC-9 S7 typed EPERM + read-only entries; post-drop zeros + scan completes | **Met** | `S7(a): open_raw_socket → EPERM without CAP_NET_RAW; read-only path returned exactly 2 lab-learned entries` (child drops CAP_NET_RAW via the approved `caps` crate; CapEff bit 13 verified 0); `S7(b): after the drop CapEff=CapPrm=0, the scan completed and discovered both devices` — §4.4 |
| AC-10 S8/S9 tables, 3 cycles, JSON+MD, seeds+mechanism, two-run variance | **Met** | §5: 15 cells × 3 cycles = 45 records × 2 runs; `target/netns/measure/netns-measure-run{1,2}.{json,md}`; every record carries its seed and `"impairment_mechanism": "helper responder"`; run-to-run recall/count differences: **0** (§5.3) |
| AC-11 CI netns job; push trigger fixed; fuzz/target/ ignored | **Met (workflow level)** | `.github/workflows/ci.yml`: new `netns` job (§4.6), trigger `branches: [main]` (§4.7), `.gitignore` += `fuzz/target/`; the job's own green run happens on the PR (this sandbox cannot open the PR's CI) — §5/§10 |
| AC-12 all §11.3 gates green; zero src/ changes; SPDX everywhere | **Met** | §4.1–§4.2: fmt/clippy/test/doc/audit/deny all exit 0; `git diff --stat` = ci.yml + .gitignore + Cargo.toml (test-target registration), `src/` untouched (§4.8); SPDX check clean (§4.2) |
| AC-13 grep: no privileged helper, no named-netns registration; RFC 5737; `02:…` MACs | **Met** | `grep -rn -e 'sudo' -e 'ip netns add' tests/ examples/` → no output (§4.5); all lab subnets are 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 slices (RFC 5737); every synthetic MAC is `02:…` (locally administered, asserted by the harness self-check) |

## 3. What changed

| File | Change |
|---|---|
| `Cargo.toml` | `autotests = false` + explicit `[[test]] name = "netns" path = "tests/netns/main.rs" harness = false` — the self-reexec dispatch needs a real `fn main`; the comment block explains why (no dependency change; `Cargo.lock` untouched) |
| `tests/netns/main.rs` | new — subcommand dispatch (`--responder`, `--probe`, `--measure`), the opt-in gate (skip / fail-fast / run), the sequential scenario runner with per-scenario watchdog (180 s) and `catch_unwind`, the environment probe with the exact remediation command, the harness self-checks as scenario 0 |
| `tests/netns/lab.rs` | new — the lab builder/teardown: veth pair, nested `unshare --net` child (bash script → `exec` responder), PID-file + READY bounded waits, fresh artifacts per build, `Drop` teardown (kill child + delete host veth), `parse_cidr`, `process_cpu_ms` |
| `tests/netns/responder.rs` | new — the dev-only responder (option (a)): `AF_PACKET` via the production `open_raw_socket` + `LinuxArpTransport`, answer table, seeded impairment chain (ignore-first → drop → fraction → delay), concurrent per-answer delayed replies (thread + `Arc` transport), the five hostile modes with determinism guards, 900 s lifetime cap |
| `tests/netns/config.rs` | new — the responder config file format (writer + total fail-closed parser, 256 KiB bound), `Impairment` (P0–P3, S9 variants), `Hostile` |
| `tests/netns/rxlog.rs` | new — the receive log: line-flushing writer (200 k-line cap) + total size-bounded parser (64 MiB), request/window/gap statistics used by S2/S6, guard-violation lookup |
| `tests/netns/frames.rs` | new — ARP reply builder (raw-octet sender MAC — `MacAddr` cannot represent the hostile multicast source by design), minimal total ARP request parser, self-tests |
| `tests/netns/rng.rs` | new — SplitMix64 seeded RNG (`chance`, `range`) + the recorded seed constants |
| `tests/netns/probes.rs` | new — the S7 child probes (`cap-drop`, `drop-and-scan`) printing `key=value` lines the parent parses |
| `tests/netns/scenarios.rs` | new — S1–S7 (S1 through the live worker; S5 as five separate labs, one per hostile mode) |
| `tests/netns/measure.rs` | new — the S8/S9 matrix (`--measure`), Appendix D per-run records, hand-rolled JSON + Markdown emitters, dependency-free UTC timestamp |
| `.github/workflows/ci.yml` | new `netns` job (warm build outside the wrapper; suite + privileged `--ignored` tests inside `unshare --user --map-root-user --net`; commented AppArmor sysctl relax per the card) and the push-trigger fix |
| `.gitignore` | `fuzz/target/` |

`src/`, `plan.md`, `docs/adr/`, `Cargo.lock`: **untouched** (§4.8, AC-12).

## 4. Verification results

### 4.1 Engineering gates (§11.3)

```text
$ cargo fmt --check
(no output; exit 0)

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.42s   (exit 0)

$ cargo test --locked --all-features        # no gate variable
     Running unittests src/lib.rs
test result: ok. 188 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.10s
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed; 0 ignored
     Running tests/netns/main.rs (…/deps/netns-8c93d9087622066f)
netns suite: skipped (OSZA_NETMON_TESTS is not set; set it and run inside unshare --user --map-root-user --net to enable)
     Doc-tests osza_netmon
test result: ok. 9 passed; 0 failed

$ cargo doc --no-deps (RUSTDOCFLAGS="-D warnings", --locked)
    Generated target/doc/osza_netmon/index.html   (exit 0)

$ cargo audit   (cargo-audit 0.22.2, the CI-pinned tarball)
    Scanning Cargo.lock for vulnerabilities (194 crate dependencies)   (exit 0, no findings)

$ cargo deny check   (cargo-deny 0.20.2, the CI-pinned tarball)
advisories ok, bans ok, licenses ok, sources ok   (exit 0)
```

MSRV note: the CI `msrv` job runs `cargo build --locked` at 1.89 — that command compiles lib+bin only, not test targets, so the harness (std-only, edition 2024) does not affect it; the `[[test]]`/`autotests` keys predate the MSRV by years.

### 4.2 SPDX header check (the CI method)

```text
every .rs file in the tree starts with // SPDX-License-Identifier: GPL-3.0-only — 0 misses
```

### 4.3 Opt-in gating, both directions

```text
$ OSZA_NETMON_TESTS=1 cargo test --locked --all-features --test netns   # OUTSIDE the wrapper
thread 'main' panicked at tests/netns/main.rs:268:9:
netns suite: the environment is not usable: this process lacks user-namespace root
(CapEff=0000000000000000); run the suite inside its wrapper:
unshare --user --map-root-user --net bash -c 'cd /home/z/my-project/osza-netmon && OSZA_NETMON_TESTS=1 cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture'
(if unprivileged user namespaces are unavailable on this host, an administrator can enable them,
e.g. by relaxing kernel.apparmor_restrict_unprivileged_userns)
error: test failed, to rerun pass `--test netns`
```

(fail fast with the exact remediation command — requirement 1; verified in this sandbox as the plain unprivileged user; the printed command embeds the caller's working directory.)

### 4.4 The netns suite inside the wrapper (card §9 command, verbatim flags)

```text
$ unshare --user --map-root-user --net bash -c \
  'OSZA_NETMON_TESTS=1 cargo test --locked --all-features --test netns -- --test-threads=1 --nocapture'
netns suite: 12 scenario(s), serialized, watchdog 180s
scenario ok: harness self-checks (codec/log/config round trips) (0.0s)
S1: 20/20 discovered (10 kernel + 10 helper), 0 duplicates, 0 extras, outcome Complete, elapsed 7.395s
scenario ok: S1 20 mixed responders, all discovered (7.5s)
S2: 250/250 in 5.080s (NFR-02 budget 10 s, CI margin 49%); targets=256 sent=256 window-max=100 min-gap=Some(9)ms
scenario ok: S2 250 addresses within NFR-02 (5.4s)
S3: 13 silent targets, complete in 2.749s, zero accepted
scenario ok: S3 silent targets, clean completion (2.8s)
S4: 12 distinct IPs behind one MAC (02:00:00:00:00:99), none merged or dropped
scenario ok: S4 proxy ARP, one MAC many IPs (2.7s)
S5/unsolicited: rejected (1× NotSolicited { found: 203.0.113.46 }), accepted set unchanged (2 devices)
S5/truncated: rejected (1× Truncated { needed: 42, found: 20 }), accepted set unchanged (2 devices)
S5/multicast-mac: rejected (1× InvalidMac { reason: MulticastAddress }), accepted set unchanged (2 devices)
S5/out-of-scope: rejected (1× OutOfScope { found: 198.51.100.99 }), accepted set unchanged (2 devices)
S5/flood: 1500 hostile replies, accepted 8 ≤ cap 8, cap_dropped 10, duplicates 89, complete in 2.67s
scenario ok: S5 hostile: … (5 scenarios, 2.7–2.8s each)
S6: 22 ARP requests out (all in-scope), 0 non-ARP frames, window-max 13 ≤ 110, lab environment frames from other sources: 2
scenario ok: S6 egress: only ARP requests to in-scope targets (2.8s)
S7(a): open_raw_socket → EPERM without CAP_NET_RAW; read-only path returned exactly 2 lab-learned entries
S7(b): after the drop CapEff=CapPrm=0, the scan completed and discovered both devices
scenario ok: S7 privilege model (SR-06) (2.8s)
netns suite: 12 scenario(s), 0 failure(s), 37.9s total
```

The privileged `#[ignore]` tests inside the same wrapper:

```text
$ unshare --user --map-root-user --net bash -c 'cargo test --locked --all-features -- --ignored'
test discovery::privilege::tests::privileged_drop_fails_closed_verification_catches_residual ... ok
test discovery::privilege::tests::privileged_open_raw_socket_succeeds_and_drop_verifies ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 188 filtered out
```

### 4.5 Hygiene greps (AC-13)

```text
$ grep -rn -e 'sudo' -e 'ip netns add' tests/ examples/
(no output)
```

### 4.6 CI workflow (`.github/workflows/ci.yml`)

New `netns` job: checkout + pinned toolchain (same action SHAs as the other jobs) → `cargo test --locked --all-features --no-run` (warm build **outside** the wrapper; inside the namespace cargo needs no network) → the §4.4 suite command inside `unshare --user --map-root-user --net` → the §4.4 `--ignored` command inside the same wrapper. The AppArmor relax line (`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) is present with the comment the card requires (Ubuntu 23.10+ runners restrict unprivileged user namespaces by default).

### 4.7 Push-trigger hygiene fix

`on.push.branches` carried the literal value `ain]` (broken since T-000 — the card's diagnosis); it is now `[main]` with a comment naming the fix and its origin. Verified by loading the workflow as YAML: `triggers: {'pull_request': None, 'push': {'branches': ['main']}}`.

### 4.8 No production changes

```text
$ git diff --stat            (vs main)
 .github/workflows/ci.yml | 32 ++++++++++++
 .gitignore               |  2 ++
 Cargo.toml               | 13 ++++++
 3 files changed, 47 insertions(+)
$ git status --short
 M .github/workflows/ci.yml   M .gitignore   M Cargo.toml   ?? tests/
```

`src/` and `Cargo.lock` are byte-identical to `main`; `git diff --name-only -- src/ Cargo.lock` is empty.

## 5. The S8/S9 measurement (AC-10)

### 5.1 Invocation (twice, same seeds)

```text
$ unshare --user --map-root-user --net bash -c 'OSZA_NETMON_TESTS=1 cargo test --locked \
    --all-features --test netns -- --measure --run-tag run1'
measure: 45 records across 15 cells in 212.7s
measure: JSON target/netns/measure/netns-measure-run1.json
measure: Markdown target/netns/measure/netns-measure-run1.md
$ … --measure --run-tag run2
measure: 45 records across 15 cells in 212.7s   (same outputs, run2 files)
```

Mechanism: **helper-responder impairment** (the default and the CI path per the card) — recorded in every JSON record (`"impairment_mechanism": "helper responder"`) together with the cell's seed. `tc netem` is *available* in this sandbox (probe: `tc qdisc add dev <veth> root netem delay 10ms` succeeds inside the wrapper — iproute2 6.15.0) but was **not** used for any delivered number; the netem-vs-helper comparison belongs to T-105 (card §4), and all numbers here state their mechanism.

### 5.2 The report table (per network; cycle-1/cycle-3 cumulative recall; identical in both runs)

| Network | Variant | Recall cycle 1 | Recall cycle 3 | Extras | Time to first | Sweep time | Packets | Notes |
|---|---|---|---|---|---|---|---|---|
| S1 (20 mixed: 10 kernel + 10 helper) | P0 | 100.0% | 100.0% | 0 | 0 ms | 5890 ms | 486 | seed 2129465441 |
| S1 | P1 (5% loss) | 100.0% | 100.0% | 0 | 0 ms | 5890 ms | 486 | kernel half unimpaired (helper mechanism) |
| S1 | P2 (20% loss + 50–200 ms) | 95.0% | 100.0% | 0 | 0 ms | 5912 ms | 488 | |
| S1 | P3 (sleepy) | 90.0% | 100.0% | 0 | 0 ms | 5989 ms | 496 | |
| S2 (250 addresses, helper-answered) | P0 | 100.0% | 100.0% | 0 | 1 ms | 3571 ms | 256 | seed 2129465441 |
| S2 | P1 | 100.0% | 100.0% | 0 | 1 ms | 3721 ms | 271 | re-probing covers 5% loss within one cycle |
| S2 | P2 | 95.6% | 100.0% | 0 | 114 ms | 4075 ms | 306 | |
| S2 | P3 | 75.6% | 99.6% | 0 | 3753 ms | 6090 ms | 506 | 1 device still missed after 3 cycles |
| S4 (proxy ARP: 12 IPs → one MAC) | P0 | 100.0% | 100.0% | 0 | 1 ms | 1131 ms | 14 | seed 2129465441 |
| S4 | P1 | 100.0% | 100.0% | 0 | 1 ms | 1132 ms | 14 | |
| S4 | P2 | 91.7% | 100.0% | 0 | 115 ms | 1161 ms | 17 | |
| S4 | P3 | 83.3% | 100.0% | 0 | 1334 ms | 1253 ms | 26 | |
| S9 (sleepy hosts, 12 helper-answered) | ignore-first-2 | 0.0% | 100.0% | 0 | — (none in c1) | 1252 ms | 26 | both requests of cycle 1 ignored; pass-2 snapshot semantics |
| S9 | fraction 0.5 | 75.0% | 100.0% | 0 | 1 ms | 1172 ms | 18 | |
| S9 | late 400 ms ± 100 | 100.0% | 100.0% | 0 | 342 ms | 1131 ms | 14 | delayed answers land inside the same cycle |

Reading notes (recording only — no threshold assertions in T-106): P0–P1 recall is 100% everywhere; P2 dips to 91.7–95.6% at cycle 1 and reaches 100% within 3 cycles; P3 (the combined sleepy profile) is the hardest for the 250-address network (75.6% → 99.6%); the pure S9 knobs behave as the pass semantics predict (ignore-first-2 costs exactly the first cycle). All of this is T-105's raw material against the G-1 metric.

### 5.3 Run-to-run variance (requirement 11)

Both invocations used identical seeds (fixed constants in `rng.rs`; per-cell seeds recorded in every record). A programmatic comparison of the two JSON outputs over all 45 records:

```text
records compared: 45
recall/count differences: 0
scan elapsed run1 avg 4699 ms, run2 avg 4699 ms
time-to-first run1 avg 171 ms, run2 avg 171 ms
```

Recall, discovery counts, extras and packets are identical across the two runs; the timing fields differ only in single milliseconds. Determinism holds: the impairment decisions come from one SplitMix64 stream consumed in arrival order, never from wall-clock.

## 6. Decisions and assumptions

1. **Responder vehicle: option (a), self-reexec** (`std::env::current_exe()` + `--responder`), as the card prefers — no new artifact, and the responder links the production transport by construction. The alternative (a dev-only example binary) would have duplicated the frame/transport glue in `examples/` for no gain.
2. **A custom test binary (`harness = false`), not libtest.** A generated libtest main cannot dispatch subcommands, and a hand-written `fn main` in a normal harness target is dead code (verified empirically before choosing). Consequences, all accepted deliberately: the scenario runner is hand-rolled (sequential by construction — the serialization the card asks for, stronger than asking the caller for `--test-threads=1`); each scenario runs under `catch_unwind` plus a 180 s watchdog, so the suite cannot hang CI; the harness's unit-layer checks (config/log/frame round trips) run as the first "scenario" (§11.4 in spirit). The card's verification command still works verbatim — the libtest-style flags arrive as argv and are ignored. The narrowly scoped `#![allow]` block at the top of `tests/netns/main.rs` mirrors `poc_discover.rs`: cargo compiles `harness = false` targets without `--cfg test`, so the clippy.toml test allowances do not apply; production `src/` keeps the full deny set (verified: `cargo clippy --all-targets -- -D warnings` is green with the allows scoped to that one file).
3. **No cross-test interference, both ways** (requirement 2): the runner serializes scenarios AND every scenario owns a distinct interface-name pair (`v-<tag>a/b`) plus a distinct RFC 5737 slice (see `scenarios.rs`'s address-plan table).
4. **Kernel-answered vs helper-answered per scenario.** The S2 *scenario* times a kernel-answered /24 (the realistic "250 configured addresses" reading of §11.2 and the NFR-02 budget); the S2 *measurement shape* uses 250 helper-answered devices so the impairment can actually reach every device (the kernel answers for its own addresses and cannot be impaired by the helper — stated in the S1/S2 measurement notes). The S1 measurement shape keeps the card's mixed definition (10 kernel + 10 helper); its P1–P3 rows therefore describe the impairment of the helper half only, and say so.
5. **Faithful per-device latency.** The first measurement implementation answered delayed replies inline (single-threaded responder), which serialized the delays: a phantom shared bottleneck that understated recall (S2/P2 cycle 1 measured 22.4% instead of the faithful 95.6%). Fixed before delivering: delayed answers are now sent from per-answer threads over an `Arc`-shared transport, so the delay models per-device latency. The TX log records the answer at scheduling time (send best-effort); documented in `rxlog.rs`.
6. **S1 drives the worker** (spawn → start_scan → events → ScanFinished → shutdown) to exercise T-104's batching path live; every other scenario drives the scanner API directly. Both are "the real library in-process" (card §3); the example binary is never driven.
7. **S6 egress definition.** "Egress" = frames on the wire whose Ethernet source is the scanner interface's MAC — the only source the product controls. The lab's own kernel traffic (ARP replies from the device side, and in principle IPv6) has other sources; those frames are counted and reported as environment frames instead of failing the assertion (2 in the S6 run). IPv6 generation is disabled on both veth ends via `ip link set … addrgenmode none` (the sysctl path is not writable inside user namespaces — EPERM in this environment), keeping the lab itself quiet. DNS PTR is not implemented (T-203), so ARP-only is the honest assertion today, as the card states.
8. **S7 fixtures.** (a) runs in a re-exec'd child so the *test process* keeps the capabilities later labs need; the child drops `CAP_NET_RAW` from all five sets via the already-approved `caps` crate. The "lab-learned entries" for the read-only path come from two 1-byte UDP datagrams the harness sends to synthetic RFC 5737 addresses inside the throwaway namespace — the only way to make *this* kernel populate `/proc/net/arp` (userspace ARP does not; T-104 §4.1 observed the same zero-entry table). This is harness setup traffic, not product traffic (S6 asserts the product's egress), and is disclosed here per §14.3 rule 7.
9. **Rate-evidence margins, documented:** the sliding 1 s window allows `rate + 10` (responder poll-granularity at window boundaries) and the minimum stamped request gap is asserted ≥ 5 ms (the sender paces at exactly 10 ms; S2 measured window-max 100 and min-gap 9 ms — comfortably inside).
10. **Seeds are fixed constants** (`rng.rs::seeds`), recorded in the config file, the READY log line and every measurement record; per-cell measurement seeds derive from one base so any cell reproduces alone.

## 7. Dependencies

None. The harness uses std plus the package's already-approved crates (`osza_netmon` itself, `caps` in the S7(a) probe — a `[dependencies]` entry since T-104). `Cargo.lock` is byte-identical to `main`.

## 8. Plan Questions

None. No production code change was needed (the card's §4 stop condition never fired: no scenario exposed a `src/` defect), no new dependency was required, and no plan ambiguity blocked the card's scope. The `Cargo.toml` change (test-target registration) is a build-manifest necessity of option (a), documented in §3/§6.2 — flagged for reviewer attention rather than escalated, since it adds no dependency and alters no production build.

## 9. Security and privacy notes

- **Scope of probing (§14.3 rules 7/8):** every frame the harness originates or answers stays inside throwaway user+network namespaces over veth pairs, using only RFC 5737 documentation addresses and locally-administered synthetic MACs (`02:…`). Nothing outside the wrapper is probed; the wrapper dies with the suite.
- **No privilege escalation surface:** no privileged helper is invoked, no named netns is registered (interfaces are moved by PID), the grep for both is clean (§4.5). The CI relax line is the one the Manager pre-approved, commented in the workflow.
- **Hostile-input discipline (rule 4):** the receive log and config parsers are total, never panic, and are size-bounded (64 MiB log read bound, 200 k-line write cap, 256 KiB config bound); probe output parsing on the parent side follows the same rules. The responder caps its own lifetime (900 s) and the runner's watchdog bounds every scenario.
- **Artifacts:** all artifacts (configs, logs, measurement JSON/MD) contain synthetic identifiers only; no host identifiers are recorded (interface MACs/IPs shown in the log are the lab's own, regenerated per run inside the namespace).

## 10. Known issues and limitations

- **Helper impairment cannot touch kernel-answered devices** (by construction); the S1 measurement rows under P1–P3 describe the helper half (noted per row). A link-level mechanism (`tc netem`, available here — §5.1) can impair both halves; that comparison is T-105's.
- **The suite must stay serialized** — enforced by the custom runner; the libtest `--test-threads=1` flag is accepted but inert (documented in `main.rs`).
- **AC-11's "CI green on the PR"** could not be observed from this sandbox (no ability to watch GitHub run the job); the workflow is syntactically valid YAML with the exact commands verified locally (§4.4/§4.6). The plan's AC explicitly allows the documented-local-procedure outcome; the expectation is a green job on the PR.
- **`cpu_ms` in the measurement records** is the whole test process's user+system time around one scan (from `/proc/self/stat`), so it includes harness overhead — informative, not a product benchmark (T-403 owns those).
- **`sweep_duration_ms`** is "last scanner request − first scanner request (+ one pacing interval) as observed at the responder", so for multi-pass scans it includes the inter-pass gap (visible in the S2 rows: ~3.6 s at P0 vs ~2.6 s of pure sending).
- **S2's NFR-02 margin:** measured 5.08 s against the 10 s budget (~49% headroom) on this 2-core sandbox; CI runners of the same class should be similar, but the budget is asserted, so a pathological runner would surface as an S2 failure with the actual duration in the message.

## 11. Suggested follow-ups

1. **T-105** can now run its whole campaign by driving this harness: vary rate/passes/sender-IP through the same lab builder (`LabSpec` is the extension point), and add the netem arm (available — §5.1) for the impairment-mechanism comparison.
2. The pass-2 snapshot semantics under P3 are directly visible in the data (S2/P3 cycle 1 at 75.6%; S9/ignore-first-2 at 0% for exactly one cycle) — T-105's experiment design should account for the "late answerer is re-probed once" behavior (T-104 review F-6) when interpreting these rows.
3. When cargo/libtest grows a stable way to mix a custom main with a generated harness, the runner could go back to libtest and drop the `#![allow]` block (the scenario functions need no changes).
4. `docs/limitations.md` and the ADR-009/010/011 decisions remain with T-105 per the card's out-of-scope list.
5. The CI `netns` job currently rebuilds without caching (the repo pins its actions deliberately); a caching task would be a separate, approved change.
