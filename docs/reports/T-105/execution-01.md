# Execution Report — T-105 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-03 · **Branch/commits:** `task/T-105-poc-campaign`, based on `main` at `a25b22c` (merge of PR #13, T-106-RW1) — see §3 for the file list · **Plan version:** 1.5.0 (repository copy)

## 1. Summary (≤ 5 lines)

The full Appendix D protocol ran on the T-106 harness used **as-is** (the unmodified netns test binary re-execed in `--responder` mode from a new dev-only measurement binary, `examples/poc_measure.rs`, with the T-106 config format and seed scheme) plus an isolated-Wi-Fi stand-in driving the T-104 `poc_discover` binary. 543 campaign records + 90 baseline records (T-106 `--measure` A/B, zero variance) cover the complete ADR-011 grid (S1/S2/S4 × P0–P3 × 50/100/200 pps × 1/2/3 passes, 3 cycles), S9 variants, ten-cycle periodic runs, sender-IP, unicast refresh + rotation, pass-2 snapshot semantics, the `ETH_P_ALL` cost with an `ETH_P_ARP` kernel-level witness, the neighbor-source timeline, and interface down/up. Every gated cell (P0–P2, S1/S2/S4) reaches ≥ 95% recall by cycle 3 (worst 99.2%, defaults 100%), ADR-009/010/011 are decided from the data, and `docs/poc/poc-report.md` recommends **passing Gate G-1**, with the Owner's human Wi-Fi observation (plan §13) runbook-ready and the stand-in evidence in its place.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1 Every Appendix D metric is reported with its exact measurement method | **Met** | `docs/poc/poc-report.md` §2.3 (field-by-field method table), §2.5 (exact commands); all per-run fields in `docs/poc/data/*.json` (543 records) |
| AC-2 Recall on P0–P2 ≥ 95% within 3 cycles for S1/S2/S4, or the stop/adjust condition with exhausted options | **Met (pass, no trigger)** | poc-report §3.3: worst gated cell 99.2% (S2/P2, 1-pass variant); defaults 100% at cycle 3; the whole tuning space was measured anyway (§3.2 grid tables) |
| AC-3 S9 "sleepy hosts" recall reported separately with observed metrics | **Met** | poc-report §3.4 + §3.2 S9 tables (`grid-s9.json`, `grid-s9-rates.json`): ignore-first-2 0%→100% by cycle 3; fraction-0.5 75%→100%; late-400ms 100% throughout |
| AC-4 The Owner's isolated Wi-Fi run completes cleanly; neighbor-table / limited-visibility UX verified | **Met on the netns stand-in; the real session is human-run per plan §13** | poc-report §7.1: both privilege modes exit 0 with honest counters (active: 2 of 253 targets answered, 504 sent; read-only: the `no CAP_NET_RAW` message, 1 neighbor observation); runbook §7.2; captures in `docs/poc/data/observe-run-*` |
| AC-5 The `ETH_P_ALL` vs `ETH_P_ARP` cost comparison documented with CPU/packet metrics | **Met** | poc-report §5.1–§5.2: ≤ 1.8 µs per non-ARP frame (+10 ms CPU / 5613 frames at 800 pps), witness socket received 0 non-ARP frames at every rate (`transport.json`) |
| AC-6 ADR-009, ADR-010 and ADR-011 decided and justified by empirical data | **Met** | `docs/adr/009/010/011` (Status: Accepted, evidence-linked to poc-report sections and `docs/poc/data/`); summary in poc-report §10.1 |
| AC-7 The declared gap (R-15) explicitly stated in the PoC report | **Met** | poc-report §9 L-1 (first entry of the limitation catalog) + §1 executive summary |
| AC-8 All engineering gates pass | **Met** | §4.1–§4.6: fmt, clippy, test (191 lib + 9 doctests + 7 + 11 example tests; netns suite 12/12 in 37.9 s inside the wrapper), doc, audit, deny, SPDX — all green |

## 3. What changed

| File | Change |
|---|---|
| `examples/poc_measure.rs` | new — the T-105 experimental harness (task card §5.1): lab builder mirroring `tests/netns/lab.rs` that **re-execs the unmodified T-106 test binary in `--responder` mode**, the T-106 shapes/seeds/config-format, and nine subcommands (`grid`, `sender-ip`, `unicast`, `late`, `transport`, `neighbor`, `observe`, `iface-flip`, `drop-netraw-exec`), JSON+Markdown record emitters, 11 unit tests |
| `src/discovery/arp/codec.rs` | `build_arp_request_to` — the unicast-request builder (ADR-011's unicast-refresh toggle; `build_arp_request` now delegates to a shared raw builder) + 2 tests |
| `src/discovery/arp/scanner.rs` | `ArpScanner::with_probe_sender_ip` — the RFC 5227 sender-IP toggle (outgoing sender field only; target exclusion and reply validation stay on the interface identity) + 1 test |
| `src/discovery/arp/mod.rs` | re-export `build_arp_request_to` |
| `docs/poc/poc-report.md` | new — the master PoC report (all Appendix D tables, analysis, limitation catalog, G-1 recommendation) |
| `docs/poc/data/` | new — 21 files: the raw per-run records (15 campaign JSONs + the 2 T-106 baseline A/B JSONs) and the 4 isolated-Wi-Fi stand-in output captures (synthetic identifiers only) |
| `docs/adr/009-discovery-transport-library.md` | Pending → **Accepted** (`pnet_datalink` 0.35.0 final; measured `ETH_P_ALL` cost; `ETH_P_ARP` alternative evaluated) |
| `docs/adr/010-neighbor-table-source.md` | Pending → **Accepted** (`/proc/net/arp` stands; netlink not adopted in 0.1.0) |
| `docs/adr/011-probe-strategy.md` | Pending → **Accepted** (defaults re-pinned from data; unicast refresh not adopted) |
| `docs/adr/index.md` | statuses + the pending-decisions note updated |
| `docs/poc/README.md` | points at the report and the data directory |

`tests/netns/`, `Cargo.toml`, `Cargo.lock`, `plan.md`, CI: **untouched** (§5, constraint compliance).

## 4. Verification results

### 4.1 Engineering gates (§11.3)

```text
$ cargo fmt --check
(no output; exit 0)

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.39s   (exit 0)

$ cargo test --locked --all-features
     Running unittests src/lib.rs
test result: ok. 191 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.10s
     Running unittests src/main.rs
test result: ok. 0 passed; 0 failed
     Running tests/netns/main.rs (harness = false; no gate variable)
netns suite: skipped (OSZA_NETMON_TESTS is not set; …)
     Doc-tests osza_netmon
test result: ok. 9 passed; 0 failed

$ cargo test --locked --all-features --examples        # the two boundary binaries
     Running unittests examples/poc_discover.rs
test result: ok. 7 passed; 0 failed
     Running unittests examples/poc_measure.rs
test result: ok. 11 passed; 0 failed

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
   Generated target/doc/osza_netmon/index.html          (exit 0)

$ cargo audit
    Scanning Cargo.lock for vulnerabilities (194 crate dependencies)
    (no vulnerabilities; exit 0)

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok          (exit 0)

$ SPDX header check (find . -name '*.rs' -not -path './target/*')
SPDX OK (all .rs files)
```

Test-count movement vs T-106's 188 lib tests: **+3** (2 codec, 1 scanner — the T-105 toggles); the
new example adds 11 of its own. Nothing was weakened or deleted.

### 4.2 The T-106 suite, re-run in this environment (measurement base)

```text
$ unshare --user --map-root-user --net bash -c 'OSZA_NETMON_TESTS=1 cargo test --locked \
    --all-features --test netns -- --test-threads=1 --nocapture'
netns suite: 12 scenario(s), 0 failure(s), 37.9s total
```

Matches the T-106/T-106-RW1 reports (12/12, 38 s) — the campaign ran on the
reference environment.

### 4.3 The S8/S9 baseline, reproduced and checked for determinism

```text
$ OSZA_NETMON_TESTS=1 cargo test … --test netns -- --measure --run-tag t105-base-a   (212.7s)
$ OSZA_NETMON_TESTS=1 cargo test … --test netns -- --measure --run-tag t105-base-b   (212.9s)
measure: 45 records across 15 cells …
```

A/B comparison over recall, packets, accepts, duplicates, extras, drops and
rejection tallies: **0 differences**. Committed as
`docs/poc/data/netns-measure-t105-base-{a,b}.json`.

### 4.4 The campaign (all commands in poc-report §2.5)

15 experiment invocations, 543 records, **0 failed cells** (the S9 grid's 81 records are 9 unique variant × passes combinations run three times with identical results — an incidental determinism re-check): S1/S2/S4 grids
(54+54, 54+54, 108 records), S9 (81 + 54), periodic-10 (40), sender-ip (24),
unicast (5), late (1), transport (4), neighbor (5), observe (2), iface-flip
(3). Zero extras and zero rejected replies across all campaign records.

### 4.5 Harness self-consistency

The defaults cell (S2/P0/100pps/2p) reproduces the T-106 baseline
cell-for-cell (100% / 256 packets / 3574 ms sweep / seed 2129465441), and
S4/P0 matches identically (100% / 14 / 1131 ms) — the campaign binary drives
the same seeds through the same responder binary.

### 4.6 Data-over-preference audit

Every ADR recommendation cites its measurement table: ADR-009 → poc-report
§5.1–§5.4; ADR-010 → §6.1–§6.4; ADR-011 → §4.1–§4.5 and §3.2. No decision
rests on an unmeasured claim; the one qualitative input (maintenance cadence
of `pnet_datalink`) is the plan's own recorded observation, contained behind
the `ArpTransport` trait.

## 5. Deviations from the task card

1. **The Owner's isolated-Wi-Fi session was not executed against the real
   network by this agent.** Plan §13 assigns the "one human-run observation"
   to the Owner; the sandboxed executor has no access to that network. In
   its place: a netns stand-in with the same shape (client isolation
   modeled: one answering gateway, one infrastructure peer, 252 silent
   addresses) driven through the T-104 `poc_discover` binary in **both**
   privilege modes (the read-only run via a `CAP_NET_RAW`-dropping driver),
   plus the exact runbook for the human session (poc-report §7.2). AC-4 is
   marked "Met on the stand-in; the real session is human-run per plan
   §13" rather than silently claimed.
2. **`docs/poc/data/` (raw JSON records + output captures) was added**
   beyond the card's deliverable list, so the report's tables are
   independently checkable and the campaign is reproducible record-for-record
   (the card demands "all raw data tables"; the JSONs are those tables'
   source). All identifiers are RFC 5737 / `02:…` synthetic.
3. The `ETH_P_ARP`-bound alternative could not be implemented as a real
   transport (that is the ADR-009 finding, not a shortcut): it was measured
   at the kernel level with a Python `AF_PACKET` witness socket (dev-only
   tooling inside the lab; no project code, no dependency), which counts
   what a kernel EtherType binding would deliver — poc-report §5.2.

## 6. Decisions and assumptions

* **T-106 harness "as-is"** (card §4): `tests/netns/` is untouched; the
  campaign re-execs its test binary in `--responder` mode with generated
  configs in the documented format. The lab-setup recipe (veth + nested
  `unshare --net` + PID move) is mirrored in the example — the only way to
  drive that responder with experimental scan parameters without modifying
  the harness.
* **T-105 additions to the impairment vocabulary** (fixed delay for the
  pass-2 snapshot experiment, background traffic, pre-traffic, pinned peer
  MAC) are serialized in responder configs and recorded per run; they extend
  the *config*, never the harness code.
* **Grid partitioning** (six `grid` invocations by scenario/profile halves)
  exists only to fit execution-time budgets; each invocation is a complete
  experiment with its own artifact set, and the seeds make cells
  order-independent.
* **S9 rate-variant cells** run at passes=2 only (the pass dimension is
  covered at 100 pps) — the S9 question is behavioral, not rate-sensitive;
  the grid's rate-independence finding (§4.1) covers the rest.
* Assumption: CPU deltas at 10 ms tick granularity bound the per-frame
  filter cost from above (poc-report §9 L-9 states this explicitly).

## 7. Dependencies

None added. The campaign runs on the existing, exact-pinned tree
(`pnet_datalink =0.35.0`, `caps =0.5.6`, `nix =0.31.3`, `ratatui =0.30.2`,
`thiserror`); `Cargo.toml`/`Cargo.lock` are untouched. Dev-only tooling
added by this task: the Python witness/background/pre-traffic scripts are
embedded as constants in `examples/poc_measure.rs` and executed only inside
the netns labs (documented in poc-report §5.2/§2.2). The netlink-crate
evaluation (ADR-010) used `cargo add --dry-run` probes outside the repo —
nothing was added.

## 8. Plan Questions

None. The card, Appendix D and the T-106 harness documentation were
sufficient; the two genuine ambiguities (how to drive the unmodified
responder with experimental toggles; who runs the Owner's session) are
resolved by the card's own text ("use it as-is" → subprocess re-exec; plan
§13 → the Owner) and recorded as deviations 1–3 rather than escalated.

## 9. Security and privacy notes

* Active probing happened **only** inside the T-106 netns environment (and
  the stand-in lab, which is the same mechanism); no non-designated network
  was touched (card §8; verified: every lab lives in the wrapper's
  namespace and dies with it).
* All addresses are RFC 5737 documentation addresses; all synthetic MACs
  are locally administered `02:…`; the committed captures contain no real
  identifiers (the observe stand-in models the Owner's network shape with
  synthetic values only).
* The `drop-netraw-exec` driver uses the approved `caps` crate exactly as
  the T-106 S7(a) probe does (CAP_NET_RAW removed from all five sets before
  the child runs); it grants nothing.
* No `unsafe` in project code (lint-forbidden); no new dependency surface
  (§7); `cargo audit`/`cargo deny` green.
* The witness socket (Python, `AF_PACKET`/`ETH_P_ARP`) receives frames only
  inside the lab namespace and writes only counts.

## 10. Known issues and limitations

* The Owner's real Wi-Fi session is pending (deviation 1) — the runbook is
  poc-report §7.2; T-406 will fold the result into the acceptance matrix.
* Harness asymmetry L-4 (veth raw sockets see `PACKET_OTHERHOST` frames
  that real NICs filter): it makes the U4 unicast-rotation result
  *optimistic* for the helper half; the ADR-011 conclusion uses the kernel
  half (0 of 10), which models real devices correctly.
* S1's kernel half cannot be impaired by the harness (L-3); the fully
  impaired /24 scenario S2 carries the gate's weight.
* The pnet mid-scan failure string ("Unexpected poll event") is opaque
  (ADR-009 consequence note) — classification and boundedness are correct.

## 11. Suggested follow-ups

1. **Owner runbook execution** (poc-report §7.2) before or during T-406;
   record the output, redacted, into `docs/test-matrix.md`.
2. **T-405**: carry poc-report §9 into `docs/limitations.md`, including the
   R-15 wording ("validated on synthetic networks and one client-isolated
   Wi-Fi network") for release notes.
3. **ADR-009 follow-up note** (T-204/T-301 era): map pnet's opaque fatal
   error to `InterfaceLost` at the transport boundary (one `match` in
   `transport.rs`), keeping the classification honest with a better message.
4. **Backlog candidate** (plan §18): unicast refresh of known devices
   *in addition to* periodic broadcast rediscovery — the measured 24×
   packet saving (§4.4) with the rotation blindness documented; needs its
   own ADR if ever taken.
5. Consider a `--measure`-style flag sweep inside the netns CI job for the
   campaign's headline cells (S2 × P0–P2 × defaults) so G-1 evidence stays
   continuously green — the T-106 pattern extended by one flag set.
