# Execution Report — T-104 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-01 · **Branch/commits:** `task/T-104-arp-scanner-privileges`, based on `task/T-103-arp-codec` (open PR #9, commit `60de97b` — this task depends on T-103's codec) — `836a08f` (dependencies, PQ-1), `5f43bb1` (privilege handling), `0048e63` (transport, scanner, worker), `407df67` (example), plus this report · **Plan version:** 1.3.0 (repository copy)

## 1. Summary (≤ 5 lines)

The active ARP discovery engine of plan §6.3 FR-DS-03…11 is implemented behind the transport-agnostic `ArpTransport` trait: `discovery::arp::{transport, scanner, worker}` plus `discovery::privilege` (AF_PACKET socket open, capability drop, `/proc/thread-self/status` verification). Two new crates were added under one consolidated Plan Question (PQ-1, the T-101 precedent): `pnet_datalink =0.35.0` (the only §9.1 transport candidate whose bind/send/recv path needs no `unsafe` of our own; it opens `ETH_P_ALL`, so the scanner carries the mandatory software EtherType filter) and `caps =0.5.6` (capability clearing), plus the `process` feature of the already-approved `nix` (for `prctl(PR_SET_NO_NEW_PRIVS)`). 62 new library tests (60 run + 2 `#[ignore]` privileged) and 7 example tests; every §11.3 gate green; a two-namespace synthetic lab run discovered 4 devices (2 kernel + 2 helper responder, distinct MACs) with the capability drop verified in the run output.

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-1 `ArpTransport` object-safe, `Send + Sync` | Met | `transport::tests::trait_objects_are_object_safe_and_shareable` — a `&dyn ArpTransport` is passed to a `fn assert_send_sync<T: Send + Sync + ?Sized>` and a `Box<dyn ArpTransport>` is moved across a `std::thread::spawn` boundary; the trait declares `Send + Sync` as supertraits (compile-time). |
| AC-2 target generation | Met | `scanner::tests::targets_of_a_24_exclude_network_broadcast_and_own_ip` (own IP inside), `targets_of_a_30_are_the_two_hosts_minus_our_ip` (own IP outside), `targets_of_a_31_use_both_addresses_rfc3021`, `targets_of_a_32_are_empty`, `targets_are_lazy_a_huge_scope_costs_nothing` (a /8 — 16,777,214 hosts — yields its first three targets instantly; the generator is a plain iterator, never a `Vec`). |
| AC-3 pacing | Met | `pacing_enforces_the_configured_interval_lower_bound` (13 sends, every gap ≥ 9 ms at 100 pps, span ≥ 108 ms), `rate_zero_is_clamped_to_one_packet_per_second` (gap ≥ 950 ms), `rate_is_clamped_to_one_pps_minimum_and_500_maximum` (0→1, 500→500, 501→500, `u32::MAX`→500), `send_intervals_match_the_reference_rates`, `deadline_math_never_compensates_a_late_wakeup_with_a_burst` (pure function: a missed deadline is never caught up — the next deadline is `max(prev, now) + interval`). Live: the lab scan sent 502 requests in 7.56 s. |
| AC-4 multi-pass | Met | `pass_two_probes_only_non_responders_after_the_gap` (pass-2 frames parsed from the send log: only the 4 non-responders, gap really waited ≥ 150 ms), `all_responded_skips_remaining_passes_and_the_gap` (3 passes requested, `passes_run == 1`, elapsed < the 300 ms gap, deterministic via the fake's `send_lag`), `a_full_scan_discovers_every_responder` (no request is ever repeated when everyone answers). |
| AC-5 solicited-only | Met | `replies_for_addresses_nobody_asked_are_rejected` (in-scope, not-yet-probed IP → `InvalidReply::NotSolicited`, deterministic at 4 pps), `a_fast_reply_to_a_just_sent_request_is_accepted` (solicited-before-send ordering), `replies_from_outside_the_scope_are_rejected_as_out_of_scope` (condition order). |
| AC-6 response cap | Met | `the_response_cap_drops_excess_replies_without_failing_the_scan` (cap 3: accepted 3, `cap_dropped` 20 across both passes, outcome stays `Complete`, pass 2 still runs 10 requests). |
| AC-7 listen window | Met | `a_late_reply_inside_the_listen_window_is_accepted` (reply at 150 ms, window 400 ms → accepted), `a_reply_after_the_listen_window_is_not_received` (reply at 150 ms, window 30 ms → accepted 0, `Complete`). |
| AC-8 cancellation ≤ 250 ms | Met | `cancelling_while_sending_returns_promptly` (1 pps, /22 scope — uncancelled ≈ 17 min; returns < 280 ms with the flag set at ~15 ms), `cancelling_in_the_pass_gap_returns_promptly` (600 ms gap), `cancelling_in_the_listen_window_returns_promptly` (800 ms window), `cancelling_while_blocked_in_recv_returns_promptly` (fake `recv` parks the full poll), `a_cancelled_scan_reports_the_work_done_so_far`. All waits are `CANCEL_SLICE` (≤ 50 ms) loops with flag checks. |
| AC-9 outcome classification | Met | `a_full_scan_discovers_every_responder` (`Complete`), `a_transient_send_error_makes_the_outcome_partial` (`Partial`), `a_fatal_send_error_fails_the_scan_with_the_reason` and `a_fatal_receive_error_fails_the_scan` (`Failed` + reason; no listen window), `every_send_failing_transiently_fails_the_scan` (`requests_sent == 0 && send_errors > 0`), all cancellation tests (`Cancelled`); first-terminal-event-wins via a check-and-set `Mutex<Option<Terminal>>` shared by both threads. |
| AC-10 socket open | Met | `open_raw_socket_reports_a_missing_interface`, `open_raw_socket_maps_eperm_to_permission_denied` (skips itself if the runner holds `CAP_NET_RAW`); privileged: `#[ignore]` `privileged_open_raw_socket_succeeds_and_drop_verifies` and the lab run (§4: opened with the namespace's `CAP_NET_RAW`). |
| AC-11 CapEff/CapPrm/CapInh/CapAmb = 0 | Met | `#[ignore]` `privileged_open_raw_socket_succeeds_and_drop_verifies` (dedicated thread; asserts all four sets zero); `verify_dropped_catches_every_residual`; live evidence: the lab run prints `CapInh=0000000000000000 CapPrm=0000000000000000 CapEff=0000000000000000 CapAmb=0000000000000000` after `drop_capabilities` (§4). |
| AC-12 NoNewPrivs set | Met | Same tests assert `NoNewPrivs: 1`; the lab and read-only runs print `NoNewPrivs=1`. |
| AC-13 example runs and prints | Met | Lab run in §4: observations (`192.0.2.2 … (arp reply)`) plus a counters/outcome summary, exit 0. |
| AC-14 read-only fallback; fail-closed drop | Met | Read-only: §4 unprivileged run on the host's `eth0` — `no CAP_NET_RAW: starting in read-only mode…`, neighbor table only, exit 0. Fail-closed: the example exits 1 without scanning if `drop_capabilities` or its verification fails (code path); the verification's rejection side is unit-tested (`verify_dropped_catches_every_residual`, `privileged_drop_fails_closed_verification_catches_residual` — `#[ignore]`). A live prctl failure could not be produced in the lab (see §10). |
| AC-15 engineering gates | Met | §4: fmt, clippy `-D warnings`, test, doc (`RUSTDOCFLAGS="-D warnings"`), audit, deny — all exit 0; plus the MSRV build (`rustup run 1.89.0 cargo build --locked`, exit 0). |
| AC-16 no `unsafe` in our code | Met | `grep -rnw "unsafe" src/discovery/ examples/` → no matches; `grep -n "forbid(unsafe_code)" examples/poc_discover.rs` → line 2; the crate-level `unsafe_code = "forbid"` lint stays green. Dependency `unsafe` is evaluated per §9.2 in §7. |
| AC-17 no println/eprintln outside tests/example | Met | `cargo clippy --locked --lib --all-features -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::print_stdout -D clippy::print_stderr` → exit 0. The coarse grep finds 2 `eprintln!` hits — both inside `#[cfg(test)]` modules (`privilege.rs:686,711`, skip notices), permitted by `clippy.toml`. The example carries narrowly scoped `#![allow(clippy::print_stdout, print_stderr)]` (deviation 10). |
| AC-18 SPDX header | Met | CI-mirror loop over all `.rs` files: "SPDX OK (all files)"; the in-scope loop over `src/discovery`+`examples` printed no MISSING lines. |
| AC-19 manual lab run | Met | §4: two-namespace synthetic lab (veth pair, `192.0.2.0/24`), 4 devices discovered — `.2`/`.3` by the responder namespace's kernel (same MAC, the documented multi-address case) and `.5`/`.7` by a helper responder with distinct synthetic MACs; `outcome=complete`, exit 0. No real network was probed (plan §14.3 rule 7). |
| AC-20 worker | Met | `a_scan_streams_batches_and_finishes_with_a_summary`, `a_single_observation_is_flushed_within_the_50ms_deadline` (flush at < 200 ms while the scan runs 600 ms — the timer, not scan end, delivered it), `batches_never_exceed_the_documented_maximum_size` (254 observations, all batches ≤ 32), `cancel_takes_effect_while_the_event_channel_is_full` (2,046 observations fill the 64-event channel; cancel still ends the scan; `ScanFinished(Cancelled)` delivered after draining), `shutdown_joins_cleanly_while_a_scan_is_running` (join < 5 s during a 1 pps scan), `a_stale_cancel_does_not_abort_the_next_scan`, `the_command_queue_is_bounded`. |
| AC-21 no unwrap/expect/panic | Met | The lib-only clippy run with `-D clippy::unwrap_used -D clippy::expect_used -D clippy::panic` (part of the crate's `[lints]`) exits 0; all grep hits are inside `#[cfg(test)]` (listed in §4). |
| AC-22 no upward dependencies | Met | `grep -rnE "crate::(registry|app|ui)" src/discovery/` → no matches. `AppEvent` does not exist yet: the worker emits `discovery::arp::worker::DiscoveryEvent` (re-exported as `discovery::DiscoveryEvent`); T-205 maps it — Plan Question PQ-3. |
| AC-23 no unapproved dependency | Partial (see PQ-1) | One consolidated Plan Question (PQ-1, §8) was raised for all dependency changes **before** anything was added to `Cargo.toml`, following the T-101 precedent (its PQ-1 was likewise resolved in-report): `pnet_datalink` + `caps` + the `nix` feature addition. The §9.2 evaluation of every considered crate (chosen and rejected) is in §7. The card itself directs this task to use a capability library ("Use a capability library (candidates: `caps`, `capctl`)") and ADR-005 point 7 assigns that choice to T-104, which is why PQ-1 is marked non-blocking and applied; the Manager's ratification (or veto, cost confined to `Cargo.toml`/`Cargo.lock`) is requested with this report. |

## 3. What changed

On `task/T-104-arp-scanner-privileges` (base: `task/T-103-arp-codec` @ `60de97b`, whose codec this task consumes):

- `836a08f` — the dependency decision (PQ-1):
  - `Cargo.toml` — `pnet_datalink = "=0.35.0"` (provisional production transport, behind the trait, ADR-009 stays Pending), `caps = "=0.5.6"` (capability clearing), and the `nix` entry gains the `process` feature (same crate, same `=0.31.3` pin, no new transitive dependency) for `nix::sys::prctl::set_no_new_privs`; every entry carries the reasoning comment and PQ-1 reference.
  - `Cargo.lock` — +58 lines, **6 new crates**: `caps`, `pnet_datalink`, `pnet_base`, `pnet_sys`, `ipnetwork`, `no-std-net` (`serde`/`serde_core` were already locked for the ratatui tree).
- `5f43bb1` — `src/discovery/privilege.rs` (786 lines incl. tests) — `open_raw_socket` (interface lookup, non-promiscuous Layer-2 channel, `EPERM`→`PermissionDenied`), `drop_capabilities` (no_new_privs → ambient → bounding-if-CAP_SETPCAP → inheritable/effective/permitted, then SR-06 verification), the pure, total `parse_thread_status` (`&str` → `ThreadCapsStatus`), `read_thread_status`, `RawSocket` (opaque, `Send`), `PrivilegeError`; 12 tests (10 + 2 `#[ignore]` privileged); `src/discovery/mod.rs` gains `pub mod privilege` + re-exports.
- `0048e63` — the sweep engine:
  - `src/discovery/arp/transport.rs` (528 lines) — the `ArpTransport` trait (object-safe, `Send + Sync`, transport-agnostic), `TransportError` (fatal vs transient, `from_io` classification), `LinuxArpTransport` (one mutex per direction, 1 ms-park receive loop honoring per-call timeouts, zero-timeout = one true poll); 8 tests.
  - `src/discovery/arp/scanner.rs` (1,725 lines) — `ArpScanner` (lazy target generation with `/31`//`/32` handling, deadline pacing, multi-pass with pass-start non-responder snapshots and pre-gap skip, `std::thread::scope` receive thread with solicited-before-send `RwLock` set, dedup, response cap, listen window, ≤ 50 ms cancel slices, first-terminal-event outcome classification), `Observation`/`ScanOutcome`/`ScanCounters`/`ScanResult`, the EtherType software filter; 34 tests.
  - `src/discovery/arp/worker.rs` (824 lines) — `ArpWorkerHandle` (bounded command/event channels, fresh per-scan cancel flag created at `start_scan`, `cancel()` that works mid-scan, shutdown + join on drop, named thread), the FR-DS-10 flusher thread (50 ms age deadline independent of arrivals, ≤ 32 batch size), the no-uninterruptible-blocking delivery loops, `ScanParams`/`ScanCommand`/`DiscoveryEvent`/`ScanSummary`/`WorkerError`; 8 tests.
  - `src/discovery/arp/mod.rs` — module registration, re-exports, and the shared `#[cfg(test)] test_support` (`FakeTransport` + reply-frame builder, synthetic identities).
- `407df67` — `examples/poc_discover.rs` (377 lines) — the PoC CLI: argument classification, interface lookup + scope guard (prefix shorter than /16 refused via `ABSOLUTE_MAX_HOSTS`), socket open with read-only fallback, fail-closed capability drop with printed verification, neighbor read, 2-pass sweep at 100 pps through the worker, observation and summary printing; 7 embedded tests (argument handling, exit codes, ADR-011 profile, scope-guard math).
- this commit — `docs/reports/T-104/execution-01.md`.

`plan.md`, `src/lib.rs`, `src/main.rs`, `src/net/`, `src/model/`, `src/discovery/neighbor_table.rs`, `src/discovery/arp/codec.rs`, `deny.toml` and the workflows are untouched. `src/lib.rs` needed no change: `discovery`, `net` and `model` were already publicly reachable (card §2.1 preflight item 5).

## 4. Verification results

All commands ran 2026-11-01 with the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 reinstalled at the CI pins from SHA-256-verified release tarballs, as in T-101). Every dependency-resolving command used `--locked`; `cargo fmt --check` runs without it (cargo-fmt rejects the flag).

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.71s
[exit 0]

$ cargo test --locked --all-features
test result: ok. 188 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out
test result: ok. 0 passed 0 failed   (bin target)
test result: ok. 9 passed 0 failed   (doctests)
[190 lib tests: 62 new for T-104 (60 run + 2 #[ignore]) + 128 pre-existing; 9 doctests pre-existing]

$ cargo test --locked --all-features --all-targets   (additionally: example-embedded tests)
test result: ok. 188 passed; 0 failed; 2 ignored   (lib)
test result: ok. 7 passed; 0 failed                 (example poc_discover)
[Note: plain `cargo test` compiles examples but does not run their #[cfg(test)] modules;
 --all-targets does. CI's `cargo test` covers the lib+doc targets; the example's 7 tests
 run under --all-targets, which is part of this task's verification (deviation 11).]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Generated …/target/doc/osza_netmon/index.html
[exit 0]

$ cargo audit
    Loaded 1395 security advisories (from /home/z/.cargo/advisory-db)
    Updating crates.io index
    Scanning Cargo.lock for vulnerabilities (194 crate dependencies)
[exit 0 — no vulnerabilities, no unmaintained findings, no yanked crates]

$ cargo deny check
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — no new warnings relative to the T-103 baseline: the pre-existing
 `duplicate syn` + `license-not-encountered` warnings of T-000 remain, unchanged]

$ rustup run 1.89.0 cargo build --locked     (MSRV, as in CI's msrv job)
    Finished `dev` profile [unoptimized + debuginfo] target(s)
[exit 0 — caps 0.5.6 declares rust-version 1.63; pnet_datalink 0.35.0 predates it]

$ grep -rnw "unsafe" src/discovery/ examples/ || echo "No unsafe found"
No unsafe found
$ grep -n "forbid(unsafe_code)" examples/poc_discover.rs
2:#![forbid(unsafe_code)]

$ cargo clippy --locked --lib --all-features -- -D warnings \
    -D clippy::unwrap_used -D clippy::expect_used \
    -D clippy::print_stdout -D clippy::print_stderr
    Finished `dev` profile [unoptimized + debuginfo] target(s)
[exit 0 — production code is mechanically clean]

$ grep -rnE "println!|eprintln!|dbg!" src/discovery/ --include="*.rs"
src/discovery/privilege.rs:686:            eprintln!("skipping: this test process holds CAP_NET_RAW");
src/discovery/privilege.rs:711:            eprintln!("skipping: this test process holds capabilities");
[2 hits, both inside #[cfg(test)] skip notices — acceptable per clippy.toml]

$ grep -rnE "\.unwrap\(\)|\.expect\(|panic!|todo!|unimplemented!" src/discovery/ --include="*.rs"
[99 hits — all inside #[cfg(test)] modules of privilege.rs, scanner.rs, worker.rs,
 transport.rs, arp/mod.rs and the T-102/T-103 files (read-only for this task);
 verified mechanically: a line-by-line scan of every hit against the nearest
 #[cfg(test)] boundary finds 0 non-test, non-comment matches — and the lib-only
 clippy run above is the authoritative zero-violation proof for non-test code]

$ grep -rnE "crate::(registry|app|ui)" src/discovery/ || echo "No upward dependencies"
No upward dependencies

# SPDX check (CI mirror): all .rs files under the repository
SPDX OK (all files)
```

### 4.1 Manual lab run (AC-19, §9.1) — authorized synthetic network only

**Environment adaptation (deviation 12):** this sandbox has no `sudo`, so the card's `ip netns add` recipe was adapted to unprivileged user namespaces: the whole lab runs inside `unshare --user --map-root-user --net` (the process is root *inside* its own user+network namespace — that is where `CAP_NET_RAW` comes from: user-namespace root, not host root), and the second namespace is created by a nested `unshare --net` whose veth end is moved with `ip link set veth-b netns $PID`. A helper responder (Python, AF_PACKET — the T-106 "helper responder" pattern) provides the distinct-MAC devices that the card's recipe builds with bridges. All addresses are RFC 5737 documentation addresses and the helper devices' MACs are locally-administered synthetics (`02:00:00:00:00:0X`) — plan §14.3 rule 8. Nothing outside the throwaway namespaces was probed.

```bash
# setup (inside unshare --user --map-root-user --net bash)
ip link add veth-a type veth peer name veth-b
ip addr add 192.0.2.1/24 dev veth-a && ip link set veth-a up
unshare --net bash -c 'echo $$ > /tmp/netns-pid; while [ ! -e /tmp/netns-go ]; do sleep 0.05; done;
    ip link set lo up; ip addr add 192.0.2.2/24 dev veth-b; ip addr add 192.0.2.3/24 dev veth-b;
    ip link set veth-b up; python3 …/arp_responder.py veth-b; sleep 60' &
ip link set veth-b netns "$(cat /tmp/netns-pid)"; touch /tmp/netns-go
./target/debug/examples/poc_discover veth-a
# cleanup: exit the namespace (everything disappears with it)
```

`arp_responder.py` (helper, synthetic MACs, answers requests for `192.0.2.5`/`192.0.2.7`):

```python
ANSWERS = {bytes([192,0,2,5]): bytes.fromhex("020000000005"),
           bytes([192,0,2,7]): bytes.fromhex("020000000007")}
# AF_PACKET socket bound to the interface; for each ARP request whose
# target IP is in ANSWERS, send: eth(dst=requester, src=reply_mac) +
# ARP reply(sha=reply_mac, spa=tpa, tha=requester, tpa=spa)
```

**Run output (the example's own verification lines included):**

```text
=== capabilities before the run (/proc/self/status of the lab shell) ===
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
NoNewPrivs: 0

=== ./target/debug/examples/poc_discover veth-a ===
osza-netmon PoC discovery (no TUI)
interface: veth-a (mac 22:c7:5a:17:47:c2, ip 192.0.2.1/24, scope 192.0.2.0/24)
privileges after drop: CapInh=0000000000000000 CapPrm=0000000000000000 CapEff=0000000000000000 CapBnd=0000000000000000 CapAmb=0000000000000000 NoNewPrivs=1
neighbor table: 0 entrie(s)
scan: 2 passes at 100 pps, listen window 1.5s
192.0.2.2 2e:ef:d3:bb:25:ad (arp reply)
192.0.2.3 2e:ef:d3:bb:25:ad (arp reply)
192.0.2.5 02:00:00:00:00:05 (arp reply)
192.0.2.7 02:00:00:00:00:07 (arp reply)
summary: outcome=complete
summary: targets=502 sent=502 send_errors=0 (transient=0 fatal=0) accepted=4 rejected=0 duplicates=0 cap_dropped=0 passes=2
summary: replies: accepted=4 rejected=0
summary: elapsed 7.559225864s (0 neighbor observation(s) printed before the sweep)
exit code: 0
```

Reading of the numbers: 253 probe targets (254 hosts minus our own address) → pass 1 sends 253, pass 2 sends the 249 non-responders → 502 requests; elapsed 7.56 s ≈ 2 × 2.5 s of paced sending + the 1 s pass gap + the 1.5 s listen window (the ADR-011 defaults exercised end to end). `192.0.2.2`/`.3` are answered by the responder namespace's kernel with veth-b's MAC (the card's "several addresses on one interface answer with the same MAC" case); `.5`/`.7` come from the helper responder with distinct synthetic MACs. The capability lines prove SR-06 live: full capability sets before, all-zero `CapEff`/`CapPrm`/`CapInh`/`CapAmb` (and `CapBnd`, cleared because user-namespace root holds `CAP_SETPCAP`) and `NoNewPrivs=1` after.

**Privileged `#[ignore]` tests** (exact command used):

```text
$ unshare --user --map-root-user --net cargo test --locked --all-features -- --ignored
running 2 tests
test discovery::privilege::tests::privileged_drop_fails_closed_verification_catches_residual … ok
test discovery::privilege::tests::privileged_open_raw_socket_succeeds_and_drop_verifies … ok
test result: ok. 2 passed; 0 failed
```

**Read-only fallback (AC-14)** — the unprivileged host user (no capabilities at all) on the sandbox's own `eth0`:

```text
$ ./target/debug/examples/poc_discover eth0          # as uid 1001, host namespace
osza-netmon PoC discovery (no TUI)
interface: eth0 (mac 46:c0:77:1a:2b:b2, ip 21.0.19.91/32, scope 21.0.19.91/32)
privileges after drop: CapInh=0000000000000000 CapPrm=0000000000000000 CapEff=0000000000000000 CapBnd=00000000a80425fb CapAmb=0000000000000000 NoNewPrivs=1
neighbor table: 0 entrie(s)
mode: read-only (no ARP sweep)
summary: read-only cycle, 0 neighbor-table observation(s)
exit code: 0
stderr: no CAP_NET_RAW: starting in read-only mode (neighbor table only); grant it with: setcap cap_net_raw+ep <binary>
```

(Also live evidence for the documented bounding-set limitation: without `CAP_SETPCAP`, `CapBnd` keeps its residual mask — `00000000a80425fb` — while `NoNewPrivs=1` prevents any re-grant.)

**Error paths (exit codes):** missing interface → exit 2 (`no interface named "osza-no-such-iface" exists`); no argument → exit 2 (usage); scope `/15` → exit 2 (`scope 192.0.0.0/15 is too large for this example: network has 131070 usable hosts, above the cap of 65534`).

## 5. Deviations from the task card

1. **Two new crates and one feature addition applied under a raised, non-blocking Plan Question (PQ-1).** The card §2.1 requires the consolidated Plan Question *before* adding anything to `Cargo.toml`; like T-101 (whose PQ-1 was resolved inside its report and ratified by the Manager's ACCEPT), the evaluation and the addition travel together — the alternative (option 3 in PQ-1's options) would have delivered the entire active-discovery half of this task behind fakes only. The rework cost of a veto is confined to `Cargo.toml`/`Cargo.lock` and the one production module.
2. **`worker.rs` lives at `src/discovery/arp/worker.rs`.** Plan §8.1's suggested layout lists `discovery/worker.rs`, but the card's §3.4/R1 explicitly name `src/discovery/arp/worker.rs` ("or the file §8.1 names for it"); §8.1 is marked "suggested" and the repository already deviates from it (`net/interfaces.rs`), so the card's primary path was taken.
3. **`Observation` is defined here, not reused from T-102.** Card §2.1 expected "the observation type [to] already carr[y] a source", but the repository has no such type: T-102 delivered `NeighborEntry` (ip/mac/hw/flags/device — no source) and T-103 delivered `ArpReply` (no source). Plan §5.1/§8.5 define "Observation" as `(MAC, IPv4)` evidence *with its source*, and `model::field::Source` exists for exactly that — so `discovery::arp::scanner::Observation { ip, mac, source }` was created with `Source::ArpReply` for scanner output and `Observation::from_neighbor` bridging T-102 rows (no duplicate type: there was none to duplicate). Raised as PQ-3.
4. **`DiscoveryEvent` instead of `AppEvent`.** `AppEvent` does not exist (T-205 has not run; there is no `app` module), so per card §3.4 the worker defines `DiscoveryEvent { Observations(Vec<Observation>), ScanFinished(Box<ScanSummary>) }` in `discovery::arp::worker`, re-exported at `discovery::DiscoveryEvent` for T-205 to map (PQ-3). The `Box` keeps `clippy::large_enum_variant` green (the summary outweighs a batch ~10:1).
5. **`ETH_P_ALL` + software EtherType filter (anticipated by the card).** `pnet_datalink` cannot select the EtherType when it opens the `AF_PACKET` socket, so the socket hears every frame the interface receives. The scanner's receive loop therefore drops non-ARP frames (EtherType ≠ `0x0806`) *before* T-103's validator — which still enforces FR-DS-06 condition 1 on everything that passes — and does not count them as rejected *replies* (they are other traffic; counting every broadcast frame on a busy LAN would swamp the counters). Promiscuous mode is explicitly disabled. Reported per card §2.1; the deviation from "bound to `ETH_P_ARP`" is a documented input to T-105's ADR-009 decision.
6. **Receive timeout granularity is 1 ms.** `pnet_datalink` fixes its poll timeout at channel construction, so the channel is built in true-poll mode and `LinuxArpTransport::recv` adds the wait itself in ≤ 1 ms park slices: a zero timeout is exactly one non-blocking poll; longer timeouts are honored within one slice of overshoot. Cost: a ~1 kHz wakeup rate *during active scans only*.
7. **Bounding set cleared only when `CAP_SETPCAP` is held.** ADR-005 does not require clearing `CapBnd` (its verification covers CapEff/CapPrm — the card adds CapInh/CapAmb), and `PR_CAPBSET_DROP` fails with `EPERM` without `CAP_SETPCAP`. The card's alternative ("state in the report that it is not covered") applies: the bounding set is narrowed opportunistically (before the effective set is cleared, when the capability is present — as in the root/userns lab, where `CapBnd` reached zero), never counted as a failure otherwise; `NoNewPrivs` prevents a residual bounding set from re-granting anything.
8. **Unknown I/O errors classify as fatal.** The card lists which errors are transient; everything unrecognized maps to `FatalIo` (fail closed) rather than being silently retried. A weird-but-benign errno would end the scan as `Failed` — the conservative choice for a security-sensitive tool.
9. **`MAX_PASSES = 3`.** The card says to clamp `passes` to "the maximum allowed by ADR-011" and to raise a Plan Question if the plan states none. ADR-011 fixes defaults (2 for the initial scan, 1 for periodic) but no maximum; the plan's experiment space is "passes 1/2/3" (Appendix D), which is what the clamp uses. PQ-2 asks the Manager to confirm.
10. **The example carries narrowly scoped `#![allow(clippy::print_stdout, print_stderr)]`.** The crate's `[lints.clippy]` denies printing for *all* targets including examples, and `allow-print-in-tests` covers only test code; the card exempts examples from SR-03 (AC-17: "non-test, non-example code") and the example *is* a print-by-design PoC. Same pattern and justification as `src/main.rs` (T-000 §5.3); scoped to this one file.
11. **Example-embedded tests need `--all-targets`.** CI's `cargo test --locked --all-features` compiles examples but does not run their `#[cfg(test)]` modules; the 7 example tests were verified with `cargo test --locked --all-features --all-targets` (§4). An integration test under `tests/` would have been outside the card's file scope (§4 of the card).
12. **The §9.1 lab recipe was adapted** (no `sudo`/`ip netns` in this sandbox): user+network namespaces via `unshare`, the second namespace via a nested `unshare --net` + `ip link set … netns $PID`, and the distinct-MAC devices via a Python helper responder instead of bridged veth pairs. Functionally equivalent: two kernel stacks, synthetic RFC 5737 addresses, documented in §4.1.
13. **The pre-gap "no non-responders" skip check inherently races in-flight replies.** The check runs immediately after a pass's last send, so the last target's reply may not have been received yet (the card's own "replies keep being received during the gap" acknowledges replies land late). Whichever way the race resolves, pass 2's pass-start snapshot re-evaluates and no answered target is ever re-probed (`requests_sent` is invariant — asserted in `a_full_scan_discovers_every_responder`); the skip itself is made deterministic in `all_responded_skips_remaining_passes_and_the_gap` via the fake's `send_lag`. No other early-exit optimization was added.
14. **`drop_capabilities` also runs in read-only mode.** The card makes it optional ("the read-only fallback can call it too"); running it in both modes means the process never retains capabilities it does not need, and the unprivileged case is idempotent by construction.

## 6. Decisions and assumptions

**Decisions:**

- **D-1 Transport = `pnet_datalink` (provisional, behind the trait).** Of the three §9.1 candidates, it is the only one that can open, bind *and* use the `AF_PACKET` socket with zero `unsafe` in our code (see §7 for the per-candidate analysis: `nix` has no safe `sockaddr_ll` constructor and no `ETH_P_ARP` protocol variant; `socket2` has `Domain::PACKET` + `Protocol::from(i32)` but likewise no safe `sockaddr_ll`). ADR-009 stays Pending (T-105 decides with real data, including the `ETH_P_ALL` cost measured through this very trait); replacing the library is a one-module change.
- **D-2 Capability library = `caps` 0.5.6** over `capctl` 0.2.4: fresher release line (2025-10-17 vs 2024-03-17 — the plan itself notes capctl's cadence), zero new transitive crates (libc only) vs capctl's `bitflags 1.3.2` duplicate, and it passes `cargo deny check` against the unchanged `deny.toml` (license string `MIT/Apache-2.0` is accepted). `no_new_privs` comes from the already-approved `nix` (`process` feature, `nix::sys::prctl::set_no_new_privs`), keeping the new-crate count at one.
- **D-3 `RawSocket` owns the pnet channel halves** and `open_raw_socket` creates them, so the socket is provably open before the capability drop and nothing afterwards needs a privilege (ADR-005 ordering); `LinuxArpTransport::new(RawSocket)` is the only consumer, keeping the library behind the trait.
- **D-4 Fatal/transient classification by errno + kind** (`EPERM`/`EACCES`/`ENETDOWN`/`ENODEV`/`EBADF` fatal; `ENOBUFS`/`EAGAIN`/`EINTR`/poll-timeout transient; unknown fatal), with `TransportError::from_io` total and table-tested.
- **D-5 One mutex per channel direction** in `LinuxArpTransport` (a blocked receive must never stall sending — FR-DS-04 pacing).
- **D-6 Scanner threading per ADR-012:** `std::thread::scope`; the calling thread sends, a named `arp-receive` thread validates and streams; only the solicited set (`RwLock`, written before each send) and the responder set (`RwLock`, snapshotted at pass start) are shared, plus one `Mutex<Option<Terminal>>` that makes outcome classification first-terminal-event-wins by construction (check-and-set). A panicked or unspawnable receive thread is a classified `Failed`, never a panic escape (verified: joining a panicked scoped thread inside the scope returns the `Err` instead of propagating).
- **D-7 `targets` counts send attempts** (one per target-loop iteration that reaches the send call, summed over passes), so `targets == requests_sent + send_errors_transient + send_errors_fatal` always holds — bounded work for huge scopes (no enumeration) and honest numbers for cancelled scans. `passes_run` counts passes whose sending began.
- **D-8 Worker cancel flags are created by the handle at `start_scan`** (not registered by the thread when it picks up the command): there is no window in which `cancel()` could miss the scan it should stop, and every scan gets a fresh flag so stale cancels cannot leak into the next scan (tested).
- **D-9 Delivery policy under backpressure:** mid-scan batches retry `try_send` in ≤ 10 ms steps and may be dropped when the consumer stalls *and* the scan is cancelled; the final flush and `ScanFinished` retry until the receiver disconnects or shutdown is requested (the card's exact rule); a disconnected receiver sets the scan's cancel flag, stopping the scan. `shutdown`/drop set a shared flag *and* send the command, so a busy worker is always interruptible and joined.
- **D-10 The flusher is a per-scan scoped thread** (10 ms tick): the 50 ms deadline must not depend on new observations arriving (FR-DS-10), and the worker thread itself is blocked inside `scan_with_sink`.
- **D-11 The example drops capabilities in both modes** and prints the verification line from its own `/proc/thread-self/status` read (SR-06 evidence in every run).
- **D-12 Scope guard via `host_range_capped(ABSOLUTE_MAX_HOSTS)`** — the card's "shorter than /16" expressed through the plan's own ceiling (65,534 hosts, FR-SC-06) instead of a bare prefix comparison.
- **D-13 `scan_with_sink` leaves `ScanResult::observations` empty** (the card's "empty when streaming"); a cancelled streaming scan's "observations so far" are the ones already sunk — `scan()` is the collecting variant (tested both ways).

**Assumptions** (per plan §0.2, written down):

- The repository's `task/T-103-arp-codec` branch (open PR #9) is the T-103 delivery the card depends on; this branch is based on it and will merge cleanly after PR #9.
- "the maximum allowed by ADR-011" for `passes` does not exist explicitly; Appendix D's "passes 1/2/3" is the plan's stated probe-strategy space (PQ-2).
- The bounding set is out of scope for the SR-06 verification (ADR-005's text and the card's own verification list agree); `no_new_privs` is the compensating control.
- `/proc/thread-self` exists (kernel ≥ 5.4 per plan §3.4; `thread-self` since 3.17).

## 7. Dependencies

**Added (PQ-1, all exact-pinned like the repo's other task-approved crates):**

1. **`pnet_datalink = "=0.35.0"`** — production `ArpTransport`. §9.2 evaluation (criteria in plan §9.2):

   | Criterion | Finding |
   |---|---|
   | 1. Necessity | The smallest alternatives cannot open *and bind* an `AF_PACKET` socket safely: `nix` 0.31.3 exposes no `ETH_P_ARP` `SockProtocol` variant (`#[non_exhaustive]`, only `EthAll`) and its `LinkAddr` has **no public constructor** (the `SockaddrLike` supertrait is sealed, so a custom `sockaddr_ll` cannot be implemented outside nix); `socket2` 0.6.0 has `Domain::PACKET` and `Protocol::from(c_int)` but `SockAddr` constructs only unix/inet/inet6 addresses — no `sockaddr_ll`. Doing it by hand needs `libc` + `unsafe`, which SR-01 forbids. `pnet_datalink` is the smallest crate that opens, binds (interface index), sends and receives with a safe API. |
   | 2. Maintenance | 0.35.0 (2024-05-30), the libpnet line; slow cadence — the plan itself flags it (ADR-009 "do not assume it", risk R-02). `cargo audit`: no advisories, no unmaintained findings. Accepted *as provisional*: fully behind the trait, replaced in one module when T-105 decides ADR-009. |
   | 3. License | `MIT OR Apache-2.0`, like its `pnet_base`/`pnet_sys`/`no-std-net`/`ipnetwork` transitives — all on the `deny.toml` allowlist; `cargo deny check licenses` ok against the **unchanged** allowlist. |
   | 4. `unsafe` footprint | The libc calls (socket/bind/sendto/recvfrom/poll, sockaddr marshalling) live inside `pnet_datalink`/`pnet_sys`; their public API is safe. Our crate stays `#![forbid(unsafe_code)]` (grep-verified). |
   | 5. Transitives / build | 6 new crates in the graph overall (`pnet_datalink`, `pnet_base`, `pnet_sys`, `ipnetwork`, `no-std-net`, `caps`); `serde`/`serde_core` were already locked for ratatui. No async runtime, no build-time data fetching; MSRV build time unchanged. |
   | 6. MSRV | Builds under the repo MSRV 1.89 (`rustup run 1.89.0 cargo build --locked`, exit 0). |
   | 7. Constraints | No runtime network beyond §2.3 (the socket it opens is the tool's own ARP pipe); no build scripts; works unprivileged-with-`CAP_NET_RAW` exactly per ADR-005. |

   How it binds and filters: `channel(&NetworkInterface, Config)` calls `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))`, `bind(sockaddr_ll{sll_ifindex})` and (when configured) `PACKET_ADD_MEMBERSHIP` promiscuous mode. **It cannot restrict the socket to `ETH_P_ARP`** — the deviation card §2.1 anticipates: software EtherType filtering is mandatory (implemented in the scanner's receive loop, deviation 5); promiscuous mode is disabled in our `Config` (FR-DS-07). Send direction: `send_to` polls `POLLOUT` with our 50 ms write timeout, then `sendto(2)` on the bound address — bounded, never indefinite. Receive: the channel is built with read timeout zero (true poll) and `LinuxArpTransport::recv` adds bounded parking (deviation 6). The `&mut` channel halves are wrapped in **separate** `Mutex`es so a blocked receive cannot stall the send side (card §3.1).

2. **`caps = "=0.5.6"`** — capability clearing (ADR-005 step 3). §9.2: necessity — dropping capabilities needs `capset`/`prctl` syscalls; no std path exists and hand-rolled `libc` needs `unsafe` (SR-01); maintenance — 0.5.6 released 2025-10-17 (current line; `cargo audit` clean); license `MIT/Apache-2.0` — accepted by `cargo deny check` against the unchanged allowlist; `unsafe` — prctl/capset calls inside the crate, safe public API; transitives — **none** (uses the already-locked `libc`); MSRV 1.63 < 1.89; no network, no build scripts. Chosen over:

   - **`capctl` 0.2.4 (rejected):** covers the same ground *and* has `prctl::set_no_new_privs`, but its last release is 2024-03-17 (the plan explicitly notes the date), it adds `bitflags 1.3.2` as a duplicate-version warning next to the tree's bitflags 2.x. License `MIT` (fine). With `nix` already approved for prctl, `caps` wins on maintenance and footprint.
   - **`nix` (already approved, ADR-017/PQ-1 of T-101):** provides `prctl::set_no_new_privs` behind its `process` feature — **feature addition only** (same `=0.31.3` pin, no new transitive crates, `Cargo.lock` unchanged by it); `cargo deny`/`audit` unaffected. It was *not* usable as the transport (see above).

   Also evaluated for the transport and rejected on criteria 1/4 (documented above): **`nix`** (no safe `sockaddr_ll` construction, no `ETH_P_ARP` variant) and **`socket2`** 0.6.0 (`Domain::PACKET` + `Protocol::from(htons(ETH_P_ARP))` work, but no safe `SockAddr` for `sockaddr_ll` → cannot bind; verified against the vendored sources).

   No other dependency was added, changed or removed; `ratatui`/`thiserror` untouched; `deny.toml` unchanged (empirically: `cargo deny check` passes with the pre-existing warnings only).

## 8. Plan Questions

- **PQ-1 (dependencies — consolidated, per card §2.1)** · Context: task card §2.1 item 3 and §8/R13: one consolidated Plan Question listing every proposed crate with its §9.2 evaluation, before anything is added to `Cargo.toml` · What the plan says: §9.1 lists the transport candidates (`pnet_datalink`/`nix`/`socket2`, decided by ADR-009 in T-105) and the capability candidates (`caps`/`capctl`, "chosen in T-104 under §9 criteria"), and gates every crate behind Manager approval; ADR-005 point 7 assigns the capability-library choice to this task; the task card itself says "Use a capability library (candidates: caps, capctl) per §2.1" and directs the §9.2 evaluation data into this report for T-105 · Ambiguity/conflict: the approval mechanism cannot complete before the report exists (the same chicken-and-egg T-101 resolved in-report), and the card demands working privileged code (AC-10…14, 19) that is unreachable without the crates · Options with consequences: (1) apply the evaluated choices now and request ratification with this report (applied) — all ACs reachable, one-module rework if vetoed; (2) deliver trait+fakes only and defer the production transport and privilege code — no new deps, but AC-10…14/19 unmet and T-105 loses its §9.2 input; (3) stop the task and wait for an out-of-band decision — cleanest process, slowest, and the report carrying the evaluation *is* the decision input · Executor's recommendation: option 1 (applied): `pnet_datalink =0.35.0` (provisional per ADR-009-Pending, fully behind the trait), `caps =0.5.6`, and the `process` feature of the already-approved `nix =0.31.3` · Blocking? No.
- **PQ-2 (maximum pass count)** · Context: card §3.2 — "`passes` is clamped to a minimum of 1 and to the maximum allowed by ADR-011 (if the plan states none, raise a Plan Question)" · What the plan says: ADR-011 fixes 2 passes for the initial scan and 1 for periodic rediscovery but states no maximum; Appendix D's experiment list is "passes 1/2/3" · Ambiguity: no stated maximum exists · Options: (1) `MAX_PASSES = 3` citing Appendix D's experiment space (applied, `scanner::MAX_PASSES`, tested) — covers every planned configuration; (2) no upper clamp — any `u8` accepted, but a caller typo (255 passes) would sweep for hours (still cancellable, but needlessly); (3) a larger arbitrary bound — invents a number the plan never mentions · Executor's recommendation: option 1; the Manager may re-pin when T-105 reports · Blocking? No.
- **PQ-3 (observation/event types vs. the card's preflight expectations)** · Context: card §2.1 — "the observation type already carries a *source*; reuse it… do not create a duplicate type"; §3.4 — if `AppEvent` does not exist, define a `DiscoveryEvent` and report it as a deviation/Plan Question · What the plan says: §5.1 defines Observation as evidence *with its source* and §8.5's lifecycle emits `Observation* (NeighborTable)` / `Observation* (ArpReply)`; §8.2 permits `discovery` to depend only on `model` and `clock`; `AppEvent` belongs to T-205 (§8.3, §13) · Ambiguity/conflict: the repository has no observation-with-source type (T-102's `NeighborEntry` and T-103's `ArpReply` carry no source field), and `AppEvent` does not exist yet · Options: (1) define `discovery::arp::Observation { ip, mac, source: model::Source }` + converters from both sources, and `discovery::arp::worker::DiscoveryEvent` re-exported as `discovery::DiscoveryEvent` (applied) — matches plan §5.1/§8.5, adds no duplicate type, keeps §8.2 clean, gives T-205 one stable import point; (2) emit raw `ArpReply`/`NeighborEntry` and let T-205 wrap — no new types, but two source-specific shapes for T-205/T-201 to reconcile and no single Observation type for the registry API (FR-RG-03); (3) put `Observation` in `model` — closer to §5.2's illustrative placement but `model` is T-002's closed, std-only boundary and adding discovery vocabulary there exceeds this card's file scope · Executor's recommendation: option 1 (applied); T-205 maps `DiscoveryEvent` onto `AppEvent` when it defines it · Blocking? No.

## 9. Security and privacy notes

- **Untrusted inputs (SR-02/SR-04):** every byte that enters through the transport is validated by T-103's total parser against the per-scan solicited set (FR-DS-06); the non-ARP EtherType pre-filter (deviation 5) drops other traffic before it is even counted. The `/proc/thread-self/status` reader is bounded (64 KiB) and its parser is total — synthetic hostile text (garbled lines, missing fields, wrong types, no newlines, 10 kB single lines) is unit-tested to error, never panic. The example's argument handling is total (non-UTF-8 argv → usage error). No indexing, `unwrap`, `expect` or `panic!` in non-test code (mechanically denied by the crate lints; §4).
- **Privileges (ADR-005, SR-06):** the socket opens first (needs `CAP_NET_RAW`), then `no_new_privs` is set, ambient/inheritable/effective/permitted capabilities are cleared (bounding opportunistically, deviation 7), and the drop is *verified* by parsing the calling thread's own status file — fail closed. The example refuses to scan (exit 1) if the drop or the verification fails, in active and read-only modes alike. Rustdoc states the per-thread contract: call `drop_capabilities` on the main thread before spawning others.
- **Network footprint (§2.3, SR-07):** the only traffic this task can originate is ARP requests inside the confirmed scope, paced and bounded (FR-DS-04); the lab runs used synthetic RFC 5737 addresses inside throwaway namespaces. Promiscuous mode is never enabled; unsolicited and non-ARP frames are dropped, counted only where the plan asks for counters.
- **Supply chain (SR-11):** `Cargo.lock` committed (+58 lines, 6 new crates, all pinned exact at the requirement level); `cargo audit` and `cargo deny check` pass against the unchanged allowlist/bans; MSRV build green.
- **No secrets, no real identifiers:** fixtures and the lab use documentation addresses and locally-administered synthetic MACs; the live evidence in §4 records interface names and synthetic values only (plan §14.3 rule 8).

## 10. Known issues and limitations

- **`ETH_P_ALL` socket (deviation 5):** the production transport receives every frame the interface sees (non-promiscuous: broadcast/multicast/unicast-to-us); each costs one cheap EtherType comparison. The kernel-level `ETH_P_ARP` filter ADR-005 describes is not achievable with `pnet_datalink`; T-105's transport comparison should weigh it.
- **Bounding set not always cleared (deviation 7):** without `CAP_SETPCAP` the bounding set keeps its mask (visible in the read-only run: `CapBnd=00000000a80425fb`); `no_new_privs` is the compensating control. ADR-005's verification deliberately does not cover `CapBnd`.
- **Receive granularity 1 ms (deviation 6):** ~1 kHz wakeups during active scans (never at idle — no scan, no transport).
- **The pre-gap skip check races in-flight replies (deviation 13):** the skip may miss the last target's reply and run a pass that then sends nothing; harmless (no re-probing), documented and tested.
- **Live fail-closed demonstration gap (AC-14):** no way was found to make prctl/capset *fail* in the sandbox lab, so the exit-1 branch of a failed drop is evidenced by code and unit tests (verification rejects residual capabilities; the example's other error paths are exercised live), not by an end-to-end run.
- **Example-embedded tests do not run under plain `cargo test`** (deviation 11) — verified with `--all-targets`; if the Manager prefers them in CI, adding `--all-targets` to the CI test step (or moving them under `tests/` in a later task) is a one-line change.
- **The helper-responder lab variant (deviation 12)** answers in userspace; T-106 is the task that formalizes responder harnesses and impairment profiles — the script used here is a PoC-grade precursor, kept out of the repository (its essence is inline in §4.1).
- **`pnet_datalink` maintenance cadence** (risk R-02): accepted only because the trait isolates it; the §9.2 data T-105 needs (bind/EtherType mechanics, unsafe footprint, transitives) is in §7.
- **`cargo deny`'s acceptance of `caps`' `MIT/Apache-2.0` license string:** it passes the check as configured; a stricter future `deny.toml` (SPDX-strict parsing) might need a clarification entry — noted for T-404's dependency review.

## 11. Suggested follow-ups

1. Manager: resolve PQ-1 (ratify `pnet_datalink`/`caps`/nix-`process`, or order the rework), PQ-2 (`MAX_PASSES = 3`) and PQ-3 (`Observation`/`DiscoveryEvent` placement for T-205 to map onto `AppEvent`).
2. T-105: reuse §7's transport evaluation as the ADR-009 input — in particular the `ETH_P_ALL` + software-filter trade-off and the "no safe `sockaddr_ll` anywhere except pnet" finding; measure this transport through the trait.
3. T-106: formalize the netns lab of §4.1 (the nested-`unshare` recipe works without `sudo`; the Python helper responder is the precursor of the planned responder harness for sleepy/hostile devices).
4. Consider running the example's embedded tests in CI by extending the test step with `--all-targets`.
5. T-201 will want `Observation` to carry the observing `ScanId` when the registry's stale-scan rule (FR-RG-03) lands — the type is the natural extension point.
6. When ADR-009 is decided: if the winner is not `pnet_datalink`, port `LinuxArpTransport` (one module) and drop the EtherType pre-filter only if the new transport truly binds `ETH_P_ARP`.
