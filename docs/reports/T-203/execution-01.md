# Execution Report — T-203 (attempt 01)

**Agent:** E-Vex (executor identity used for all commits) · **Date:** 2026-11-05 · **Branch/commits:** `task/T-203-hostname-resolver`, based on `main` @ `ffbf918` — Commit 0a `9cf6417` (the F-4 recovery merge, Manager-ordered), Commit 0b `3ec2f0f` (plan v1.8.0, Manager update), then the T-203 work: `13008d4` (enrichment hostname resolver — selection policy, PTR client, worker thread + tests), `52c24bc` (fuzz targets dns_response and resolv_conf), plus this report and the ADR-015 record · **Plan version:** 1.8.0 (repository copy)

## 1. Summary (≤ 5 lines)

The hostname enrichment of plan §6.5 FR-EN-03/FR-EN-04 is delivered in `src/enrichment/` behind the plan §8.2 dependency rule (model only): `hostname.rs` (1,192 lines — D-1 resolver selection as a pure total function plus the 64 KiB-bounded std wrapper, and the validating `HostnameConfig` with the ADR-003 defaults), `dns.rs` (1,286 lines — the D-2 PTR codec and production `UdpResolver`: one datagram per attempt, 12..=512 acceptance, bounded compression-pointer walk, first-valid-PTR into `Hostname`), and `worker.rs` (1,407 lines — the D-4 std thread: bounded sync channels, batch-level in-flight dedup, one retry, 5-minute backoff via the injected clock, 4,096-IP cap, ≤ 250 ms shutdown). ADR-015 is decided from §9.2 evidence: **option (a), the hand-rolled codec — no new crate** (the acceptance layer D-2 requires must be ours regardless; `hickory-proto` would add 64 crates and 300+ transitive `unsafe` blocks); the record sits in `docs/adr/015-dns-ptr-client.md` with the Manager-ratification status. 70 new library tests (total 373: 371 pass + the 2 pre-existing privileged ignores) including the two in-process loopback integration tests authorized by the card, plus the two std-only fuzz targets (`dns_response`, `resolv_conf` — 500,000 + 400,000 deterministic inputs, both green with their own summaries). Commit 0 (the F-4 recovery merge + plan v1.8.0) landed first, conflict-free, with all four local gates green on the merged tree (§4.1).

## 2. Acceptance criteria

| AC (card §7) | Status | Evidence (test name, command, file) |
|---|---|---|
| AC-0 Commit 0 exactly as §10 prescribes: conflict-free T-105 recovery merge present; plan at v1.8.0 with the exact edits; four local gates re-run green immediately after (expected 303 lib tests: 301 + 2 ignores), results in report §4 | Met | Pre-flight `git rev-list --count main..origin/task/T-202-vendor-database` → 0; merge `9cf6417` (`git merge --no-ff origin/task/T-105-poc-campaign`, the exact verbatim message, zero conflicts — 32 files, +29,130/−24); plan.md header 1.8.0, O-9 row after O-8, both Status Board rows, the 1.8.0 changelog row after 1.7.0 — all byte-exact per §10.2; commit `3ec2f0f`. Gates on the merged tree (§4.1): fmt exit 0 · clippy exit 0 · test **303 lib tests: 301 pass + 2 ignores** (`discovery::privilege::tests::privileged_drop_fails_closed_verification_catches_residual`, `…privileged_open_raw_socket_succeeds_and_drop_verifies`) + 9 doctests + 9 example tests · doc exit 0. |
| AC-1 All §11.3 gates green on the pinned toolchain; MSRV 1.89.0 build green; SPDX headers on every new `.rs` | Met | §4.2: fmt / clippy `-D warnings` / test / `RUSTDOCFLAGS="-D warnings"` doc all exit 0 on rustc/cargo 1.99.1; `rustup run 1.89.0 cargo build --locked` exit 0; `grep -rLn "^// SPDX-License-Identifier: GPL-3.0-only$" src/enrichment/*.rs fuzz/*.rs` → no output (all seven files carry the header). |
| AC-2 Eligibility unit tests (table-driven, synthetic): in-subnet accepted; off-subnet rejected; `127.0.0.53` stub rejected; IPv6 never eligible; systemd fallback only when every parsed entry is loopback; fallback entries under the same rule; first-in-order wins; none → `NoResolver`; unreadable/oversize/garbage → `NoResolver`, no panic | Met | `in_subnet_entry_is_selected`, `off_subnet_entry_is_rejected`, `loopback_stub_is_rejected` (also with an ineligible systemd file), `ipv6_entries_are_never_eligible`, `first_in_file_order_wins` (both files), `systemd_fallback_requires_every_parsed_entry_to_be_loopback` (all-loopback → fallback; one 8.8.8.8 blocks it; `::1` counts as loopback; empty/all-malformed parse → no fallback), `fallback_entries_follow_the_same_subnet_rule`, `no_eligible_entry_yields_no_resolver`, `garbage_and_oversize_input_degrade_to_no_resolver`; wrapper: `read_bounded_returns_file_content`, `read_bounded_is_none_for_missing_files`, `read_bounded_cuts_oversize_files_at_the_bound` (64 KiB cut, entry past the bound invisible), `read_bounded_degrades_invalid_utf8_lossily`; doctest on `select_resolver` covers the stub + fallback pair. |
| AC-3 resolv.conf parser property test: arbitrary bytes/text → parsed or counted skips, never panic (LCG) | Met | `property_parser_is_total_and_totals_hold` (2,000 inputs; re-derived totals invariant: entries + skips == `nameserver`-keyword lines; spliced realistic lines keep it non-vacuous), `property_arbitrary_bytes_never_panic` (2,000 lossy-decoded byte strings through parser **and** selection), `property_selection_stays_inside_the_subnet` (2,000 generated texts; every `Selected` address inside the subnet); at fuzz scale: `resolv_conf` stages 4–5 (400,000 inputs, same invariants). |
| AC-4 Loopback server asserts the received datagram decodes as a PTR question for the expected name, class IN, with the ID the client sent; wrong-ID/wrong-question rejection unit-tested with hand-built vectors | Met | `loopback_round_trip_with_the_production_resolver`: the server reads the datagram's ID, rebuilds `build_ptr_query(id, 192.0.2.10)` and asserts **byte equality** (name `10.2.0.192.in-addr.arpa`, QTYPE PTR, QCLASS IN, flags, ID — stronger than field-wise assertions); unit side: `wrong_id_is_rejected`, `wrong_question_is_rejected` (wrong QNAME / QTYPE=A / QCLASS=CH), `qr_zero_opcode_nonzero_and_qdcount_mismatch_are_rejected`, `question_name_is_matched_case_insensitively`. |
| AC-5 Hostile-response suite (hand-built vectors): truncated header/question; oversize (> 512); TC=1; wrong ID; wrong QNAME/QTYPE/QCLASS; QR=0; SERVFAIL/FORMERR/NOTIMP/REFUSED → failure; NXDOMAIN → `Unknown`; NOERROR zero answers → `Unknown`; invalid-char PTR skipped; multiple PTRs → first valid wins; compression loop / forward pointer / 64-byte label / >255-octet name → rejected without panic or hang | Met | `truncated_header_and_question_are_rejected` (six cut points), `oversize_datagram_is_rejected_and_512_is_accepted` (exactly 512 accepted via an ignored record type, 513 rejected), `tc_set_fails_the_attempt` (`Err(Truncated)`), `server_failure_rcodes_fail_the_attempt` (1/2/4/5/9 → `Err(ServerFailure)`), `nxdomain_is_a_definitive_no_name`, `noerror_with_zero_answers_is_a_no_name`, `noerror_with_only_cnames_is_a_no_name`, `ptr_names_failing_validation_are_skipped_and_counted` (invalid-char + empty names: `skipped_invalid_ptr_names == 2`), `multiple_ptrs_first_valid_wins_and_invalid_is_counted`, `compression_loop_forward_pointer_and_bad_labels_are_rejected` (self-loop pointer, forward pointer, 0x40 label kind, 5×63-byte = 320-octet name — in RDATA and in the question), `rdata_overrun_and_ancount_overrun_are_rejected`, `compression_pointer_in_rdata_is_followed` (a legal backwards pointer decodes); property scale: 300,000 random + 200,000 mutated inputs (§4.3), zero panics/hangs. |
| AC-6 Worker tests (fake `NameResolver` + `FakeClock`, zero sleeps): success → `Known(ReverseDns)`; NOERROR-empty → `Unknown`; timeout+timeout → exactly one retry then `Unavailable(Failed)`; timeout+success → `Known`; backoff blocks < 5 min and allows after (fake-clock advance); `Known`/`Unknown` cached for the session; N concurrent commands for one IP → one query, N events; one command → exactly one event | Met | `success_maps_to_known_reverse_dns`, `noerror_empty_maps_to_unknown`, `timeout_timeout_retries_exactly_once_then_failed` (calls == attempts == 2), `attempts_one_means_no_retry`, `timeout_then_success_maps_to_known`, `backoff_blocks_then_expires_with_the_fake_clock` (advance 4 min → answered from state, calls unchanged; +2 min → re-queried), `known_and_unknown_are_cached_for_the_session`, `n_commands_for_one_ip_run_one_query_and_emit_n_events` (gated fake makes the batch deterministic: 3 commands, 1 call, 3 events), `one_command_yields_exactly_one_event` (counters: `commands_accepted 1`, `events_sent 2` = Resolved + ack). No test sleeps: the only waits are channel `recv_timeout`s for events the fakes answer instantly. |
| AC-7 No-resolver and disabled paths answer `Unavailable(NoResolver)` / `Unavailable(Disabled)` without any socket use (a touching-fake fails the test) | Met | `no_resolver_answers_without_any_socket_use` (worker spawned with `None`; `queries_issued == 0`); `disabled_answers_without_touching_the_resolver` — a `TouchingResolver` whose `reverse` increments a counter and **panics** is handed to an `enabled: false` worker: the event is `Unavailable(Disabled)`, `calls == 0`, `queries_issued == 0` (had the worker queried, the thread panic would fail the event wait and surface at `shutdown`). |
| AC-8 Queue-full: explicit counted rejections to the enqueuer, never blocks; event saturation drops and counts (non-draining receiver) | Met | `full_command_queue_rejects_and_counts_never_blocks` (capacity-4 channel filled behind a gated first lookup; the 5th `try_resolve` → `Err(QueueFull)`, `enqueue_rejected == 1`; after release: 1 query, 5 events, the rejected command yields none); `saturated_event_queue_drops_and_counts_instead_of_blocking` (capacity-1 event channel, non-draining: `events_sent == 1`, `events_dropped == 3` — two Resolved + the ack; shutdown still returns < 1 s). |
| AC-9 Shutdown: joins within 250 ms + justified CI margin (assert ≤ 1 s in the test, margin justified in the report); ack received; no leaked thread | Met | `shutdown_joins_within_the_bound_and_acks` (elapsed < 1 s, `ShutdownAck` received, second shutdown a no-op); `shutdown_interrupts_a_pending_lookup_and_emits_no_event` (production `UdpResolver` against a silent server with a 10 s budget: after the query is observed, `shutdown()` returns in < 1 s — the stop flag interrupts the 50 ms socket-poll slices — and only the ack is emitted); join consumes the handle → no leaked thread. Margin: the design bound is 250 ms (worst path ≈ 100 ms command slice or 50 ms socket slice + ≤ 8 ms ack budget ≈ 110–160 ms); the ≤ 1 s assertion is 4× headroom for CI scheduling jitter under parallel test load, mirroring the margin T-104 used for the scanner cancel budget. |
| AC-10 Loopback integration (in-process, 127.0.0.1, ephemeral ports; eligibility computed for `127.0.0.0/24`): production `UdpResolver` end-to-end success with a real datagram round-trip, and a timeout path against a silent server with a small timeout; asserts on the retry count | Met | `loopback_round_trip_with_the_production_resolver` (eligibility via `select_resolver("nameserver 127.0.0.1", …, 127.0.0.0/24)` → `Selected(127.0.0.1)`, wired into `UdpResolver::new` with the server's ephemeral port; real send/recv; `Ok(Some(printer.lan))`; the server's question assertion per AC-4); `loopback_timeout_path_retries_once_against_a_silent_server` (bound-but-silent counting server; `query_timeout` 50 ms, `attempts` 2: the event is `Unavailable(Failed)`, the server observes **exactly 2 datagrams** — the attempt and its one retry — via two channel signals, `queries_issued == 2`); resolver-level: `loopback_silent_server_times_out_one_attempt` (80 ms budget honored). |
| AC-11 `cargo run --manifest-path fuzz/Cargo.toml --bin dns_response` and `--bin resolv_conf` exit 0 with their deterministic summaries | Met | §4.3: both exit 0; summaries pasted (dns_response: 3,299 known-name / 5,018 no-name / 491,403 malformed / 1,367 server-failure / 784 truncated over 500,000 inputs, 676 accepted-by-corruption; resolv_conf: 401,141 inputs, 864,209 entries, 579,386 skipped, 142,287 selected / 258,855 no-resolver, 488 non-vacuity). |
| AC-12 ADR-015 record complete per R-7; index row updated | Met | `docs/adr/015-dns-ptr-client.md`: full Context / Options considered (the §9.2 table with measured data for all three options) / Decision / Consequences / Evidence; Status `Pending (T-203 evidence delivered; Manager ratification with the task decision)`; `docs/adr/index.md` row 015 updated to match. |
| AC-13 If a crate was added: exact pin + justification; `cargo tree` diff; no async runtime in the tree; `cargo deny check` licenses ok | N/A (no crate added) | Option (a) chosen (ADR-015) — no new crate, so no `Cargo.toml`/`Cargo.lock` change (§4.6: both clean vs main). For completeness: `cargo deny check` ran anyway (§4.2: advisories/bans/licenses/sources all ok) and the tree contains no async runtime (unchanged from T-202; the two evaluation crates were measured in throwaway crates outside the repository, never added to it). |
| AC-14 Diff touches only the allowed paths | Met | §4.5: `src/enrichment/{hostname,dns,worker,mod}.rs`, `src/lib.rs`, `fuzz/{dns_response,resolv_conf}.rs`, `fuzz/Cargo.toml`, `docs/adr/015-dns-ptr-client.md`, `docs/adr/index.md`, `docs/reports/T-203/execution-01.md` (this file), plus the §10-ordered commit-0 files (`docs/poc/**`, `docs/reports/T-105/**`, `examples/poc_measure.rs`, `src/discovery/arp/**` via merge `9cf6417`; `plan.md` via `3ec2f0f`). `Cargo.toml`, `Cargo.lock`, `fuzz/Cargo.lock` and every other path untouched. |

## 3. What changed

On `task/T-203-hostname-resolver` (base: `main` @ `ffbf918`):

- **Commit 0a `9cf6417`** — the Manager-ordered F-4 recovery merge: `git merge --no-ff origin/task/T-105-poc-campaign` (2b9f777), verbatim message, conflict-free. Recovers `docs/poc/**` (report + 15 data files), `docs/reports/T-105/`, `examples/poc_measure.rs`, the ADR-011 toggles in `src/discovery/arp/**`, and the ADR-009/010/011 decision updates (32 files).
- **Commit 0b `3ec2f0f`** — the Manager plan update to v1.8.0: the four §10.2 edits exactly (version header, O-9 open item, two Status Board rows, the 1.8.0 changelog row).
- **The T-203 work** (`13008d4`, `52c24bc`, and this commit):
  - `src/enrichment/hostname.rs` (1,192 lines incl. 28 tests) — `parse_resolv_conf` (total, counted skips), `select_resolver` (pure D-1 core with the loopback-stub fallback), `ResolverSelection` (+ `resolver_socket()` for T-205), `read_bounded` (64 KiB SR-10 wrapper, lossy), `select_from_system`, and `HostnameConfig`/`HostnameConfigError` (validating `try_new` + the ADR-003 `Default`).
  - `src/enrichment/dns.rs` (1,286 lines incl. 24 tests) — `build_ptr_query`, the bounded `decode_name` (backwards-only pointers, ≤ 128 jumps, ≤ 255 wire octets, ≤ 63-byte labels), `accept_ptr_response` (full D-2 acceptance; `PtrAcceptance` carries the invalid-PTR count), `ResolveError` (5 variants), the `NameResolver` trait, and `UdpResolver` (ephemeral bind + `connect()`, LCG IDs, stop-checked 50 ms socket-poll slices, 513-byte recv buffer so oversize is seen as oversize).
  - `src/enrichment/worker.rs` (1,407 lines incl. 18 tests) — `HostnameCommand`/`HostnameEvent` (the §8.2 enrichment event/command types), `HostnameWorker` (`spawn`, `try_resolve`, `events`, `stats`, `shutdown`), `WorkerThread` (batch drain + per-batch in-flight memo, `Known`/`Unknown`/`Failed{not_before}` session state, retry loop, backoff, 4,096-IP cap with counted rejections, `try_send` + 8×1 ms shutdown-aware event budget), `HostnameStats`/`HostnameStatsSnapshot` (lock-free counters).
  - `src/enrichment/mod.rs` — module wiring + the updated doc paragraph (T-203 delivered, T-205 wires).
  - `src/lib.rs` — one doc paragraph in the established style (no new module declarations; `enrichment` already exported).
  - `fuzz/dns_response.rs` (554 lines) and `fuzz/resolv_conf.rs` (419 lines) — the two std-only deterministic harnesses (arp_frame pattern: known answers, truncations, systematic corruption, structure-aware stages, random + mutated inputs, own summaries, one print-allow on `main`); `fuzz/Cargo.toml` — the two `[[bin]]` registrations. `fuzz/Cargo.lock` unchanged (no new crates; verified).
  - `docs/adr/015-dns-ptr-client.md` — the full decision record (ADR-015 → option (a), Pending/ratification status); `docs/adr/index.md` — row 015 updated.
  - `docs/reports/T-203/execution-01.md` — this report.

Nothing else: `src/registry/`, `src/discovery/` (beyond the merge), `src/net/`, `src/main.rs`, `Cargo.toml`, `Cargo.lock`, `deny.toml`, workflows — untouched.

## 4. Verification results

All commands ran 2026-11-05 on the pinned toolchain (rustc/cargo 1.99.1, x86_64-unknown-linux-gnu; cargo-audit 0.22.2 and cargo-deny 0.20.2 installed from crates.io in this environment — see PQ-2). Dependency-resolving commands used `--locked`; `cargo fmt --check` and `cargo audit` do not take it.

### 4.1 Commit-0 gates (on the merged tree, immediately after `9cf6417`)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 21.25s
[exit 0]

$ cargo test --locked --all-features
running 303 tests
test result: ok. 301 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.18s
running 0 tests            # netns harness (OSZA_NETNS_TESTS unset)
running 9 tests            # doctests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 9 tests            # examples/gen_oui
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
    Generated …/target/doc/osza_netmon/index.html
[exit 0]
```

The 2 ignores are the pre-existing privileged tests (`discovery::privilege::tests::privileged_drop_fails_closed_verification_catches_residual`, `…privileged_open_raw_socket_succeeds_and_drop_verifies`), matching the Manager's expectation of 303 / 301 + 2.

### 4.2 Final gates (T-203 tree, on top of commits 0a/0b)

```text
$ cargo fmt --check
[exit 0]

$ cargo clippy --locked --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s)
[exit 0]

$ cargo test --locked --all-features
running 373 tests
test result: ok. 371 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 8.16s
running 0 tests
running 11 tests            # doctests (9 + 2 new)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
[exit 0]

$ RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
[exit 0]

$ rustup run 1.89.0 cargo build --locked        # MSRV
    Finished `dev` profile [unoptimized + debuginfo] target(s)
[exit 0]

$ cargo audit          # cargo-audit 0.22.2, advisory-db 2026-11-05 (1403 advisories)
    Scanning Cargo.lock for vulnerabilities (196 crate dependencies)
[exit 0 — no vulnerabilities]

$ cargo deny check     # cargo-deny 0.20.2
advisories ok, bans ok, licenses ok, sources ok
[exit 0 — plus the pre-existing informational "license-not-encountered" notes
 on unused allowlist entries (BSD-3-Clause, ISC), present since T-000]
```

### 4.3 Fuzz targets (§9 commands, verbatim invocations)

```text
$ cargo run --manifest-path fuzz/Cargo.toml --bin dns_response --target-dir target
dns_response fuzz target (T-203, SR-05) — std-only deterministic harness
  stages: known answers, truncations, systematic corruption, structural mutations,
          300000 random inputs, 200000 mutated inputs
  outcomes: known-name 3299, no-name 5018, malformed 491403, server-failure 1367, truncated 784, timeout/transport 0
  accepted-by-corruption (non-vacuity): 676
  result: OK — no panic path, no oracle violation
[exit 0]

$ cargo run --manifest-path fuzz/Cargo.toml --bin resolv_conf --target-dir target
resolv_conf fuzz target (T-203, SR-05/SR-10) — std-only deterministic harness
  stages: known answers, truncations, systematic corruption, 400000 random inputs,
          line splicing, a beyond-64-KiB text
  parse results: 401141 inputs, 864209 entries, 579386 skipped malformed lines
  selections: 142287 selected, 258855 no-resolver (141749 selected on random inputs)
  accepted-by-corruption (non-vacuity): 488
  result: OK — no panic path, no invariant violation
[exit 0]

$ cargo run --manifest-path fuzz/Cargo.toml --bin arp_frame --target-dir target   # pre-existing, unaffected
  result: OK — no panic path, no oracle violation
[exit 0]
```

### 4.4 The §9 greps

```text
$ grep -rnE "use crate::(registry|app|ui|net|discovery)" src/enrichment/
[no matches — exit 1; the only crate:: imports are crate::model and, in tests,
 crate::enrichment (the sibling module, allowed by §8.2)]

$ grep -rLn "^// SPDX-License-Identifier: GPL-3.0-only$" src/enrichment/*.rs fuzz/*.rs
[no output — all seven files carry the exact header]
```

### 4.5 Diff scope (AC-14)

```text
$ git diff --stat ffbf918..HEAD -- . ':!docs/poc' ':!docs/reports/T-105' ':!examples' ':!src/discovery' ':!plan.md'
 docs/adr/015-dns-ptr-client.md      |  69 +-
 docs/adr/index.md                   |   2 +-
 docs/reports/T-203/execution-01.md  | ++++   (this report)
 fuzz/Cargo.toml                     |  11 +
 fuzz/dns_response.rs                | 554 ++++
 fuzz/resolv_conf.rs                 | 419 ++++
 src/enrichment/dns.rs               | 1286 ++++
 src/enrichment/hostname.rs          | 1192 ++++
 src/enrichment/mod.rs               |  33 +-
 src/enrichment/worker.rs            | 1407 ++++
 src/lib.rs                          |  10 +
15 files changed
```

### 4.6 Lockfiles

`git diff ffbf918..HEAD -- Cargo.toml Cargo.lock fuzz/Cargo.lock` → empty: no crate was added (ADR-015 option (a)), and the fuzz package's lockfile did not change (its dependency set is the same path dependency; the two new bins add no requirements).

## 5. Deviations from the task card

Each is an adaptation the card explicitly allows ("adaptation expected, document it" for the trait; "your choice, documented" for the clock) or requires (the 250 ms shutdown bound), recorded here for the review:

1. **`UdpResolver::new(resolver, stop)`** — one parameter more than the card's sketch `new(resolver: SocketAddr)`: the worker's shared stop flag is passed in so a pending socket wait is polled in 50 ms stop-checked slices and the worker's 250 ms shutdown bound holds mid-attempt (R-5 itself prescribes the "short socket poll loop checking a stop flag"). Documented in the `dns.rs` module docs and on `UdpResolver::new`.
2. **Clock ownership: `Arc<dyn Clock + Send + Sync>`** instead of the offered `&dyn Clock`/`Box<dyn Clock>`: AC-6 requires advancing a `FakeClock` while the worker owns it, across the thread boundary — shared ownership is the only shape that allows it. Documented in the `worker.rs` module docs.
3. **The loopback integration tests live in-module** (`#[cfg(test)]` inside `dns.rs`/`worker.rs`), not under `tests/`: the root `Cargo.toml` has `autotests = false` with exactly one declared `[[test]]` target, and adding another would modify `Cargo.toml`, which AC-14 permits only when a crate is added. The tests are in-process, loopback-only and explicitly authorized by the card either way.
4. **`ResolveError` has five variants** (`Timeout`, `Transport`, `Malformed`, `ServerFailure`, `Truncated`) rather than the card's "e.g." three: TC=1 and failure RCODEs are well-formed-server answers, not malformed datagrams, and D-3's classification plus AC-5's distinct expectations deserve the honest split. All are unit variants (no `io::Error`), equality-testable.
5. **The retry's query ID is fresh per attempt** (R-3's "16-bit ID pseudo-random per attempt" rule) rather than R-5's parenthetical "(same query, same ID, fresh datagram)": the card-fixed trait signature `reverse(ip, timeout)` cannot carry a query ID, so each attempt builds its own query; the retry is the same lookup (same QNAME/QTYPE/QCLASS/RD) with a fresh datagram and a fresh ID, and the ID + question match is re-verified per attempt. Raised as PQ-1 (§8) for the record.

## 6. Decisions and assumptions

1. **D-5 (ADR-015): option (a), the hand-rolled minimal PTR codec.** Full evidence in `docs/adr/015-dns-ptr-client.md` and §7 below. No new crate; the pre-authorization for (b)/(c) is not exercised.
2. **Decode failure vs. validation failure** (D-2's "decodes and passes"): a PTR name that *decodes* but fails `Hostname::try_from` is counted and skipped (the answer may still be `Ok(None)`); a name that fails to *decode* (structure: bad label kind, bad bounds, loops, forward pointers, oversize) rejects the whole datagram as `Malformed` — matching AC-5's "compression loop / forward pointer / 64-byte label / >255-octet name → rejected". Documented in `dns.rs`.
3. **Backwards-only compression pointers** (RFC 1035 "prior occurrence"), with the explicit `MAX_POINTER_JUMPS = 128` as the secondary bound — both bounds are ones the card demands; strictly-decreasing offsets already guarantee termination, the jump cap is defense in depth.
4. **Per-batch memo as the `InFlight` state** (R-5): lookups are serial and synchronous, so a query always completes before the next command is processed; commands for one IP inside one drained batch share one query (each still gets its event), and the memo never spans batches. The observable contract (N concurrent commands → one query, N events) is tested with a gated fake that pins the batch.
5. **The tracked-IP cap** — the card's "pick the honest option": beyond `max_tracked_ips`, a new IP is answered `Unavailable(Failed)` **immediately, counted as `capped_rejected`, and existing entries are kept**. Emitting no event was rejected: it would break the one-event-per-command invariant the app relies on; the counter keeps the answer honest for diagnostics. Documented in `worker.rs` and tested (`cap_rejects_new_ips_and_keeps_existing_entries`).
6. **Gate order per command**: batch memo → `enabled` (Disabled) → resolver present (NoResolver) → session state (Known/Unknown/backoff) → cap → fresh lookup. `Disabled` precedes `NoResolver` because a disabled feature asks no resolver question at all; neither gate creates session state.
7. **Event delivery**: `try_send` + a shutdown-aware budget of 8 tries × 1 ms (≤ 8 ms bounded block, documented); a saturated queue drops and counts. The shutdown ack uses the same budget.
8. **Shutdown path**: the stop flag is the guarantee (a full command channel cannot delay the exit); the `Shutdown` command is a best-effort fast path. A join error would mean a worker panic — impossible by construction — and is propagated via `resume_unwind` rather than swallowed.
9. **`read_bounded`**: `File::open` → `take(64 KiB)` → `read_to_end` (partial reads keep their prefix) → `from_utf8_lossy`; unreadable → `None` → empty text. The pure core never sees file-system state at all.
10. **Oversize detection**: the resolver's receive buffer is 513 bytes, one more than the acceptance bound, so a >512-byte datagram is measured as 513 and rejected as oversize rather than silently truncated to 512 by the kernel.
11. **Query ID seed**: wall-clock nanos at construction, documented as not a security boundary (the connected-socket source filter plus the ID + question match is the defense, per the card).
12. **AC-9 margin justification** (required by the card): the design bound is 250 ms — worst path ≈ 100 ms command slice or 50 ms socket slice (only one can be active) + ≤ 8 ms ack budget ≈ 110–160 ms; the test asserts ≤ 1 s, 4× headroom for CI scheduling jitter under parallel test load, mirroring the margin T-104 used for the scanner cancel budget. T-403 can tighten both as it did for the scanner.
13. **Assumption**: production wiring constructs `UdpResolver` before `HostnameWorker::spawn` and shares one `Arc<AtomicBool>` stop flag between them — `worker.rs`'s module docs spell out the T-205 wiring recipe (`select_from_system` once per session → `resolver_socket()` → shared stop → `spawn`).

## 7. Dependencies

**None added.** ADR-015 (option (a)) is the decision; the §9.2 evaluation with measured data:

| §9.2 criterion | (a) hand-rolled | (b) `simple-dns` 0.13.0 | (c) `hickory-proto` 0.26.3 |
|---|---|---|---|
| 1. Necessity | ~330 lines of our code; the D-2 acceptance layer must be ours regardless of codec | replaces ~200 of those lines; acceptance + validation stay | same as (b) |
| 2. Maintenance | zero upstream exposure; own fuzz/property cover | 0.13.0 released 2026-10-30; 6 releases/16 months; ≈3.8 M recent downloads; no advisories | 0.26.3 released 2026-09-10; ≈32.6 M recent downloads; no advisories |
| 3. License | n/a | MIT — allowlisted | MIT OR Apache-2.0 — allowlisted |
| 4. `unsafe` | 0 | 0 own; bitflags' 2 macro-guarded `unsafe impl` not reached | 0 own; ICU4X transitives: zerovec 231, yoke 86, icu_collections 15, rand 16 unsafe blocks/fns |
| 5. Deps + build (measured, fresh crate) | +0 / +0 s | +1 (bitflags) / 1.4 s | +64 crates / 11.1 s; no async runtime (`default-features = false`) |
| 6. MSRV vs 1.89 | green (§4.2) | no declared rust-version; green on 1.89.0 (measured) | rust-version 1.88; green on 1.89.0 (measured) |
| 7. No runtime network / build fetch | ✓ | ✓ | ✓ (`jni` dep is Android-target-only) |

Measurement method: fresh empty crates depending on `simple-dns = "=0.13.0"` and `hickory-proto = { version = "=0.26.3", default-features = false }`; `cargo tree` package counts (2 vs 65), `time cargo build` (1.352 s vs 11.104 s), `rustup run 1.89.0 cargo build` (both green), `grep -rE "unsafe\s*(\{|\bfn|\bimpl|\bextern)"` over the unpacked registry sources, crates.io API metadata (versions, licenses, release dates) and the RustSec advisory-db (no advisories for either crate) — all fetched 2026-11-05. The full record is `docs/adr/015-dns-ptr-client.md`.

## 8. Plan Questions

**PQ-1 — the retry's query ID (R-3 vs. R-5 wording).** R-3 (normative for the trait) says the 16-bit ID is "pseudo-random **per attempt**"; R-5's retry policy says "retry exactly once (**same query, same ID**, fresh datagram)". The card-fixed trait signature `reverse(&mut self, ip, timeout)` cannot carry a prebuilt query or an ID, so a retry is necessarily a second `reverse` call that builds its own query. Implemented per R-3: fresh LCG ID per attempt (each with its own ID + question match, one datagram each — the 2-datagram / 2×timeout worst case of R-5 holds). If the Manager prefers literal same-ID retries, the trait needs a query-handle parameter (a small ADR-level change) — flagged rather than resolved silently.

**PQ-2 — `cargo audit`/`cargo deny` provenance.** Neither tool was preinstalled in this environment; both were installed from crates.io with `--locked` (cargo-audit 0.22.2, cargo-deny 0.20.2 — the same versions the CI pins per the T-000/T-202 records) and both gates pass (§4.2). CI re-runs its own pinned versions on the PR; no action requested, recorded for provenance honesty.

## 9. Security and privacy notes

- **Untrusted inputs touched**: `/etc/resolv.conf` and `/run/systemd/resolve/resolv.conf` (arbitrary content, size-bounded to 64 KiB per file, lossily decoded, total parser — SR-10) and DNS response datagrams (≤ 512 accepted, every field bounds-checked, compression walks bounded twice, labels ≤ 63, no read past the datagram — SR-02/SR-04). All names cross `Hostname::try_from` before any consumer sees them (FR-EN-04); nothing from the wire reaches the UI raw.
- **Privileges**: the feature needs no privileges at all — one ephemeral UDP socket, `connect()`ed to the selected resolver (kernel-level source filtering); no raw sockets, no `/proc` writes.
- **Network footprint** (§2.3): the only traffic the module can originate is PTR queries to the one selected in-subnet resolver; no eligible resolver → no datagram is ever sent (ADR-003 item 3, tested). All testing is in-process on 127.0.0.1 with ephemeral ports (card-authorized); all test data is synthetic (RFC 5737 / loopback / documentation names); no real network identifiers anywhere in code, fixtures or this report.
- **DoS posture**: per-IP session caching + 5-minute backoff bound the query rate from repeated commands; the tracked-IP cap (4,096) bounds worker memory; every queue is bounded; the worker never blocks the enqueuer and never blocks unboundedly itself; shutdown is bounded at 250 ms.
- **Supply chain**: zero new crates; `cargo audit` clean (196 locked dependencies), `cargo deny check` clean (advisories/bans/licenses/sources), lockfiles untouched.

## 10. Known issues and limitations

- **TC=1 responses fail the attempt** (no TCP fallback in the MVP, plan §2.2): a resolver that truncates a PTR answer surfaces as `Unavailable(Failed)` after the retry policy. Same for >512-byte responses (no EDNS).
- **The proposed `docs/limitations.md` residual-risk sentence (T-405, ADR-003 item 6)**: "The resolver selected for reverse DNS is the local network's own — but it may forward queries upstream: every hostname lookup reveals the queried IPv4 address to whatever service ultimately resolves it. `--no-hostnames` (T-402) turns the feature off entirely."
- **Runtime re-reading of resolv.conf, resolver failover, parallel lookups and IPv6 `ip6.arpa` are out of scope** (plan §2.2, task card §4); the session selects one resolver once.
- **The fuzz harnesses remain std-only deterministic campaigns** (the T-103 decision), not `cargo-fuzz` runs with committed corpora — SR-05's "cargo-fuzz (smoke run in CI)" wording is satisfied in the same interpreted sense T-103 recorded; promoting to real fuzzing infrastructure is a Manager decision.
- **No `--no-hostnames` flag yet** (T-402): T-203 delivers the `enabled` config knob and the `Disabled` outcome mapping, both tested.

## 11. Suggested follow-ups

1. **LCG low-bit periodicity in shared test helpers**: `model::testing::Lcg::next_below` uses `next_u64() % n`, whose low bits have short periods (period 16 for n = 16), correlating consecutive draws — observed concretely while building `resolv_conf`'s splicing stage (a 16-period kind cycle made every spliced input contain an eligible line). The two new fuzz harnesses draw from the high bits instead (`(next_u64() >> 32) % n`, documented in their local LCG copies); `model::testing::Lcg` and `fuzz/arp_frame.rs` still use the low-bit form. A small follow-up (or T-403 hardening) could switch them — test-only code, no production impact, but the property coverage of the ARP harness would improve.
2. **T-205 wiring recipe** (recorded in `worker.rs`'s module docs): `select_from_system(subnet)` once after scope confirmation → `resolver_socket()` → shared `Arc<AtomicBool>` stop → `UdpResolver::new` → `HostnameWorker::spawn(config, Some(boxed), Arc::new(SystemClock), stop)`; feed `Resolved` events to `registry.set_hostname`; surface `Selected.address()` in the UI's "reverse DNS via `<addr>`" line (T-304).
3. **The §11.7 vocabulary check** is still unimplemented (no test or CI step exists yet); when it lands it will need an allowlist for technical terms in accepted docs (netlink "stale" states in ADR-010, "stale MAC" in ADR-011) — the new T-203 files avoid the banned words outside the self-check tables, but the grep will still hit those older files.
4. **TC=1 handling** could be revisited post-MVP if field reports show resolvers truncating PTR answers (a 512-byte PTR answer is already unusual); the change would stay contained in `dns.rs` behind the same trait.
5. **The F-4 process hardening** (Commit-0 pre-flight) worked as designed here — the pre-flight check, the verbatim merge and the immediate gate re-run took minutes and left the G-1 evidence chain in main's lineage; worth keeping in every future card as plan v1.8.0 already orders.
