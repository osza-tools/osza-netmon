# ADR-009: Discovery transport library

- **Status:** Accepted (decided by T-105, 2026-11-03; interim selection ratified T-104 confirmed final)
- **Date:** 2026-10-28 (transcribed), 2026-11-03 (decided)
- **Deciding task / owner:** T-105 — PoC measurement campaign (evidence below)

## Context

Source: plan.md v1.1.0 §4 (ADR-009 — Discovery transport library — Pending (T-105)), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records this decision in the shared block "ADR-009/010/011 Pending, with provisional defaults for implementation".

## Options considered

> Candidates: `pnet_datalink` (its latest release, 0.35.0, dates from May 2024 — slow cadence; do not assume it), `nix` safe wrappers, `socket2`.

(T-001 note) Also recorded in the plan.md §9.2 candidates table ("decision by ADR in the named task"): transport: `pnet_datalink` / `nix` / `socket2` (T-105) — evaluate against §9.2 in the report; Manager approves.

## Decision

**Accept `pnet_datalink =0.35.0` as the production `ArpTransport`** — the interim selection ratified by the Manager in T-104 becomes final on the T-105 measured evidence. The `ETH_P_ALL` binding plus the software EtherType filter (T-104 deviation 5) is accepted with its measured cost; a swap remains a one-module change behind the `ArpTransport` trait (the plan's isolation constraint, quoted by T-001):

> Criteria in §9.2; also the transport is hidden behind the `ArpTransport` trait so replacing it costs one module.

The plan's evaluation criteria (§9.2) were applied to the measured data (poc-report §5.4): necessity (no safe `AF_PACKET` path in std/`nix`/`socket2` without `unsafe` — T-104's source-verified finding, unchanged), maintenance (0.35.0, May 2024, slow cadence — contained behind the trait), license (MIT/Apache-2.0, inside the `deny.toml` allowlist), `unsafe` footprint (library-internal only; project code forbids `unsafe`), transitive weight (ipnetwork, pnet_base, pnet_sys, libc; no async runtime), MSRV (1.89 verified at T-000), and runtime/build constraints (no network, no build-time fetches).

## Consequences (positive, negative, follow-ups)

- The transport is hidden behind the `ArpTransport` trait so replacing it costs one module. (plan.md §4)
- Evaluation happens against the plan.md §9.2 criteria, with Manager approval (plan.md §4, §9.2).
- (T-001 cross-reference, task card §5.4) ADR-009, ADR-010 (Neighbor-table source) and ADR-011 (Probe strategy) are decided together by T-105 (plan.md §4, §13).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

All from `docs/poc/poc-report.md` (T-105, 2026-11-03), raw records in `docs/poc/data/`:

* **The `ETH_P_ALL` + software-filter cost (deviation 5, measured):** the S1 scan under 0–800 pps of controlled non-ARP background traffic — 5613 non-ARP frames delivered to userspace cost **+10 ms CPU per 7.4 s scan (≤ 1.8 µs per frame)**, with zero effect on scan duration, recall or acceptance at every rate (`transport.json`, report §5.1). The socket also accumulates a bounded receive backlog while unread between scans (measured ~300 frames per sweep, report §5.1).
* **The `ETH_P_ARP` alternative (measured at the kernel level):** an `AF_PACKET`/`ETH_P_ARP` witness socket received **0 non-ARP frames** over the same windows where the production socket received 5613 — the kernel filter eliminates the entire measured cost (report §5.2). It **cannot be implemented in project code without `unsafe` or a new dependency**: `pnet_datalink` hardcodes `ETH_P_ALL` for `ChannelType::Layer2`; `nix 0.31.3`'s `LinkAddr` (`sockaddr_ll`) is crate-private with no `ETH_P_ARP` variant; `socket2 0.6.3`'s raw `SockAddr` constructors are `unsafe` (T-104 finding, re-verified).
* **Failure behavior (Appendix D):** interface down mid-scan → `Failed` within ~8 ms with observations retained; down at start → typed `InterfaceLost` on the first send; recovery scan → `Complete` with full recall (`iface-flip.json`, report §5.3). One consequence recorded: pnet's mid-scan failure string ("Unexpected poll event") is opaque; a native implementation would map POLLHUP to `InterfaceLost`.
* **Recall across the whole campaign:** 543 records, 0 extras, 0 rejected replies — the transport adds no noise to the discovery data (report §3).
* **§9.2 evaluation table:** poc-report §5.4.
* **Prior evidence:** T-104 §7 (the seven-criteria evaluation and the interim selection), T-104 review §1.5 (independent source verification of the `nix`/`socket2` gaps).

### Interim selection — T-104 (ratified 2026-11-02)

- **Approved requirements (Manager ratification of T-104 PQ-1):** `pnet_datalink =0.35.0` (interim production `ArpTransport`), `caps =0.5.6` (capability clearing), and the `process` feature of the already-approved `nix =0.31.3` (for `prctl::set_no_new_privs`) — all exact-pinned.
- **Necessity (source-verified):** in `nix 0.31.3`, the `LinkAddr` field that wraps `sockaddr_ll` is crate-private, and `SockProtocol` has no `ETH_P_ARP` variant; in `socket2 0.6.3`, the raw-storage constructors of `SockAddr` are `unsafe`. Neither library can open and bind an `AF_PACKET` socket without `unsafe`, which SR-01 forbids in our own code. Independently source-verified: `docs/reports/T-104/review-01.md` §1.5.
- **Containment:** the interim selection is entirely behind the `ArpTransport` trait (`src/discovery/arp/transport.rs`); replacing it costs one module (risk R-02).
- **Known limitation to measure at T-105:** `pnet_datalink` `ChannelType::Layer2` binds `ETH_P_ALL`, so the socket sees all interface traffic and an EtherType filter drops non-ARP frames in software before validation and before counting; `promiscuous = false`. FR-DS-07 is preserved (nothing is collected), but the cost and a possible `ETH_P_ARP`-binding alternative are T-105 experiment inputs.
- **Links:** `docs/reports/T-104/execution-01.md` §7 (the seven-criteria §9.2 evaluation) and `docs/reports/T-104/review-01.md` (independent verification).
