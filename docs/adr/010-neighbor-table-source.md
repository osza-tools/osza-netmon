# ADR-010: Neighbor-table source (`/proc/net/arp` vs netlink)

- **Status:** Accepted (decided by T-105, 2026-11-03 — `/proc/net/arp` stands; netlink not adopted in 0.1.0)
- **Date:** 2026-10-28 (transcribed), 2026-11-03 (decided)
- **Deciding task / owner:** T-105 — PoC measurement campaign (evidence below)

## Context

Source: plan.md v1.1.0 §4 (ADR-010 — Neighbor-table source (`/proc/net/arp` vs netlink) — Pending (T-105)), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records this decision in the shared block "ADR-009/010/011 Pending, with provisional defaults for implementation".

## Options considered

> `/proc/net/arp` (simple; no state) vs netlink `RTM_GETNEIGH` (state: reachable/stale/failed).

## Decision

**Keep `/proc/net/arp` as the sole neighbor-table source** — the T-102 implementation stands; netlink `RTM_GETNEIGH` is **not adopted in 0.1.0**. The interim path recorded in plan.md §4 is confirmed by measurement:

> T-102 implements `/proc/net/arp`; T-105 decides whether netlink is worth the dependency.

The measurement (poc-report §6) decided the "worth" question on four points: (1) the two sources yield **identical entry sets** at every sample point of a 75 s timeline with real device→host traffic; (2) netlink's only addition, the state word, **does not map to the product's model** — kernel `STALE` ≠ our `Idle` (ADR-002) and aging is cycle-based (ADR-007), so no 0.1.0 decision consumes it; (3) the neighbor table itself yields only peers that **ARPed us** (1 of 5 talking devices appeared — receiving IP traffic does not populate it), which bounds what either source can offer the read-only mode; (4) the read cost of the production reader is ≈ 10 µs — not a differentiator. A Rust netlink client means new dependencies (`netlink-sys` + `netlink-packet-route`; `rtnetlink` is deprecated), which the measured benefit does not justify.

## Consequences (positive, negative, follow-ups)

- T-102 implements `/proc/net/arp`; T-105 decides whether netlink is worth the dependency. (plan.md §4)
- (T-001 cross-reference, task card §5.4) ADR-009 (Discovery transport library), ADR-010 and ADR-011 (Probe strategy) are decided together by T-105 (plan.md §4, §13).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

All from `docs/poc/poc-report.md` §6 (T-105, 2026-11-03), raw records in `docs/poc/data/neighbor.json`:

* **Timeline comparison:** five kernel-answered devices sent one-way UDP to the host for 10 s; both sources sampled at t = 2/12/45/75 s and after an active scan — identical single-entry sets (192.0.2.2) everywhere; netlink showed `STALE` throughout and `REACHABLE` only after the scan's reply confirmed the entry.
* **What populates the table:** only the first ARP resolution (192.0.2.2) appeared although all five devices sent traffic; the host's IPv4 ARP keeps one entry per destination, and receiving IP traffic creates no entries. Our own 2-pass sweep (5/5 devices accepted) added **no** rows — raw-socket probes and unsolicited replies do not create kernel neighbor entries (`arp_accept=0`).
* **Read costs:** production `/proc/net/arp` reader ≈ 10 µs (mean of 200); `ip neigh` spawn ≈ 1.1 ms (mean of 20 — an upper bound for a netlink client; the `RTM_GETNEIGH` dump itself is a handful of syscalls).
* **Dependency cost of the alternative:** `netlink-sys` 0.9.0 + `netlink-packet-route` (the no-async pair); `rtnetlink` deprecated / async-leaning.
* **Backlog linkage:** plan §18 item 5 ("Netlink neighbor states if not adopted in 0.1.0") — this ADR is the decision that entry anticipated.
