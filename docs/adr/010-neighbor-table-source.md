# ADR-010: Neighbor-table source (`/proc/net/arp` vs netlink)

- **Status:** Pending (T-105)
- **Date:** 2026-10-28
- **Deciding task / owner:** Pending — decided by T-105

## Context

Source: plan.md v1.1.0 §4 (ADR-010 — Neighbor-table source (`/proc/net/arp` vs netlink) — Pending (T-105)), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records this decision in the shared block "ADR-009/010/011 Pending, with provisional defaults for implementation".

## Options considered

> `/proc/net/arp` (simple; no state) vs netlink `RTM_GETNEIGH` (state: reachable/stale/failed).

## Decision

Pending — decided by T-105. The interim implementation path recorded in plan.md §4:

> T-102 implements `/proc/net/arp`; T-105 decides whether netlink is worth the dependency.

## Consequences (positive, negative, follow-ups)

- T-102 implements `/proc/net/arp`; T-105 decides whether netlink is worth the dependency. (plan.md §4)
- (T-001 cross-reference, task card §5.4) ADR-009 (Discovery transport library), ADR-010 and ADR-011 (Probe strategy) are decided together by T-105 (plan.md §4, §13).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

To be produced by T-105.
