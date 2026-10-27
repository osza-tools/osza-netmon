# ADR-011: Probe strategy (passes, rate, sender IP, unicast refresh)

- **Status:** Pending (T-105), defaults below
- **Date:** 2026-10-28
- **Deciding task / owner:** Pending — decided by T-105

## Context

Source: plan.md v1.1.0 §4 (ADR-011 — Probe strategy (passes, rate, sender IP, unicast refresh) — Pending (T-105), defaults below), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records this decision in the shared block "ADR-009/010/011 Pending, with provisional defaults for implementation". The provisional defaults are reproduced under Decision below.

## Options considered

Plan.md §4 records the variants that T-105 evaluates:

> T-105 also evaluates sender `0.0.0.0` (RFC 5227 style probes) and unicast ARP refresh of known devices.

## Decision

Pending — decided by T-105. Provisional defaults recorded in plan.md §4:

> Provisional defaults: sender IP = interface IP; **100 packets/s**; initial scan and manual refresh use **2 passes** (second pass only to addresses that did not answer, after ≥ 1 s); periodic rediscovery uses **1 pass**; listen window **1.5 s** after the last send.

## Consequences (positive, negative, follow-ups)

- The defaults above are provisional until T-105 decides (plan.md §4). (T-001 note: plan.md §6.3 FR-DS-03/FR-DS-04/FR-DS-05 implement "ADR-011 defaults".)
- (T-001 cross-reference, task card §5.4) ADR-009 (Discovery transport library), ADR-010 (Neighbor-table source) and ADR-011 are decided together by T-105 (plan.md §4, §13).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

To be produced by T-105.
