# ADR-011: Probe strategy (passes, rate, sender IP, unicast refresh)

- **Status:** Accepted (decided by T-105, 2026-11-03 — provisional defaults re-pinned from measurement; unicast refresh not adopted)
- **Date:** 2026-10-28 (transcribed), 2026-11-03 (decided)
- **Deciding task / owner:** T-105 — PoC measurement campaign (evidence below)

## Context

Source: plan.md v1.1.0 §4 (ADR-011 — Probe strategy (passes, rate, sender IP, unicast refresh) — Pending (T-105), defaults below), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records this decision in the shared block "ADR-009/010/011 Pending, with provisional defaults for implementation". The provisional defaults are reproduced under Decision below.

## Options considered

Plan.md §4 records the variants that T-105 evaluates:

> T-105 also evaluates sender `0.0.0.0` (RFC 5227 style probes) and unicast ARP refresh of known devices.

## Decision

**Accepted, re-pinned from measurement.** The provisional defaults recorded in plan.md §4 are confirmed with one sharpened boundary and one rejection:

> Provisional defaults: sender IP = interface IP; **100 packets/s**; initial scan and manual refresh use **2 passes** (second pass only to addresses that did not answer, after ≥ 1 s); periodic rediscovery uses **1 pass**; listen window **1.5 s** after the last send.

* **Sender IP = the interface address** (confirmed). `0.0.0.0` (RFC 5227 probe form) measured identical recall, timing and acceptance on both kernel- and helper-answered targets; the measured difference is the target-side footprint — the interface IP leaves one ARP-table row naming us on kernel targets, `0.0.0.0` leaves none. The interface IP stays (standard form, lets caching targets reach us back); the equivalence is recorded for any future privacy-driven revisit.
* **100 pps** (re-pinned from data, not preference). Recall is rate-independent at every profile and pass count (the impairment decisions follow request arrival order); rate only trades time against offered load. 50 pps **violates NFR-02** under P3 impairment (12.6 s for a /24 2-pass cycle vs the 10 s budget); 200 pps halves sweep time but doubles instantaneous load for identical recall. 100 pps meets NFR-02 everywhere (worst 7.6 s, 24% margin).
* **2 passes for the initial scan and manual refresh; 1 pass for periodic rediscovery** (confirmed). 2 passes reaches ≥ 95.6% within the *first* cycle on P0–P2 (S2); 3 passes adds ~48% packets for ≤ 2.8 pp of cycle-1 recall and no cycle-3 gain; 1-pass periodic converges to 100% by cycle 4 (S2/P2) and cycle 6 (S2/P3, sleepy) over ten cycles.
* **Listen window 1.5 s** (confirmed): S9-late-400ms reaches 100% in one cycle at every pass count, and the fixed-2500 ms experiment shows the window plus the pass-start snapshot bound a late answer to exactly one extra probe.
* **Unicast refresh of known devices: not adopted.** It works and is cheap (20 packets vs 486 for a /24 sweep, 24× fewer) but is blind to MAC rotation — the scenario R-11 calls out: kernel stacks drop unicast requests addressed to a stale MAC (measured 0 of 10). The broadcast sweep it would replace is inside every plan budget. Recorded as a backlog candidate (report §4.4).
* The pass clamp (1..=3, T-104 PQ-2) stands unchanged.

## Consequences (positive, negative, follow-ups)

- The defaults above are provisional until T-105 decides (plan.md §4). (T-001 note: plan.md §6.3 FR-DS-03/FR-DS-04/FR-DS-05 implement "ADR-011 defaults".)
- (T-001 cross-reference, task card §5.4) ADR-009 (Discovery transport library), ADR-010 (Neighbor-table source) and ADR-011 are decided together by T-105 (plan.md §4, §13).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

All from `docs/poc/poc-report.md` §3–§4 (T-105, 2026-11-03), raw records in `docs/poc/data/`:

* **The full grid** (S1/S2/S4 × P0–P3 × 50/100/200 pps × 1/2/3 passes, 3 cycles; 108 cells): every gated cell (P0–P2) reaches ≥ 95% by cycle 3 — worst 99.2% (S2/P2, 1 pass), defaults 100% (`grid-*.json`, report §3.2–§3.3).
* **Rate:** identical recall columns across rates at every (profile, passes); NFR-02 table — 50 pps 12641 ms (violated), 100 pps 7589 ms, 200 pps 5061 ms on S2/P3 2-pass (`grid-s2-*.json`, report §4.1).
* **Passes and periodicity:** cycle-1 recall by pass count (S2: 1p 80% / 2p 95.6% / 3p 98.4% on P2); ten-cycle 1-pass convergence 100% by cycle 4 (P2) and cycle 6 (P3) (`grid-periodic10.json`, report §4.2).
* **Sender IP:** 24 records, identical recall/ttf per cell; device-side `/proc/net/arp` rows after scan: 1 (interface IP) vs 0 (`0.0.0.0`) on the kernel half (`sender-ip.json`, report §4.3).
* **Unicast refresh:** U1–U5 phases incl. the rotation lab — kernel half 0 of 10 on stale MACs, broadcast recovery 20/20 (`unicast.json`, report §4.4).
* **Pass-2 snapshot (T-104 review F-6):** 233 of 253 addresses re-probed exactly once under a fixed 2500 ms delay; 100% recall within the scan (`late.json`, report §4.5).
* **Sleepy hosts (S9):** ignore-first-2 0%→100% by cycle 3; fraction-0.5 75%→100%; late-400ms 100% throughout (`grid-s9*.json`, report §3.4).
