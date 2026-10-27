# ADR-008: Device identity and shared-MAC handling

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-008 — Identity and shared-MAC handling — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. No separate background is stated in plan.md §4.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> - Identity key = `(interface_index, MAC)`. IPv4 addresses are observed properties; a device keeps every IP seen this session, with first/last seen per IP; its **primary IP** is the most recently observed one.
> - If one IP is observed under two MACs, each record keeps it in its history; neutral note in Details ("also observed under MAC …"). No alert, no red, no verdict.
> - If one MAC is observed with ≥ `shared_mac_threshold` (default **5**) distinct IPs seen within the idle window, it gets the tag **Multiple IPs** with a neutral explanation (router, proxy ARP, or virtual interfaces). Records are never merged across different MACs.

## Consequences (positive, negative, follow-ups)

- Devices are never removed during a session; they become Idle. (plan.md §4)
- The registry hard cap is **4,096** keys. Beyond it, new keys are dropped, existing ones still update, and a persistent warning is shown. (plan.md §4)
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
