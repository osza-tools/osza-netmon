# ADR-007: Aging model (scan-cycle based)

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-007 — Aging model — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. No separate background is stated in plan.md §4.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> A device becomes **Idle** only when **both** hold:
> - it was absent from `idle_after_cycles` (default **3**) *consecutive complete scan cycles*, and
> - `now − last_seen ≥ idle_min_age` (default **120 s**).
>
> Only cycles with outcome `Complete` age devices; `Partial`, `Failed` and `Cancelled` cycles never do. Any new observation immediately returns a device to **Recent**.

## Consequences (positive, negative, follow-ups)

- The age floor prevents manual-refresh spamming from idling everything within seconds. (plan.md §4)
- In read-only mode a successful neighbor-table read is one cycle; because kernel entries linger, Idle appears later in that mode (documented). (plan.md §4)
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
