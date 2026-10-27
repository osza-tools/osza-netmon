# ADR-013: Persistence: none, except the notice acknowledgment

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-013 — Persistence: none, except the notice acknowledgment — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. Plan.md §4 records ADR-012/013 in one shared block.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> In-memory state per session. No config file in the MVP; options come from CLI flags. The notice acknowledgment is the sole persisted item.

## Consequences (positive, negative, follow-ups)

- The notice acknowledgment is the sole persisted item (plan.md §4).
- (T-001 cross-reference) ADR-004 (Authorization notice policy) defines the acknowledgment's contents, storage location (`$XDG_CONFIG_HOME/osza-netmon/notice-ack`, fallback `~/.config/...`) and mode `0600`; ADR-005 (Privilege model) runs the process unprivileged while writing it.
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
