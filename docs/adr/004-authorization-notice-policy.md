# ADR-004: Authorization notice policy

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Manager — plan.md v1.0.0 §4 (plan status: approved for execution)

## Context

Source: plan.md v1.1.0 §4 (ADR-004 — Authorization notice policy — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references added by task T-001, not plan text. No separate background is stated in plan.md §4; the policy is reproduced in full under Decision.

## Options considered

See plan.md §4 — options were evaluated during plan authoring (plan.md §22, Changelog v1.0.0: the Manager's assessment).

## Decision

> - First run, or whenever the notice text version changes: a full-screen notice requiring explicit acknowledgment (`y`) before **any** discovery. The acknowledgment (notice version + timestamp) is stored in `$XDG_CONFIG_HOME/osza-netmon/notice-ack` (fallback `~/.config/...`), mode `0600`. If it cannot be written, the app continues and asks again next run (non-fatal).
> - Every run: a one-line reminder in the dashboard header and on the scope screen ("Authorized networks only. Active discovery sends ARP requests.").
> - Notice text (the product name is substituted):
>
>   > {DISPLAY_NAME} is intended only for networks you own or are explicitly authorized to monitor. Local discovery sends network probes. Use this tool only within an authorized network.

## Consequences (positive, negative, follow-ups)

- This is the only persisted state in the MVP (ADR-013) (plan.md §4).
- (T-001 cross-reference) ADR-013 (Persistence model) defines this acknowledgment file as the sole persisted item; its storage location and mode come from this ADR.
- Follow-up (plan.md §20, open item O-6): confirm first-run-only full notice — decided by T-302.
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports.
