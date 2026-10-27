# ADR-016: CI provider: GitHub Actions

- **Status:** Accepted
- **Date:** 2026-10-28
- **Deciding task / owner:** Owner — GitHub Actions confirmed in plan v1.1.0 (open item O-3 resolved; plan.md §20, §22)

## Context

Source: plan.md v1.1.0 §4 (ADR-016 — CI — Accepted), transcribed by task T-001. Prose marked as a quotation is verbatim plan.md §4 text; lines marked "(T-001 …)" are cross-references or notes added by task T-001, not plan text. No separate background is stated in plan.md §4; "the repository above" is https://github.com/osza-tools/osza-netmon.

## Options considered

The CI provider was an owner decision (open item O-3, plan.md §20), confirmed as GitHub Actions in plan v1.1.0 (plan.md §22, Changelog). See plan.md §4.

## Decision

> GitHub Actions on the repository above. Every action is pinned by full commit SHA; workflows use `permissions: contents: read` unless a job needs more.

## Consequences (positive, negative, follow-ups)

> The netns job uses `sudo` on a GitHub-hosted Ubuntu runner; whether it works as expected, including `tc netem` availability, is verified in T-106.

- Follow-up: the netns job (sudo, `tc netem` availability) is verified in T-106 (plan.md §4).
- No further consequences are stated in plan.md §4.

## Evidence (links to PoC data, reports, benchmarks)

See plan.md §4 and future reports. GitHub Actions CI has run since T-000: green run on PR #1 (https://github.com/osza-tools/osza-netmon/actions/runs/40406852633) and four red enforcement runs on the never-merged proof branch (https://github.com/osza-tools/osza-netmon/pull/2). The netns job is to be verified by T-106.
