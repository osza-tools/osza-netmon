# ADR Index — osza-netmon

Architecture Decision Records for `osza-netmon`, transcribed from `plan.md` v1.1.0 §4 (Decision Log) by task T-001, using the ADR template from `plan.md` Appendix G. `plan.md` §4 remains the single source of truth; these files reproduce it faithfully and must stay consistent with it at all times.

Status vocabulary (plan.md §4): **Accepted** · **Provisional** (accepted, owner confirmation pending) · **Pending** (decided by evidence in a named task) · **Open** (owner decision) · **Superseded**.

| ADR | Title | Status | File |
|---|---|---|---|
| 001 | Product naming | Accepted | [001-product-naming.md](001-product-naming.md) |
| 002 | Status vocabulary (Recent / Idle) | Accepted | [002-status-vocabulary.md](002-status-vocabulary.md) |
| 003 | Hostname resolution policy | Accepted | [003-hostname-resolution-policy.md](003-hostname-resolution-policy.md) |
| 004 | Authorization notice policy | Accepted | [004-authorization-notice-policy.md](004-authorization-notice-policy.md) |
| 005 | Privilege model | Accepted (mechanism details Pending T-104/T-105) | [005-privilege-model.md](005-privilege-model.md) |
| 006 | Single-package repository (lib + bin) | Accepted | [006-single-package-repository.md](006-single-package-repository.md) |
| 007 | Aging model (scan-cycle based) | Accepted | [007-aging-model.md](007-aging-model.md) |
| 008 | Device identity and shared-MAC handling | Accepted | [008-device-identity-shared-mac.md](008-device-identity-shared-mac.md) |
| 009 | Discovery transport library | Pending (T-105) | [009-discovery-transport-library.md](009-discovery-transport-library.md) |
| 010 | Neighbor-table source (`/proc/net/arp` vs netlink) | Pending (T-105) | [010-neighbor-table-source.md](010-neighbor-table-source.md) |
| 011 | Probe strategy (passes, rate, sender IP, unicast refresh) | Pending (T-105), provisional defaults | [011-probe-strategy.md](011-probe-strategy.md) |
| 012 | Concurrency: std threads, no async runtime | Accepted | [012-concurrency-model.md](012-concurrency-model.md) |
| 013 | Persistence: none, except the notice acknowledgment | Accepted | [013-persistence-model.md](013-persistence-model.md) |
| 014 | Project license | Accepted (variant to confirm, O-7) | [014-project-license.md](014-project-license.md) |
| 015 | DNS PTR client implementation | Pending (T-203) | [015-dns-ptr-client.md](015-dns-ptr-client.md) |
| 016 | CI provider: GitHub Actions | Accepted | [016-ci-provider.md](016-ci-provider.md) |
| 017 | Interface data source (`getifaddrs` via `nix`) | Accepted (Manager confirmation pending, PQ-1) | [017-interface-data-source.md](017-interface-data-source.md) |

Notes:

- All ADRs carry the transcription date 2026-10-28 (task T-001).
- ADR-001…016 are transcriptions of `plan.md` §4 (task T-001). **ADR-017 is the first ADR that originates from a task-card decision** (T-101 §3 authorizes choosing the interface data source): it is not plan.md §4 text, and its status reflects the task's PQ-1 Manager confirmation rather than a §4 entry. `plan.md` remains the single source of truth for ADR-001…016.
- Statuses are exactly those of `plan.md` v1.1.0 §4. Task card T-001 §5.2 listed three statuses that match the superseded plan v1.0.0 instead (ADR-001 "Provisional", ADR-014 "Open", ADR-016 "Open"); per `plan.md` §0.2 precedence (plan > task card) and the card's own rule "Every ADR's status must exactly match §4 of `plan.md`", the v1.1.0 statuses above are authoritative. See `docs/reports/T-001/execution-01.md`, Plan Question PQ-1.
- Pending decisions: ADR-009/010/011 are decided together by T-105; ADR-015 is decided by T-203; the ADR-005 capability-library mechanism is chosen by T-104; the ADR-014 SPDX variant remains open item O-7 (plan.md §20). ADR-017 awaits the Manager's PQ-1 decision (T-101 execution report).
