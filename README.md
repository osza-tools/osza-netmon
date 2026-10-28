# osza-netmon

**osza Network Monitor** — a lightweight terminal application that discovers
devices on the local IPv4 network and shows what is known about them.

> **Status: pre-release / under construction.**
> The repository, build and CI gates are in place, the ADR records are
> transcribed, and the validated domain-model layer has landed in
> `src/model/` (`MacAddr`, `Hostname`, `DisplayText`, `Field<T>`, clock
> abstractions, IPv4 classification and `Ipv4Net` — tasks T-000…T-002).
> No discovery, scanning or UI behavior is implemented yet.
> See [`plan.md`](plan.md) for the scope and the roadmap.

- **License:** GPL-3.0-only (see [`LICENSE`](LICENSE))
- **Plan:** [`plan.md`](plan.md) — the single source of truth for this project

## Documentation

- [`docs/adr/`](docs/adr/) — architecture decision records (ADR-001…016),
  master index at [`docs/adr/index.md`](docs/adr/index.md)
- [`docs/tasks/`](docs/tasks/) — task cards issued from `plan.md` §13
- [`docs/reports/`](docs/reports/) — per-task execution and review reports
- [`docs/poc/`](docs/poc/) — proof-of-concept experiments and decision
  reports (task T-105)

Device visibility is not guaranteed: what a scan can observe depends on the
network, its configuration, and the devices themselves. The project's
documentation will describe these limitations explicitly.
