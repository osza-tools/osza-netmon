Proof-of-concept experiments, raw measurement data and decision reports
(task T-105, protocol in `plan.md` Appendix D).

- `poc-report.md` — the master PoC report: all Appendix D tables, the
  ADR-009/010/011 decision evidence, the limitation catalog and the
  Gate G-1 recommendation (T-105, 2026-11-03).
- `data/` — the raw per-run records (JSON, one file per experiment; 498
  campaign records + 90 T-106 baseline records) and the isolated-Wi-Fi
  stand-in output captures. Regenerate with the commands in
  `poc-report.md` §2.5 (`examples/poc_measure.rs`).
