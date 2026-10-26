# AGENTS.md — rules for agents working on osza-netmon
Authority: plan.md. Read your task card and the plan sections it cites before coding.
1. Do exactly what the task card says. Out-of-scope ideas go to "Suggested follow-ups".
2. Stop and write a Plan Question when the plan is ambiguous or conflicts with the card.
3. No new dependencies without Manager approval. No `unsafe`. No println!/eprintln! outside main.rs pre-init/post-restore.
4. External input is hostile: validate at the boundary, never panic, bound all sizes and waits.
5. Never weaken, skip or delete tests to get green.
6. Run before submitting: cargo fmt --check; cargo clippy --all-targets --all-features -- -D warnings;
   cargo test --all-features; cargo doc --no-deps; cargo audit; cargo deny check.
7. Probe networks only inside netns or Owner-designated lab networks. Use synthetic data in fixtures/reports.
8. UI wording follows the controlled vocabulary (plan.md §5.4). Unknown stays "Unknown".
9. Submit docs/reports/T-xxx/execution-NN.md using the template in plan.md Appendix B.
10. Reviewers verify independently and never edit code; they write findings only.
