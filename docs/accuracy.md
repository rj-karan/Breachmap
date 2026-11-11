# Accuracy

Measured, not claimed. Every number here is produced by a command in this
repo on the seeded lab. Update it in the same PR as any change to the
evaluator, the fixtures or the answer key.

## Answer-key reproduction (M1)

```
uv run breachmap check --fixture lab/fixtures/v1-oidc --answer-key lab/answer-keys/v1-oidc.json
```

| Fixture | Decisions | Reproduced | Date |
|---|---|---|---|
| `v1-oidc` | 28 | 28 (100%) | 2026-11-11 |

Reproduced means the evaluator returns the expected outcome **and** the
expected blocking reason. Twenty-six are allow/deny; one is `unknown` by
design (`aws:SourceIp` of a hosted runner); the reasons exercised are
`condition_mismatch`, `trust_mismatch`, `scp`, `permission_boundary`,
`explicit_deny`, `no_permission` and `resource_policy`.

## Mutation pass rate (M1 subset)

```
uv run breachmap mutate --fixture lab/fixtures/v1-oidc --answer-key lab/answer-keys/v1-oidc.json --mutations lab/mutations/v1-oidc.json
```

| Mutation set | Mutations | Passing | Rate | Target |
|---|---|---|---|---|
| `lab/mutations/v1-oidc.json` | 24 | 24 | 100% | ≥ 95% |

A mutation passes only when the set of decisions whose verdict changed is
exactly the set it declared. Three mutations declare no change and exist to
catch over-sensitivity.

These mutations act on the evaluator's decisions. M6 extends the set to
whole paths once the path engine exists, and generates mutations
automatically from the fixture.

## Not yet measured

| Metric | Milestone | Status |
|---|---|---|
| Edge agreement with the IAM policy simulator and Access Analyzer | M3 | needs the lab account |
| Path recall and precision | M4 | needs the path engine |
| Fix success | M5 | needs the fix verifier |
