# Breachmap

Attack-path analysis across GitHub Actions, AWS IAM and Kubernetes, with a
min-cut that picks the cheapest fix and measured accuracy on a lab where the
right answer is known in advance.

> **Status: M1 in progress.** The repo, process, design doc, milestone plan
> and a tested Python scaffold exist. No analysis runs yet. See
> [Status](#status) and the [Roadmap](#roadmap) before expecting anything to
> work.

## Why

Every security tool sees one layer. A secret scanner flags a token, a cloud
scanner flags a broad IAM role, a Kubernetes scanner flags an over-privileged
service account. Each lands as "medium" in a different dashboard owned by a
different team. An attacker doesn't care about layers; they walk from one
weakness to the next.

**The example this project is built around.** In 2023 Tinder's security team
found that many AWS IAM roles trusted GitHub Actions through OIDC without
checking the token's `sub` claim. The trust policy looked like this:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" }
  }
}
```

Only `aud` is checked, and every GitHub Actions token has that `aud`. So a
workflow in *anyone's* repository can assume the role. They found vulnerable
roles across many organisations within hours, including roles owned by AWS
itself.

On its own, that is a small IAM mistake. Joined to what the role can reach, it
is a full breach from outside the company:

```
AnyGitHubUser ──CAN_TRIGGER──> Workflow (pull_request_target, id-token: write)
  ──GETS_TOKEN_FOR──> GitHubOIDCClaim (sub: repo:attacker/anything:ref:...)
  ──CAN_ASSUME──> IamRole (trust policy matches on aud only)
  ──CAN_ACCESS──> S3Bucket customer-data (s3:GetObject)
```

Breachmap exists to find that join, to say which single edge to cut so every
such path is gone, and to be honest about how sure it is.

## What it does

1. **Collects** read-only state from GitHub (workflows, triggers, OIDC), AWS
   (IAM, STS, S3, KMS, Secrets Manager, SCPs) and Kubernetes (RBAC, service
   accounts).
2. **Builds a graph** of "who can reach what". Every edge carries its
   evidence (the exact policy statement or file and line), an evidence level,
   when it was observed and which fix would remove it. **No edge without
   evidence** is enforced by the data model, not by convention.
3. **Evaluates permissions properly.** Its own implementation of AWS's
   documented policy evaluation logic: explicit deny wins, SCPs must allow,
   resource policies, permission boundaries and identity policies combined in
   AWS's order, and conditions (`sub`, `aud`, org ID, source IP) actually
   evaluated. Most tools check identity policies only.
4. **Cross-checks with AWS** using the free IAM policy simulator API and IAM
   Access Analyzer, and with Kubernetes using `SubjectAccessReview`. Edges
   are labeled **Verified**, **Derived**, **Possible** or **Disputed**, and a
   path is only as strong as its weakest edge.
5. **Finds paths** from entry points to crown jewels and runs a **minimum
   cut** to choose the cheapest set of edges that disconnects all of them.
   One cut at a shared role beats patching three entry points.
6. **Generates fixes** as pull requests (trust-policy and workflow-trigger
   patches), accepted only after deterministic checks prove the path is gone
   and nothing broke. An LLM may draft the patch; it never decides anything.
7. **Emits detections** (Sigma rules on CloudTrail `AssumeRoleWithWebIdentity`)
   for paths that stay open, each shipping with a sample event that must
   trigger it and one that must not.
8. **Measures itself** on a seeded lab with an answer key, CloudGoat and
   pathfinding.cloud scenarios, and mutation tests. Recall, precision and
   edge agreement are numbers in `docs/accuracy.md`, not claims.

### Where it differs from Prowler, Cartography and friends

Prowler App and Cartography are excellent at their layer. The wedge here is
narrow and deliberate:

- the **cross-layer join** GitHub → AWS → Kubernetes as one graph;
- the **min-cut fix** instead of a list of findings;
- **measured accuracy** with evidence levels shown on every edge.

Everything else is reused, not rebuilt: cloud-audit for AWS privilege
escalation edges, zizmor findings for `CAN_TRIGGER` edges, Cartography for
any collector beyond IAM, CloudGoat and pathfinding.cloud as answer keys.

## Architecture

```
            ┌──────────────── control plane ────────────────┐
            │  FastAPI (auth, audit)  ──  PostgreSQL          │
            │  (jobs, users, graph snapshots per scan)        │
            └───────────────────────┬────────────────────────┘
                                    │ Redis + RQ
            ┌──────────────── worker plane ─────────────────┐
  GitHub ──>│ collectors ─> evaluator ─> path engine ─> fix   │──> pull requests
  AWS    ──>│ (read-only)   (policies   (NetworkX    verifier │──> Sigma rules
  kind   ──>│               + oracles)   min-cut)   (checks)  │──> CIS mapping
            └───────────────────────────────────────────────┘
```

- **Python 3.12**, FastAPI, Pydantic v2, SQLAlchemy, Redis + RQ, NetworkX,
  boto3, the official Kubernetes client, pySigma.
- Postgres + NetworkX in memory; no Neo4j in v1
  ([ADR-0001](docs/adr/0001-python-stack.md)).
- Lab: kind on a laptop plus an AWS free-plan account for IAM/STS/S3/KMS/
  Secrets Manager, budget alarm at $5, everything tagged `breachmap-lab=true`
  ([ADR-0002](docs/adr/0002-free-tier-lab.md)).
- Full design: [docs/design.md](docs/design.md).

## Status

| Area | State |
|---|---|
| Repo, process, design doc, ADRs, milestone plan | done |
| Python scaffold and hardened CI | done |
| Lab answer key and fixtures | done, `v1-oidc`: 16 roles, 28 decisions, 7 paths, 8 non-paths |
| Offline AWS policy evaluator | done for the five v1 actions; all 28 answer-key decisions reproduce |
| Terraform lab, kind config | not started |
| Collectors, graph, oracles, paths, min-cut, fixes, detections | not started |

Honest caveats that will stay in this section:

- Kubernetes runs on **kind**, not EKS. RBAC and `SubjectAccessReview` are
  identical; EKS-only links (IRSA, Pod Identity, access entries) have no
  oracle here and are always labeled **Derived**.
- v1 is **one path family** (GitHub OIDC → IAM role → S3/Secret/KMS, optional
  Kubernetes service account) done to the accuracy targets. Lambda, EC2,
  security groups, Falco, Azure/GCP and log ingestion are out of scope.
- Accuracy numbers appear only after they are measured.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/) (it installs Python 3.12 itself).

```
git clone https://github.com/rj-karan/Breachmap.git
cd Breachmap
uv sync --all-groups
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
```

That is the whole CI, locally. No cloud account is needed; everything in
`tests/` runs on JSON fixtures. Two commands exist so far, both offline:

```
uv run breachmap check  --fixture lab/fixtures/v1-oidc --answer-key lab/answer-keys/v1-oidc.json
uv run breachmap mutate --fixture lab/fixtures/v1-oidc --answer-key lab/answer-keys/v1-oidc.json \
                        --mutations lab/mutations/v1-oidc.json
```

The first reproduces every decision in the answer key with the evaluator and
prints the reason for each; the second changes one fact at a time and checks
that exactly the declared decisions flip. Numbers live in
[docs/accuracy.md](docs/accuracy.md).

## Roadmap

| Milestone | Builds | Exit test | Due |
|---|---|---|---|
| [M1](docs/milestones/M1.md) Lab + answer key + evaluator | Seeded fixtures, answer key, offline IAM evaluator, Terraform lab | `pytest tests/lab tests/iam` green; `terraform plan` succeeds | 2026-11-24 |
| [M2](docs/milestones/M2.md) Collectors + graph | GitHub, AWS, kind collectors; edges with evidence | all answer-key edges collected, none without evidence | 2026-12-08 |
| [M3](docs/milestones/M3.md) Accuracy engine | Simulator, Access Analyzer, SubjectAccessReview oracles | ≥ 99% edge agreement | 2026-12-29 |
| [M4](docs/milestones/M4.md) Paths + min-cut | Path search, cost model, cut chooser | recall and precision ≥ 95% | 2027-01-19 |
| [M5](docs/milestones/M5.md) Fix + verify | Fix templates, patch drafter, five checks, PRs | ≥ 90% of lab fixes pass | 2027-02-09 |
| [M6](docs/milestones/M6.md) Detect + report | Sigma rules, CIS mapping, mutation suite | rules pass own tests; mutation ≥ 95% | 2027-03-02 |

## Security model

Breachmap holds a map of exactly how to breach its users, so it is designed
as a target.

- **Never write access to the cloud.** Read-only `SecurityAudit`-style roles,
  short-lived credentials, external ID. Changes happen only through pull
  requests a human merges.
- **The LLM never decides.** Repository text, tags and workflow content are
  data. Scores, edges and fix acceptance are deterministic. Secrets are
  redacted before any prompt.
- **Lab replay is fenced** to resources tagged `breachmap-lab=true` and an
  allowlist, enforced in code.
- **Supply chain for this repo:** `permissions: {}` at the top of every
  workflow, every action pinned to a full commit SHA, `persist-credentials:
  false`, actionlint and zizmor on our own workflows, Dependabot with a
  cooldown.

Report vulnerabilities privately: see [SECURITY.md](SECURITY.md).

## How this repo is run

Single maintainer, run like a team:

- every change is an issue → branch `type/N-slug` → Conventional Commits with
  `Refs #N` → PR with `Closes #N` → CI → squash merge; nobody pushes to `main`;
- a [project board](https://github.com/rj-karan/Breachmap/projects) tracks
  M1–M6, each milestone file carries its exit test;
- every IAM evaluation rule is a test quoting the AWS doc sentence before it
  is code;
- [docs/learning-path.md](docs/learning-path.md) records what each milestone
  teaches, with one source per topic.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Contributing

Issues and PRs are welcome, especially new adversarial IAM fixtures (a policy
where the evaluator is wrong is the most valuable contribution there is).
Read [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[Apache-2.0](LICENSE).
