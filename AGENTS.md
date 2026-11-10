# Breachmap

Attack-path analysis across GitHub Actions, AWS IAM and Kubernetes, with a
min-cut fix chooser. Full design: `docs/design.md`. Current milestone files:
`docs/milestones/`.

## Stack

Python 3.12, FastAPI, Pydantic v2, SQLAlchemy, Redis + RQ, NetworkX, boto3,
kubernetes client, pySigma. Tooling: uv, ruff, mypy `--strict`, pytest with
coverage. Postgres + NetworkX in memory (no Neo4j in v1, see
`docs/adr/0001-python-stack.md`).

## Commands

```
uv sync --all-groups         # install
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest                # coverage report is on by default
```

Run lint and tests locally before every push and report the real result.

## Hard rules

- Read-only cloud access. Breachmap never needs write credentials; changes
  land only as pull requests a human merges.
- No edge without evidence. Every graph edge carries evidence, evidence level,
  observed-at time, collector version and a fix template.
- Every IAM evaluation rule gets a unit test written from the AWS docs before
  the code. Never guess AWS behaviour.
- Lab replay runs only against resources tagged `breachmap-lab=true`.
- Free tier only: no EKS, no paid analyzers, no LocalStack. kind for
  Kubernetes, AWS free plan for IAM/STS/S3/KMS/Secrets Manager.
- Workflow: issue -> branch `type/N-slug` -> Conventional Commits with
  `Refs #N` -> PR with `Closes #N` -> CI green -> squash merge. Never push to
  `main`.
- No AI attribution anywhere: no Co-Authored-By, no "Generated with", no
  session links in commits, PRs or files.
- CI workflows: `permissions: {}` at the top, every `uses:` pinned to a full
  SHA with a version comment, `timeout-minutes` on every job,
  `persist-credentials: false`.
