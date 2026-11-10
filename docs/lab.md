# The seeded lab

The lab is the ground truth Breachmap is measured against. It exists in two
forms that must always agree:

1. **Fixtures** under `lab/fixtures/<name>/`: JSON snapshots of what the
   collectors would read from GitHub (`github.json`), AWS (`aws.json`) and a
   Kubernetes cluster (`kubernetes.json`). Schemas live in
   `src/breachmap/lab/fixtures.py`. Unknown keys are errors, references
   (attached policies, SCPs) must resolve, and policy documents are kept as
   raw AWS JSON exactly as the APIs return them.
2. **Answer keys** under `lab/answer-keys/<name>.json`: what must be found
   and what must not. Schema in `src/breachmap/lab/answer_key.py`.

Every test in `tests/` runs on these files. No cloud account is needed. The
Terraform under `lab/aws/` (M1, issue #7) builds the same resources for real
so the oracle cross-checks in M3 have something to talk to.

## Answer-key contents

| Section | Used from | What it states |
|---|---|---|
| `decisions` | M1 | One allow / deny / unknown question for the policy evaluator: principal, action, resource, context, the expected outcome, the blocking reason for denies, and the AWS or GitHub doc sentence it rests on |
| `paths` | M4 | Attacker-to-crown-jewel routes that must be reported, as `NodeType:identifier` nodes with the edge type between each pair, and the evidence level the whole path should carry |
| `non_paths` | M4 | Routes that look open to a naive tool but must not be reported, with the index of the edge that does not exist and why |

Node identifiers: workflows are `owner/repo:.github/workflows/file.yml`, AWS
resources are ARNs, Kubernetes objects are `namespace/name`, OIDC claims are
the `sub` string, and `AnyGitHubUser:*` is the single entry point used in v1.

Blocking reasons: `explicit_deny`, `scp`, `permission_boundary`,
`resource_policy`, `condition_mismatch`, `no_permission`, `trust_mismatch`.
For a deny, `reason` is the *first* rule in AWS evaluation order that blocks
the request, so an explicit deny inside a bucket policy is `explicit_deny`,
not `resource_policy`.

## The `v1-oidc` fixture

Two accounts in one organization (`111111111111` lab, `222222222222`
partner), the GitHub OIDC provider, a stand-in cluster issuer for IRSA, and
sixteen roles, each built to exercise one rule:

| Role | Trust | What it tests |
|---|---|---|
| `deploy-aud-only` | `aud` only | The Tinder case. Any GitHub repo can assume it. Also has an EKS access entry (cluster admin) |
| `deploy-scoped` | `aud` + `sub` = `repo:acme/app:ref:refs/heads/main` | Correct scoping. Still reachable through `pull_request_target`, whose token carries the base-branch `sub` |
| `deploy-org-wildcard` | `StringLike` `repo:acme/*` | Any repo in the org |
| `deploy-prod-env` | `sub` = `repo:acme/app:environment:prod` | Environment scoping blocks the branch `sub` |
| `deploy-scp-blocked` | `aud` only | Assumable, but an SCP on the OU denies `secretsmanager:GetSecretValue` for everyone except `secrets-reader` |
| `deploy-boundary` | `aud` only | Identity allows S3 and KMS; the boundary allows S3 only |
| `ci-legacy-reader` | `aud` only | Identity allows S3; the bucket policy explicitly denies non-`deploy-*` principals |
| `ci-bootstrap` | `aud` only | Can `sts:AssumeRole` into two roles |
| `admin-breakglass` | trusts `ci-bootstrap` | Role chaining succeeds |
| `locked-role` | trusts `ci-bootstrap` with `aws:MultiFactorAuthPresent` | Role chaining fails the `Bool` condition |
| `secrets-reader` | `aud` + `sub` main | The one principal the SCP lets through; `kms:Decrypt` only `kms:ViaService` Secrets Manager |
| `irsa-app` | kind issuer, `sub` = `system:serviceaccount:payments:app-sa` | IRSA-style mapping from a service account |
| `deploy-ip-locked` | `aud` + `sub` main + `aws:SourceIp` | The runner IP is unknowable offline: outcome `unknown`, evidence level Possible |
| `breachmap-audit` | account root with external ID | The collector's own read-only role; on no path |
| `partner-reader` (222) | partner root | Cross-account read: bucket policy and identity policy both allow |
| `partner-noidentity` (222) | partner root | Cross-account: bucket policy allows, identity policy missing, so denied |

Three repos: `acme/app` (a `pull_request_target` workflow that checks out PR
code with `id-token: write`, a safe push-triggered deploy, an environment-
gated release), `acme/website` (another unsafe preview workflow) and a private
`acme/infra` with a safe CI workflow. The `pull_request_target` workflows carry
the zizmor findings a real scan would produce.

The kind cluster has one namespace of interest, `payments`, with pod `app`
running as `app-sa`, which is annotated with the `irsa-app` role ARN.

Crown jewels: the `acme-customer-data` bucket, the `prod/db-credentials`
secret and the prod KMS key.

## Adding a case

1. Add the resource to the fixture JSON. Keep policy documents in AWS's own
   shape.
2. Add a decision (`dNN`) with the expected outcome and, for a deny, the
   reason. Quote the doc sentence in `cites`.
3. If it changes a route, add or edit a path or non-path and reference the
   decision ids.
4. Run `uv run pytest tests/lab`. The answer key is cross-checked against the
   fixture so a typo in an ARN fails fast.
