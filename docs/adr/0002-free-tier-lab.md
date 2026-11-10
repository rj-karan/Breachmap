# ADR-0002: Free-tier lab (kind, AWS free plan, no LocalStack), single path family for v1

- Status: accepted
- Date: 2026-11-10

## Context

The design doc assumes an EKS cluster, a Terraform-managed AWS + GitHub lab,
and a budget cap. The maintainer is a student. Everything must be free, and the
v1 scope in the doc (EC2, Lambda, security groups, Falco, log ingestion) is
wider than one person can build to the stated accuracy targets.

## Decision

**Kubernetes: kind on the laptop, not EKS.** RBAC and `SubjectAccessReview`
behave identically. EKS-specific links (IRSA, Pod Identity, access entries)
have no oracle on kind, so edges derived from them carry the design's
**Derived** evidence level and the docs say so.

**AWS: a fresh account on the AWS free plan** (credits up to $200 over six
months), limited to IAM, STS, S3, KMS and Secrets Manager. Terraform tags
every resource `breachmap-lab = "true"`, creates an AWS Budgets alarm at $5,
and `terraform destroy` tears everything down. Only free oracles are used: the
IAM policy simulator API (`SimulatePrincipalPolicy`, `SimulateCustomPolicy`)
and IAM Access Analyzer external-access findings.

**No LocalStack.** The community edition is archived and IAM enforcement is a
paid feature, so it cannot serve as an oracle. **No paid analyzers.**

**GitHub Actions and GHCR** for CI and images (free for public repos). Grafana
Cloud free tier if hosted monitoring is ever needed.

**Everything else runs offline on JSON fixtures.** The evaluator, path engine,
fix chooser and detection rules are all tested without any cloud account. The
cloud account is only for oracle cross-checks and lab replay.

**v1 is one path family, done to the accuracy targets:**

```
AnyGitHubUser
  -> Workflow            (pull_request_target, unpinned action, OIDC)
  -> GitHubOIDCClaim
  -> IamRole             (trust policy with sub/aud conditions evaluated)
  -> S3Bucket | Secret | KmsKey
  -> optional kind ServiceAccount via IRSA-style mapping (Derived)
```

Plus the min-cut fix chooser, fix PRs for trust policies and workflow
triggers, Sigma rules for the `AssumeRoleWithWebIdentity` step, and CIS
mapping for those edges. The AWS evaluator covers exactly
`sts:AssumeRoleWithWebIdentity`, `sts:AssumeRole`, `s3:GetObject`,
`secretsmanager:GetSecretValue` and `kms:Decrypt`, including explicit deny,
SCPs, resource policies, permission boundaries, `NotAction` and condition
keys.

**Out of v1:** Falco, Lambda, EC2, security groups, Azure/GCP, log ingestion.

**Reuse, don't rebuild:** cloud-audit for AWS privilege-escalation edges,
Datadog's pathfinding.cloud and CloudGoat as answer keys, zizmor findings as
`CAN_TRIGGER` edges, Cartography for any collector beyond IAM.

## Consequences

- Any EKS-only edge is labeled Derived in every output. The README says this.
- The lab answer key is written before the lab exists, in JSON, so M1 does not
  block on AWS account creation.
- The Terraform lab is small enough that a full apply + destroy cycle fits
  inside free-tier limits many times over; the $5 alarm is a backstop.
