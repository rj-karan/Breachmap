# Lab

The seeded lab exists three times, and tests keep the copies identical:

| Copy | Where | Needs |
|---|---|---|
| JSON fixture + answer key | `fixtures/`, `answer-keys/`, `mutations/` | nothing; every test runs on these |
| AWS half | `aws/` (Terraform) | an AWS free-plan account, only for `apply` |
| Kubernetes half | `kind/` | Docker, `kind`, `kubectl` |
| GitHub half | `github/workflows/` | throwaway lab repositories |

`tests/lab/test_lab_sources.py` compares the Terraform plan, the kind
manifests and the lab workflows with the fixture.

## AWS (offline plan, no account)

```
make lab-plan
```

Runs `fmt`, `validate`, and `plan` with dummy credentials (`offline.tfvars`
sets `offline_plan = true`), writes `aws/plan.json`, and checks it against the
fixture. 41 resources. All 14 lab-account trust policies are compared
exactly. Five of the twelve inline policies reference KMS key or secret ARNs
that only exist after apply, so the plan cannot show them and they are
skipped.

## AWS (real account)

Only for the oracle cross-checks in M3 and lab replay in M5.

1. Create a new AWS account on the free plan. Do not use an account that
   holds anything real.
2. `cp aws/lab.auto.tfvars.example aws/lab.auto.tfvars` and fill in the
   account id, an email for the budget alarm, and a unique bucket suffix.
3. `make lab-apply`. Review the plan before typing `yes`.
4. `make lab-destroy` when done.

Cost: IAM, STS and the OIDC providers are free. Two S3 buckets with no data,
one Secrets Manager secret and two KMS keys are the only billable items,
a few US dollars a month at most and inside the free-plan credits. A budget
alarm emails at 80% of $5 actual and 100% forecast; AWS Budgets is free for
the first two budgets. KMS keys have a 7-day deletion window after destroy.

Every resource carries `breachmap-lab = "true"` through provider
`default_tags`. Lab replay (M5) refuses to touch anything without that tag.

The Organizations SCP in the fixture is **not** in Terraform: creating an
organization changes the account in ways that are hard to undo. SCP edges
are covered offline and labeled accordingly until an org-backed lab exists.

## Kubernetes (kind)

```
make kind-up      # create cluster breachmap-lab and apply kind/manifests
make kind-down
```

RBAC checks with Kubernetes' own authorizer (the same SubjectAccessReview the
M3 oracle will use):

```
kubectl --context kind-breachmap-lab auth can-i create pods --subresource=exec -n payments \
  --as=someone --as-group=breachmap:deployers                      # yes
kubectl --context kind-breachmap-lab auth can-i list configmaps -n payments \
  --as=system:serviceaccount:payments:app-sa                       # yes
kubectl --context kind-breachmap-lab auth can-i create pods --subresource=exec -n payments \
  --as=system:serviceaccount:payments:app-sa                       # no
```

Pass a subresource with `--subresource`. Writing `pods/exec` as the resource
returns "no" even when the binding allows exec, because the authorizer sees a
resource literally named `pods/exec`.

kind has no IRSA. The `eks.amazonaws.com/role-arn` annotation on `app-sa` is
data for the collector; nothing can exchange the pod's token for AWS
credentials. Every edge through it is **Derived** (ADR-0002).

## GitHub

See [github/README.md](github/README.md). The workflows are deliberately
unsafe and live outside `.github/workflows/` so they never run here.
