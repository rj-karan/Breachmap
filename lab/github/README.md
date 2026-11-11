# Lab workflows (deliberately unsafe)

These files are the workflows described in `lab/fixtures/v1-oidc/github.json`.
**They are vulnerable on purpose.** They live here, not in `.github/workflows/`,
so they never run in this repository.

To use them, create throwaway repositories in a lab GitHub org (`acme/app`,
`acme/website`, `acme/infra` in the fixture), copy the matching files into
each repository's `.github/workflows/`, and point `role-to-assume` at the lab
account. Never put them in a repository that can reach a real AWS account.

| File | Repo | What makes it unsafe |
|---|---|---|
| `app/pr-preview.yml` | `acme/app` | `pull_request_target` checks out the PR head with `id-token: write`; actions pinned to tags |
| `app/deploy.yml` | `acme/app` | Safe: push-only, SHA-pinned |
| `app/release.yml` | `acme/app` | Safe: environment-gated |
| `website/preview.yml` | `acme/website` | Same pattern as `pr-preview.yml`, reaching the org-wildcard role |
| `infra/ci.yml` | `acme/infra` | Safe: no OIDC |

Running zizmor on this directory reproduces the findings recorded in the
fixture:

```
uvx zizmor --pedantic lab/github/workflows
```
