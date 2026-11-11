# Learning path

One checklist per milestone. Each topic has one good source. Tick as you go.
The point of this project is to understand every piece, not just to have it.

## M0 — Bootstrap (repo and process)

- [ ] Conventional Commits and why squash merges make them matter —
      https://www.conventionalcommits.org/en/v1.0.0/
- [ ] Architecture Decision Records (the Nygard format) —
      https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions
- [ ] GitHub branch protection, rulesets and required status checks —
      https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches
- [ ] GitHub Projects v2 and the GraphQL API behind `gh project` —
      https://docs.github.com/en/issues/planning-and-tracking-with-projects
- [ ] Apache-2.0 vs MIT: the patent grant —
      https://choosealicense.com/licenses/apache-2.0/
- [ ] The Tinder GitHub OIDC finding (the motivating example) —
      https://lifeattinder.com/blog/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations

## M1 — Lab + answer key + offline IAM evaluator

IAM evaluation, the core of the project:

- [ ] How AWS decides allow or deny, step by step (explicit deny, SCP, resource policy, identity, boundary, session) —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html
- [ ] Cross-account evaluation: why both sides must allow —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html
- [ ] SCP inheritance: an Allow is needed at every level, a Deny at any level wins —
      https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
- [ ] Policy elements: Action/NotAction, Resource/NotResource, Principal/NotPrincipal —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
- [ ] Resource ARN wildcards, including the trailing-star rule that crosses colons —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html
- [ ] Condition operators and the missing-key rules (negated operators, IfExists, Null) —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
- [ ] ForAllValues vs ForAnyValue, and why ForAllValues on a missing key is a permission hole —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
- [ ] Policy variables, default values and the `${*}` escapes —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html
- [ ] Permissions boundaries (intersection, and how they limit resource-policy grants to a role) —
      https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
- [ ] KMS key policies and the "Enable IAM policies" root statement —
      https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html

GitHub Actions OIDC, the attack the project is built around:

- [ ] OIDC in GitHub Actions: token claims and `sub` formats (including the immutable form) —
      https://docs.github.com/en/actions/reference/security/oidc
- [ ] Configuring a trust policy for GitHub in AWS, and what `aud` and `sub` really restrict —
      https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws
- [ ] The Tinder write-up: aud-only trust is assumable from any repository —
      https://lifeattinder.com/blog/identifying-vulnerabilities-in-github-actions-aws-oidc-configurations
- [ ] `pull_request_target` and "pwn requests": why a base-branch token plus PR code is dangerous —
      https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- [ ] zizmor's audits (dangerous-triggers, unpinned-uses, excessive-permissions, artipacked) —
      https://docs.zizmor.sh/audits/

Testing and measurement:

- [ ] Known-answer testing and why the answer key comes before the code —
      https://martinfowler.com/bliki/TestDrivenDevelopment.html
- [ ] Mutation testing: proving a test suite notices the right changes —
      https://en.wikipedia.org/wiki/Mutation_testing
- [ ] Three-valued logic for "we cannot know" (Kleene), the idea behind the `unknown` outcome —
      https://en.wikipedia.org/wiki/Three-valued_logic
- [ ] Pydantic v2 models, validators and strict schemas —
      https://docs.pydantic.dev/latest/concepts/models/
- [ ] mypy strict mode and what each flag catches —
      https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-strict

Infrastructure and supply chain:

- [ ] Terraform `for_each`, `default_tags` and planning without credentials —
      https://developer.hashicorp.com/terraform/language/meta-arguments/for_each
- [ ] Reading `terraform show -json` plan output —
      https://developer.hashicorp.com/terraform/internals/json-format
- [ ] AWS Budgets alarms as a cost backstop —
      https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html
- [ ] kind clusters and `kubectl auth can-i` (pass subresources with `--subresource`) —
      https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access
- [ ] Kubernetes RBAC: Role, ClusterRole, bindings, groups —
      https://kubernetes.io/docs/reference/access-authn-authz/rbac/
- [ ] Hardening GitHub Actions: `permissions: {}`, SHA pinning, `persist-credentials: false` —
      https://docs.github.com/en/actions/reference/security/secure-use

## M2 — Collectors + graph

## M3 — Accuracy engine

## M4 — Paths + min-cut

## M5 — Fix + verify

## M6 — Detect + report
