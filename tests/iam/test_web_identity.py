"""GitHub OIDC subject formats and trust evaluation, from GitHub's OIDC reference and the
AWS 'Principal' and 'Condition' references."""

from typing import Any

import pytest

from breachmap.iam import PolicyDocument
from breachmap.iam.environment import Environment, ResourcePolicy, RoleRecord
from breachmap.iam.evaluator import evaluate
from breachmap.iam.web_identity import (
    GitHubClaims,
    github_request,
    provider_host,
    web_identity_request,
)

A = "111111111111"
GH = f"arn:aws:iam::{A}:oidc-provider/token.actions.githubusercontent.com"
HOST = "token.actions.githubusercontent.com"
ROLE = f"arn:aws:iam::{A}:role/deploy"


def trust(condition: dict[str, Any], federated: str = GH) -> PolicyDocument:
    return PolicyDocument.parse(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"Federated": federated},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": condition,
            },
        }
    )


def env_with(trust_policy: PolicyDocument) -> Environment:
    record = RoleRecord(arn=ROLE, account_id=A, trust_policy=trust_policy)
    return Environment(
        roles={ROLE: record},
        resource_policies={
            ROLE: ResourcePolicy(kind="iam-trust", arn=ROLE, account_id=A, document=trust_policy)
        },
    )


def decide(trust_policy: PolicyDocument, token: GitHubClaims) -> tuple[str, str | None]:
    d = evaluate(github_request(GH, token, ROLE), env_with(trust_policy))
    return d.outcome, d.reason


# ---- subject formats


def test_sub_for_branch_ref() -> None:
    """'Branch references: "repo:octo-org/octo-repo:ref:refs/heads/demo-branch"'"""
    assert (
        GitHubClaims(repository="octo-org/octo-repo", ref="refs/heads/demo-branch").sub
        == "repo:octo-org/octo-repo:ref:refs/heads/demo-branch"
    )


def test_sub_for_tag_ref() -> None:
    """'Tag references: "repo:octo-org/octo-repo:ref:refs/tags/demo-tag"'"""
    assert (
        GitHubClaims(repository="octo-org/octo-repo", ref="refs/tags/demo-tag").sub
        == "repo:octo-org/octo-repo:ref:refs/tags/demo-tag"
    )


def test_sub_for_pull_request_event() -> None:
    """'Pull request events: "repo:octo-org/octo-repo:pull_request"'"""
    token = GitHubClaims(
        repository="octo-org/octo-repo", ref="refs/pull/7/merge", event_name="pull_request"
    )
    assert token.sub == "repo:octo-org/octo-repo:pull_request"


def test_sub_for_environment_takes_precedence() -> None:
    """'Environment filtering: "repo:octo-org/octo-repo:environment:Production"'"""
    token = GitHubClaims(
        repository="octo-org/octo-repo", ref="refs/heads/main", environment="Production"
    )
    assert token.sub == "repo:octo-org/octo-repo:environment:Production"


def test_pull_request_target_runs_in_the_base_context() -> None:
    """A pull_request_target job runs on the base branch, so its token carries the base ref,
    which is exactly why a sub scoped to refs/heads/main does not stop it."""
    token = GitHubClaims(
        repository="acme/app", ref="refs/heads/main", event_name="pull_request_target"
    )
    assert token.sub == "repo:acme/app:ref:refs/heads/main"


def test_immutable_sub_format() -> None:
    """'"repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main"' for repositories created
    after 15 July 2026."""
    token = GitHubClaims(
        repository="octo-org/octo-repo", ref="refs/heads/main", owner_id="123456", repo_id="456789"
    )
    assert token.sub == "repo:octo-org@123456/octo-repo@456789:ref:refs/heads/main"


def test_push_token_needs_a_ref() -> None:
    with pytest.raises(ValueError, match="needs a ref"):
        _ = GitHubClaims(repository="a/b").sub


def test_claims_mapping_and_host() -> None:
    token = GitHubClaims(
        repository="acme/app",
        ref="refs/heads/main",
        actor="alice",
        job_workflow_ref="acme/app/.github/workflows/x.yml@refs/heads/main",
    )
    claims = token.as_claims()
    assert claims["repository_owner"] == "acme"
    assert claims["actor"] == "alice"
    assert "environment" not in claims
    assert provider_host(GH) == HOST
    with pytest.raises(ValueError, match="not an OIDC provider ARN"):
        provider_host("arn:aws:iam::111111111111:role/x")
    req = github_request(GH, token, ROLE)
    assert req.context.single(f"{HOST}:sub") == "repo:acme/app:ref:refs/heads/main"
    assert req.principal.provider_arn == GH


# ---- trust policy evaluation


def test_aud_only_trust_admits_any_repository() -> None:
    """The Tinder case. aud is chosen by the caller (configure-aws-credentials asks for
    sts.amazonaws.com; the `audience` input can request anything), so an aud-only condition
    does not restrict which repository may assume the role."""
    policy = trust({"StringEquals": {f"{HOST}:aud": "sts.amazonaws.com"}})
    assert decide(policy, GitHubClaims(repository="attacker/evil", ref="refs/heads/main")) == (
        "allow",
        None,
    )
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/main")) == (
        "allow",
        None,
    )


def test_sub_scoped_trust() -> None:
    """StringEquals: 'Exact matching, case sensitive'."""
    policy = trust(
        {
            "StringEquals": {
                f"{HOST}:aud": "sts.amazonaws.com",
                f"{HOST}:sub": "repo:acme/app:ref:refs/heads/main",
            }
        }
    )
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/main")) == (
        "allow",
        None,
    )
    assert decide(policy, GitHubClaims(repository="attacker/evil", ref="refs/heads/main")) == (
        "deny",
        "condition_mismatch",
    )
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/feature")) == (
        "deny",
        "condition_mismatch",
    )
    assert decide(
        policy,
        GitHubClaims(repository="acme/app", ref="refs/pull/1/merge", event_name="pull_request"),
    ) == ("deny", "condition_mismatch")
    assert decide(
        policy,
        GitHubClaims(
            repository="acme/app", ref="refs/heads/main", event_name="pull_request_target"
        ),
    ) == ("allow", None)


def test_string_equals_with_a_wildcard_never_matches() -> None:
    """A common mistake: '*' under StringEquals is a literal asterisk."""
    policy = trust({"StringEquals": {f"{HOST}:sub": "repo:acme/*"}})
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/main")) == (
        "deny",
        "condition_mismatch",
    )


def test_string_like_org_wildcard() -> None:
    """StringLike: 'The values can include multi-character match wildcards (*)'."""
    policy = trust(
        {
            "StringEquals": {f"{HOST}:aud": "sts.amazonaws.com"},
            "StringLike": {f"{HOST}:sub": "repo:acme/*"},
        }
    )
    assert decide(policy, GitHubClaims(repository="acme/website", ref="refs/heads/main")) == (
        "allow",
        None,
    )
    assert decide(policy, GitHubClaims(repository="attacker/evil", ref="refs/heads/main")) == (
        "deny",
        "condition_mismatch",
    )


def test_string_like_repo_wildcard_admits_everyone() -> None:
    policy = trust({"StringLike": {f"{HOST}:sub": "repo:*"}})
    assert decide(policy, GitHubClaims(repository="attacker/evil", ref="refs/heads/main")) == (
        "allow",
        None,
    )


def test_environment_scoped_trust() -> None:
    policy = trust({"StringEquals": {f"{HOST}:sub": "repo:acme/app:environment:prod"}})
    assert decide(
        policy, GitHubClaims(repository="acme/app", ref="refs/heads/main", environment="prod")
    ) == ("allow", None)
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/main")) == (
        "deny",
        "condition_mismatch",
    )


def test_for_any_value_sub_list() -> None:
    policy = trust(
        {
            "ForAnyValue:StringLike": {
                f"{HOST}:sub": ["repo:acme/app:ref:refs/heads/main", "repo:acme/app:environment:*"]
            }
        }
    )
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/main")) == (
        "allow",
        None,
    )
    assert decide(policy, GitHubClaims(repository="acme/app", environment="staging")) == (
        "allow",
        None,
    )
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/dev")) == (
        "deny",
        "condition_mismatch",
    )


def test_missing_aud_condition_with_other_audience() -> None:
    policy = trust({"StringEquals": {f"{HOST}:sub": "repo:acme/app:ref:refs/heads/main"}})
    assert decide(
        policy,
        GitHubClaims(repository="acme/app", ref="refs/heads/main", aud="https://github.com/acme"),
    ) == ("allow", None)


def test_wrong_provider_is_a_trust_mismatch() -> None:
    """'the Federated principal must be the provider that issued the token'."""
    kind = f"arn:aws:iam::{A}:oidc-provider/oidc.lab.local/kind"
    policy = trust(
        {"StringEquals": {"oidc.lab.local/kind:sub": "system:serviceaccount:payments:app-sa"}},
        federated=kind,
    )
    assert decide(policy, GitHubClaims(repository="acme/app", ref="refs/heads/main")) == (
        "deny",
        "trust_mismatch",
    )
    sa = web_identity_request(
        kind, {"sub": "system:serviceaccount:payments:app-sa", "aud": "sts.amazonaws.com"}, ROLE
    )
    assert evaluate(sa, env_with(policy)).outcome == "allow"


def test_source_ip_on_a_hosted_runner_is_unknown() -> None:
    policy = trust(
        {
            "StringEquals": {f"{HOST}:sub": "repo:acme/app:ref:refs/heads/main"},
            "IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
        }
    )
    req = github_request(
        GH,
        GitHubClaims(repository="acme/app", ref="refs/heads/main"),
        ROLE,
        unknown_keys=("aws:SourceIp",),
    )
    d = evaluate(req, env_with(policy))
    assert d.outcome == "unknown"
    assert d.unknown_keys == ("aws:sourceip",)
