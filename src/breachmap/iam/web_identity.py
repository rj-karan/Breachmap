"""OIDC web-identity callers: GitHub Actions claims and the STS request they make.

GitHub's ``sub`` formats come from "OpenID Connect reference" (Example subject
claims): ``repo:<org>/<repo>:environment:<name>`` when a job references an
environment, ``repo:<org>/<repo>:pull_request`` for ``pull_request`` events,
and ``repo:<org>/<repo>:ref:<ref>`` for branch and tag refs. Repositories
created after 15 July 2026 default to the immutable form
``repo:<org>@<owner-id>/<repo>@<repo-id>:...``.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

from breachmap.iam.context import RequestContext, RequestPrincipal
from breachmap.iam.evaluator import Request

GITHUB_ISSUER = "token.actions.githubusercontent.com"
ASSUME_WITH_WEB_IDENTITY = "sts:AssumeRoleWithWebIdentity"


class GitHubClaims(BaseModel):
    """The claims a GitHub Actions job's OIDC token carries.

    ``aud`` is chosen by the caller: the ``configure-aws-credentials`` action
    requests ``sts.amazonaws.com``, and any workflow can request any audience
    through the ``audience`` input, so a trust policy that checks only ``aud``
    does not restrict which repository may assume the role.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    repository: str = Field(pattern=r"^[^/]+/[^/]+$")
    ref: str | None = Field(default=None, description="e.g. refs/heads/main or refs/tags/v1")
    event_name: str = "push"
    environment: str | None = None
    aud: str = "sts.amazonaws.com"
    actor: str | None = None
    job_workflow_ref: str | None = None
    owner_id: str | None = Field(default=None, description="Set with repo_id for the immutable sub")
    repo_id: str | None = None

    @property
    def repository_owner(self) -> str:
        """The org or user that owns the repository."""
        return self.repository.split("/", 1)[0]

    @property
    def sub(self) -> str:
        """The subject claim exactly as GitHub builds it."""
        owner, name = self.repository.split("/", 1)
        prefix = (
            f"repo:{owner}@{self.owner_id}/{name}@{self.repo_id}"
            if self.owner_id and self.repo_id
            else f"repo:{self.repository}"
        )
        if self.environment:
            return f"{prefix}:environment:{self.environment}"
        if self.event_name == "pull_request":
            return f"{prefix}:pull_request"
        if self.ref is None:
            msg = "a push-style token needs a ref"
            raise ValueError(msg)
        return f"{prefix}:ref:{self.ref}"

    def as_claims(self) -> dict[str, str]:
        """All claims as a flat mapping, including the computed ``sub``."""
        claims = {
            "sub": self.sub,
            "aud": self.aud,
            "repository": self.repository,
            "repository_owner": self.repository_owner,
            "event_name": self.event_name,
        }
        for key in ("ref", "environment", "actor", "job_workflow_ref"):
            value = getattr(self, key)
            if value is not None:
                claims[key] = value
        return claims


def provider_host(provider_arn: str) -> str:
    """The issuer host of an IAM OIDC provider ARN (the part after ``oidc-provider/``)."""
    marker = ":oidc-provider/"
    if marker not in provider_arn:
        msg = f"{provider_arn!r} is not an OIDC provider ARN"
        raise ValueError(msg)
    return provider_arn.split(marker, 1)[1]


def web_identity_request(
    provider_arn: str,
    claims: Mapping[str, str],
    role_arn: str,
    *,
    unknown_keys: tuple[str, ...] = (),
) -> Request:
    """Build the ``sts:AssumeRoleWithWebIdentity`` request a token holder makes.

    Each claim becomes the condition key ``<issuer-host>:<claim>`` that trust
    policies reference, e.g. ``token.actions.githubusercontent.com:sub``.
    """
    host = provider_host(provider_arn)
    context = RequestContext(
        {f"{host}:{name}": value for name, value in claims.items()}, unknown_keys
    )
    return Request(
        principal=RequestPrincipal.federated(provider_arn),
        action=ASSUME_WITH_WEB_IDENTITY,
        resource=role_arn,
        context=context,
    )


def github_request(
    provider_arn: str, token: GitHubClaims, role_arn: str, *, unknown_keys: tuple[str, ...] = ()
) -> Request:
    """``web_identity_request`` for a GitHub Actions token."""
    return web_identity_request(
        provider_arn, token.as_claims(), role_arn, unknown_keys=unknown_keys
    )
