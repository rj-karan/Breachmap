"""The policies an evaluation can see: roles, resource policies and the SCP tree.

An ``Environment`` is what the collectors (M2) or the lab fixture produce.
It is deliberately dumb: lookups only, no evaluation.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from breachmap.iam.policy import PolicyDocument

ResourceKind = Literal["s3", "kms", "secretsmanager", "iam-trust", "other"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RoleRecord(_Strict):
    """A role with its parsed policies."""

    arn: str
    account_id: str
    trust_policy: PolicyDocument
    identity_policies: list[PolicyDocument] = Field(default_factory=list)
    boundary: PolicyDocument | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class ResourcePolicy(_Strict):
    """A resource-based policy attached to the resource identified by ``arn``.

    For S3, ``arn`` is the bucket ARN and the policy also governs objects
    under it. For a role trust policy, ``arn`` is the role ARN.
    """

    kind: ResourceKind
    arn: str
    account_id: str
    document: PolicyDocument


class Environment(_Strict):
    """Everything the evaluator may consult."""

    roles: dict[str, RoleRecord] = Field(default_factory=dict)
    resource_policies: dict[str, ResourcePolicy] = Field(default_factory=dict)
    scp_levels: dict[str, list[list[PolicyDocument]]] = Field(
        default_factory=dict,
        description="account id -> SCP documents per level from the root down to the account",
    )
    org_id: str | None = None
    resource_accounts: dict[str, str] = Field(
        default_factory=dict,
        description="resource ARN (bucket ARN for S3) -> owning account, for ARNs without one",
    )

    def role(self, arn: str) -> RoleRecord | None:
        """The role record, if known."""
        return self.roles.get(arn)

    def resource_policy_for(self, resource_arn: str) -> ResourcePolicy | None:
        """The resource policy governing ``resource_arn`` (an S3 object maps to its bucket)."""
        key = _policy_key(resource_arn)
        return self.resource_policies.get(key)

    def resource_account(self, resource_arn: str) -> str | None:
        """The account that owns the resource, from the ARN or the recorded owner."""
        parts = resource_arn.split(":", 5)
        if len(parts) == 6 and parts[4]:
            return parts[4]
        return self.resource_accounts.get(_policy_key(resource_arn))

    def scps_for(self, account_id: str) -> list[list[PolicyDocument]]:
        """SCP documents per organization level for the account (empty when not in an org)."""
        return self.scp_levels.get(account_id, [])

    def with_roles(self, roles: Iterable[RoleRecord]) -> Environment:
        """A copy with extra roles (used by tests)."""
        merged = dict(self.roles)
        merged.update({r.arn: r for r in roles})
        return self.model_copy(update={"roles": merged})


def _policy_key(resource_arn: str) -> str:
    if resource_arn.startswith("arn:aws:s3:::"):
        bucket = resource_arn.removeprefix("arn:aws:s3:::").split("/", 1)[0]
        return f"arn:aws:s3:::{bucket}"
    return resource_arn
