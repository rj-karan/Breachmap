"""Schemas for seeded-lab fixtures.

A fixture is a snapshot of what the collectors would read from GitHub, AWS
and a Kubernetes cluster, written by hand so the right answers are known
before any collector exists. Policy documents are kept as raw AWS JSON
(``PolicyJson``) exactly as the APIs return them; the IAM package parses
them into typed statements.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

PolicyJson = dict[str, Any]

AccountId = Annotated[str, StringConstraints(pattern=r"^\d{12}$")]
_ARN_PATTERN = r"^arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{0,12}:.+$"
Arn = Annotated[str, StringConstraints(pattern=_ARN_PATTERN)]
RepoFullName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]

_ACCOUNT_IN_ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:(\d{12}):")


class _Strict(BaseModel):
    """Base for all fixture models: unknown keys are errors, instances are frozen."""

    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- GitHub


class ActionRef(_Strict):
    """One ``uses:`` reference in a workflow."""

    uses: str = Field(description="As written, e.g. actions/checkout@v4 or owner/repo@<sha>")
    pinned_to_sha: bool = Field(description="True when the ref is a full 40-hex commit SHA")


class ZizmorFinding(_Strict):
    """A finding zizmor would report for this workflow, by audit id."""

    audit: str = Field(description="zizmor audit id, e.g. dangerous-triggers, unpinned-uses")
    severity: Literal["informational", "low", "medium", "high"]


class Workflow(_Strict):
    """One GitHub Actions workflow file and the facts that matter for CAN_TRIGGER."""

    path: str = Field(pattern=r"^\.github/workflows/[^/]+\.ya?ml$")
    triggers: list[str] = Field(min_length=1, description="Event names from the `on:` block")
    permissions: dict[str, Literal["read", "write", "none"]] = Field(default_factory=dict)
    environment: str | None = None
    checks_out_untrusted_code: bool = Field(
        default=False,
        description="Runs code from a PR head (e.g. checkout with pull_request.head.sha)",
    )
    uses: list[ActionRef] = Field(default_factory=list)
    assumes_role_arn: str | None = Field(
        default=None, description="role-to-assume passed to configure-aws-credentials"
    )
    zizmor_findings: list[ZizmorFinding] = Field(default_factory=list)

    @property
    def requests_oidc_token(self) -> bool:
        """True when the workflow can mint a GitHub OIDC token."""
        return self.permissions.get("id-token") == "write"


class Repo(_Strict):
    """A GitHub repository with its workflows."""

    full_name: RepoFullName
    visibility: Literal["public", "private"]
    default_branch: str = "main"
    workflows: list[Workflow] = Field(default_factory=list)


class GitHubFixture(_Strict):
    """Everything collected from GitHub."""

    repos: list[Repo]


# --------------------------------------------------------------------------- AWS


class OrgUnit(_Strict):
    """An Organizations OU (or the root, whose parent is None)."""

    id: str
    parent_id: str | None = None
    scp_ids: list[str] = Field(default_factory=list)


class Account(_Strict):
    """A member account and where it sits in the organization."""

    id: AccountId
    alias: str
    parent_ou_id: str
    scp_ids: list[str] = Field(default_factory=list)


class ServiceControlPolicy(_Strict):
    """An SCP document; attachment is recorded on the OU or account."""

    id: str
    name: str
    document: PolicyJson


class Organization(_Strict):
    """The organization tree. Empty when the lab is a standalone account."""

    id: str
    root_id: str
    org_units: list[OrgUnit] = Field(default_factory=list)
    accounts: list[Account]
    scps: list[ServiceControlPolicy] = Field(default_factory=list)


class OidcProvider(_Strict):
    """An IAM OIDC identity provider (GitHub, or an EKS/kind cluster issuer)."""

    arn: Arn
    url: str = Field(description="Issuer host, e.g. token.actions.githubusercontent.com")
    client_ids: list[str] = Field(min_length=1)


class ManagedPolicy(_Strict):
    """A customer- or AWS-managed policy."""

    arn: Arn
    name: str
    document: PolicyJson


class IamRole(_Strict):
    """An IAM role with its trust policy and permissions."""

    arn: Arn
    name: str
    trust_policy: PolicyJson
    attached_policy_arns: list[str] = Field(default_factory=list)
    inline_policies: dict[str, PolicyJson] = Field(default_factory=dict)
    permissions_boundary_arn: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def account_id(self) -> str:
        """The account the role lives in, from its ARN."""
        return _account_of(self.arn)


class S3Bucket(_Strict):
    """An S3 bucket, optionally a crown jewel."""

    name: str
    account_id: AccountId
    bucket_policy: PolicyJson | None = None
    crown_jewel: bool = False
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def arn(self) -> str:
        """The bucket ARN."""
        return f"arn:aws:s3:::{self.name}"


class Secret(_Strict):
    """A Secrets Manager secret."""

    arn: Arn
    name: str
    kms_key_arn: str | None = Field(default=None, description="None means the AWS-managed key")
    resource_policy: PolicyJson | None = None
    crown_jewel: bool = False

    @property
    def account_id(self) -> str:
        """The owning account, from the ARN."""
        return _account_of(self.arn)


class KmsKey(_Strict):
    """A KMS customer-managed key with its key policy."""

    arn: Arn
    key_id: str
    key_policy: PolicyJson
    crown_jewel: bool = False

    @property
    def account_id(self) -> str:
        """The owning account, from the ARN."""
        return _account_of(self.arn)


class EksAccessEntry(_Strict):
    """An EKS access entry (or its kind stand-in) mapping an IAM role to cluster access."""

    cluster: str
    principal_arn: Arn
    kubernetes_groups: list[str] = Field(default_factory=list)
    access_policy: str | None = Field(
        default=None, description="e.g. AmazonEKSClusterAdminPolicy; None for group-only mapping"
    )


class AwsFixture(_Strict):
    """Everything collected from AWS."""

    organization: Organization
    oidc_providers: list[OidcProvider] = Field(default_factory=list)
    roles: list[IamRole] = Field(default_factory=list)
    managed_policies: list[ManagedPolicy] = Field(default_factory=list)
    buckets: list[S3Bucket] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    kms_keys: list[KmsKey] = Field(default_factory=list)
    eks_access_entries: list[EksAccessEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _references_resolve(self) -> AwsFixture:
        known_policies = {p.arn for p in self.managed_policies}
        for role in self.roles:
            for arn in role.attached_policy_arns:
                if arn not in known_policies and not arn.startswith("arn:aws:iam::aws:policy/"):
                    msg = f"role {role.name} attaches unknown policy {arn}"
                    raise ValueError(msg)
            boundary = role.permissions_boundary_arn
            if boundary and boundary not in known_policies:
                msg = f"role {role.name} has unknown boundary {role.permissions_boundary_arn}"
                raise ValueError(msg)
        known_scps = {s.id for s in self.organization.scps}
        attached = [
            *(s for ou in self.organization.org_units for s in ou.scp_ids),
            *(s for a in self.organization.accounts for s in a.scp_ids),
        ]
        for scp_id in attached:
            if scp_id not in known_scps:
                msg = f"unknown SCP {scp_id} attached"
                raise ValueError(msg)
        return self


# --------------------------------------------------------------------------- Kubernetes


class ServiceAccount(_Strict):
    """A Kubernetes service account; the IRSA annotation links it to an IAM role."""

    namespace: str
    name: str
    annotations: dict[str, str] = Field(default_factory=dict)

    @property
    def iam_role_arn(self) -> str | None:
        """The IRSA-style role ARN, if annotated."""
        return self.annotations.get("eks.amazonaws.com/role-arn")


class Pod(_Strict):
    """A running pod and the service account it uses."""

    namespace: str
    name: str
    service_account: str = "default"


class PolicyRule(_Strict):
    """One RBAC rule."""

    api_groups: list[str] = Field(default_factory=lambda: [""])
    resources: list[str]
    verbs: list[str]


class RbacRole(_Strict):
    """A Role (namespaced) or ClusterRole (namespace None)."""

    name: str
    namespace: str | None = None
    rules: list[PolicyRule]


class Subject(_Strict):
    """An RBAC binding subject."""

    kind: Literal["User", "Group", "ServiceAccount"]
    name: str
    namespace: str | None = None


class RbacBinding(_Strict):
    """A RoleBinding (namespaced) or ClusterRoleBinding (namespace None)."""

    name: str
    namespace: str | None = None
    role_ref_kind: Literal["Role", "ClusterRole"]
    role_ref_name: str
    subjects: list[Subject]


class KubernetesFixture(_Strict):
    """Everything collected from one cluster."""

    cluster: str
    namespaces: list[str]
    service_accounts: list[ServiceAccount] = Field(default_factory=list)
    pods: list[Pod] = Field(default_factory=list)
    roles: list[RbacRole] = Field(default_factory=list)
    bindings: list[RbacBinding] = Field(default_factory=list)


# --------------------------------------------------------------------------- Whole lab


class LabFixture(_Strict):
    """One seeded lab: a GitHub, an AWS and a Kubernetes snapshot."""

    name: str
    github: GitHubFixture
    aws: AwsFixture
    kubernetes: KubernetesFixture

    def role_by_arn(self, arn: str) -> IamRole:
        """Look up a role; raises KeyError when the fixture has no such role."""
        for role in self.aws.roles:
            if role.arn == arn:
                return role
        raise KeyError(arn)

    def workflow_by_ref(self, repo_full_name: str, path: str) -> Workflow:
        """Look up a workflow by repo and path."""
        for repo in self.github.repos:
            if repo.full_name == repo_full_name:
                for wf in repo.workflows:
                    if wf.path == path:
                        return wf
        raise KeyError(f"{repo_full_name}:{path}")


def load_fixture(directory: Path) -> LabFixture:
    """Load ``github.json``, ``aws.json`` and ``kubernetes.json`` from a fixture directory."""
    parts = {}
    for name in ("github", "aws", "kubernetes"):
        file = directory / f"{name}.json"
        with file.open(encoding="utf-8") as fh:
            parts[name] = json.load(fh)
    return LabFixture(name=directory.name, **parts)


def _account_of(arn: str) -> str:
    match = _ACCOUNT_IN_ARN.match(arn)
    if match is None:
        msg = f"ARN {arn!r} carries no account id"
        raise ValueError(msg)
    return match.group(1)
