"""The answer key: what must be found in a fixture, and what must not.

Three kinds of truth, used at different milestones:

* ``decisions`` are single allow/deny questions for the policy evaluator (M1).
* ``paths`` are attacker-to-crown-jewel routes the path engine must find (M4).
* ``non_paths`` look open to a naive tool but must not be reported, with the
  edge that blocks them and why (M4, and M1 for the blocking decision).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from breachmap.lab.fixtures import LabFixture
from breachmap.types import EdgeType, EvidenceLevel, NodeRef, NodeType

Outcome = Literal["allow", "deny", "unknown"]
BlockReason = Literal[
    "explicit_deny",
    "scp",
    "permission_boundary",
    "resource_policy",
    "condition_mismatch",
    "no_permission",
    "trust_mismatch",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Principal(_Strict):
    """Who is asking. Exactly one of the fields is set."""

    role_arn: str | None = None
    web_identity: WebIdentity | None = None

    @model_validator(mode="after")
    def _exactly_one(self) -> Principal:
        if (self.role_arn is None) == (self.web_identity is None):
            msg = "principal needs exactly one of role_arn or web_identity"
            raise ValueError(msg)
        return self


class WebIdentity(_Strict):
    """A federated caller presenting an OIDC token to STS."""

    provider_arn: str
    claims: dict[str, str] = Field(description="At least sub and aud; others as needed")

    @field_validator("claims")
    @classmethod
    def _has_sub_and_aud(cls, claims: dict[str, str]) -> dict[str, str]:
        missing = {"sub", "aud"} - claims.keys()
        if missing:
            msg = f"web identity claims missing {sorted(missing)}"
            raise ValueError(msg)
        return claims


class Decision(_Strict):
    """One evaluator question with its documented answer."""

    id: str = Field(pattern=r"^d\d{2,}$")
    description: str
    principal: Principal
    action: str = Field(pattern=r"^[a-z0-9-]+:[A-Za-z0-9*]+$")
    resource: str
    context: dict[str, str | list[str]] = Field(
        default_factory=dict,
        description="Context keys beyond those implied by the principal, e.g. kms:ViaService",
    )
    unknown_context_keys: list[str] = Field(
        default_factory=list,
        description="Context keys whose value cannot be known offline; gives outcome unknown",
    )
    outcome: Outcome
    reason: BlockReason | None = Field(
        default=None, description="Required when outcome is deny; the first rule that blocks"
    )
    cites: str | None = Field(default=None, description="The AWS/GitHub doc sentence this rests on")

    @model_validator(mode="after")
    def _deny_has_reason(self) -> Decision:
        if self.outcome == "deny" and self.reason is None:
            msg = f"decision {self.id} denies without a reason"
            raise ValueError(msg)
        if self.outcome != "deny" and self.reason is not None:
            msg = f"decision {self.id} has a reason but does not deny"
            raise ValueError(msg)
        return self


class Route(_Strict):
    """A node sequence with the edge types between consecutive nodes."""

    nodes: list[str] = Field(min_length=2)
    edges: list[EdgeType] = Field(min_length=1)

    @field_validator("nodes")
    @classmethod
    def _nodes_parse(cls, nodes: list[str]) -> list[str]:
        for node in nodes:
            NodeRef.parse(node)
        return nodes

    @model_validator(mode="after")
    def _lengths_match(self) -> Route:
        if len(self.edges) != len(self.nodes) - 1:
            msg = f"route has {len(self.nodes)} nodes but {len(self.edges)} edges"
            raise ValueError(msg)
        return self

    @property
    def refs(self) -> list[NodeRef]:
        """Parsed node references."""
        return [NodeRef.parse(n) for n in self.nodes]


class ExpectedPath(Route):
    """A path that must be reported."""

    id: str = Field(pattern=r"^p\d{2,}$")
    description: str
    evidence_level: EvidenceLevel = Field(
        description="The level the whole path should carry (weakest edge)"
    )
    decisions: list[str] = Field(
        default_factory=list, description="Decision ids that justify the AWS edges on this path"
    )


class ExpectedNonPath(Route):
    """A route that looks open but must not be reported."""

    id: str = Field(pattern=r"^n\d{2,}$")
    description: str
    blocked_at: int = Field(ge=0, description="Index into edges of the edge that does not exist")
    reason: BlockReason
    decisions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _blocked_in_range(self) -> ExpectedNonPath:
        if self.blocked_at >= len(self.edges):
            msg = f"non-path {self.id}: blocked_at {self.blocked_at} is past the last edge"
            raise ValueError(msg)
        return self


class AnswerKey(_Strict):
    """The complete known answer for one fixture."""

    fixture: str
    decisions: list[Decision]
    paths: list[ExpectedPath] = Field(default_factory=list)
    non_paths: list[ExpectedNonPath] = Field(default_factory=list)

    @model_validator(mode="after")
    def _ids_unique_and_resolve(self) -> AnswerKey:
        decision_ids = [d.id for d in self.decisions]
        route_ids = [r.id for r in self.routes]
        for ids, kind in ((decision_ids, "decision"), (route_ids, "route")):
            dupes = {i for i in ids if ids.count(i) > 1}
            if dupes:
                msg = f"duplicate {kind} ids: {sorted(dupes)}"
                raise ValueError(msg)
        known = set(decision_ids)
        for route in self.routes:
            for did in route.decisions:
                if did not in known:
                    msg = f"route {route.id} cites unknown decision {did}"
                    raise ValueError(msg)
        return self

    @property
    def routes(self) -> list[ExpectedPath | ExpectedNonPath]:
        """Paths and non-paths together."""
        return [*self.paths, *self.non_paths]

    def decision(self, decision_id: str) -> Decision:
        """Look up a decision by id."""
        for d in self.decisions:
            if d.id == decision_id:
                return d
        raise KeyError(decision_id)

    def check_against(self, fixture: LabFixture) -> list[str]:
        """Return every reference that does not resolve in the fixture (empty means consistent)."""
        problems: list[str] = []
        if self.fixture != fixture.name:
            problems.append(f"answer key is for {self.fixture!r}, fixture is {fixture.name!r}")
        known = _node_ids(fixture)
        for route in self.routes:
            for ref in route.refs:
                if ref.node_type in known and ref.identifier not in known[ref.node_type]:
                    problems.append(f"{route.id}: unknown {ref}")
        role_arns = known[NodeType.IAM_ROLE]
        for d in self.decisions:
            if d.principal.role_arn and d.principal.role_arn not in role_arns:
                problems.append(f"{d.id}: unknown principal role {d.principal.role_arn}")
            if d.action.startswith("sts:AssumeRole") and d.resource not in role_arns:
                problems.append(f"{d.id}: unknown target role {d.resource}")
        return problems


def load_answer_key(file: Path) -> AnswerKey:
    """Load an answer key JSON file."""
    with file.open(encoding="utf-8") as fh:
        return AnswerKey.model_validate(json.load(fh))


def _node_ids(fixture: LabFixture) -> dict[NodeType, set[str]]:
    """Identifiers the fixture defines, for the node types an answer key can reference."""
    ids: dict[NodeType, set[str]] = {
        NodeType.REPO: {r.full_name for r in fixture.github.repos},
        NodeType.WORKFLOW: {
            f"{r.full_name}:{w.path}" for r in fixture.github.repos for w in r.workflows
        },
        NodeType.IAM_ROLE: {r.arn for r in fixture.aws.roles},
        NodeType.S3_BUCKET: {b.arn for b in fixture.aws.buckets},
        NodeType.SECRET: {s.arn for s in fixture.aws.secrets},
        NodeType.KMS_KEY: {k.arn for k in fixture.aws.kms_keys},
        NodeType.CLUSTER: {fixture.kubernetes.cluster},
        NodeType.NAMESPACE: set(fixture.kubernetes.namespaces),
        NodeType.SERVICE_ACCOUNT: {
            f"{sa.namespace}/{sa.name}" for sa in fixture.kubernetes.service_accounts
        },
        NodeType.POD: {f"{p.namespace}/{p.name}" for p in fixture.kubernetes.pods},
    }
    return ids
