"""Shared vocabulary: node types, edge types and evidence levels.

These enums are the contract between the lab answer key, the collectors and
the graph. They mirror the tables in ``docs/design.md`` ("The graph model").
"""

from enum import StrEnum


class NodeType(StrEnum):
    """Every kind of node the graph can hold."""

    # Entry points
    INTERNET = "Internet"
    ANY_GITHUB_USER = "AnyGitHubUser"
    PUBLIC_REPO = "PublicRepo"
    PUBLIC_ENDPOINT = "PublicEndpoint"
    LEAKED_SECRET = "LeakedSecret"  # noqa: S105
    VULNERABLE_IMAGE = "VulnerableImage"
    # Code and CI
    REPO = "Repo"
    BRANCH = "Branch"
    WORKFLOW = "Workflow"
    JOB = "Job"
    ENVIRONMENT = "Environment"
    GITHUB_OIDC_CLAIM = "GitHubOIDCClaim"
    # Cloud
    AWS_ACCOUNT = "AwsAccount"
    IAM_ROLE = "IamRole"
    IAM_USER = "IamUser"
    POLICY = "Policy"
    S3_BUCKET = "S3Bucket"
    KMS_KEY = "KmsKey"
    SECRET = "Secret"  # noqa: S105
    EC2_INSTANCE = "Ec2Instance"
    LAMBDA = "Lambda"
    SECURITY_GROUP = "SecurityGroup"
    # Kubernetes
    CLUSTER = "Cluster"
    NAMESPACE = "Namespace"
    SERVICE_ACCOUNT = "ServiceAccount"
    POD = "Pod"
    ROLE = "Role"
    CLUSTER_ROLE = "ClusterRole"
    SERVICE = "Service"
    INGRESS = "Ingress"


class EdgeType(StrEnum):
    """Every kind of edge; each one is a single attacker step."""

    CAN_TRIGGER = "CAN_TRIGGER"
    GETS_TOKEN_FOR = "GETS_TOKEN_FOR"  # noqa: S105
    CAN_ASSUME = "CAN_ASSUME"
    CAN_ACCESS = "CAN_ACCESS"
    CAN_EXEC_INTO = "CAN_EXEC_INTO"
    CAN_CREATE_POD = "CAN_CREATE_POD"
    RUNS_AS = "RUNS_AS"
    EXPOSED_TO = "EXPOSED_TO"
    CONTAINS = "CONTAINS"


class EvidenceLevel(StrEnum):
    """How sure we are about an edge. A path is as weak as its weakest edge."""

    VERIFIED = "verified"
    DERIVED = "derived"
    POSSIBLE = "possible"
    DISPUTED = "disputed"

    @property
    def rank(self) -> int:
        """Higher is stronger. Used to take the minimum over a path."""
        return _RANK[self]


_RANK: dict[EvidenceLevel, int] = {
    EvidenceLevel.DISPUTED: 0,
    EvidenceLevel.POSSIBLE: 1,
    EvidenceLevel.DERIVED: 2,
    EvidenceLevel.VERIFIED: 3,
}


class NodeRef:
    """Parse and format ``"NodeType:identifier"`` strings used in answer keys."""

    __slots__ = ("identifier", "node_type")

    def __init__(self, node_type: NodeType, identifier: str) -> None:
        """Create a reference; ``identifier`` is the collector-stable id (ARN, path, claim)."""
        self.node_type = node_type
        self.identifier = identifier

    @classmethod
    def parse(cls, text: str) -> "NodeRef":
        """Parse ``"IamRole:arn:aws:iam::111111111111:role/x"``; the id may contain colons."""
        head, sep, tail = text.partition(":")
        if not sep:
            msg = f"node ref {text!r} must look like 'NodeType:identifier'"
            raise ValueError(msg)
        try:
            node_type = NodeType(head)
        except ValueError as exc:
            msg = f"unknown node type {head!r} in {text!r}"
            raise ValueError(msg) from exc
        if not tail:
            msg = f"node ref {text!r} has an empty identifier"
            raise ValueError(msg)
        return cls(node_type, tail)

    def __str__(self) -> str:
        """Format back to ``"NodeType:identifier"``."""
        return f"{self.node_type}:{self.identifier}"

    def __repr__(self) -> str:
        """Debug form."""
        return f"NodeRef({str(self)!r})"

    def __eq__(self, other: object) -> bool:
        """Two refs are equal when type and identifier match."""
        return isinstance(other, NodeRef) and str(self) == str(other)

    def __hash__(self) -> int:
        """Hash on the string form."""
        return hash(str(self))
