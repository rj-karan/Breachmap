import pytest
from pydantic import ValidationError

from breachmap.lab import AnswerKey, LabFixture
from breachmap.lab.answer_key import Decision, ExpectedNonPath, Principal, Route
from breachmap.types import EdgeType, EvidenceLevel, NodeRef, NodeType


def test_answer_key_matches_fixture(v1_answer_key: AnswerKey, v1_fixture: LabFixture) -> None:
    assert v1_answer_key.check_against(v1_fixture) == []


def test_counts(v1_answer_key: AnswerKey) -> None:
    assert len(v1_answer_key.decisions) == 28
    assert len(v1_answer_key.paths) == 7
    assert len(v1_answer_key.non_paths) == 8


def test_every_route_starts_at_an_entry_point(v1_answer_key: AnswerKey) -> None:
    for route in v1_answer_key.routes:
        assert route.refs[0].node_type == NodeType.ANY_GITHUB_USER, route.id


def test_every_path_ends_at_a_crown_jewel(v1_answer_key: AnswerKey, v1_fixture: LabFixture) -> None:
    jewels = {
        *(b.arn for b in v1_fixture.aws.buckets if b.crown_jewel),
        *(s.arn for s in v1_fixture.aws.secrets if s.crown_jewel),
        *(k.arn for k in v1_fixture.aws.kms_keys if k.crown_jewel),
    }
    for path in v1_answer_key.paths:
        assert path.refs[-1].identifier in jewels, path.id


def test_tinder_case_is_present_and_verified(v1_answer_key: AnswerKey) -> None:
    d01 = v1_answer_key.decision("d01")
    assert d01.outcome == "allow"
    assert d01.principal.web_identity is not None
    assert d01.principal.web_identity.claims["sub"].startswith("repo:attacker/")
    p01 = v1_answer_key.paths[0]
    assert p01.evidence_level is EvidenceLevel.VERIFIED
    assert p01.edges == [EdgeType.GETS_TOKEN_FOR, EdgeType.CAN_ASSUME, EdgeType.CAN_ACCESS]


def test_paths_through_can_trigger_are_derived(v1_answer_key: AnswerKey) -> None:
    for path in v1_answer_key.paths:
        if EdgeType.CAN_TRIGGER in path.edges:
            assert path.evidence_level is EvidenceLevel.DERIVED, path.id


def test_every_deny_decision_has_a_reason(v1_answer_key: AnswerKey) -> None:
    for d in v1_answer_key.decisions:
        assert (d.reason is not None) == (d.outcome == "deny"), d.id


def test_unknown_decisions_name_the_missing_key(v1_answer_key: AnswerKey) -> None:
    unknowns = [d for d in v1_answer_key.decisions if d.outcome == "unknown"]
    assert unknowns
    for d in unknowns:
        assert d.unknown_context_keys


def test_unknown_decision_lookup(v1_answer_key: AnswerKey) -> None:
    with pytest.raises(KeyError):
        v1_answer_key.decision("d99")


def test_check_against_reports_mismatches(v1_answer_key: AnswerKey, v1_fixture: LabFixture) -> None:
    other = v1_fixture.model_copy(update={"name": "other"})
    problems = v1_answer_key.check_against(other)
    assert problems and "other" in problems[0]
    bad_route = v1_answer_key.paths[0].model_copy(
        update={"nodes": ["AnyGitHubUser:*", "IamRole:arn:aws:iam::111111111111:role/ghost"]}
    )
    key = v1_answer_key.model_copy(update={"paths": [bad_route]})
    assert any("ghost" in p for p in key.check_against(v1_fixture))
    bad_decision = v1_answer_key.decision("d09").model_copy(
        update={"principal": Principal(role_arn="arn:aws:iam::111111111111:role/ghost")}
    )
    key = v1_answer_key.model_copy(update={"decisions": [bad_decision]})
    problems = key.check_against(v1_fixture)
    assert any("unknown principal role" in p for p in problems)
    bad_target = v1_answer_key.decision("d15").model_copy(
        update={"resource": "arn:aws:iam::111111111111:role/ghost"}
    )
    key = v1_answer_key.model_copy(update={"decisions": [bad_target]})
    assert any("unknown target role" in p for p in key.check_against(v1_fixture))


def test_route_rejects_mismatched_lengths() -> None:
    with pytest.raises(ValidationError, match="nodes but"):
        Route(
            nodes=["AnyGitHubUser:*", "S3Bucket:arn:aws:s3:::x"],
            edges=[EdgeType.CAN_ACCESS, EdgeType.CAN_ACCESS],
        )


def test_non_path_blocked_at_must_be_in_range() -> None:
    with pytest.raises(ValidationError, match="past the last edge"):
        ExpectedNonPath(
            id="n99",
            description="x",
            nodes=["AnyGitHubUser:*", "S3Bucket:arn:aws:s3:::x"],
            edges=[EdgeType.CAN_ACCESS],
            blocked_at=1,
            reason="scp",
        )


def test_decision_consistency_rules() -> None:
    base = {
        "id": "d50",
        "description": "x",
        "principal": {"role_arn": "arn:aws:iam::111111111111:role/x"},
        "action": "s3:GetObject",
        "resource": "arn:aws:s3:::x/y",
    }
    with pytest.raises(ValidationError, match="without a reason"):
        Decision.model_validate({**base, "outcome": "deny"})
    with pytest.raises(ValidationError, match="does not deny"):
        Decision.model_validate({**base, "outcome": "allow", "reason": "scp"})
    with pytest.raises(ValidationError, match="exactly one"):
        Decision.model_validate({**base, "outcome": "allow", "principal": {}})
    with pytest.raises(ValidationError, match="missing"):
        Decision.model_validate(
            {
                **base,
                "outcome": "allow",
                "principal": {"web_identity": {"provider_arn": "arn:x", "claims": {"sub": "s"}}},
            }
        )


def test_answer_key_rejects_duplicate_and_dangling_ids(v1_answer_key: AnswerKey) -> None:
    dupe = v1_answer_key.decisions[0]
    with pytest.raises(ValidationError, match="duplicate decision"):
        AnswerKey(fixture="v1-oidc", decisions=[dupe, dupe])
    path = v1_answer_key.paths[0].model_copy(update={"decisions": ["d99"]})
    with pytest.raises(ValidationError, match="unknown decision"):
        AnswerKey(fixture="v1-oidc", decisions=[dupe], paths=[path])
    with pytest.raises(ValidationError, match="duplicate route"):
        AnswerKey(fixture="v1-oidc", decisions=[], paths=[path, path])


def test_node_ref_parsing() -> None:
    ref = NodeRef.parse("IamRole:arn:aws:iam::111111111111:role/x")
    assert ref.node_type is NodeType.IAM_ROLE
    assert ref.identifier == "arn:aws:iam::111111111111:role/x"
    assert str(ref) == "IamRole:arn:aws:iam::111111111111:role/x"
    assert repr(ref).startswith("NodeRef(")
    assert ref == NodeRef(NodeType.IAM_ROLE, "arn:aws:iam::111111111111:role/x")
    assert hash(ref) == hash(str(ref))
    assert ref != "not a ref"
    for bad in ("nocolon", "Bogus:x", "IamRole:"):
        with pytest.raises(ValueError, match="node"):
            NodeRef.parse(bad)


def test_evidence_rank_orders_levels() -> None:
    assert EvidenceLevel.VERIFIED.rank > EvidenceLevel.DERIVED.rank > EvidenceLevel.POSSIBLE.rank
    assert EvidenceLevel.POSSIBLE.rank > EvidenceLevel.DISPUTED.rank
