"""Policy document parsing, from the IAM JSON policy element reference."""

import pytest

from breachmap.iam import PolicyDocument, Principal, Statement
from breachmap.lab import load_fixture

from ..conftest import LAB


def test_statement_may_be_a_single_object_or_a_list() -> None:
    single = PolicyDocument.parse(
        {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "s3:GetObject"}}
    )
    listed = PolicyDocument.parse(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]}
    )
    assert single.statements == listed.statements
    assert single.statements[0].actions == ["s3:GetObject"]


def test_string_or_list_fields_are_normalised() -> None:
    """'You can specify multiple values for the Action element.' (and Resource, Principal)."""
    doc = PolicyDocument.parse(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "Multi",
                "Effect": "Deny",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"],
                "Principal": {"AWS": ["111111111111", "arn:aws:iam::222222222222:root"]},
                "Condition": {"StringEquals": {"aws:username": "bob"}},
            },
        }
    )
    stmt = doc.statements[0]
    assert stmt.sid == "Multi"
    assert not stmt.is_allow
    assert stmt.actions == ["s3:GetObject", "s3:PutObject"]
    assert stmt.resources == ["arn:aws:s3:::a/*", "arn:aws:s3:::b/*"]
    assert stmt.principal is not None
    assert stmt.principal.aws == ["111111111111", "arn:aws:iam::222222222222:root"]
    assert stmt.condition == {"StringEquals": {"aws:username": ["bob"]}}


def test_action_or_not_action_exactly_one() -> None:
    """'Statements must include either an Action or NotAction element.'"""
    with pytest.raises(ValueError, match="exactly one of Action or NotAction"):
        Statement.from_json({"Effect": "Allow", "Resource": "*"})
    with pytest.raises(ValueError, match="exactly one of Action or NotAction"):
        Statement.from_json({"Effect": "Allow", "Action": "s3:*", "NotAction": "s3:*"})
    stmt = Statement.from_json({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert stmt.not_actions == ["iam:*"]
    assert stmt.actions is None


def test_resource_is_optional_for_trust_policies() -> None:
    stmt = Statement.from_json(
        {
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::111111111111:oidc-provider/x"},
            "Action": "sts:AssumeRoleWithWebIdentity",
        }
    )
    assert stmt.resources is None
    assert stmt.not_resources is None
    assert stmt.principal is not None
    assert stmt.principal.federated == ["arn:aws:iam::111111111111:oidc-provider/x"]


def test_resource_and_not_resource_are_exclusive() -> None:
    with pytest.raises(ValueError, match="both Resource and NotResource"):
        Statement.from_json(
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*", "NotResource": "*"}
        )


def test_principal_and_not_principal_are_exclusive() -> None:
    with pytest.raises(ValueError, match="both Principal and NotPrincipal"):
        Statement.from_json(
            {"Effect": "Deny", "Action": "s3:*", "Principal": "*", "NotPrincipal": "*"}
        )


def test_principal_star_forms_are_equivalent() -> None:
    """'For anonymous users, the following elements are equivalent:
    "Principal": "*" and "Principal" : { "AWS" : "*" }'."""
    assert Principal.from_json("*").everyone
    assert Principal.from_json({"AWS": "*"}).everyone
    mixed = Principal.from_json({"AWS": ["*", "111111111111"]})
    assert mixed.everyone
    assert mixed.aws == ["111111111111"]


def test_principal_types() -> None:
    p = Principal.from_json(
        {
            "Service": ["ecs.amazonaws.com", "elasticloadbalancing.amazonaws.com"],
            "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
        }
    )
    assert p.service == ["ecs.amazonaws.com", "elasticloadbalancing.amazonaws.com"]
    assert len(p.canonical_user) == 1
    assert not p.everyone
    with pytest.raises(ValueError, match="unknown Principal type"):
        Principal.from_json({"Bogus": "x"})
    with pytest.raises(ValueError, match="must be '\\*' or an object"):
        Principal.from_json(42)


def test_version_gates_policy_variables() -> None:
    """'Variables were introduced in version 2012-10-17. Earlier versions of the policy
    language don't support policy variables.'"""
    new = PolicyDocument.parse({"Version": "2012-10-17", "Statement": []})
    old = PolicyDocument.parse({"Version": "2008-10-17", "Statement": []})
    none = PolicyDocument.parse({"Statement": []})
    assert new.supports_variables
    assert not old.supports_variables
    assert not none.supports_variables
    with pytest.raises(ValueError, match="unsupported policy Version"):
        PolicyDocument.parse({"Version": "2026-01-01", "Statement": []})


def test_malformed_documents_are_rejected() -> None:
    with pytest.raises(ValueError, match="unknown policy element"):
        PolicyDocument.parse({"Statement": [], "Statements": []})
    with pytest.raises(ValueError, match="Statement must be"):
        PolicyDocument.parse({"Statement": "nope"})
    with pytest.raises(ValueError, match="Effect must be Allow or Deny"):
        Statement.from_json({"Effect": "Maybe", "Action": "s3:*"})
    with pytest.raises(ValueError, match="unknown statement element"):
        Statement.from_json({"Effect": "Allow", "Action": "s3:*", "Resources": "*"})
    with pytest.raises(ValueError, match="must be a string or a list of strings"):
        Statement.from_json({"Effect": "Allow", "Action": [1, 2]})
    with pytest.raises(ValueError, match="Condition must be an object"):
        Statement.from_json({"Effect": "Allow", "Action": "s3:*", "Condition": []})
    with pytest.raises(ValueError, match="must map keys to values"):
        Statement.from_json({"Effect": "Allow", "Action": "s3:*", "Condition": {"Bool": "x"}})


def test_policy_id_is_kept() -> None:
    doc = PolicyDocument.parse({"Version": "2012-10-17", "Id": "key-default-1", "Statement": []})
    assert doc.id == "key-default-1"


def test_every_policy_in_the_v1_fixture_parses() -> None:
    fixture = load_fixture(LAB / "fixtures" / "v1-oidc")
    docs = [
        *(r.trust_policy for r in fixture.aws.roles),
        *(p for r in fixture.aws.roles for p in r.inline_policies.values()),
        *(p.document for p in fixture.aws.managed_policies),
        *(s.document for s in fixture.aws.organization.scps),
        *(b.bucket_policy for b in fixture.aws.buckets if b.bucket_policy),
        *(k.key_policy for k in fixture.aws.kms_keys),
    ]
    assert len(docs) >= 30
    for raw in docs:
        parsed = PolicyDocument.parse(raw)
        assert parsed.supports_variables
        assert parsed.statements
