"""Reproduce the answer key's decisions for IAM-role principals with the offline evaluator.
Web-identity decisions (GitHub OIDC claims) are covered once the claim mapping lands (#6)."""

import pytest

from breachmap.iam import RequestContext, RequestPrincipal
from breachmap.iam.evaluator import Request, evaluate
from breachmap.lab import AnswerKey, LabFixture
from breachmap.lab.answer_key import Decision
from breachmap.lab.environment import environment_from_fixture

from ..conftest import LAB  # noqa: F401 - session fixtures come from conftest


def role_decisions(key: AnswerKey) -> list[Decision]:
    return [d for d in key.decisions if d.principal.role_arn is not None]


@pytest.fixture(scope="module")
def ids(v1_answer_key: AnswerKey) -> list[str]:
    return [d.id for d in role_decisions(v1_answer_key)]


def test_role_decisions_are_the_expected_set(v1_answer_key: AnswerKey) -> None:
    assert [d.id for d in role_decisions(v1_answer_key)] == [
        "d09", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18",
        "d19", "d20", "d21", "d23", "d24", "d25", "d28",
    ]  # fmt: skip


@pytest.mark.parametrize("decision_id", [
    "d09", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18",
    "d19", "d20", "d21", "d23", "d24", "d25", "d28",
])  # fmt: skip
def test_answer_key_role_decision(
    decision_id: str, v1_answer_key: AnswerKey, v1_fixture: LabFixture
) -> None:
    expected = v1_answer_key.decision(decision_id)
    env = environment_from_fixture(v1_fixture)
    assert expected.principal.role_arn is not None
    record = env.role(expected.principal.role_arn)
    assert record is not None, expected.principal.role_arn
    request = Request(
        principal=RequestPrincipal.role(record.arn, record.tags),
        action=expected.action,
        resource=expected.resource,
        context=RequestContext(expected.context, expected.unknown_context_keys),
    )
    actual = evaluate(request, env)
    assert actual.outcome == expected.outcome, (decision_id, expected.description, actual)
    assert actual.reason == expected.reason, (decision_id, expected.description, actual)
    if actual.outcome == "allow":
        assert any(m.effect == "Allow" for m in actual.matched), "an allow needs evidence"
