"""Reproduce the answer key's web-identity decisions (GitHub OIDC and the kind issuer)."""

import pytest

from breachmap.iam.evaluator import evaluate
from breachmap.iam.web_identity import web_identity_request
from breachmap.lab import AnswerKey, LabFixture
from breachmap.lab.environment import environment_from_fixture

WEB_IDENTITY_IDS = ["d01", "d02", "d03", "d04", "d05", "d06", "d07", "d08", "d22", "d26", "d27"]


def test_web_identity_decisions_are_the_expected_set(v1_answer_key: AnswerKey) -> None:
    assert [d.id for d in v1_answer_key.decisions if d.principal.web_identity] == WEB_IDENTITY_IDS


@pytest.mark.parametrize("decision_id", WEB_IDENTITY_IDS)
def test_answer_key_web_identity_decision(
    decision_id: str, v1_answer_key: AnswerKey, v1_fixture: LabFixture
) -> None:
    expected = v1_answer_key.decision(decision_id)
    identity = expected.principal.web_identity
    assert identity is not None
    env = environment_from_fixture(v1_fixture)
    request = web_identity_request(
        identity.provider_arn,
        identity.claims,
        expected.resource,
        unknown_keys=tuple(expected.unknown_context_keys),
    )
    actual = evaluate(request, env)
    assert actual.outcome == expected.outcome, (decision_id, expected.description, actual)
    assert actual.reason == expected.reason, (decision_id, expected.description, actual)
    if actual.outcome == "allow":
        assert any(m.source == "trust" and m.effect == "Allow" for m in actual.matched)


def test_every_answer_key_decision_is_covered(v1_answer_key: AnswerKey) -> None:
    """Role decisions are reproduced in test_decisions.py; together they cover the key."""
    covered = set(WEB_IDENTITY_IDS) | {
        d.id for d in v1_answer_key.decisions if d.principal.role_arn
    }
    assert covered == {d.id for d in v1_answer_key.decisions}
