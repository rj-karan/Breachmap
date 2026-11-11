"""Evaluate answer-key decisions with the offline evaluator."""

from __future__ import annotations

from dataclasses import dataclass

from breachmap.iam import RequestContext, RequestPrincipal
from breachmap.iam.environment import Environment
from breachmap.iam.evaluator import Decision as EvalDecision
from breachmap.iam.evaluator import Request, evaluate
from breachmap.iam.web_identity import web_identity_request
from breachmap.lab.answer_key import AnswerKey, Decision


@dataclass(frozen=True)
class Verdict:
    """What the evaluator said for one answer-key decision."""

    outcome: str
    reason: str | None

    @classmethod
    def expected(cls, decision: Decision) -> Verdict:
        """The answer key's own verdict."""
        return cls(decision.outcome, decision.reason)


def evaluate_decision(decision: Decision, env: Environment) -> EvalDecision:
    """Run one answer-key decision through the evaluator."""
    identity = decision.principal.web_identity
    if identity is not None:
        request = web_identity_request(
            identity.provider_arn,
            identity.claims,
            decision.resource,
            unknown_keys=tuple(decision.unknown_context_keys),
        )
    else:
        role_arn = decision.principal.role_arn
        if role_arn is None:  # pragma: no cover - the schema guarantees one of the two
            msg = f"decision {decision.id} has no principal"
            raise ValueError(msg)
        record = env.role(role_arn)
        tags = record.tags if record else {}
        request = Request(
            principal=RequestPrincipal.role(role_arn, tags),
            action=decision.action,
            resource=decision.resource,
            context=RequestContext(decision.context, decision.unknown_context_keys),
        )
    return evaluate(request, env)


def verdicts(key: AnswerKey, env: Environment) -> dict[str, Verdict]:
    """Evaluator verdicts for every decision in the key, by id."""
    out: dict[str, Verdict] = {}
    for decision in key.decisions:
        result = evaluate_decision(decision, env)
        out[decision.id] = Verdict(result.outcome, result.reason)
    return out
