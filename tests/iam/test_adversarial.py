"""Adversarial policy fixtures: cases where naive evaluators get it wrong.

Each file under ``adversarial/`` is self-contained: the policies, the request,
the expected decision and the documentation sentence it rests on. Add a case by
dropping a new file; no code change is needed.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from breachmap.iam import PolicyDocument, RequestContext, RequestPrincipal
from breachmap.iam.environment import Environment, ResourcePolicy, RoleRecord
from breachmap.iam.evaluator import Request, evaluate

CASES = sorted((Path(__file__).parent / "adversarial").glob("*.json"))


def load(file: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(file.read_text())
    return data


def build(case: dict[str, Any]) -> tuple[Request, Environment]:
    arn: str = case["principal_role_arn"]
    account = arn.split(":")[4]
    role = RoleRecord(
        arn=arn,
        account_id=account,
        trust_policy=PolicyDocument.parse({"Version": "2012-10-17", "Statement": []}),
        identity_policies=[PolicyDocument.parse(d) for d in case["identity"]],
        boundary=PolicyDocument.parse(case["boundary"]) if case["boundary"] else None,
    )
    policies: dict[str, ResourcePolicy] = {}
    rp = case["resource_policy"]
    if rp:
        policies[rp["arn"]] = ResourcePolicy(
            kind=rp["kind"],
            arn=rp["arn"],
            account_id=rp["account_id"],
            document=PolicyDocument.parse(rp["document"]),
        )
    owners = {rp["arn"]: rp["account_id"]} if rp and rp["kind"] == "s3" else {}
    env = Environment(
        roles={arn: role},
        resource_policies=policies,
        scp_levels={
            account: [[PolicyDocument.parse(d) for d in level] for level in case["scp_levels"]]
        }
        if case["scp_levels"]
        else {},
        org_id=case["org_id"],
        resource_accounts=owners,
    )
    request = Request(
        principal=RequestPrincipal.role(arn),
        action=case["action"],
        resource=case["resource"],
        context=RequestContext(case["context"], case["unknown_context_keys"]),
    )
    return request, env


def test_corpus_is_not_empty() -> None:
    assert len(CASES) >= 18


@pytest.mark.parametrize("file", CASES, ids=[f.stem for f in CASES])
def test_adversarial_case(file: Path) -> None:
    case = load(file)
    assert case["id"] == file.stem
    assert case["cites"], "every case cites the sentence it rests on"
    request, env = build(case)
    decision = evaluate(request, env)
    assert (decision.outcome, decision.reason) == (
        case["expected"]["outcome"],
        case["expected"]["reason"],
    ), case["description"]
