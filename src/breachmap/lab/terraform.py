"""Check that the Terraform lab builds what the fixture describes.

Input is ``terraform show -json`` of a plan. Values Terraform cannot know
until apply (KMS key ARNs, the boundary policy ARN) are absent from the plan
and are skipped; everything known is compared exactly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from breachmap.lab.fixtures import LabFixture

PlanJson = dict[str, Any]


def planned_resources(plan: PlanJson) -> list[dict[str, Any]]:
    """Every resource in the planned root module and its children."""
    out: list[dict[str, Any]] = []
    stack = [plan.get("planned_values", {}).get("root_module", {})]
    while stack:
        module = stack.pop()
        out.extend(module.get("resources", []))
        stack.extend(module.get("child_modules", []))
    return out


def compare_plan(plan: PlanJson, fixture: LabFixture, account_id: str) -> list[str]:
    """Return every difference between the plan and the fixture's lab-account roles."""
    problems: list[str] = []
    resources = planned_resources(plan)
    planned_roles = {
        r["values"]["name"]: r["values"] for r in resources if r["type"] == "aws_iam_role"
    }
    fixture_roles = {r.name: r for r in fixture.aws.roles if r.account_id == account_id}

    for name in sorted(fixture_roles.keys() - planned_roles.keys()):
        problems.append(f"role {name} is in the fixture but not in Terraform")
    for name in sorted(planned_roles.keys() - fixture_roles.keys()):
        problems.append(f"role {name} is in Terraform but not in the fixture")

    for name in sorted(fixture_roles.keys() & planned_roles.keys()):
        planned_trust = planned_roles[name].get("assume_role_policy")
        if (
            planned_trust is not None
            and json.loads(planned_trust) != fixture_roles[name].trust_policy
        ):
            problems.append(f"role {name}: trust policy differs")
        if (planned_roles[name].get("tags") or {}).get("breachmap-lab") not in (None, "true"):
            problems.append(f"role {name}: breachmap-lab tag overridden")

    planned_inline: dict[str, dict[str, str | None]] = {}
    for r in resources:
        if r["type"] == "aws_iam_role_policy":
            values = r["values"]
            planned_inline.setdefault(values["role"], {})[values["name"]] = values.get("policy")
    for name, role in sorted(fixture_roles.items()):
        expected = set(role.inline_policies)
        actual = set(planned_inline.get(name, {}))
        if expected != actual:
            problems.append(
                f"role {name}: inline policies {sorted(actual)} != fixture {sorted(expected)}"
            )
            continue
        for policy_name, policy_json in planned_inline.get(name, {}).items():
            if (
                policy_json is not None
                and json.loads(policy_json) != role.inline_policies[policy_name]
            ):
                problems.append(f"role {name}: inline policy {policy_name} differs")

    tags = plan.get("configuration", {}).get("provider_config", {}).get("aws", {})
    default_tags = tags.get("expressions", {}).get("default_tags", [{}])
    lab_tag = (default_tags[0] if default_tags else {}).get("tags", {}).get("constant_value", {})
    if lab_tag.get("breachmap-lab") != "true":
        problems.append("provider default_tags must set breachmap-lab = true")
    return problems


def load_plan(file: Path) -> PlanJson:
    """Read ``terraform show -json`` output."""
    with file.open(encoding="utf-8") as fh:
        data: PlanJson = json.load(fh)
    return data
