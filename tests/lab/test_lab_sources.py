"""The Terraform, kind manifests and lab workflows must describe the same lab as the fixture."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from breachmap.lab import LabFixture
from breachmap.lab.terraform import compare_plan, load_plan, planned_resources

from ..conftest import LAB

LAB_ACCOUNT = "111111111111"


def load_manifests() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for file in sorted((LAB / "kind" / "manifests").glob("*.yaml")):
        docs.extend(d for d in yaml.safe_load_all(file.read_text()) if d)
    return docs


def test_kind_manifests_match_the_fixture(v1_fixture: LabFixture) -> None:
    docs = load_manifests()
    k8s = v1_fixture.kubernetes
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for d in docs:
        by_kind.setdefault(d["kind"], []).append(d)
        assert d["metadata"]["labels"]["breachmap-lab"] == "true", d["metadata"]["name"]

    assert {n["metadata"]["name"] for n in by_kind["Namespace"]} <= set(k8s.namespaces)
    sas = {
        (s["metadata"]["namespace"], s["metadata"]["name"]): s for s in by_kind["ServiceAccount"]
    }
    for sa in k8s.service_accounts:
        if sa.annotations:
            assert sas[(sa.namespace, sa.name)]["metadata"]["annotations"] == sa.annotations
    pods = {(p["metadata"]["namespace"], p["metadata"]["name"]): p for p in by_kind["Pod"]}
    for pod in k8s.pods:
        assert pods[(pod.namespace, pod.name)]["spec"]["serviceAccountName"] == pod.service_account

    roles = {
        (r["metadata"].get("namespace"), r["metadata"]["name"]): r
        for r in by_kind["Role"] + by_kind["ClusterRole"]
    }
    for role in k8s.roles:
        manifest = roles[(role.namespace, role.name)]
        assert [
            (sorted(r["apiGroups"]), sorted(r["resources"]), sorted(r["verbs"]))
            for r in manifest["rules"]
        ] == [(sorted(r.api_groups), sorted(r.resources), sorted(r.verbs)) for r in role.rules]
    bindings = {
        b["metadata"]["name"]: b for b in by_kind["RoleBinding"] + by_kind["ClusterRoleBinding"]
    }
    for binding in k8s.bindings:
        manifest = bindings[binding.name]
        assert manifest["roleRef"]["kind"] == binding.role_ref_kind
        assert manifest["roleRef"]["name"] == binding.role_ref_name
        assert {(s["kind"], s["name"]) for s in manifest["subjects"]} == {
            (s.kind, s.name) for s in binding.subjects
        }


def test_lab_workflows_match_the_fixture(v1_fixture: LabFixture) -> None:
    root = LAB / "github" / "workflows"
    for repo in v1_fixture.github.repos:
        short = repo.full_name.split("/")[1]
        for wf in repo.workflows:
            file = root / short / Path(wf.path).name
            data = yaml.safe_load(file.read_text())
            triggers = data[True] if True in data else data["on"]  # YAML 1.1 reads `on` as True
            assert sorted(triggers) == sorted(wf.triggers), file
            assert data.get("permissions", {}) == wf.permissions, file
            steps = [s for job in data["jobs"].values() for s in job["steps"]]
            uses = [s["uses"].split(" ")[0] for s in steps if "uses" in s]
            assert uses == [u.uses for u in wf.uses], file
            roles = [
                s["with"]["role-to-assume"]
                for s in steps
                if "configure-aws-credentials" in s.get("uses", "")
            ]
            assert roles == ([wf.assumes_role_arn] if wf.assumes_role_arn else []), file
            checks_out_head = any(
                "head.sha" in str(s.get("with", {}).get("ref", "")) for s in steps
            )
            assert checks_out_head == wf.checks_out_untrusted_code, file
            for u in wf.uses:
                assert u.pinned_to_sha == bool(len(u.uses.split("@")[1]) == 40), u.uses


def synthetic_plan(fixture: LabFixture) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    for role in fixture.aws.roles:
        if role.account_id != LAB_ACCOUNT:
            continue
        resources.append(
            {
                "type": "aws_iam_role",
                "values": {
                    "name": role.name,
                    "assume_role_policy": json.dumps(role.trust_policy),
                    "tags": {},
                },
            }
        )
        for name, doc in role.inline_policies.items():
            resources.append(
                {
                    "type": "aws_iam_role_policy",
                    "values": {"role": role.name, "name": name, "policy": json.dumps(doc)},
                }
            )
    return {
        "planned_values": {
            "root_module": {
                "resources": resources[:5],
                "child_modules": [{"resources": resources[5:]}],
            }
        },
        "configuration": {
            "provider_config": {
                "aws": {
                    "expressions": {
                        "default_tags": [{"tags": {"constant_value": {"breachmap-lab": "true"}}}]
                    }
                }
            }
        },
    }


def test_compare_plan_accepts_a_matching_plan(v1_fixture: LabFixture) -> None:
    plan = synthetic_plan(v1_fixture)
    assert len(planned_resources(plan)) > 5
    assert compare_plan(plan, v1_fixture, LAB_ACCOUNT) == []


def test_compare_plan_reports_every_kind_of_drift(v1_fixture: LabFixture) -> None:
    plan = synthetic_plan(v1_fixture)
    resources = (
        plan["planned_values"]["root_module"]["resources"]
        + plan["planned_values"]["root_module"]["child_modules"][0]["resources"]
    )
    roles = [r for r in resources if r["type"] == "aws_iam_role"]
    roles[0]["values"]["assume_role_policy"] = json.dumps(
        {"Version": "2012-10-17", "Statement": []}
    )
    roles[1]["values"]["tags"] = {"breachmap-lab": "false"}
    roles[2]["values"]["name"] = "extra-role"
    inline = [r for r in resources if r["type"] == "aws_iam_role_policy"]
    inline[0]["values"]["policy"] = json.dumps({"Version": "2012-10-17", "Statement": []})
    inline[-1]["values"]["name"] = "renamed"
    plan["configuration"] = {}
    problems = compare_plan(plan, v1_fixture, LAB_ACCOUNT)
    text = "\n".join(problems)
    assert "trust policy differs" in text
    assert "tag overridden" in text
    assert "in Terraform but not in the fixture" in text
    assert "in the fixture but not in Terraform" in text
    assert "inline policy" in text and "differs" in text
    assert "inline policies" in text
    assert "default_tags" in text


def test_load_plan(tmp_path: Path) -> None:
    file = tmp_path / "plan.json"
    file.write_text('{"planned_values": {}}')
    assert planned_resources(load_plan(file)) == []


def test_real_plan_if_available(v1_fixture: LabFixture) -> None:
    """CI writes the offline plan here before running pytest; locally it is optional."""
    file = LAB / "aws" / "plan.json"
    if not file.exists():
        pytest.skip("run `make lab-plan` (or the CI terraform job) to produce lab/aws/plan.json")
    assert compare_plan(load_plan(file), v1_fixture, LAB_ACCOUNT) == []
