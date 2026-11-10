import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from breachmap.lab import LabFixture, load_fixture
from breachmap.lab.fixtures import AwsFixture, Workflow

from .conftest import LAB


def test_every_fixture_directory_loads() -> None:
    dirs = [p for p in (LAB / "fixtures").iterdir() if p.is_dir()]
    assert dirs, "no fixture directories"
    for d in dirs:
        fixture = load_fixture(d)
        assert fixture.name == d.name


def test_v1_shape(v1_fixture: LabFixture) -> None:
    assert len(v1_fixture.aws.roles) == 16
    assert {r.full_name for r in v1_fixture.github.repos} == {
        "acme/app",
        "acme/website",
        "acme/infra",
    }
    assert v1_fixture.kubernetes.cluster == "lab"
    jewels = [b.name for b in v1_fixture.aws.buckets if b.crown_jewel]
    assert jewels == ["acme-customer-data"]


def test_lookups(v1_fixture: LabFixture) -> None:
    role = v1_fixture.role_by_arn("arn:aws:iam::111111111111:role/deploy-aud-only")
    assert role.account_id == "111111111111"
    wf = v1_fixture.workflow_by_ref("acme/app", ".github/workflows/pr-preview.yml")
    assert wf.requests_oidc_token
    assert wf.checks_out_untrusted_code
    with pytest.raises(KeyError):
        v1_fixture.role_by_arn("arn:aws:iam::111111111111:role/nope")
    with pytest.raises(KeyError):
        v1_fixture.workflow_by_ref("acme/app", ".github/workflows/nope.yml")


def test_irsa_annotation_resolves_to_a_fixture_role(v1_fixture: LabFixture) -> None:
    arns = {r.arn for r in v1_fixture.aws.roles}
    for sa in v1_fixture.kubernetes.service_accounts:
        if sa.iam_role_arn is not None:
            assert sa.iam_role_arn in arns


def test_every_lab_resource_is_tagged(v1_fixture: LabFixture) -> None:
    for role in v1_fixture.aws.roles:
        assert role.tags.get("breachmap-lab") == "true", role.name
    for bucket in v1_fixture.aws.buckets:
        assert bucket.tags.get("breachmap-lab") == "true", bucket.name


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Workflow.model_validate(
            {"path": ".github/workflows/x.yml", "triggers": ["push"], "bogus": 1}
        )


def test_dangling_policy_reference_is_rejected() -> None:
    data = json.loads((LAB / "fixtures" / "v1-oidc" / "aws.json").read_text())
    data["roles"][0]["attached_policy_arns"] = ["arn:aws:iam::111111111111:policy/Missing"]
    with pytest.raises(ValidationError, match="unknown policy"):
        AwsFixture.model_validate(data)


def test_dangling_scp_reference_is_rejected() -> None:
    data = json.loads((LAB / "fixtures" / "v1-oidc" / "aws.json").read_text())
    data["organization"]["org_units"][0]["scp_ids"] = ["p-missing"]
    with pytest.raises(ValidationError, match="unknown SCP"):
        AwsFixture.model_validate(data)


def test_missing_file_is_a_clear_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_fixture(tmp_path)
