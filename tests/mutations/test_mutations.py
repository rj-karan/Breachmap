"""The mutation harness and the v1-oidc mutation set."""

from typing import Any

import pytest

from breachmap.lab import AnswerKey
from breachmap.lab.environment import environment_from_fixture
from breachmap.lab.evaluate import Verdict, verdicts
from breachmap.lab.fixtures import LabFixture
from breachmap.lab.mutations import (
    Edit,
    ExpectedChange,
    Mutation,
    MutationSet,
    apply_edits,
    load_mutations,
    load_raw_fixture,
    parse_path,
    run_all,
    run_mutation,
)

from ..conftest import LAB

MUTATIONS = load_mutations(LAB / "mutations" / "v1-oidc.json")
RAW = load_raw_fixture(LAB / "fixtures" / "v1-oidc")


@pytest.fixture(scope="module")
def baseline(v1_answer_key: AnswerKey) -> dict[str, Verdict]:
    fixture = LabFixture(name="v1-oidc", **RAW)
    return verdicts(v1_answer_key, environment_from_fixture(fixture))


def test_mutation_set_is_for_the_fixture() -> None:
    assert MUTATIONS.fixture == "v1-oidc"
    assert len(MUTATIONS.mutations) >= 20
    ids = [m.id for m in MUTATIONS.mutations]
    assert len(ids) == len(set(ids))


def test_every_expected_decision_exists(v1_answer_key: AnswerKey) -> None:
    known = {d.id for d in v1_answer_key.decisions}
    for m in MUTATIONS.mutations:
        for e in m.expected:
            assert e.decision in known, (m.id, e.decision)


@pytest.mark.parametrize("mutation", MUTATIONS.mutations, ids=[m.id for m in MUTATIONS.mutations])
def test_mutation(
    mutation: Mutation, v1_answer_key: AnswerKey, baseline: dict[str, Verdict]
) -> None:
    result = run_mutation(mutation, RAW, v1_answer_key, baseline)
    assert result.error is None, result.error
    assert result.unexpected == {}, f"{mutation.id} changed more than declared: {result.unexpected}"
    assert result.missing == {}, (
        f"{mutation.id} did not produce the declared change: {result.missing}"
    )
    assert result.passed


def test_run_all_pass_rate(v1_answer_key: AnswerKey) -> None:
    results = run_all(MUTATIONS, RAW, v1_answer_key)
    assert all(r.passed for r in results)


def test_harness_catches_an_undeclared_change(
    v1_answer_key: AnswerKey, baseline: dict[str, Verdict]
) -> None:
    """A mutation that changes d13 but declares nothing must fail."""
    m = Mutation(
        id="m99",
        description="undeclared",
        edits=[
            Edit(
                op="delete", file="aws", path="roles[name=deploy-boundary].permissions_boundary_arn"
            )
        ],
    )
    result = run_mutation(m, RAW, v1_answer_key, baseline)
    assert not result.passed
    assert set(result.unexpected) == {"d13"}


def test_harness_catches_a_missing_change(
    v1_answer_key: AnswerKey, baseline: dict[str, Verdict]
) -> None:
    m = Mutation(
        id="m98",
        description="declares a change that does not happen",
        edits=[Edit(op="set", file="aws", path="roles[name=deploy-scoped].tags.note", value="x")],
        expected=[ExpectedChange(decision="d02", outcome="allow")],
    )
    result = run_mutation(m, RAW, v1_answer_key, baseline)
    assert not result.passed
    assert set(result.missing) == {"d02"}


def test_invalid_edit_is_reported_not_raised(
    v1_answer_key: AnswerKey, baseline: dict[str, Verdict]
) -> None:
    m = Mutation(
        id="m97",
        description="bad path",
        edits=[Edit(op="delete", file="aws", path="roles[name=ghost].arn")],
    )
    result = run_mutation(m, RAW, v1_answer_key, baseline)
    assert not result.passed
    assert result.error is not None and "ghost" in result.error
    broken = Mutation(
        id="m96",
        description="breaks the schema",
        edits=[Edit(op="set", file="aws", path="roles[0].arn", value="not-an-arn")],
    )
    assert run_mutation(broken, RAW, v1_answer_key, baseline).error


def test_path_language() -> None:
    assert parse_path("a.b[2].c[name=x y]") == ["a", "b", 2, "c", ("name", "x y")]
    with pytest.raises(ValueError, match="bad path"):
        parse_path("a[")
    with pytest.raises(ValueError, match="empty"):
        parse_path("")
    raw: dict[str, dict[str, Any]] = {"aws": {"roles": [{"name": "r", "tags": {}}], "n": 1}}
    out = apply_edits(raw, [Edit(op="set", file="aws", path="roles[name=r].tags.k", value="v")])
    assert out["aws"]["roles"][0]["tags"] == {"k": "v"}
    assert raw["aws"]["roles"][0]["tags"] == {}, "the original is untouched"
    out = apply_edits(raw, [Edit(op="append", file="aws", path="roles", value={"name": "s"})])
    assert [r["name"] for r in out["aws"]["roles"]] == ["r", "s"]
    out = apply_edits(raw, [Edit(op="delete", file="aws", path="roles[0]")])
    assert out["aws"]["roles"] == []
    with pytest.raises(TypeError, match="not a list"):
        apply_edits(raw, [Edit(op="append", file="aws", path="n", value=1)])
    with pytest.raises(TypeError, match="non-object"):
        apply_edits(raw, [Edit(op="set", file="aws", path="roles.x", value=1)])
    with pytest.raises(TypeError, match="non-object"):
        apply_edits(raw, [Edit(op="delete", file="aws", path="roles.x")])
    with pytest.raises(TypeError, match="non-object"):
        apply_edits(raw, [Edit(op="set", file="aws", path="n.x", value=1)])
    with pytest.raises(TypeError, match="non-list"):
        apply_edits(raw, [Edit(op="set", file="aws", path="n[0]", value=1)])


def test_mutation_set_schema() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        MutationSet.model_validate(
            {"fixture": "x", "mutations": [{"id": "m01", "description": "d", "edits": []}]}
        )
