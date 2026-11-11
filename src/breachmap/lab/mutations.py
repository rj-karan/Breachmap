"""Mutation tests: change one fact, check that exactly the expected decisions change.

A mutation is a list of edits on the raw fixture JSON plus the verdicts that
must differ from the baseline afterwards. Any other difference is a failure:
the evaluator must be sensitive to the right things and nothing else.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from breachmap.lab.answer_key import AnswerKey
from breachmap.lab.environment import environment_from_fixture
from breachmap.lab.evaluate import Verdict, verdicts
from breachmap.lab.fixtures import LabFixture

FixtureFile = Literal["github", "aws", "kubernetes"]
_SEGMENT = re.compile(r"([^.\[\]]+)|\[(\d+)\]|\[([^=\]]+)=([^\]]*)\]")
PathSegment = str | int | tuple[str, str]
type JsonNode = dict[str, JsonNode] | list[JsonNode] | str | int | float | bool | None


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Edit(_Strict):
    """One edit on a fixture file.

    ``path`` is dotted: ``roles[name=deploy-scoped].trust_policy.Statement[0].Condition``.
    ``[N]`` indexes a list, ``[field=value]`` selects the list element whose
    ``field`` equals ``value``.
    """

    op: Literal["set", "delete", "append"]
    file: FixtureFile
    path: str
    value: Any = None


class ExpectedChange(_Strict):
    """A decision whose verdict must change."""

    decision: str
    outcome: Literal["allow", "deny", "unknown"]
    reason: str | None = None


class Mutation(_Strict):
    """One mutation with its expected effect."""

    id: str = Field(pattern=r"^m\d{2,}$")
    description: str
    edits: list[Edit] = Field(min_length=1)
    expected: list[ExpectedChange] = Field(
        default_factory=list, description="Empty means the mutation must change nothing"
    )


class MutationSet(_Strict):
    """All mutations for one fixture."""

    fixture: str
    mutations: list[Mutation]


class MutationResult(_Strict):
    """Outcome of running one mutation."""

    id: str
    passed: bool
    unexpected: dict[str, tuple[str, str | None]] = Field(default_factory=dict)
    missing: dict[str, tuple[str, str | None]] = Field(default_factory=dict)
    error: str | None = None


RawFixture = dict[str, dict[str, Any]]


def load_raw_fixture(directory: Path) -> RawFixture:
    """Read the three fixture files as plain JSON."""
    out: RawFixture = {}
    for name in ("github", "aws", "kubernetes"):
        with (directory / f"{name}.json").open(encoding="utf-8") as fh:
            out[name] = json.load(fh)
    return out


def load_mutations(file: Path) -> MutationSet:
    """Load a mutation set."""
    with file.open(encoding="utf-8") as fh:
        return MutationSet.model_validate(json.load(fh))


def apply_edits(raw: RawFixture, edits: list[Edit]) -> RawFixture:
    """Return a deep copy of ``raw`` with the edits applied."""
    mutated = copy.deepcopy(raw)
    for edit in edits:
        _apply(mutated[edit.file], edit)
    return mutated


def mutated_fixture(raw: RawFixture, name: str, edits: list[Edit]) -> LabFixture:
    """Apply edits and validate the result under the fixture schema."""
    data = apply_edits(raw, edits)
    return LabFixture(name=name, **data)


def run_mutation(
    mutation: Mutation, raw: RawFixture, key: AnswerKey, baseline: dict[str, Verdict]
) -> MutationResult:
    """Apply one mutation, re-evaluate every decision, compare the diff with the expectation."""
    try:
        fixture = mutated_fixture(raw, key.fixture, mutation.edits)
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        return MutationResult(id=mutation.id, passed=False, error=str(exc))
    actual = verdicts(key, environment_from_fixture(fixture))
    changed = {did: v for did, v in actual.items() if v != baseline[did]}
    expected = {e.decision: Verdict(e.outcome, e.reason) for e in mutation.expected}
    unexpected = {
        did: (v.outcome, v.reason) for did, v in changed.items() if expected.get(did) != v
    }
    missing = {did: (v.outcome, v.reason) for did, v in expected.items() if changed.get(did) != v}
    return MutationResult(
        id=mutation.id,
        passed=not unexpected and not missing,
        unexpected=unexpected,
        missing=missing,
    )


def run_all(mutations: MutationSet, raw: RawFixture, key: AnswerKey) -> list[MutationResult]:
    """Run every mutation against the baseline verdicts of the unmodified fixture."""
    baseline_fixture = LabFixture(name=key.fixture, **raw)
    baseline = verdicts(key, environment_from_fixture(baseline_fixture))
    return [run_mutation(m, raw, key, baseline) for m in mutations.mutations]


# --------------------------------------------------------------------------- path edits


def _apply(root: dict[str, Any], edit: Edit) -> None:
    segments = parse_path(edit.path)
    parent: JsonNode = root
    for seg in segments[:-1]:
        parent = _step(parent, seg)
    last = segments[-1]
    if edit.op == "set":
        _assign(parent, last, edit.value)
    elif edit.op == "append":
        target = _step(parent, last)
        if not isinstance(target, list):
            msg = f"{edit.path} is not a list"
            raise TypeError(msg)
        target.append(copy.deepcopy(edit.value))
    else:
        _remove(parent, last)


def parse_path(path: str) -> list[PathSegment]:
    """Split a dotted path into keys, indexes and ``(field, value)`` selectors."""
    segments: list[PathSegment] = []
    pos = 0
    while pos < len(path):
        if path[pos] == ".":
            pos += 1
            continue
        match = _SEGMENT.match(path, pos)
        if match is None:
            msg = f"bad path {path!r} at {pos}"
            raise ValueError(msg)
        key, index, field_name, field_value = match.groups()
        if key is not None:
            segments.append(key)
        elif index is not None:
            segments.append(int(index))
        else:
            segments.append((field_name, field_value))
        pos = match.end()
    if not segments:
        msg = "empty path"
        raise ValueError(msg)
    return segments


def _step(container: JsonNode, seg: PathSegment) -> JsonNode:
    if isinstance(seg, str):
        if not isinstance(container, dict):
            msg = f"cannot read key {seg!r} from a non-object"
            raise TypeError(msg)
        return container[seg]
    items = _as_list(container, seg)
    return items[_index(items, seg)]


def _as_list(container: JsonNode, seg: PathSegment) -> list[JsonNode]:
    if not isinstance(container, list):
        msg = f"cannot apply {seg!r} to a non-list"
        raise TypeError(msg)
    return container


def _index(items: list[JsonNode], seg: int | tuple[str, str]) -> int:
    if isinstance(seg, int):
        return seg
    field_name, field_value = seg
    for i, item in enumerate(items):
        if isinstance(item, dict) and str(item.get(field_name)) == field_value:
            return i
    msg = f"no element with {field_name}={field_value}"
    raise KeyError(msg)


def _assign(container: JsonNode, seg: PathSegment, value: JsonNode) -> None:
    if isinstance(seg, str):
        if not isinstance(container, dict):
            msg = f"cannot set key {seg!r} on a non-object"
            raise TypeError(msg)
        container[seg] = copy.deepcopy(value)
    else:
        items = _as_list(container, seg)
        items[_index(items, seg)] = copy.deepcopy(value)


def _remove(container: JsonNode, seg: PathSegment) -> None:
    if isinstance(seg, str):
        if not isinstance(container, dict):
            msg = f"cannot delete key {seg!r} from a non-object"
            raise TypeError(msg)
        del container[seg]
    else:
        items = _as_list(container, seg)
        del items[_index(items, seg)]
