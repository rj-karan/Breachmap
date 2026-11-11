import json
from pathlib import Path

import pytest

from breachmap.cli import main

from .conftest import LAB

FIX = str(LAB / "fixtures" / "v1-oidc")
KEY = str(LAB / "answer-keys" / "v1-oidc.json")
MUT = str(LAB / "mutations" / "v1-oidc.json")


def test_check_reproduces_the_answer_key(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--fixture", FIX, "--answer-key", KEY]) == 0
    out = capsys.readouterr().out
    assert "28/28 decisions reproduce" in out
    assert "BAD" not in out


def test_mutate_runs_and_lists(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(["mutate", "--fixture", FIX, "--answer-key", KEY, "--mutations", MUT, "--list"]) == 0
    )
    assert "m01 " in capsys.readouterr().out
    assert main(["mutate", "--fixture", FIX, "--answer-key", KEY, "--mutations", MUT]) == 0
    out = capsys.readouterr().out
    assert "mutations pass (100.0%)" in out


def test_mutate_rejects_mismatched_fixture(tmp_path: Path) -> None:
    other = tmp_path / "m.json"
    other.write_text('{"fixture": "other", "mutations": []}')
    assert main(["mutate", "--fixture", FIX, "--answer-key", KEY, "--mutations", str(other)]) == 2


def test_check_reports_failures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = json.loads(Path(KEY).read_text())
    key["decisions"][0]["outcome"] = "deny"
    key["decisions"][0]["reason"] = "scp"
    broken = tmp_path / "key.json"
    broken.write_text(json.dumps(key))
    assert main(["check", "--fixture", FIX, "--answer-key", str(broken)]) == 1
    assert "BAD d01" in capsys.readouterr().out
