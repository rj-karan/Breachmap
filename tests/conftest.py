from pathlib import Path

import pytest

from breachmap.lab import AnswerKey, LabFixture, load_answer_key, load_fixture

LAB = Path(__file__).resolve().parents[1] / "lab"


@pytest.fixture(scope="session")
def v1_fixture() -> LabFixture:
    return load_fixture(LAB / "fixtures" / "v1-oidc")


@pytest.fixture(scope="session")
def v1_answer_key() -> AnswerKey:
    return load_answer_key(LAB / "answer-keys" / "v1-oidc.json")
