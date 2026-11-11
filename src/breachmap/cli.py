"""The ``breachmap`` command line. v1 offers the lab checks only."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from breachmap.lab import load_answer_key, load_fixture
from breachmap.lab.environment import environment_from_fixture
from breachmap.lab.evaluate import Verdict, verdicts
from breachmap.lab.mutations import load_mutations, load_raw_fixture, run_all


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(prog="breachmap")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="reproduce an answer key with the offline evaluator")
    check.add_argument("--fixture", type=Path, required=True)
    check.add_argument("--answer-key", type=Path, required=True)

    mutate = sub.add_parser("mutate", help="run a mutation set against a fixture")
    mutate.add_argument("--fixture", type=Path, required=True)
    mutate.add_argument("--answer-key", type=Path, required=True)
    mutate.add_argument("--mutations", type=Path, required=True)
    mutate.add_argument("--list", action="store_true", help="list mutations without running")

    args = parser.parse_args(argv)
    if args.command == "check":
        return _check(args.fixture, args.answer_key)
    return _mutate(args.fixture, args.answer_key, args.mutations, list_only=args.list)


def _check(fixture_dir: Path, key_file: Path) -> int:
    key = load_answer_key(key_file)
    fixture = load_fixture(fixture_dir)
    problems = key.check_against(fixture)
    for problem in problems:
        print(f"answer key: {problem}")
    actual = verdicts(key, environment_from_fixture(fixture))
    failures = 0
    for decision in key.decisions:
        expected = Verdict.expected(decision)
        got = actual[decision.id]
        status = "ok " if got == expected else "BAD"
        failures += got != expected
        print(
            f"{status} {decision.id} {got.outcome:7} {got.reason or '-':20} {decision.description}"
        )
    total = len(key.decisions)
    print(f"{total - failures}/{total} decisions reproduce")
    return 1 if failures or problems else 0


def _mutate(fixture_dir: Path, key_file: Path, mutations_file: Path, *, list_only: bool) -> int:
    key = load_answer_key(key_file)
    mutations = load_mutations(mutations_file)
    if mutations.fixture != key.fixture:
        print(f"mutations are for {mutations.fixture!r}, answer key is for {key.fixture!r}")
        return 2
    if list_only:
        for m in mutations.mutations:
            print(f"{m.id} {m.description}")
        return 0
    results = run_all(mutations, load_raw_fixture(fixture_dir), key)
    for m, r in zip(mutations.mutations, results, strict=True):
        print(f"{'ok ' if r.passed else 'BAD'} {r.id} {m.description}")
        if r.error:
            print(f"      error: {r.error}")
        for did, (outcome, reason) in r.unexpected.items():
            print(f"      unexpected: {did} -> {outcome} {reason or ''}")
        for did, (outcome, reason) in r.missing.items():
            print(f"      missing:    {did} should be {outcome} {reason or ''}")
    passed = sum(r.passed for r in results)
    print(f"{passed}/{len(results)} mutations pass ({100 * passed / len(results):.1f}%)")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
