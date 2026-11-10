"""Evaluation of the ``Condition`` element.

Semantics come from "IAM JSON policy elements: Condition operators" and
"Single-valued vs. multivalued context keys". The result is three-valued:
a condition on a key whose value is unknowable offline (see
``RequestContext.unknown``) yields ``UNKNOWN`` instead of a guess.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import Enum

from breachmap.iam.context import RequestContext
from breachmap.iam.matching import glob_match, match_arn, substitute_variables
from breachmap.iam.policy import ConditionBlock


class Match(Enum):
    """Outcome of a condition (or a whole block)."""

    MATCH = "match"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


_SET_QUALIFIERS = ("ForAllValues:", "ForAnyValue:")
_IF_EXISTS = "IfExists"

# Base operators: name -> (negated?, comparator(policy_value, request_value) -> bool).
# Comparators receive one policy value and one request value and say whether they match
# in the operator's *positive* sense; negation is applied by the caller.
_Comparator = Callable[[str, str], bool]


def _str_eq(p: str, r: str) -> bool:
    return p == r


def _str_eq_ic(p: str, r: str) -> bool:
    return p.lower() == r.lower()


def _str_like(p: str, r: str) -> bool:
    return glob_match(p, r)


def _num(p: str, r: str, cmp: Callable[[float, float], bool]) -> bool:
    try:
        return cmp(float(r), float(p))
    except ValueError:
        return False


def _date(p: str, r: str, cmp: Callable[[datetime, datetime], bool]) -> bool:
    try:
        return cmp(_parse_date(r), _parse_date(p))
    except ValueError:
        return False


def _parse_date(text: str) -> datetime:
    if re.fullmatch(r"\d+", text):
        return datetime.fromtimestamp(int(text), tz=UTC)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _bool(p: str, r: str) -> bool:
    return p.lower() in ("true", "false") and p.lower() == r.lower()


def _binary(p: str, r: str) -> bool:
    try:
        return base64.b64decode(p, validate=True) == base64.b64decode(r, validate=True)
    except ValueError:
        return False


def _ip(p: str, r: str) -> bool:
    try:
        network = ipaddress.ip_network(p, strict=False)
        address = ipaddress.ip_address(r)
    except ValueError:
        return False
    return address.version == network.version and address in network


def _arn(p: str, r: str) -> bool:
    return match_arn(p, r, trailing_star_crosses_segments=False)


_OPERATORS: dict[str, tuple[bool, _Comparator, bool]] = {
    # name: (negated, comparator, supports policy variables)
    "StringEquals": (False, _str_eq, True),
    "StringNotEquals": (True, _str_eq, True),
    "StringEqualsIgnoreCase": (False, _str_eq_ic, True),
    "StringNotEqualsIgnoreCase": (True, _str_eq_ic, True),
    "StringLike": (False, _str_like, True),
    "StringNotLike": (True, _str_like, True),
    "NumericEquals": (False, lambda p, r: _num(p, r, lambda a, b: a == b), False),
    "NumericNotEquals": (True, lambda p, r: _num(p, r, lambda a, b: a == b), False),
    "NumericLessThan": (False, lambda p, r: _num(p, r, lambda a, b: a < b), False),
    "NumericLessThanEquals": (False, lambda p, r: _num(p, r, lambda a, b: a <= b), False),
    "NumericGreaterThan": (False, lambda p, r: _num(p, r, lambda a, b: a > b), False),
    "NumericGreaterThanEquals": (False, lambda p, r: _num(p, r, lambda a, b: a >= b), False),
    "DateEquals": (False, lambda p, r: _date(p, r, lambda a, b: a == b), False),
    "DateNotEquals": (True, lambda p, r: _date(p, r, lambda a, b: a == b), False),
    "DateLessThan": (False, lambda p, r: _date(p, r, lambda a, b: a < b), False),
    "DateLessThanEquals": (False, lambda p, r: _date(p, r, lambda a, b: a <= b), False),
    "DateGreaterThan": (False, lambda p, r: _date(p, r, lambda a, b: a > b), False),
    "DateGreaterThanEquals": (False, lambda p, r: _date(p, r, lambda a, b: a >= b), False),
    "Bool": (False, _bool, True),
    "BinaryEquals": (False, _binary, False),
    "IpAddress": (False, _ip, False),
    "NotIpAddress": (True, _ip, False),
    "ArnEquals": (False, _arn, True),
    "ArnLike": (False, _arn, True),
    "ArnNotEquals": (True, _arn, True),
    "ArnNotLike": (True, _arn, True),
}


class ConditionError(ValueError):
    """A condition operator the evaluator does not know."""


def evaluate_condition(
    block: ConditionBlock, context: RequestContext, *, variables: bool = True
) -> Match:
    """Evaluate a whole ``Condition`` block.

    Operators are ANDed, keys inside an operator are ANDed, and the values
    for one key are ORed. The block is ``NO_MATCH`` if any part fails,
    ``UNKNOWN`` if nothing fails but some part depends on an unknowable key,
    and ``MATCH`` otherwise. An empty block matches.
    """
    saw_unknown = False
    for operator, keys in block.items():
        for key, values in keys.items():
            result = evaluate_one(operator, key, values, context, variables=variables)
            if result is Match.NO_MATCH:
                return Match.NO_MATCH
            if result is Match.UNKNOWN:
                saw_unknown = True
    return Match.UNKNOWN if saw_unknown else Match.MATCH


def evaluate_one(
    operator: str,
    key: str,
    policy_values: Sequence[str],
    context: RequestContext,
    *,
    variables: bool = True,
) -> Match:
    """Evaluate one ``operator: {key: values}`` entry."""
    if context.is_unknown(key):
        return Match.UNKNOWN
    if operator == "Null":
        return _null(key, policy_values, context)
    qualifier, base = _split_qualifier(operator)
    if_exists = base.endswith(_IF_EXISTS)
    if if_exists:
        base = base[: -len(_IF_EXISTS)]
    if base not in _OPERATORS:
        msg = f"unknown condition operator {operator!r}"
        raise ConditionError(msg)
    negated, compare, allows_variables = _OPERATORS[base]

    request_values = context.get(key)
    if request_values is None:
        return _missing_key(negated=negated, if_exists=if_exists, qualifier=qualifier)

    resolved = _resolve_values(policy_values, context, enabled=variables and allows_variables)

    def value_matches(request_value: str) -> bool:
        positive = any(compare(p, request_value) for p in resolved)
        return positive != negated

    return _to_match(_combine(qualifier, request_values, value_matches, negated=negated))


def _combine(
    qualifier: str,
    request_values: Sequence[str],
    value_matches: Callable[[str], bool],
    *,
    negated: bool,
) -> bool:
    """Apply the set qualifier (or none) over the request's values."""
    if qualifier == "ForAllValues:":
        return all(value_matches(v) for v in request_values)
    if qualifier == "ForAnyValue:":
        return any(value_matches(v) for v in request_values)
    if len(request_values) != 1:
        # "Multivalued context keys require a condition set operator." Without one the
        # comparison cannot be made; treat as not matching for positive operators and
        # as matching for negated ones (nothing equals the set), mirroring the missing-key rule.
        return negated
    return value_matches(request_values[0])


def _null(key: str, policy_values: Sequence[str], context: RequestContext) -> Match:
    """``Null``: "true (the key doesn't exist - it is null) or false (the key exists ...)"."""
    present = context.get(key) not in (None, [], [""])
    wants_absent = policy_values[0].lower() == "true" if policy_values else True
    return _to_match(present != wants_absent)


def _missing_key(*, negated: bool, if_exists: bool, qualifier: str) -> Match:
    """Key absent from the request context.

    "If the key that you specify in a policy condition is not present in the
    request context, the values do not match and the condition is false. If
    the policy condition requires that the key is not matched, such as
    StringNotLike or ArnNotLike, and the right key is not present, the
    condition is true." ``...IfExists``: "If the key is not present, evaluate
    the condition element as true." ``ForAllValues`` "also returns true if
    there are no context keys in the request"; ``ForAnyValue``: "if the key
    does not exist, the condition returns false".
    """
    if if_exists:
        return Match.MATCH
    if qualifier == "ForAllValues:":
        return Match.MATCH
    if qualifier == "ForAnyValue:":
        return Match.NO_MATCH
    return _to_match(negated)


def _split_qualifier(operator: str) -> tuple[str, str]:
    for q in _SET_QUALIFIERS:
        if operator.startswith(q):
            return q, operator[len(q) :]
    return "", operator


def _resolve_values(values: Sequence[str], context: RequestContext, *, enabled: bool) -> list[str]:
    """Substitute policy variables; a value whose variable has no value is dropped.

    "When you use a variable with no value in the condition element of an IAM
    policy, condition operators like StringEquals or StringLike do not match."
    Dropping the value achieves that for positive operators and, for negated
    ones, makes them match ("Inverted condition operators like StringNotEquals
    or StringNotLike do match against a null value").
    """
    resolved: list[str] = []
    for value in values:
        out = substitute_variables(value, context, enabled=enabled)
        if out is not None:
            resolved.append(out)
    return resolved


def _to_match(ok: bool) -> Match:
    return Match.MATCH if ok else Match.NO_MATCH
