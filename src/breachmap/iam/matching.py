"""Matching rules for actions, resource ARNs, principals and policy variables.

Each public function implements one documented rule and is tested from the
sentence that defines it. Literal ``*`` and ``?`` produced by policy
variables (``${*}``, ``${?}`` or a substituted value) are carried as
private-use sentinel characters so they are never treated as wildcards.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from breachmap.iam.context import PrincipalKind, RequestContext, RequestPrincipal
from breachmap.iam.policy import Principal

LITERAL_STAR = ""
LITERAL_QMARK = ""
_VARIABLE = re.compile(r"\$\{([^}]*)\}")
_DEFAULTED = re.compile(r"^\s*([^,]+?)\s*,\s*'([^']*)'\s*$")
_ARN_SEGMENTS = 6


def glob_to_regex(pattern: str) -> str:
    """Translate an IAM glob (``*`` any run, ``?`` one char) into an anchored regex."""
    out: list[str] = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == LITERAL_STAR:
            out.append(re.escape("*"))
        elif ch == LITERAL_QMARK:
            out.append(re.escape("?"))
        else:
            out.append(re.escape(ch))
    return "".join(out)


def glob_match(pattern: str, value: str, *, ignore_case: bool = False) -> bool:
    """Whole-string glob match."""
    flags = re.IGNORECASE | re.DOTALL if ignore_case else re.DOTALL
    return re.fullmatch(glob_to_regex(pattern), value, flags) is not None


def match_action(pattern: str, action: str) -> bool:
    """Does an ``Action`` entry cover ``action``?

    "The prefix and the action name are case insensitive." and "You can also
    use wildcards (* or ?) as part of the action name."
    """
    return glob_match(pattern, action, ignore_case=True)


def match_arn(pattern: str, arn: str, *, trailing_star_crosses_segments: bool = True) -> bool:
    """Does a ``Resource`` entry (or an ``ArnLike`` value) cover ``arn``?

    "You can use wildcard characters (* and ?) within the individual segments
    of an ARN (the parts separated by colons)". For the Resource element,
    "If the * wildcard is the last character of a resource ARN segment, it can
    expand to match beyond the colon boundaries." For ``ArnLike``, "Each of
    the six colon-delimited components of the ARN is checked separately", so
    callers pass ``trailing_star_crosses_segments=False``.
    """
    if pattern == "*":
        return True
    p_segs = pattern.split(":", _ARN_SEGMENTS - 1)
    a_segs = arn.split(":", _ARN_SEGMENTS - 1)
    if trailing_star_crosses_segments:
        return _match_segments_crossing(p_segs, a_segs)
    if len(p_segs) != len(a_segs):
        return False
    return all(glob_match(p, a) for p, a in zip(p_segs, a_segs, strict=True))


def _match_segments_crossing(p_segs: Sequence[str], a_segs: Sequence[str]) -> bool:
    """Segment-wise match where a segment ending in ``*`` may absorb the rest of the ARN."""
    if not p_segs:
        return not a_segs
    head, rest = p_segs[0], p_segs[1:]
    if head.endswith("*") and not head.endswith(LITERAL_STAR):
        # The star may stop inside this segment or run across any number of later ones.
        for split in range(len(a_segs)):
            candidate = ":".join(a_segs[: split + 1])
            if glob_match(head, candidate) and _match_segments_crossing(rest, a_segs[split + 1 :]):
                return True
        return False
    if not a_segs or not glob_match(head, a_segs[0]):
        return False
    return _match_segments_crossing(rest, a_segs[1:])


def match_principal(element: Principal, requester: RequestPrincipal) -> bool:
    """Does a ``Principal`` element name the requester?

    "You cannot use a wildcard to match part of a principal name or ARN", so
    every comparison is exact. An account entry ("arn:aws:iam::123456789012:root"
    or "123456789012") "delegates authority to the account": any IAM principal
    of that account matches. A role ARN matches the role session; a session ARN
    matches only that session.
    """
    if element.everyone:
        return True
    if requester.kind is PrincipalKind.SERVICE:
        return requester.service_name in element.service
    if requester.kind is PrincipalKind.FEDERATED:
        return requester.provider_arn in element.federated
    if requester.kind is PrincipalKind.ANONYMOUS:
        return False
    account = requester.account_id
    accepted = {account, f"arn:aws:iam::{account}:root", requester.arn, requester.session_arn}
    return any(entry in accepted for entry in element.aws)


def substitute_variables(text: str, context: RequestContext, *, enabled: bool = True) -> str | None:
    """Replace ``${key}`` policy variables with request-context values.

    Returns None when a variable "has no value or is not present in an
    authorization context", since then "the resource that includes a policy
    variable with no value will not match any resource". Defaults use the
    documented form ``${aws:PrincipalTag/team, 'company-wide'}``. The special
    variables ``${*}``, ``${?}`` and ``${$}`` yield literal characters. With
    ``enabled`` false (policy Version other than 2012-10-17) the text is
    returned untouched: variables "are treated as literal strings".
    """
    if not enabled:
        return text
    out: list[str] = []
    pos = 0
    for match in _VARIABLE.finditer(text):
        out.append(text[pos : match.start()])
        pos = match.end()
        body = match.group(1)
        if body == "*":
            out.append(LITERAL_STAR)
            continue
        if body == "?":
            out.append(LITERAL_QMARK)
            continue
        if body == "$":
            out.append("$")
            continue
        key, default = body, None
        defaulted = _DEFAULTED.match(body)
        if defaulted:
            key, default = defaulted.group(1), defaulted.group(2)
        value = context.single(key)
        if value is None:
            if default is None:
                return None
            value = default
        out.append(_escape_literal(value))
    out.append(text[pos:])
    return "".join(out)


def _escape_literal(value: str) -> str:
    return value.replace("*", LITERAL_STAR).replace("?", LITERAL_QMARK)
