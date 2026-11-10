"""Condition operators, from 'IAM JSON policy elements: Condition operators' and
'Single-valued vs. multivalued context keys'."""

import pytest

from breachmap.iam import RequestContext
from breachmap.iam.conditions import ConditionError, Match, evaluate_condition, evaluate_one

M, N, U = Match.MATCH, Match.NO_MATCH, Match.UNKNOWN


def one(op: str, key: str, values: list[str] | str, ctx: RequestContext, **kw: bool) -> Match:
    return evaluate_one(op, key, [values] if isinstance(values, str) else values, ctx, **kw)


# --------------------------------------------------------------------------- string


def test_string_equals_exact_case_sensitive() -> None:
    """StringEquals: 'Exact matching, case sensitive'. The doc table: iamuser-admin matches,
    dev-ops does not, missing key does not."""
    key = "aws:PrincipalTag/job-category"
    assert one("StringEquals", key, "iamuser-admin", RequestContext({key: "iamuser-admin"})) is M
    assert one("StringEquals", key, "iamuser-admin", RequestContext({key: "dev-ops"})) is N
    assert one("StringEquals", key, "iamuser-admin", RequestContext({key: "IAMUSER-ADMIN"})) is N
    assert one("StringEquals", key, "iamuser-admin", RequestContext()) is N


def test_string_equals_or_across_values() -> None:
    ctx = RequestContext({"aws:RequestTag/environment": "storage"})
    assert one("StringEquals", "aws:RequestTag/environment", ["preprod", "storage"], ctx) is M


def test_string_equals_ignore_case() -> None:
    """'StringEqualsIgnoreCase: Exact matching, ignoring case'. Doc: PreProd resolves to true."""
    ctx = RequestContext({"aws:RequestTag/environment": "PreProd"})
    assert (
        one("StringEqualsIgnoreCase", "aws:RequestTag/environment", ["preprod", "storage"], ctx)
        is M
    )
    assert one("StringEqualsIgnoreCase", "aws:RequestTag/environment", "prod", ctx) is N


def test_string_like_wildcards() -> None:
    """StringLike: 'The values can include multi-character match wildcards (*) and
    single-character match wildcards (?) anywhere in the string.'"""
    sub = "token.actions.githubusercontent.com:sub"
    ctx = RequestContext({sub: "repo:acme/app:ref:refs/heads/main"})
    assert one("StringLike", sub, "repo:acme/*", ctx) is M
    assert one("StringLike", sub, "repo:acme/app:ref:refs/heads/ma?n", ctx) is M
    assert one("StringLike", sub, "repo:other/*", ctx) is N
    assert one("StringLike", sub, "repo:acme/app", ctx) is N, "partial match needs a wildcard"


def test_string_equals_treats_star_literally() -> None:
    """'You must specify wildcards to achieve partial string matches' applies to StringLike;
    StringEquals is exact, so '*' is just a character."""
    sub = "token.actions.githubusercontent.com:sub"
    assert one("StringEquals", sub, "repo:acme/*", RequestContext({sub: "repo:acme/app"})) is N
    assert one("StringEquals", sub, "repo:acme/*", RequestContext({sub: "repo:acme/*"})) is M


def test_negated_string_operators_match_when_key_is_missing() -> None:
    """'If the policy condition requires that the key is not matched, such as StringNotLike or
    ArnNotLike, and the right key is not present, the condition is true.'"""
    ctx = RequestContext()
    assert one("StringNotEquals", "aws:username", "bob", ctx) is M
    assert one("StringNotLike", "aws:username", "b*", ctx) is M
    assert one("StringNotEqualsIgnoreCase", "aws:username", "bob", ctx) is M
    assert one("ArnNotLike", "aws:PrincipalArn", "arn:aws:iam::*:role/x", ctx) is M
    assert one("NotIpAddress", "aws:SourceIp", "203.0.113.0/24", ctx) is M


def test_negated_string_operators_with_values() -> None:
    ctx = RequestContext({"aws:username": "bob"})
    assert one("StringNotEquals", "aws:username", "bob", ctx) is N
    assert one("StringNotEquals", "aws:username", "alice", ctx) is M
    assert one("StringNotLike", "aws:username", "b*", ctx) is N
    assert one("StringNotEqualsIgnoreCase", "aws:username", "BOB", ctx) is N


# --------------------------------------------------------------------------- set operators


def test_for_any_value_matches_on_any_overlap() -> None:
    """ForAnyValue doc table: environment -> Match; environment,dept -> Match; dept -> No match;
    missing key -> No match."""
    op, key, pol = "ForAnyValue:StringEquals", "aws:TagKeys", ["environment", "cost-center"]
    assert one(op, key, pol, RequestContext({key: ["environment"]})) is M
    assert one(op, key, pol, RequestContext({key: ["environment", "dept"]})) is M
    assert one(op, key, pol, RequestContext({key: ["dept"]})) is N
    assert one(op, key, pol, RequestContext()) is N


def test_for_all_values_requires_every_request_value_to_match() -> None:
    """ForAllValues doc table: environment,cost-center -> Match; environment,dept -> No match."""
    op, key, pol = "ForAllValues:StringEquals", "aws:TagKeys", ["environment", "cost-center"]
    assert one(op, key, pol, RequestContext({key: ["environment", "cost-center"]})) is M
    assert one(op, key, pol, RequestContext({key: ["environment", "dept"]})) is N


def test_for_all_values_is_true_when_the_key_is_missing() -> None:
    """'It also returns true if there are no context keys in the request.' and the ArnLike table:
    'No logs:LogGeneratingResourceArns in the request context. | Match'."""
    assert one("ForAllValues:StringEquals", "aws:TagKeys", ["environment"], RequestContext()) is M
    assert (
        one("ForAllValues:ArnLike", "logs:LogGeneratingResourceArns", ["arn:*"], RequestContext())
        is M
    )


def test_for_all_values_with_null_guard_closes_the_hole() -> None:
    """Doc: pairing ForAllValues with Null:false means a missing key is 'No match'."""
    block = {
        "ForAllValues:StringEquals": {"aws:TagKeys": ["environment", "cost-center"]},
        "Null": {"aws:TagKeys": ["false"]},
    }
    assert evaluate_condition(block, RequestContext()) is N
    assert evaluate_condition(block, RequestContext({"aws:TagKeys": ["environment"]})) is M


def test_for_all_values_negated() -> None:
    """'ForAllValues:StringNotLike: Negated matching. None of the values of the context key in
    the request can match any of the context key values in your policy.' (The worked table on
    that page labels its rows by the Deny statement's effect, not by the operator, so the
    operator definition is what this test follows.)"""
    op, key = "ForAllValues:StringNotLike", "aws:ResourceOrgPaths"
    pol = ["o-acorg/r-acroot/ou-acroot-mediaou/", "o-acorg/r-acroot/ou-acroot-sportsou/*"]
    inside = "o-acorg/r-acroot/ou-acroot-sportsou/costcenter/"
    exact = "o-acorg/r-acroot/ou-acroot-mediaou/"
    outside = "o-acorg/r-acroot/ou-other/"
    assert one(op, key, pol, RequestContext({key: [inside]})) is N
    assert one(op, key, pol, RequestContext({key: [exact]})) is N
    assert one(op, key, pol, RequestContext({key: [outside]})) is M
    assert one(op, key, pol, RequestContext({key: [outside, inside]})) is N


def test_for_any_value_negated() -> None:
    """'ForAnyValue:StringNotEquals: At least one context key value in the request must NOT
    match any of values in the context key in your policy.'"""
    op, key = "ForAnyValue:StringNotEquals", "aws:TagKeys"
    assert one(op, key, ["a"], RequestContext({key: ["a", "b"]})) is M
    assert one(op, key, ["a", "b"], RequestContext({key: ["a", "b"]})) is N


def test_single_operator_on_multivalued_key() -> None:
    """'Multivalued context keys require a condition set operator.' Without one we do not match
    positively (and match for negated operators)."""
    ctx = RequestContext({"aws:TagKeys": ["a", "b"]})
    assert one("StringEquals", "aws:TagKeys", "a", ctx) is N
    assert one("StringNotEquals", "aws:TagKeys", "a", ctx) is M


# --------------------------------------------------------------------------- IfExists and Null


def test_if_exists_matches_when_key_absent() -> None:
    """'If the key is not present, evaluate the condition element as true.' Doc table:
    t1.micro -> Match; m2.micro -> No match; missing -> Match."""
    op, key, pol = "StringLikeIfExists", "ec2:InstanceType", ["t1.*", "t2.*", "m3.*"]
    assert one(op, key, pol, RequestContext({key: "t1.micro"})) is M
    assert one(op, key, pol, RequestContext({key: "m2.micro"})) is N
    assert one(op, key, pol, RequestContext()) is M


def test_negated_if_exists_matches_when_key_absent() -> None:
    """'If you are using an "Effect": "Deny" element with a negated condition operator like
    StringNotEqualsIfExists, the request is still denied even if the condition key is not
    present.'"""
    assert one("StringNotEqualsIfExists", "aws:username", "bob", RequestContext()) is M
    assert (
        one(
            "StringNotEqualsIfExists",
            "aws:username",
            "bob",
            RequestContext({"aws:username": "bob"}),
        )
        is N
    )


def test_null_operator() -> None:
    """'use either true (the key doesn't exist - it is null) or false (the key exists and its
    value is not null)'."""
    assert (
        one("Null", "aws:TokenIssueTime", "false", RequestContext({"aws:TokenIssueTime": "1"})) is M
    )
    assert one("Null", "aws:TokenIssueTime", "false", RequestContext()) is N
    assert one("Null", "aws:TokenIssueTime", "true", RequestContext()) is M
    assert (
        one("Null", "aws:TokenIssueTime", "true", RequestContext({"aws:TokenIssueTime": "1"})) is N
    )
    assert one("Null", "aws:TagKeys", "true", RequestContext({"aws:TagKeys": []})) is M


# ---- numeric, date, bool, binary


def test_numeric_operators() -> None:
    """'NumericLessThanEquals ... the requester can list up to 10 objects'."""
    key = "s3:max-keys"
    assert one("NumericLessThanEquals", key, "10", RequestContext({key: "10"})) is M
    assert one("NumericLessThanEquals", key, "10", RequestContext({key: "11"})) is N
    assert one("NumericLessThan", key, "10", RequestContext({key: "9"})) is M
    assert one("NumericGreaterThan", key, "10", RequestContext({key: "11"})) is M
    assert one("NumericGreaterThanEquals", key, "10", RequestContext({key: "10"})) is M
    assert one("NumericEquals", key, "10", RequestContext({key: "10.0"})) is M
    assert one("NumericNotEquals", key, "10", RequestContext({key: "3"})) is M
    assert one("NumericEquals", key, "10", RequestContext({key: "ten"})) is N
    assert one("NumericEquals", key, "10", RequestContext()) is N


def test_date_operators() -> None:
    """'DateGreaterThan ... aws:TokenIssueTime: 2020-01-01T00:00:01Z'; values in ISO 8601 or
    epoch time."""
    key = "aws:TokenIssueTime"
    assert (
        one(
            "DateGreaterThan",
            key,
            "2020-01-01T00:00:01Z",
            RequestContext({key: "2021-06-01T00:00:00Z"}),
        )
        is M
    )
    assert (
        one(
            "DateGreaterThan",
            key,
            "2020-01-01T00:00:01Z",
            RequestContext({key: "2019-06-01T00:00:00Z"}),
        )
        is N
    )
    assert (
        one("DateLessThan", key, "1577836801", RequestContext({key: "2019-06-01T00:00:00Z"})) is M
    )
    assert one("DateEquals", key, "2020-01-01T00:00:01Z", RequestContext({key: "1577836801"})) is M
    assert (
        one("DateNotEquals", key, "2020-01-01T00:00:01Z", RequestContext({key: "1577836801"})) is N
    )
    assert (
        one("DateLessThanEquals", key, "2020-01-01T00:00:01Z", RequestContext({key: "1577836801"}))
        is M
    )
    assert (
        one(
            "DateGreaterThanEquals", key, "2020-01-01T00:00:01", RequestContext({key: "1577836801"})
        )
        is M
    )
    assert one("DateEquals", key, "not-a-date", RequestContext({key: "1577836801"})) is N
    assert one("DateGreaterThan", key, "2020-01-01T00:00:01Z", RequestContext()) is N


def test_bool_operator() -> None:
    """Bool doc table: false -> Match; true -> No match; missing -> No match."""
    key = "aws:SecureTransport"
    assert one("Bool", key, "false", RequestContext({key: "false"})) is M
    assert one("Bool", key, "false", RequestContext({key: "true"})) is N
    assert one("Bool", key, "false", RequestContext()) is N
    assert (
        one(
            "Bool",
            "aws:MultiFactorAuthPresent",
            "true",
            RequestContext({"aws:MultiFactorAuthPresent": "True"}),
        )
        is M
    )
    assert one("Bool", key, "yes", RequestContext({key: "yes"})) is N


def test_binary_equals() -> None:
    """'compares the value of the specified key byte for byte against a base-64 encoded
    representation'. Doc table: same base64 -> Match; other -> No match; missing -> No match."""
    v = "QmluYXJ5VmFsdWVJbkJhc2U2NA=="
    assert one("BinaryEquals", "key", v, RequestContext({"key": v})) is M
    assert one("BinaryEquals", "key", v, RequestContext({"key": "ASIAIOSFODNN7EXAMPLE"})) is N
    assert one("BinaryEquals", "key", v, RequestContext()) is N
    assert one("BinaryEquals", "key", "!!notbase64", RequestContext({"key": v})) is N


# --------------------------------------------------------------------------- ip and arn


def test_ip_address_cidr() -> None:
    """IpAddress doc table: 203.0.113.1 in 203.0.113.0/24 -> Match; 198.51.100.1 -> No match.
    'If you specify an IP address without the associated routing prefix, IAM uses the default
    prefix value of /32.'"""
    key = "aws:SourceIp"
    assert one("IpAddress", key, "203.0.113.0/24", RequestContext({key: "203.0.113.1"})) is M
    assert one("IpAddress", key, "203.0.113.0/24", RequestContext({key: "198.51.100.1"})) is N
    assert one("IpAddress", key, "203.0.113.7", RequestContext({key: "203.0.113.7"})) is M
    assert one("IpAddress", key, "203.0.113.7", RequestContext({key: "203.0.113.8"})) is N
    assert (
        one(
            "IpAddress",
            key,
            ["203.0.113.0/24", "2001:DB8:1234:5678::/64"],
            RequestContext({key: "2001:db8:1234:5678::1"}),
        )
        is M
    )
    assert one("IpAddress", key, "203.0.113.0/24", RequestContext({key: "2001:db8::1"})) is N
    assert one("NotIpAddress", key, "203.0.113.0/24", RequestContext({key: "198.51.100.1"})) is M
    assert one("IpAddress", key, "garbage", RequestContext({key: "203.0.113.1"})) is N
    assert one("IpAddress", key, "203.0.113.0/24", RequestContext()) is N


def test_arn_operators_check_components() -> None:
    """ArnEquals/ArnLike: 'Each of the six colon-delimited components of the ARN is checked
    separately and each can include multi-character match wildcards (*) or single-character
    match wildcards (?). The ArnEquals and ArnLike condition operators behave identically.'"""
    key = "aws:SourceArn"
    topic = "arn:aws:sns:us-west-2:123456789012:TOPIC-ID"
    assert one("ArnEquals", key, topic, RequestContext({key: topic})) is M
    assert one("ArnLike", key, topic, RequestContext({key: topic})) is M
    assert (
        one(
            "ArnEquals",
            key,
            topic,
            RequestContext({key: "arn:aws:sns:us-west-2:777788889999:TOPIC-ID"}),
        )
        is N
    )
    assert (
        one("ArnLike", key, "arn:aws:sns:*:123456789012:TOPIC-*", RequestContext({key: topic})) is M
    )
    assert one("ArnEquals", key, topic, RequestContext()) is N
    assert one("ArnNotEquals", key, topic, RequestContext({key: topic})) is N
    assert one("ArnNotLike", key, "arn:aws:sns:*:*:*", RequestContext({key: topic})) is N
    assert one("ArnNotLike", key, "arn:aws:sqs:*:*:*", RequestContext({key: topic})) is M


def test_arn_not_like_against_principal_arn_list() -> None:
    """The v1 bucket policy: deny unless aws:PrincipalArn matches a listed pattern."""
    key = "aws:PrincipalArn"
    pats = [
        "arn:aws:iam::111111111111:role/deploy-*",
        "arn:aws:iam::111111111111:role/admin-breakglass",
    ]
    assert (
        one(
            "ArnNotLike",
            key,
            pats,
            RequestContext({key: "arn:aws:iam::111111111111:role/deploy-scoped"}),
        )
        is N
    )
    assert (
        one(
            "ArnNotLike",
            key,
            pats,
            RequestContext({key: "arn:aws:iam::111111111111:role/ci-legacy-reader"}),
        )
        is M
    )


# ---- variables, blocks, unknowns


def test_policy_variables_in_string_values() -> None:
    """'You can use a policy variable for Condition values in any condition that involves the
    string operators or the ARN operators.'"""
    ctx = RequestContext({"s3:ExistingObjectTag/owner": "alice", "aws:PrincipalTag/owner": "alice"})
    assert one("StringEquals", "s3:ExistingObjectTag/owner", "${aws:PrincipalTag/owner}", ctx) is M
    other = RequestContext({"s3:ExistingObjectTag/owner": "alice", "aws:PrincipalTag/owner": "bob"})
    assert (
        one("StringEquals", "s3:ExistingObjectTag/owner", "${aws:PrincipalTag/owner}", other) is N
    )


def test_variable_with_no_value_does_not_match_but_negated_does() -> None:
    """'condition operators like StringEquals or StringLike do not match ... Inverted condition
    operators like StringNotEquals or StringNotLike do match against a null value'."""
    ctx = RequestContext({"s3:ExistingObjectTag/Team": "blue"})
    assert one("StringEquals", "s3:ExistingObjectTag/Team", "${aws:PrincipalTag/Team}", ctx) is N
    assert one("StringNotEquals", "s3:ExistingObjectTag/Team", "${aws:PrincipalTag/Team}", ctx) is M


def test_variables_not_expanded_for_numeric_or_when_disabled() -> None:
    """'You can't use a policy variable with other operators, such as Numeric, Date, Boolean,
    Binary, IP Address, or Null operators.'"""
    ctx = RequestContext({"s3:max-keys": "5", "aws:PrincipalTag/n": "5"})
    assert one("NumericEquals", "s3:max-keys", "${aws:PrincipalTag/n}", ctx) is N
    ctx2 = RequestContext({"aws:username": "${aws:username}"})
    assert one("StringEquals", "aws:username", "${aws:username}", ctx2, variables=False) is M


def test_block_ands_operators_and_keys() -> None:
    """Doc example: StringEqualsIgnoreCase on aws:RequestTag/environment AND
    ForAnyValue:StringEquals on aws:TagKeys. All rows of the doc table."""
    block = {
        "StringEqualsIgnoreCase": {"aws:RequestTag/environment": ["preprod", "storage"]},
        "ForAnyValue:StringEquals": {"aws:TagKeys": ["environment"]},
    }
    rows: list[tuple[dict[str, str | list[str]], Match]] = [
        ({"aws:TagKeys": ["environment"], "aws:RequestTag/environment": "preprod"}, M),
        (
            {"aws:TagKeys": ["environment", "costcenter"], "aws:RequestTag/environment": "PreProd"},
            M,
        ),
        ({"aws:TagKeys": ["Environment"], "aws:RequestTag/Environment": "preprod"}, N),
        ({"aws:TagKeys": ["costcenter"], "aws:RequestTag/environment": "preprod"}, N),
        ({"aws:RequestTag/environment": "storage"}, N),
        ({"aws:TagKeys": ["environment"]}, N),
        ({}, N),
    ]
    for values, expected in rows:
        assert evaluate_condition(block, RequestContext(values)) is expected, values


def test_empty_block_matches() -> None:
    assert evaluate_condition({}, RequestContext()) is M


def test_unknown_key_yields_unknown_unless_something_else_fails() -> None:
    ctx = RequestContext({"aws:username": "bob"}, unknown=["aws:SourceIp"])
    assert one("IpAddress", "aws:SourceIp", "203.0.113.0/24", ctx) is U
    block = {
        "IpAddress": {"aws:SourceIp": ["203.0.113.0/24"]},
        "StringEquals": {"aws:username": ["bob"]},
    }
    assert evaluate_condition(block, ctx) is U
    block["StringEquals"] = {"aws:username": ["alice"]}
    assert evaluate_condition(block, ctx) is N


def test_unknown_operator_is_an_error() -> None:
    with pytest.raises(ConditionError, match="unknown condition operator"):
        one("StringFuzzy", "k", "v", RequestContext({"k": "v"}))
    with pytest.raises(ConditionError):
        one("ForAnyValue:Nope", "k", "v", RequestContext({"k": "v"}))
