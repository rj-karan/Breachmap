"""Matching rules, each from the sentence in the IAM reference that defines it."""

import pytest

from breachmap.iam import Principal, RequestContext, RequestPrincipal
from breachmap.iam.context import PrincipalKind
from breachmap.iam.matching import (
    LITERAL_STAR,
    glob_match,
    match_action,
    match_arn,
    match_principal,
    substitute_variables,
)

# --------------------------------------------------------------------------- actions


def test_action_prefix_and_name_are_case_insensitive() -> None:
    """'The prefix and the action name are case insensitive. For example,
    iam:ListAccessKeys is the same as IAM:listaccesskeys.'"""
    assert match_action("iam:ListAccessKeys", "IAM:listaccesskeys")
    assert match_action("S3:GETOBJECT", "s3:GetObject")


def test_action_service_wildcard() -> None:
    """'"Action": "s3:*" ... applies to all S3 actions.'"""
    assert match_action("s3:*", "s3:GetObject")
    assert match_action("s3:*", "s3:PutBucketPolicy")
    assert not match_action("s3:*", "sts:AssumeRole")


def test_action_wildcard_inside_name() -> None:
    """'"Action": "iam:*AccessKey*" ... applies to all IAM actions that include the string
    AccessKey, including CreateAccessKey, DeleteAccessKey, ListAccessKeys, and
    UpdateAccessKey.'"""
    for name in ("CreateAccessKey", "DeleteAccessKey", "ListAccessKeys", "UpdateAccessKey"):
        assert match_action("iam:*AccessKey*", f"iam:{name}")
    assert not match_action("iam:*AccessKey*", "iam:CreateUser")


def test_action_single_character_wildcard() -> None:
    """'single-character match wildcards (?)'"""
    assert match_action("s3:Get?bject", "s3:GetObject")
    assert not match_action("s3:Get?bject", "s3:GetBucket")


def test_action_star_alone_matches_everything() -> None:
    assert match_action("*", "kms:Decrypt")


def test_action_no_partial_match_without_wildcard() -> None:
    assert not match_action("s3:Get", "s3:GetObject")


# --------------------------------------------------------------------------- resources


def test_resource_star_matches_all() -> None:
    assert match_arn("*", "arn:aws:s3:::anything/at/all")


def test_resource_wildcard_within_segment() -> None:
    """'You can use wildcard characters (* and ?) within the individual segments of an ARN'"""
    assert match_arn(
        "arn:aws:iam::111111111111:user/accounting/*",
        "arn:aws:iam::111111111111:user/accounting/alice",
    )
    assert match_arn("arn:aws:s3:::amzn-s3-demo-bucket/*", "arn:aws:s3:::amzn-s3-demo-bucket/x")
    assert not match_arn("arn:aws:s3:::amzn-s3-demo-bucket/*", "arn:aws:s3:::amzn-s3-demo-bucket")


def test_resource_star_spans_slashes_inside_a_segment() -> None:
    """'The asterisk (*) character can expand to replace everything within a segment,
    including characters like a forward slash (/)'. The doc's own match list."""
    pattern = "arn:aws:s3:::amzn-s3-demo-bucket/*/test/*"
    for obj in (
        "1/test/object.jpg",
        "1/2/test/object.jpg",
        "1/2/test/3/object.jpg",
        "1/2/3/test/4/object.jpg",
        "1///test///object.jpg",
        "1/test/.jpg",
        "/test/object.jpg",
        "1/test/",
    ):
        assert match_arn(pattern, f"arn:aws:s3:::amzn-s3-demo-bucket/{obj}"), obj
    for obj in ("1-test/object.jpg", "test/object.jpg", "1/2/test.jpg"):
        assert not match_arn(pattern, f"arn:aws:s3:::amzn-s3-demo-bucket/{obj}"), obj


def test_resource_trailing_star_crosses_colon_boundaries() -> None:
    """'If the * wildcard is the last character of a resource ARN segment, it can expand to
    match beyond the colon boundaries.'"""
    assert match_arn("arn:aws:s3:*", "arn:aws:s3:::bucket/key")
    assert match_arn("arn:aws:kms:us-east-1:*", "arn:aws:kms:us-east-1:111111111111:key/abc")
    assert match_arn(
        "arn:aws:secretsmanager:*",
        "arn:aws:secretsmanager:us-east-1:111111111111:secret:prod/db-AbCdEf",
    )


def test_resource_star_in_middle_of_segment_does_not_cross_colons() -> None:
    """Only a *trailing* star may expand beyond colons; a star mid-segment stays inside it."""
    assert match_arn(
        "arn:aws:kms:us-*-1:111111111111:key/abc", "arn:aws:kms:us-east-1:111111111111:key/abc"
    )
    assert not match_arn("arn:aws:kms:us-*-1:key/abc", "arn:aws:kms:us-east-1:111111111111:key/abc")


def test_resource_case_sensitive() -> None:
    """'In the Resource element, the IAM user name is case sensitive.'"""
    assert not match_arn("arn:aws:iam::111111111111:user/Bob", "arn:aws:iam::111111111111:user/bob")


def test_resource_question_mark() -> None:
    assert match_arn("arn:aws:s3:::bucket-?/*", "arn:aws:s3:::bucket-1/key")
    assert not match_arn("arn:aws:s3:::bucket-?/*", "arn:aws:s3:::bucket-12/key")


def test_arnlike_checks_each_component_separately() -> None:
    """ArnLike: 'Each of the six colon-delimited components of the ARN is checked separately
    and each can include multi-character match wildcards (*) or single-character match
    wildcards (?).'"""
    kw = {"trailing_star_crosses_segments": False}
    assert match_arn(
        "arn:aws:iam::*:role/deploy-*", "arn:aws:iam::111111111111:role/deploy-x", **kw
    )
    assert not match_arn("arn:aws:iam:*", "arn:aws:iam::111111111111:role/x", **kw)
    assert not match_arn("arn:aws:iam::111111111111:role", "arn:aws:iam::111111111111:role/x", **kw)
    assert match_arn("*", "arn:aws:iam::111111111111:role/x", **kw)


def test_literal_star_from_variable_is_not_a_wildcard() -> None:
    assert not match_arn(f"arn:aws:s3:::bucket/{LITERAL_STAR}", "arn:aws:s3:::bucket/x")
    assert match_arn(f"arn:aws:s3:::bucket/{LITERAL_STAR}", "arn:aws:s3:::bucket/*")
    assert not match_arn(f"arn:aws:s3:::bucket/{LITERAL_STAR}", "arn:aws:s3:::bucket/*:extra")


def test_glob_match_literal_question_mark() -> None:
    assert glob_match("a", "a?")
    assert not glob_match("a", "ab")


# --------------------------------------------------------------------------- principals

ROLE = RequestPrincipal.role("arn:aws:iam::111111111111:role/deploy")
SESSION = RequestPrincipal(
    kind=PrincipalKind.ROLE,
    arn="arn:aws:iam::111111111111:role/deploy",
    account_id="111111111111",
    session_arn="arn:aws:sts::111111111111:assumed-role/deploy/run-42",
)


def test_everyone_matches_any_principal() -> None:
    """'using a wildcard (*) with an Allow effect grants access to all users, including
    anonymous users'"""
    star = Principal.from_json("*")
    for p in (ROLE, RequestPrincipal.root("1" * 12), RequestPrincipal.federated("arn:x")):
        assert match_principal(star, p)
    assert match_principal(star, RequestPrincipal(kind=PrincipalKind.ANONYMOUS))


def test_account_root_arn_and_bare_id_delegate_to_the_account() -> None:
    """'The account ARN and the shortened account ID behave the same way. Both delegate
    permissions to the account. Using the account ARN in the Principal element does not limit
    permissions to only the root user of the account.'"""
    by_arn = Principal.from_json({"AWS": "arn:aws:iam::111111111111:root"})
    by_id = Principal.from_json({"AWS": "111111111111"})
    user = RequestPrincipal.user("arn:aws:iam::111111111111:user/alice")
    for element in (by_arn, by_id):
        assert match_principal(element, ROLE)
        assert match_principal(element, user)
        assert match_principal(element, RequestPrincipal.root("111111111111"))
        assert not match_principal(
            element, RequestPrincipal.role("arn:aws:iam::222222222222:role/x")
        )


def test_role_arn_matches_the_role_session_only() -> None:
    element = Principal.from_json({"AWS": "arn:aws:iam::111111111111:role/deploy"})
    assert match_principal(element, ROLE)
    assert match_principal(element, SESSION)
    assert not match_principal(
        element, RequestPrincipal.role("arn:aws:iam::111111111111:role/other")
    )


def test_session_arn_matches_that_session() -> None:
    element = Principal.from_json({"AWS": "arn:aws:sts::111111111111:assumed-role/deploy/run-42"})
    assert match_principal(element, SESSION)
    assert not match_principal(element, ROLE)


def test_no_wildcards_inside_principal_arns() -> None:
    """'You cannot use a wildcard to match part of a principal name or ARN.'"""
    element = Principal.from_json({"AWS": "arn:aws:iam::111111111111:role/*"})
    assert not match_principal(element, ROLE)


def test_federated_principal_matches_provider_arn() -> None:
    gh = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
    element = Principal.from_json({"Federated": gh})
    assert match_principal(element, RequestPrincipal.federated(gh))
    assert not match_principal(
        element, RequestPrincipal.federated("arn:aws:iam::111111111111:oidc-provider/other")
    )
    assert not match_principal(element, ROLE)


def test_service_principal() -> None:
    element = Principal.from_json({"Service": "ecs.amazonaws.com"})
    assert match_principal(element, RequestPrincipal.service("ecs.amazonaws.com"))
    assert not match_principal(element, RequestPrincipal.service("lambda.amazonaws.com"))
    assert not match_principal(element, ROLE)


def test_anonymous_matches_only_everyone() -> None:
    anon = RequestPrincipal(kind=PrincipalKind.ANONYMOUS)
    assert not match_principal(Principal.from_json({"AWS": "111111111111"}), anon)


def test_request_principal_shape_rules() -> None:
    with pytest.raises(ValueError, match="needs arn and account_id"):
        RequestPrincipal(kind=PrincipalKind.ROLE)
    with pytest.raises(ValueError, match="needs provider_arn"):
        RequestPrincipal(kind=PrincipalKind.FEDERATED)
    with pytest.raises(ValueError, match="needs service_name"):
        RequestPrincipal(kind=PrincipalKind.SERVICE)
    with pytest.raises(ValueError, match="12-digit account id"):
        RequestPrincipal.role("arn:aws:iam::nope:role/x")
    assert ROLE.account_id == "111111111111"
    assert ROLE.tags == {}


# --------------------------------------------------------------------------- variables


def test_variable_is_replaced_from_the_request_context() -> None:
    """'When the policy is evaluated, the policy variables are replaced with values that come
    from the conditional context keys passed in the request.'"""
    ctx = RequestContext({"aws:username": "david"})
    assert (
        substitute_variables("arn:aws:s3:::bucket/${aws:username}/*", ctx)
        == "arn:aws:s3:::bucket/david/*"
    )


def test_variable_key_names_are_case_insensitive() -> None:
    """'Key names are case-insensitive. For example, aws:CurrentTime is equivalent to
    AWS:currenttime.'"""
    ctx = RequestContext({"aws:PrincipalTag/team": "yellow"})
    assert substitute_variables("${AWS:principaltag/TEAM}", ctx) == "yellow"


def test_variable_with_no_value_matches_nothing() -> None:
    """'If a variable that has no value in the authorization context is used as part of the
    Resource or NotResource element of a policy, the resource that includes a policy variable
    with no value will not match any resource.'"""
    assert substitute_variables("arn:aws:s3:::bucket/${aws:username}", RequestContext()) is None


def test_variable_default_value() -> None:
    """'"Resource":"arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}"'
    ... 'For users without team tags, it sets a default value of company-wide'."""
    text = "arn:aws:s3:::amzn-s3-demo-bucket-${aws:PrincipalTag/team, 'company-wide'}"
    assert (
        substitute_variables(text, RequestContext())
        == "arn:aws:s3:::amzn-s3-demo-bucket-company-wide"
    )
    assert (
        substitute_variables(text, RequestContext({"aws:PrincipalTag/team": "yellow"}))
        == "arn:aws:s3:::amzn-s3-demo-bucket-yellow"
    )


def test_special_variables_yield_literal_characters() -> None:
    """'${*} - use where you need an * (asterisk) character. ${?} - use where you need a ?
    (question mark) character. ${$} - use where you need a $ (dollar sign) character.'"""
    out = substitute_variables("a${*}b${?}c${$}d", RequestContext())
    assert out is not None
    assert glob_match(out, "a*b?c$d")
    assert not glob_match(out, "aXbYc$d")


def test_substituted_values_are_literal_not_wildcards() -> None:
    ctx = RequestContext({"aws:PrincipalTag/x": "*"})
    out = substitute_variables("bucket/${aws:PrincipalTag/x}", ctx)
    assert out is not None
    assert glob_match(out, "bucket/*")
    assert not glob_match(out, "bucket/anything")


def test_variables_are_literal_without_the_2012_version() -> None:
    """'If you don't include the Version element and set it to an appropriate version date,
    variables like ${aws:username} are treated as literal strings in the policy.'"""
    ctx = RequestContext({"aws:username": "david"})
    assert substitute_variables("x/${aws:username}", ctx, enabled=False) == "x/${aws:username}"


def test_multivalued_key_cannot_be_a_variable() -> None:
    """'You can't use a multivalued condition key as a variable.'"""
    ctx = RequestContext({"aws:TagKeys": ["a", "b"]})
    assert substitute_variables("${aws:TagKeys}", ctx) is None


# --------------------------------------------------------------------------- context


def test_request_context_basics() -> None:
    ctx = RequestContext(
        {"aws:SourceIp": "203.0.113.1", "aws:TagKeys": ["a", "b"]}, unknown=["aws:SourceVpc"]
    )
    assert ctx.get("AWS:SOURCEIP") == ["203.0.113.1"]
    assert ctx.single("aws:SourceIp") == "203.0.113.1"
    assert ctx.single("aws:TagKeys") is None
    assert ctx.get("missing") is None
    assert ctx.is_unknown("aws:sourcevpc")
    assert not ctx.is_unknown("aws:SourceIp")
    assert ctx.keys() == {"aws:sourceip", "aws:tagkeys"}
    merged = ctx.with_values({"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"})
    assert merged.single("kms:ViaService") == "secretsmanager.us-east-1.amazonaws.com"
    assert merged.get("aws:SourceIp") == ["203.0.113.1"]
    assert merged.is_unknown("aws:SourceVpc")
