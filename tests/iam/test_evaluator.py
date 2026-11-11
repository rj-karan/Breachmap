"""Evaluation order, from 'How AWS enforcement code logic evaluates requests to allow or deny
access' and 'Cross-account policy evaluation logic'. Each test builds the smallest environment
that exercises one rule."""

from typing import Any

from breachmap.iam import PolicyDocument, RequestContext, RequestPrincipal
from breachmap.iam.environment import Environment, ResourcePolicy, RoleRecord
from breachmap.iam.evaluator import Request, evaluate

A = "111111111111"
B = "222222222222"
ROLE = f"arn:aws:iam::{A}:role/app"
OBJ = "arn:aws:s3:::data/file.csv"
BUCKET = "arn:aws:s3:::data"


def doc(*statements: dict[str, Any]) -> PolicyDocument:
    return PolicyDocument.parse({"Version": "2012-10-17", "Statement": list(statements)})


def allow(action: str = "s3:GetObject", resource: str = OBJ, **extra: Any) -> dict[str, Any]:
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def deny(action: str = "s3:GetObject", resource: str = OBJ, **extra: Any) -> dict[str, Any]:
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def trust(principal: dict[str, Any], **extra: Any) -> PolicyDocument:
    return doc({"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole", **extra})


def role(
    arn: str = ROLE,
    *policies: PolicyDocument,
    boundary: PolicyDocument | None = None,
    tags: dict[str, str] | None = None,
) -> RoleRecord:
    account = arn.split(":")[4]
    return RoleRecord(
        arn=arn,
        account_id=account,
        trust_policy=trust({"AWS": f"arn:aws:iam::{account}:root"}),
        identity_policies=list(policies),
        boundary=boundary,
        tags=tags or {},
    )


def env(
    *roles: RoleRecord,
    bucket_policy: PolicyDocument | None = None,
    scp_levels: dict[str, list[list[PolicyDocument]]] | None = None,
    kms: dict[str, PolicyDocument] | None = None,
    org_id: str | None = None,
) -> Environment:
    policies: dict[str, ResourcePolicy] = {
        r.arn: ResourcePolicy(
            kind="iam-trust", arn=r.arn, account_id=r.account_id, document=r.trust_policy
        )
        for r in roles
    }
    if bucket_policy is not None:
        policies[BUCKET] = ResourcePolicy(
            kind="s3", arn=BUCKET, account_id=A, document=bucket_policy
        )
    for arn, document in (kms or {}).items():
        policies[arn] = ResourcePolicy(kind="kms", arn=arn, account_id=A, document=document)
    return Environment(
        roles={r.arn: r for r in roles},
        resource_policies=policies,
        scp_levels=scp_levels or {},
        org_id=org_id,
        resource_accounts={BUCKET: A},
    )


def ask(  # noqa: PLR0917
    environment: Environment,
    principal: RequestPrincipal | str = ROLE,
    action: str = "s3:GetObject",
    resource: str = OBJ,
    context: RequestContext | None = None,
    session_policy: PolicyDocument | None = None,
) -> tuple[str, str | None]:
    if isinstance(principal, str):
        record = environment.role(principal)
        principal = RequestPrincipal.role(principal, record.tags if record else None)
    d = evaluate(
        Request(principal, action, resource, context or RequestContext(), session_policy),
        environment,
    )
    return d.outcome, d.reason


# ---- defaults and identity policies


def test_implicit_deny_by_default() -> None:
    """'By default, all requests are implicitly denied with the exception of the AWS account
    root user, which has full access.'"""
    assert ask(env(role())) == ("deny", "no_permission")
    assert ask(env(role()), RequestPrincipal.root(A)) == ("allow", None)


def test_identity_policy_allow() -> None:
    """'If any statement in any applicable identity-based policies allows the requested action,
    the code evaluation continues.'"""
    assert ask(env(role(ROLE, doc(allow())))) == ("allow", None)
    assert ask(env(role(ROLE, doc(allow(resource="arn:aws:s3:::other/*"))))) == (
        "deny",
        "no_permission",
    )


def test_explicit_deny_overrides_allow() -> None:
    """'An explicit deny overrides an explicit allow.'"""
    assert ask(env(role(ROLE, doc(allow(), deny())))) == ("deny", "explicit_deny")
    assert ask(env(role(ROLE, doc(allow()), doc(deny("s3:*", "*"))))) == ("deny", "explicit_deny")


def test_condition_failure_is_reported_as_such() -> None:
    cond: dict[str, Any] = {"Condition": {"StringEquals": {"aws:PrincipalTag/env": "prod"}}}
    assert ask(env(role(ROLE, doc(allow(**cond))))) == ("deny", "condition_mismatch")
    assert ask(env(role(ROLE, doc(allow(**cond)), tags={"env": "prod"}))) == ("allow", None)


def test_not_action_allows_everything_except_the_list() -> None:
    policy = doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert ask(env(role(ROLE, policy))) == ("allow", None)
    assert ask(env(role(ROLE, policy)), action="iam:CreateUser", resource="*") == (
        "deny",
        "no_permission",
    )


def test_not_action_deny_denies_everything_except_the_list() -> None:
    policy = doc(allow("*", "*"), {"Effect": "Deny", "NotAction": "s3:*", "Resource": "*"})
    assert ask(env(role(ROLE, policy))) == ("allow", None)
    assert ask(
        env(role(ROLE, policy)),
        action="kms:Decrypt",
        resource="arn:aws:kms:us-east-1:111111111111:key/k",
    ) == ("deny", "explicit_deny")


def test_not_resource() -> None:
    policy = doc(
        {"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::data/*"}
    )
    assert ask(env(role(ROLE, policy))) == ("deny", "no_permission")
    assert ask(env(role(ROLE, policy)), resource="arn:aws:s3:::other/x") == ("allow", None)


def test_policy_variable_in_resource() -> None:
    policy = doc(allow(resource="arn:aws:s3:::data/${aws:PrincipalTag/team}/*"))
    assert ask(
        env(role(ROLE, policy, tags={"team": "blue"})), resource="arn:aws:s3:::data/blue/x"
    ) == ("allow", None)
    assert ask(
        env(role(ROLE, policy, tags={"team": "blue"})), resource="arn:aws:s3:::data/red/x"
    ) == ("deny", "no_permission")
    assert ask(env(role(ROLE, policy)), resource="arn:aws:s3:::data/blue/x") == (
        "deny",
        "no_permission",
    )


# ---- SCPs


def test_scp_deny_wins_over_identity_allow() -> None:
    """'An explicit deny in the identity-based policy, an SCP, or an RCP overrides the allow.'"""
    scps = {A: [[doc(allow("*", "*"))], [doc(allow("*", "*")), doc(deny("s3:*", "*"))]]}
    assert ask(env(role(ROLE, doc(allow())), scp_levels=scps)) == ("deny", "scp")


def test_scp_must_allow_at_every_level() -> None:
    """'there must be an explicit Allow statement at every level from the root through each OU
    in the direct path to the account'"""
    full = doc(allow("*", "*"))
    ec2_only = doc(allow("ec2:*", "*"))
    assert ask(env(role(ROLE, doc(allow())), scp_levels={A: [[full], [full], [full]]})) == (
        "allow",
        None,
    )
    assert ask(env(role(ROLE, doc(allow())), scp_levels={A: [[full], [ec2_only], [full]]})) == (
        "deny",
        "scp",
    )
    assert ask(env(role(ROLE, doc(allow())), scp_levels={A: [[], [full]]})) == ("deny", "scp")


def test_scp_does_not_apply_to_accounts_outside_the_org() -> None:
    assert ask(env(role(ROLE, doc(allow())), scp_levels={B: [[doc(deny("*", "*"))]]})) == (
        "allow",
        None,
    )


def test_scp_condition_on_principal_arn() -> None:
    scp = doc(
        allow("*", "*"),
        deny(
            "secretsmanager:GetSecretValue",
            "*",
            Condition={"ArnNotEquals": {"aws:PrincipalArn": f"arn:aws:iam::{A}:role/reader"}},
        ),
    )
    secret = f"arn:aws:secretsmanager:us-east-1:{A}:secret:x"
    reader = role(
        f"arn:aws:iam::{A}:role/reader", doc(allow("secretsmanager:GetSecretValue", secret))
    )
    other = role(ROLE, doc(allow("secretsmanager:GetSecretValue", secret)))
    e = env(reader, other, scp_levels={A: [[scp]]})
    assert ask(e, reader.arn, "secretsmanager:GetSecretValue", secret) == ("allow", None)
    assert ask(e, other.arn, "secretsmanager:GetSecretValue", secret) == ("deny", "scp")


# ---- resource-based policies, same account


def test_same_account_resource_policy_allow_is_sufficient_when_it_names_the_role() -> None:
    """'For most resources, you only need an explicit Allow for the principal in either an
    identity-based policy or a resource-based policy to grant access.'"""
    bucket = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": ROLE},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    assert ask(env(role(), bucket_policy=bucket)) == ("allow", None)


def test_same_account_resource_policy_naming_the_account_still_needs_identity_allow() -> None:
    """An account entry 'delegates authority to the account': the identity policy must allow."""
    bucket = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": A},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    assert ask(env(role(), bucket_policy=bucket)) == ("deny", "no_permission")
    assert ask(env(role(ROLE, doc(allow())), bucket_policy=bucket)) == ("allow", None)


def test_resource_policy_explicit_deny_beats_identity_allow() -> None:
    """'An explicit deny in either of these policies overrides the allow.'"""
    bucket = doc(
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
            "Condition": {"ArnNotLike": {"aws:PrincipalArn": f"arn:aws:iam::{A}:role/deploy-*"}},
        }
    )
    assert ask(env(role(ROLE, doc(allow())), bucket_policy=bucket)) == ("deny", "explicit_deny")
    ok = role(f"arn:aws:iam::{A}:role/deploy-x", doc(allow()))
    assert ask(env(ok, bucket_policy=bucket), ok.arn) == ("allow", None)


def test_not_principal_deny() -> None:
    bucket = doc(
        {
            "Effect": "Deny",
            "NotPrincipal": {"AWS": ROLE},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    other = role(f"arn:aws:iam::{A}:role/other", doc(allow()))
    assert ask(env(role(ROLE, doc(allow())), other, bucket_policy=bucket)) == ("allow", None)
    assert ask(env(role(ROLE, doc(allow())), other, bucket_policy=bucket), other.arn) == (
        "deny",
        "explicit_deny",
    )


def test_kms_key_policy_must_explicitly_allow() -> None:
    """'IAM role trust policies and KMS key policies are exceptions to this logic, because they
    must explicitly allow access for principals.' The root statement delegates to IAM."""
    key = f"arn:aws:kms:us-east-1:{A}:key/abc"
    delegating = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{A}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    )
    direct = doc(
        {"Effect": "Allow", "Principal": {"AWS": ROLE}, "Action": "kms:Decrypt", "Resource": "*"}
    )
    nothing = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{A}:role/other"},
            "Action": "kms:*",
            "Resource": "*",
        }
    )
    with_identity = role(ROLE, doc(allow("kms:Decrypt", key)))
    assert ask(env(with_identity, kms={key: delegating}), action="kms:Decrypt", resource=key) == (
        "allow",
        None,
    )
    assert ask(env(role(), kms={key: delegating}), action="kms:Decrypt", resource=key) == (
        "deny",
        "no_permission",
    )
    assert ask(env(role(), kms={key: direct}), action="kms:Decrypt", resource=key) == (
        "allow",
        None,
    )
    assert ask(env(with_identity, kms={key: nothing}), action="kms:Decrypt", resource=key) == (
        "deny",
        "resource_policy",
    )


def test_kms_via_service_condition() -> None:
    key = f"arn:aws:kms:us-east-1:{A}:key/abc"
    delegating = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{A}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    )
    via = doc(
        allow(
            "kms:Decrypt",
            key,
            Condition={
                "StringEquals": {"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"}
            },
        )
    )
    e = env(role(ROLE, via), kms={key: delegating})
    assert ask(e, action="kms:Decrypt", resource=key) == ("deny", "condition_mismatch")
    ctx = RequestContext({"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"})
    assert ask(e, action="kms:Decrypt", resource=key, context=ctx) == ("allow", None)


# ---- permissions boundary and session policy


def test_boundary_is_an_intersection() -> None:
    """'the resulting permissions are the intersection of the two categories'"""
    s3_only = doc(allow("s3:*", "*"))
    key = f"arn:aws:kms:us-east-1:{A}:key/abc"
    r = role(ROLE, doc(allow(), allow("kms:Decrypt", key)), boundary=s3_only)
    delegating = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{A}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }
    )
    e = env(r, kms={key: delegating})
    assert ask(e) == ("allow", None)
    assert ask(e, action="kms:Decrypt", resource=key) == ("deny", "permission_boundary")


def test_boundary_allows_but_identity_does_not() -> None:
    assert ask(env(role(ROLE, boundary=doc(allow("s3:*", "*"))))) == ("deny", "no_permission")


def test_boundary_limits_resource_policy_grant_to_role_arn() -> None:
    """'Resource-based policies that grant permissions to an IAM role ARN are limited by an
    implicit deny in a permissions boundary or session policy.'"""
    bucket = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": ROLE},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    r = role(ROLE, boundary=doc(allow("kms:*", "*")))
    assert ask(env(r, bucket_policy=bucket)) == ("deny", "permission_boundary")


def test_boundary_explicit_deny() -> None:
    r = role(ROLE, doc(allow()), boundary=doc(allow("*", "*"), deny()))
    assert ask(env(r)) == ("deny", "explicit_deny")


def test_session_policy_must_allow() -> None:
    """'If a session policy is present and does not allow the requested action, then the request
    is implicitly denied.'"""
    e = env(role(ROLE, doc(allow())))
    assert ask(e, session_policy=doc(allow("s3:ListBucket", "*"))) == ("deny", "session_policy")
    assert ask(e, session_policy=doc(allow())) == ("allow", None)
    assert ask(e, session_policy=doc(allow("*", "*"), deny())) == ("deny", "explicit_deny")


# ---- cross-account


def test_cross_account_needs_both_sides() -> None:
    """'AWS allows the request only if both account policy evaluations allow the request.'"""
    partner = f"arn:aws:iam::{B}:role/partner"
    bucket = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": partner},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    with_identity = role(partner, doc(allow()))
    without = role(partner)
    assert ask(env(with_identity, bucket_policy=bucket), partner) == ("allow", None)
    assert ask(env(without, bucket_policy=bucket), partner) == ("deny", "no_permission")
    assert ask(env(with_identity), partner) == ("deny", "resource_policy")
    unrelated = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": ROLE},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    assert ask(env(with_identity, bucket_policy=unrelated), partner) == ("deny", "resource_policy")


def test_cross_account_scps_apply_to_the_principals_account() -> None:
    partner = f"arn:aws:iam::{B}:role/partner"
    bucket = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": B},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    e = env(
        role(partner, doc(allow())),
        bucket_policy=bucket,
        scp_levels={B: [[doc(allow("ec2:*", "*"))]]},
    )
    assert ask(e, partner) == ("deny", "scp")


# ---- role assumption (trust policies)


def test_assume_role_requires_trust_policy_allow() -> None:
    """A trust policy 'must explicitly allow access for principals'."""
    source = role(ROLE, doc(allow("sts:AssumeRole", f"arn:aws:iam::{A}:role/target")))
    target = RoleRecord(
        arn=f"arn:aws:iam::{A}:role/target", account_id=A, trust_policy=trust({"AWS": ROLE})
    )
    locked = RoleRecord(
        arn=f"arn:aws:iam::{A}:role/locked",
        account_id=A,
        trust_policy=trust({"AWS": f"arn:aws:iam::{A}:role/other"}),
    )
    e = env(source, target, locked)
    assert ask(e, action="sts:AssumeRole", resource=target.arn) == ("allow", None)
    assert ask(e, action="sts:AssumeRole", resource=locked.arn) == ("deny", "trust_mismatch")


def test_assume_role_via_account_root_trust_needs_identity_allow() -> None:
    target = RoleRecord(
        arn=f"arn:aws:iam::{A}:role/target",
        account_id=A,
        trust_policy=trust({"AWS": f"arn:aws:iam::{A}:root"}),
    )
    assert ask(env(role(), target), action="sts:AssumeRole", resource=target.arn) == (
        "deny",
        "no_permission",
    )
    assert ask(
        env(role(ROLE, doc(allow("sts:AssumeRole", target.arn))), target),
        action="sts:AssumeRole",
        resource=target.arn,
    ) == ("allow", None)


def test_assume_role_trust_condition() -> None:
    mfa = trust({"AWS": ROLE}, Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})
    target = RoleRecord(arn=f"arn:aws:iam::{A}:role/target", account_id=A, trust_policy=mfa)
    e = env(role(ROLE, doc(allow("sts:AssumeRole", target.arn))), target)
    assert ask(e, action="sts:AssumeRole", resource=target.arn) == ("deny", "condition_mismatch")
    ctx = RequestContext({"aws:MultiFactorAuthPresent": "true"})
    assert ask(e, action="sts:AssumeRole", resource=target.arn, context=ctx) == ("allow", None)


def test_assume_role_without_known_trust_policy_is_denied() -> None:
    e = env(role(ROLE, doc(allow("sts:AssumeRole", "*"))))
    assert ask(e, action="sts:AssumeRole", resource=f"arn:aws:iam::{A}:role/ghost") == (
        "deny",
        "resource_policy",
    )


def test_federated_caller_is_decided_by_the_trust_policy_alone() -> None:
    provider = f"arn:aws:iam::{A}:oidc-provider/idp.example"
    target = RoleRecord(
        arn=f"arn:aws:iam::{A}:role/target",
        account_id=A,
        trust_policy=doc(
            {
                "Effect": "Allow",
                "Principal": {"Federated": provider},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"idp.example:aud": "sts.amazonaws.com"}},
            }
        ),
    )
    e = env(target)
    caller = RequestPrincipal.federated(provider)
    ok = RequestContext({"idp.example:aud": "sts.amazonaws.com"})
    assert ask(e, caller, "sts:AssumeRoleWithWebIdentity", target.arn, ok) == ("allow", None)
    assert ask(e, caller, "sts:AssumeRoleWithWebIdentity", target.arn) == (
        "deny",
        "condition_mismatch",
    )
    other = RequestPrincipal.federated(f"arn:aws:iam::{A}:oidc-provider/other")
    assert ask(e, other, "sts:AssumeRoleWithWebIdentity", target.arn, ok) == (
        "deny",
        "trust_mismatch",
    )


# ---- unknown and evidence


def test_unknown_context_key_gives_unknown_outcome() -> None:
    ip = doc(allow(Condition={"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}))
    e = env(role(ROLE, ip))
    unknown = RequestContext(unknown=["aws:SourceIp"])
    d = evaluate(Request(RequestPrincipal.role(ROLE), "s3:GetObject", OBJ, unknown), e)
    assert d.outcome == "unknown"
    assert d.unknown_keys == ("aws:sourceip",)
    assert not d.allowed
    assert ask(e, context=RequestContext({"aws:SourceIp": "203.0.113.9"})) == ("allow", None)
    assert ask(e, context=RequestContext({"aws:SourceIp": "198.51.100.9"})) == (
        "deny",
        "condition_mismatch",
    )


def test_unknown_deny_makes_the_outcome_unknown() -> None:
    policy = doc(allow(), deny(Condition={"NotIpAddress": {"aws:SourceIp": "203.0.113.0/24"}}))
    d = evaluate(
        Request(
            RequestPrincipal.role(ROLE),
            "s3:GetObject",
            OBJ,
            RequestContext(unknown=["aws:SourceIp"]),
        ),
        env(role(ROLE, policy)),
    )
    assert d.outcome == "unknown"


def test_unknown_in_scp_boundary_session_and_resource() -> None:
    cond: dict[str, Any] = {"Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}
    unknown = RequestContext(unknown=["aws:SourceIp"])
    assert (
        ask(
            env(role(ROLE, doc(allow())), scp_levels={A: [[doc(allow("*", "*", **cond))]]}),
            context=unknown,
        )[0]
        == "unknown"
    )
    assert (
        ask(env(role(ROLE, doc(allow()), boundary=doc(allow("*", "*", **cond)))), context=unknown)[
            0
        ]
        == "unknown"
    )
    assert (
        ask(
            env(role(ROLE, doc(allow()))),
            context=unknown,
            session_policy=doc(allow("*", "*", **cond)),
        )[0]
        == "unknown"
    )
    bucket = doc(
        {
            "Effect": "Allow",
            "Principal": {"AWS": ROLE},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::data/*",
            **cond,
        }
    )
    assert ask(env(role(), bucket_policy=bucket), context=unknown)[0] == "unknown"


def test_decision_carries_matched_statements_as_evidence() -> None:
    policy = doc({"Sid": "ReadData", "Effect": "Allow", "Action": "s3:GetObject", "Resource": OBJ})
    d = evaluate(Request(RequestPrincipal.role(ROLE), "s3:GetObject", OBJ), env(role(ROLE, policy)))
    assert d.allowed
    assert [(m.source, m.sid, m.effect) for m in d.matched] == [("identity", "ReadData", "Allow")]
    bucket = doc(
        {
            "Sid": "DenyAll",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "arn:aws:s3:::data/*",
        }
    )
    d = evaluate(
        Request(RequestPrincipal.role(ROLE), "s3:GetObject", OBJ),
        env(role(ROLE, policy), bucket_policy=bucket),
    )
    assert d.reason == "explicit_deny"
    assert {(m.source, m.sid) for m in d.matched} == {
        ("identity", "ReadData"),
        ("resource", "DenyAll"),
    }
    assert d.matched[0].policy_arn is None or d.matched[0].policy_arn == BUCKET


def test_derived_context_keys() -> None:
    policy = doc(
        allow(
            Condition={
                "StringEquals": {
                    "aws:PrincipalOrgID": "o-lab",
                    "aws:ResourceAccount": A,
                    "aws:PrincipalType": "AssumedRole",
                }
            }
        )
    )
    assert ask(env(role(ROLE, policy), org_id="o-lab")) == ("allow", None)
    assert ask(env(role(ROLE, policy), org_id="o-other")) == ("deny", "condition_mismatch")
