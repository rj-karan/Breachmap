"""AWS policy evaluation logic.

Implements "How AWS enforcement code logic evaluates requests to allow or
deny access" and "Cross-account policy evaluation logic". The steps, in
order, are the methods of ``_Evaluation`` below:

1. an explicit deny anywhere wins;
2. SCPs must allow at every organization level of the principal's account;
3. a resource-based policy that names the principal can allow on its own
   within the account, still limited by boundary and session policy for roles;
   IAM role trust policies and KMS key policies must explicitly allow, and a
   cross-account request needs the resource policy to allow;
4. identity-based policies must allow;
5. the permissions boundary must allow;
6. the session policy must allow;
7. otherwise the request is implicitly denied.

Every decision carries the statements that produced it; that is the
evidence an edge needs before it may enter the graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from breachmap.iam.conditions import Match, evaluate_condition
from breachmap.iam.context import PrincipalKind, RequestContext, RequestPrincipal
from breachmap.iam.environment import Environment, ResourcePolicy
from breachmap.iam.matching import match_action, match_arn, match_principal, substitute_variables
from breachmap.iam.policy import PolicyDocument, Statement

Outcome = Literal["allow", "deny", "unknown"]
Reason = Literal[
    "explicit_deny",
    "scp",
    "permission_boundary",
    "session_policy",
    "resource_policy",
    "condition_mismatch",
    "no_permission",
    "trust_mismatch",
]
Source = Literal["identity", "resource", "scp", "boundary", "session", "trust"]

_EXPLICIT_RESOURCE_KINDS = {"kms", "iam-trust"}
_STS_ASSUME = ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml")
_PRINCIPAL_TYPE = {
    PrincipalKind.ROOT: "Account",
    PrincipalKind.USER: "User",
    PrincipalKind.ROLE: "AssumedRole",
    PrincipalKind.FEDERATED: "FederatedUser",
    PrincipalKind.SERVICE: "Service",
    PrincipalKind.ANONYMOUS: "Anonymous",
}


@dataclass(frozen=True)
class Request:
    """One authorization question."""

    principal: RequestPrincipal
    action: str
    resource: str
    context: RequestContext = field(default_factory=RequestContext)
    session_policy: PolicyDocument | None = None


@dataclass(frozen=True)
class MatchedStatement:
    """A statement that applied to the request (evidence)."""

    source: Source
    policy_arn: str | None
    sid: str | None
    effect: Literal["Allow", "Deny"]
    match: Match


@dataclass(frozen=True)
class Decision:
    """The answer, the first rule that blocked, and the evidence."""

    outcome: Outcome
    reason: Reason | None
    matched: tuple[MatchedStatement, ...]
    unknown_keys: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        """True only for a definite allow."""
        return self.outcome == "allow"


@dataclass
class _SetResult:
    """How one set of policies sees the request."""

    allow: Match = Match.NO_MATCH
    deny: Match = Match.NO_MATCH
    matched: list[MatchedStatement] = field(default_factory=list)
    near_miss: bool = False  # an Allow matched everything but its condition
    direct: bool = False  # an Allow named this principal itself, not just its account


def evaluate(request: Request, env: Environment) -> Decision:
    """Evaluate ``request`` against ``env`` and return a ``Decision`` with evidence."""
    return _Evaluation(request, env).decide()


class _Evaluation:
    """All policy sets for one request, then the ordered decision steps."""

    def __init__(self, request: Request, env: Environment) -> None:
        self.request = request
        self.principal = request.principal
        self.context = _enrich_context(request, env)
        role = env.role(self.principal.arn) if self.principal.arn else None
        self.resource_policy = env.resource_policy_for(request.resource)
        owner = env.resource_account(request.resource)
        self.same_account = (
            self.principal.account_id is not None and self.principal.account_id == owner
        )

        self.identity = self._set(
            [(p, "identity", None) for p in (role.identity_policies if role else [])]
        )
        self.boundary = (
            self._set([(role.boundary, "boundary", None)]) if role and role.boundary else None
        )
        self.session = (
            self._set([(request.session_policy, "session", None)])
            if request.session_policy
            else None
        )
        rp = self.resource_policy
        self.resource = (
            self._set([(rp.document, _source_for(rp), rp.arn)], resource_based=True) if rp else None
        )
        in_org = self.principal.kind in (PrincipalKind.ROLE, PrincipalKind.USER)
        self.scp_levels = (
            [
                self._set([(d, "scp", None) for d in level])
                for level in env.scps_for(self.principal.account_id)
            ]
            if in_org and self.principal.account_id
            else []
        )
        self.sets = [
            s
            for s in (self.identity, self.boundary, self.session, self.resource, *self.scp_levels)
            if s is not None
        ]

    # ----------------------------------------------------------------- the ordered steps

    def decide(self) -> Decision:
        """Run the steps in AWS order; the first that blocks decides."""
        steps = (
            self._explicit_deny,
            self._scps,
            self._resource_based,
            self._identity_based,
            self._boundary,
            self._session_policy,
        )
        for step in steps:
            blocked = step()
            if blocked is not None:
                return blocked
        return self._final()

    def _explicit_deny(self) -> Decision | None:
        """Step 1: an explicit deny anywhere wins.

        "If the enforcement code finds even one explicit deny that applies, the
        enforcement code returns a final decision of Deny."
        """
        if any(s.deny is Match.MATCH for s in self.scp_levels):
            return self._deny("scp")
        if any(s.deny is Match.MATCH for s in self._account_sets()):
            return self._deny("explicit_deny")
        return None

    def _scps(self) -> Decision | None:
        """Step 2: SCPs must allow at every level from the root to the account.

        "If the enforcement code does not find any applicable Allow statements in
        the SCPs, the enforcement code returns a final decision of Deny."
        """
        if any(s.allow is Match.NO_MATCH for s in self.scp_levels):
            return self._deny("scp")
        return None

    def _resource_based(self) -> Decision | None:
        """Step 3: trust and KMS key policies must allow; cross-account needs the resource side.

        "IAM role trust policies and KMS key policies are exceptions to this logic,
        because they must explicitly allow access for principals." and "The request
        is allowed only if both evaluations return a decision of Allow."
        """
        rp, result = self.resource_policy, self.resource
        must_allow = (
            rp is not None and rp.kind in _EXPLICIT_RESOURCE_KINDS
        ) or not self.same_account
        if result is not None and result.allow is Match.NO_MATCH and must_allow:
            return self._deny(_resource_reason(result, rp))
        if result is None and (not self.same_account or _is_sts_assume(self.request.action)):
            return self._deny("resource_policy")
        return None

    def _identity_based(self) -> Decision | None:
        """Step 4: identity-based policies must allow.

        "If there are no identity-based policies or no statements in identity-based
        policies that allow the requested action, then the request is implicitly
        denied." Skipped when a same-account resource policy grants the principal
        directly; the root user and federated callers have no identity policies.
        """
        if self._direct_grant() or self.principal.kind in (
            PrincipalKind.ROOT,
            PrincipalKind.FEDERATED,
        ):
            return None
        if self.identity.allow is Match.NO_MATCH:
            return self._deny("condition_mismatch" if self.identity.near_miss else "no_permission")
        return None

    def _boundary(self) -> Decision | None:
        """Step 5: the permissions boundary must allow.

        "If the policy that is used to set the permissions boundary does not allow
        the requested action, then the request is implicitly denied." It applies to
        role sessions even when a resource policy names the role ARN.
        """
        if self.boundary is not None and self.boundary.allow is Match.NO_MATCH:
            return self._deny("permission_boundary")
        return None

    def _session_policy(self) -> Decision | None:
        """Step 6: the session policy must allow.

        "If a session policy is present and does not allow the requested action,
        then the request is implicitly denied."
        """
        if self.session is not None and self.session.allow is Match.NO_MATCH:
            return self._deny("session_policy")
        return None

    def _final(self) -> Decision:
        """Nothing blocked. Allow unless a deciding part depends on an unknowable key."""
        resource_unknown = self.resource is not None and self.resource.allow is Match.UNKNOWN
        identity_unknown = not self._direct_grant() and self.identity.allow is Match.UNKNOWN
        uncertain = (
            any(s.deny is Match.UNKNOWN for s in self.sets)
            or any(s.allow is Match.UNKNOWN for s in self.scp_levels)
            or resource_unknown
            or identity_unknown
            or (self.boundary is not None and self.boundary.allow is Match.UNKNOWN)
            or (self.session is not None and self.session.allow is Match.UNKNOWN)
        )
        return Decision("unknown" if uncertain else "allow", None, self._matched(), self._unknown())

    # ----------------------------------------------------------------- helpers

    def _direct_grant(self) -> bool:
        """Whether a same-account resource policy names this principal itself.

        "If a resource-based policy grants permission directly to the IAM user or
        the session principal that is making the request, then an implicit deny in
        an identity-based policy ... does not impact the final decision."
        """
        return (
            self.resource is not None
            and self.resource.direct
            and self.same_account
            and self.resource.allow is not Match.NO_MATCH
        )

    def _account_sets(self) -> list[_SetResult]:
        return [
            s for s in (self.identity, self.boundary, self.session, self.resource) if s is not None
        ]

    def _deny(self, reason: Reason) -> Decision:
        return Decision("deny", reason, self._matched(), self._unknown())

    def _matched(self) -> tuple[MatchedStatement, ...]:
        return tuple(m for s in self.sets for m in s.matched)

    def _unknown(self) -> tuple[str, ...]:
        return tuple(sorted(self.context.unknown_keys()))

    def _set(
        self,
        policies: list[tuple[PolicyDocument, Source, str | None]],
        *,
        resource_based: bool = False,
    ) -> _SetResult:
        result = _SetResult()
        for document, source, arn in policies:
            for stmt in document.statements:
                outcome = self._statement(stmt, document, resource_based, result)
                if outcome is Match.NO_MATCH:
                    continue
                result.matched.append(MatchedStatement(source, arn, stmt.sid, stmt.effect, outcome))
                if stmt.is_allow:
                    result.allow = _stronger(result.allow, outcome)
                else:
                    result.deny = _stronger(result.deny, outcome)
        return result

    def _statement(
        self, stmt: Statement, document: PolicyDocument, resource_based: bool, result: _SetResult
    ) -> Match:
        if not _action_applies(stmt, self.request.action):
            return Match.NO_MATCH
        if not self._resource_applies(stmt, document, resource_based):
            return Match.NO_MATCH
        if resource_based:
            applies, direct = _principal_applies(stmt, self.principal)
            if not applies:
                return Match.NO_MATCH
            if stmt.is_allow and direct:
                result.direct = True
        condition = evaluate_condition(
            stmt.condition, self.context, variables=document.supports_variables
        )
        if condition is Match.NO_MATCH and stmt.is_allow:
            result.near_miss = True
        return condition

    def _resource_applies(
        self, stmt: Statement, document: PolicyDocument, resource_based: bool
    ) -> bool:
        """Match ``Resource``/``NotResource`` after variable substitution.

        An absent element means the resource the policy is attached to (trust
        policies carry no Resource element).
        """
        patterns = stmt.resources if stmt.resources is not None else stmt.not_resources
        if patterns is None:
            return resource_based
        resolved = [
            r
            for r in (
                substitute_variables(p, self.context, enabled=document.supports_variables)
                for p in patterns
            )
            if r is not None
        ]
        hit = any(match_arn(p, self.request.resource) for p in resolved)
        return hit if stmt.resources is not None else not hit


def _action_applies(stmt: Statement, action: str) -> bool:
    """``Action`` lists what applies; ``NotAction`` applies to everything except the list."""
    if stmt.actions is not None:
        return any(match_action(p, action) for p in stmt.actions)
    return not any(match_action(p, action) for p in stmt.not_actions or [])


def _principal_applies(stmt: Statement, principal: RequestPrincipal) -> tuple[bool, bool]:
    """Returns (applies, named_directly).

    "named directly" is true when the element names the principal's own ARN or
    session rather than its account: an account entry "delegates authority to
    the account" and still needs an identity policy.
    """
    if stmt.principal is not None:
        if not match_principal(stmt.principal, principal):
            return False, False
        return True, _names_directly(stmt, principal)
    if stmt.not_principal is not None:
        return not match_principal(stmt.not_principal, principal), False
    return False, False


def _names_directly(stmt: Statement, principal: RequestPrincipal) -> bool:
    element = stmt.principal
    if element is None or element.everyone:
        return element is not None
    if principal.kind is PrincipalKind.FEDERATED:
        return principal.provider_arn in element.federated
    if principal.kind is PrincipalKind.SERVICE:
        return principal.service_name in element.service
    named = {principal.arn, principal.session_arn} - {None}
    return any(entry in named for entry in element.aws)


def _resource_reason(result: _SetResult, policy: ResourcePolicy | None) -> Reason:
    if result.near_miss:
        return "condition_mismatch"
    if policy is not None and policy.kind == "iam-trust":
        return "trust_mismatch"
    return "resource_policy"


def _source_for(policy: ResourcePolicy) -> Source:
    return "trust" if policy.kind == "iam-trust" else "resource"


def _is_sts_assume(action: str) -> bool:
    return action.lower() in _STS_ASSUME


def _stronger(current: Match, new: Match) -> Match:
    order = {Match.NO_MATCH: 0, Match.UNKNOWN: 1, Match.MATCH: 2}
    return new if order[new] > order[current] else current


def _enrich_context(request: Request, env: Environment) -> RequestContext:
    """Add the global condition keys AWS derives from the principal and the resource.

    Values the request supplies win over derived ones.
    """
    p = request.principal
    derived: dict[str, str | list[str]] = {"aws:PrincipalType": _PRINCIPAL_TYPE[p.kind]}
    if p.arn:
        derived["aws:PrincipalArn"] = p.arn
    if p.account_id:
        derived["aws:PrincipalAccount"] = p.account_id
        if env.org_id:
            derived["aws:PrincipalOrgID"] = env.org_id
    for key, value in p.tags.items():
        derived[f"aws:PrincipalTag/{key}"] = value
    owner = env.resource_account(request.resource)
    if owner:
        derived["aws:ResourceAccount"] = owner
    derived.update(dict(request.context.items()))
    return RequestContext(derived, request.context.unknown_keys())
