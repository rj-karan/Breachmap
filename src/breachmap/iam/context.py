"""Who is asking, and the request context keys available to conditions."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PrincipalKind(StrEnum):
    """The kind of principal making a request."""

    ROOT = "root"
    USER = "user"
    ROLE = "role"
    FEDERATED = "federated"
    SERVICE = "service"
    ANONYMOUS = "anonymous"


class RequestPrincipal(BaseModel):
    """The requester, as far as policy matching needs to know.

    A role principal represents the role session: the docs say that when a
    role is named in a resource policy "the principal that makes the request
    is the IAM role session". ``arn`` is the role ARN; ``session_arn`` is the
    ``arn:aws:sts::...:assumed-role/name/session`` form when known.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: PrincipalKind
    arn: str | None = Field(default=None, description="IAM ARN of the user or role, or root ARN")
    account_id: str | None = None
    session_arn: str | None = None
    provider_arn: str | None = Field(default=None, description="OIDC/SAML provider for FEDERATED")
    service_name: str | None = Field(default=None, description="e.g. ecs.amazonaws.com for SERVICE")
    tags: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _shape(self) -> RequestPrincipal:
        needs_arn = {PrincipalKind.ROOT, PrincipalKind.USER, PrincipalKind.ROLE}
        if self.kind in needs_arn and (self.arn is None or self.account_id is None):
            msg = f"{self.kind} principal needs arn and account_id"
            raise ValueError(msg)
        if self.kind is PrincipalKind.FEDERATED and self.provider_arn is None:
            msg = "federated principal needs provider_arn"
            raise ValueError(msg)
        if self.kind is PrincipalKind.SERVICE and self.service_name is None:
            msg = "service principal needs service_name"
            raise ValueError(msg)
        return self

    @classmethod
    def role(cls, arn: str, tags: Mapping[str, str] | None = None) -> RequestPrincipal:
        """Build a role-session principal from a role ARN."""
        return cls(
            kind=PrincipalKind.ROLE, arn=arn, account_id=_account_of(arn), tags=dict(tags or {})
        )

    @classmethod
    def user(cls, arn: str, tags: Mapping[str, str] | None = None) -> RequestPrincipal:
        """Build an IAM user principal from a user ARN."""
        return cls(
            kind=PrincipalKind.USER, arn=arn, account_id=_account_of(arn), tags=dict(tags or {})
        )

    @classmethod
    def root(cls, account_id: str) -> RequestPrincipal:
        """Build the account root principal."""
        return cls(
            kind=PrincipalKind.ROOT, arn=f"arn:aws:iam::{account_id}:root", account_id=account_id
        )

    @classmethod
    def federated(cls, provider_arn: str) -> RequestPrincipal:
        """Build an OIDC/SAML federated caller (before any role is assumed)."""
        return cls(kind=PrincipalKind.FEDERATED, provider_arn=provider_arn)

    @classmethod
    def service(cls, service_name: str) -> RequestPrincipal:
        """Build an AWS service principal."""
        return cls(kind=PrincipalKind.SERVICE, service_name=service_name)


class RequestContext:
    """Condition context keys for one request.

    Keys are case-insensitive ("Key names are case-insensitive. For example,
    aws:CurrentTime is equivalent to AWS:currenttime"). Every key holds a list
    of values; single-valued keys hold one. Keys in ``unknown`` are ones whose
    value exists in AWS but cannot be known offline (a hosted runner's source
    IP); conditions on them yield an *unknown* result rather than false.
    """

    __slots__ = ("_unknown", "_values")

    def __init__(
        self,
        values: Mapping[str, str | Iterable[str]] | None = None,
        unknown: Iterable[str] = (),
    ) -> None:
        """Create a context; ``values`` may map keys to a string or an iterable of strings."""
        self._values: dict[str, list[str]] = {}
        for key, value in (values or {}).items():
            self._values[key.lower()] = [value] if isinstance(value, str) else list(value)
        self._unknown = {k.lower() for k in unknown}

    def get(self, key: str) -> list[str] | None:
        """Values for ``key``, or None when the key is absent from the request."""
        return self._values.get(key.lower())

    def single(self, key: str) -> str | None:
        """The value of a single-valued key, or None when absent or multi-valued."""
        values = self.get(key)
        if values is None or len(values) != 1:
            return None
        return values[0]

    def is_unknown(self, key: str) -> bool:
        """True when the key's value exists but is not knowable offline."""
        return key.lower() in self._unknown

    def with_values(self, extra: Mapping[str, str | Iterable[str]]) -> RequestContext:
        """A copy with ``extra`` merged in (overriding on key collision)."""
        merged: dict[str, str | Iterable[str]] = dict(self._values)
        merged.update(extra)
        return RequestContext(merged, self._unknown)

    def keys(self) -> set[str]:
        """Lower-cased key names present in the context."""
        return set(self._values)

    def unknown_keys(self) -> set[str]:
        """Lower-cased names of keys whose value is not knowable offline."""
        return set(self._unknown)

    def items(self) -> list[tuple[str, list[str]]]:
        """(key, values) pairs."""
        return [(k, list(v)) for k, v in self._values.items()]


def _account_of(arn: str) -> str:
    parts = arn.split(":", 5)
    if len(parts) < 6 or not parts[4].isdigit() or len(parts[4]) != 12:
        msg = f"ARN {arn!r} does not carry a 12-digit account id"
        raise ValueError(msg)
    return parts[4]
