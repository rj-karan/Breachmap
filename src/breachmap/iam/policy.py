"""Typed model of an AWS JSON policy document.

Parses the raw JSON AWS returns into statements with every string-or-list
field normalised to a list, so the matching and evaluation code never has
to special-case shapes. Element semantics follow the IAM JSON policy
element reference; each rule is tested from the doc sentence it implements.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Effect = Literal["Allow", "Deny"]
ConditionBlock = dict[str, dict[str, list[str]]]
"""operator -> condition key -> values, e.g. {"StringEquals": {"aws:username": ["bob"]}}."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Principal(_Strict):
    """A parsed ``Principal`` or ``NotPrincipal`` element.

    ``everyone`` is true for ``"Principal": "*"`` and ``{"AWS": "*"}``, which the
    docs call equivalent: "For anonymous users, the following elements are
    equivalent".
    """

    everyone: bool = False
    aws: list[str] = Field(default_factory=list)
    federated: list[str] = Field(default_factory=list)
    service: list[str] = Field(default_factory=list)
    canonical_user: list[str] = Field(default_factory=list)

    @classmethod
    def from_json(cls, raw: object) -> Principal:
        """Parse the raw element: ``"*"`` or a mapping of principal type to string-or-list."""
        if raw == "*":
            return cls(everyone=True)
        if not isinstance(raw, dict):
            msg = f"Principal must be '*' or an object, got {raw!r}"
            raise ValueError(msg)
        fields: dict[str, list[str]] = {}
        for key, attr in (
            ("AWS", "aws"),
            ("Federated", "federated"),
            ("Service", "service"),
            ("CanonicalUser", "canonical_user"),
        ):
            if key in raw:
                fields[attr] = _as_list(raw[key], f"Principal.{key}")
        unknown = set(raw) - {"AWS", "Federated", "Service", "CanonicalUser"}
        if unknown:
            msg = f"unknown Principal type(s) {sorted(unknown)}"
            raise ValueError(msg)
        everyone = "*" in fields.get("aws", [])
        if everyone:
            fields["aws"] = [a for a in fields["aws"] if a != "*"]
        return cls(everyone=everyone, **fields)


class Statement(_Strict):
    """One policy statement with normalised list fields.

    Exactly one of ``actions``/``not_actions`` is set ("Statements must
    include either an Action or NotAction element"). Resources are optional
    because role trust policies carry none (the role itself is the resource).
    """

    sid: str | None = None
    effect: Effect
    principal: Principal | None = None
    not_principal: Principal | None = None
    actions: list[str] | None = None
    not_actions: list[str] | None = None
    resources: list[str] | None = None
    not_resources: list[str] | None = None
    condition: ConditionBlock = Field(default_factory=dict)

    @model_validator(mode="after")
    def _exclusive_elements(self) -> Statement:
        if (self.actions is None) == (self.not_actions is None):
            msg = "statement needs exactly one of Action or NotAction"
            raise ValueError(msg)
        if self.resources is not None and self.not_resources is not None:
            msg = "statement cannot have both Resource and NotResource"
            raise ValueError(msg)
        if self.principal is not None and self.not_principal is not None:
            msg = "statement cannot have both Principal and NotPrincipal"
            raise ValueError(msg)
        return self

    @property
    def is_allow(self) -> bool:
        """True for ``"Effect": "Allow"``."""
        return self.effect == "Allow"

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Statement:
        """Parse one raw statement object."""
        known = {
            "Sid",
            "Effect",
            "Principal",
            "NotPrincipal",
            "Action",
            "NotAction",
            "Resource",
            "NotResource",
            "Condition",
        }
        unknown = set(raw) - known
        if unknown:
            msg = f"unknown statement element(s) {sorted(unknown)}"
            raise ValueError(msg)
        effect = raw.get("Effect")
        if effect not in ("Allow", "Deny"):
            msg = f"Effect must be Allow or Deny, got {effect!r}"
            raise ValueError(msg)
        return cls(
            sid=raw.get("Sid"),
            effect=effect,
            principal=Principal.from_json(raw["Principal"]) if "Principal" in raw else None,
            not_principal=(
                Principal.from_json(raw["NotPrincipal"]) if "NotPrincipal" in raw else None
            ),
            actions=_as_list(raw["Action"], "Action") if "Action" in raw else None,
            not_actions=_as_list(raw["NotAction"], "NotAction") if "NotAction" in raw else None,
            resources=_as_list(raw["Resource"], "Resource") if "Resource" in raw else None,
            not_resources=(
                _as_list(raw["NotResource"], "NotResource") if "NotResource" in raw else None
            ),
            condition=_parse_condition(raw.get("Condition", {})),
        )


class PolicyDocument(_Strict):
    """A whole policy: ``Version`` plus statements."""

    version: str | None = None
    id: str | None = None
    statements: list[Statement]

    @property
    def supports_variables(self) -> bool:
        """Policy variables need ``"Version": "2012-10-17"``.

        "If you don't include the Version element and set it to an appropriate
        version date, variables like ${aws:username} are treated as literal
        strings in the policy."
        """
        return self.version == "2012-10-17"

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> PolicyDocument:
        """Parse a raw policy object. ``Statement`` may be one object or a list."""
        unknown = set(raw) - {"Version", "Id", "Statement"}
        if unknown:
            msg = f"unknown policy element(s) {sorted(unknown)}"
            raise ValueError(msg)
        raw_statements = raw.get("Statement")
        if isinstance(raw_statements, dict):
            raw_statements = [raw_statements]
        if not isinstance(raw_statements, list):
            msg = "Statement must be an object or a list of objects"
            raise ValueError(msg)
        version = raw.get("Version")
        if version is not None and version not in ("2012-10-17", "2008-10-17"):
            msg = f"unsupported policy Version {version!r}"
            raise ValueError(msg)
        return cls(
            version=version,
            id=raw.get("Id"),
            statements=[Statement.from_json(s) for s in raw_statements],
        )


def _as_list(value: object, element: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    msg = f"{element} must be a string or a list of strings"
    raise ValueError(msg)


def _parse_condition(raw: object) -> ConditionBlock:
    if not isinstance(raw, dict):
        msg = "Condition must be an object"
        raise ValueError(msg)
    block: ConditionBlock = {}
    for operator, keys in raw.items():
        if not isinstance(keys, dict):
            msg = f"Condition operator {operator} must map keys to values"
            raise ValueError(msg)
        block[operator] = {
            key: _as_list(values, f"Condition.{operator}.{key}") for key, values in keys.items()
        }
    return block
