"""Build an evaluator ``Environment`` from a lab fixture."""

from __future__ import annotations

from breachmap.iam.environment import Environment, ResourcePolicy, RoleRecord
from breachmap.iam.policy import PolicyDocument
from breachmap.lab.fixtures import LabFixture, Organization


def environment_from_fixture(fixture: LabFixture) -> Environment:
    """Parse every policy in the fixture into an ``Environment``."""
    managed = {p.arn: PolicyDocument.parse(p.document) for p in fixture.aws.managed_policies}
    roles: dict[str, RoleRecord] = {}
    policies: dict[str, ResourcePolicy] = {}
    for role in fixture.aws.roles:
        identity = [
            *(managed[arn] for arn in role.attached_policy_arns if arn in managed),
            *(PolicyDocument.parse(doc) for doc in role.inline_policies.values()),
        ]
        boundary = managed[role.permissions_boundary_arn] if role.permissions_boundary_arn else None
        trust = PolicyDocument.parse(role.trust_policy)
        roles[role.arn] = RoleRecord(
            arn=role.arn,
            account_id=role.account_id,
            trust_policy=trust,
            identity_policies=identity,
            boundary=boundary,
            tags=role.tags,
        )
        policies[role.arn] = ResourcePolicy(
            kind="iam-trust", arn=role.arn, account_id=role.account_id, document=trust
        )
    resource_accounts: dict[str, str] = {}
    for bucket in fixture.aws.buckets:
        resource_accounts[bucket.arn] = bucket.account_id
        if bucket.bucket_policy is not None:
            policies[bucket.arn] = ResourcePolicy(
                kind="s3",
                arn=bucket.arn,
                account_id=bucket.account_id,
                document=PolicyDocument.parse(bucket.bucket_policy),
            )
    for secret in fixture.aws.secrets:
        if secret.resource_policy is not None:
            policies[secret.arn] = ResourcePolicy(
                kind="secretsmanager",
                arn=secret.arn,
                account_id=secret.account_id,
                document=PolicyDocument.parse(secret.resource_policy),
            )
    for key in fixture.aws.kms_keys:
        policies[key.arn] = ResourcePolicy(
            kind="kms",
            arn=key.arn,
            account_id=key.account_id,
            document=PolicyDocument.parse(key.key_policy),
        )
    return Environment(
        roles=roles,
        resource_policies=policies,
        scp_levels=_scp_levels(fixture.aws.organization),
        org_id=fixture.aws.organization.id,
        resource_accounts=resource_accounts,
    )


def _scp_levels(org: Organization) -> dict[str, list[list[PolicyDocument]]]:
    """For each account, the SCP documents at every level from the root down to it.

    "For a permission to be allowed for a specific account, there must be an
    explicit Allow statement at every level from the root through each OU in
    the direct path to the account (including the target account itself)."
    """
    docs = {s.id: PolicyDocument.parse(s.document) for s in org.scps}
    units = {ou.id: ou for ou in org.org_units}
    levels: dict[str, list[list[PolicyDocument]]] = {}
    for account in org.accounts:
        chain: list[list[PolicyDocument]] = [[docs[s] for s in account.scp_ids]]
        parent: str | None = account.parent_ou_id
        while parent is not None:
            unit = units[parent]
            chain.append([docs[s] for s in unit.scp_ids])
            parent = unit.parent_id
        chain.reverse()
        levels[account.id] = chain
    return levels
