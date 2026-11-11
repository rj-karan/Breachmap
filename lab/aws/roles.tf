# One role per case in lab/fixtures/v1-oidc/aws.json. Names, trust policies and
# permissions mirror the fixture; tests/lab/test_terraform.py checks that the
# two never drift apart. Inline policies are separate aws_iam_role_policy
# resources because the inline_policy argument is deprecated.

locals {
  github_roles = {
    "deploy-aud-only"     = { tags = { case = "tinder-aud-only" } }
    "deploy-scoped"       = { tags = {} }
    "deploy-org-wildcard" = { tags = {} }
    "deploy-prod-env"     = { tags = {} }
    "deploy-scp-blocked"  = { tags = {} }
    "deploy-boundary"     = { tags = {} }
    "ci-legacy-reader"    = { tags = {} }
    "ci-bootstrap"        = { tags = {} }
    "secrets-reader"      = { tags = {} }
    "deploy-ip-locked"    = { tags = {} }
  }

  # role name -> inline policy name -> policy JSON
  inline_policies = {
    "deploy-aud-only"  = { "customer-data" = local.read_customer_data }
    "deploy-scoped"    = { "customer-data" = local.read_customer_data }
    "ci-legacy-reader" = { "customer-data" = local.read_customer_data }
    "deploy-ip-locked" = { "customer-data" = local.read_customer_data }
    "locked-role"      = { "customer-data" = local.read_customer_data }
    "deploy-prod-env" = { "prod" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Sid = "ReadCustomerData", Effect = "Allow", Action = "s3:GetObject", Resource = local.objects_arn },
        { Sid = "DecryptProd", Effect = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.prod_data.arn },
      ]
    }) }
    "deploy-scp-blocked" = { "secrets" = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Sid = "ReadDbSecret", Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = aws_secretsmanager_secret.prod_db.arn }]
    }) }
    "deploy-boundary" = { "wide" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Sid = "ReadCustomerData", Effect = "Allow", Action = "s3:GetObject", Resource = local.objects_arn },
        { Sid = "DecryptProd", Effect = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.prod_data.arn },
      ]
    }) }
    "ci-bootstrap" = { "chain" = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Sid = "Chain", Effect = "Allow", Action = "sts:AssumeRole", Resource = [local.role_arn["admin-breakglass"], local.role_arn["locked-role"]] }]
    }) }
    "admin-breakglass" = { "admin" = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Sid = "All", Effect = "Allow", Action = "*", Resource = "*" }]
    }) }
    "secrets-reader" = { "secrets" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        { Sid = "ReadDbSecret", Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = aws_secretsmanager_secret.prod_db.arn },
        {
          Sid       = "DecryptViaSecretsManager"
          Effect    = "Allow"
          Action    = "kms:Decrypt"
          Resource  = aws_kms_key.secrets.arn
          Condition = { StringEquals = { "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com" } }
        },
      ]
    }) }
    "irsa-app" = { "prod-key" = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Sid = "DecryptProd", Effect = "Allow", Action = "kms:Decrypt", Resource = aws_kms_key.prod_data.arn }]
    }) }
  }

  inline_policy_list = merge([
    for role, policies in local.inline_policies : {
      for name, json in policies : "${role}/${name}" => { role = role, name = name, policy = json }
    }
  ]...)

  other_trust = {
    "admin-breakglass" = jsonencode({
      Version   = "2012-10-17"
      Statement = [{ Sid = "FromBootstrap", Effect = "Allow", Principal = { AWS = local.role_arn["ci-bootstrap"] }, Action = "sts:AssumeRole" }]
    })
    "locked-role" = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "FromBootstrapWithMfa"
        Effect    = "Allow"
        Principal = { AWS = local.role_arn["ci-bootstrap"] }
        Action    = "sts:AssumeRole"
        Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
      }]
    })
    "irsa-app" = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "KindIrsa"
        Effect    = "Allow"
        Principal = { Federated = local.kind_provider }
        Action    = "sts:AssumeRoleWithWebIdentity"
        Condition = { StringEquals = { "${local.kind_host}:aud" = "sts.amazonaws.com", "${local.kind_host}:sub" = "system:serviceaccount:payments:app-sa" } }
      }]
    })
    # The collector's own role: read-only, assumed with an external ID. Never on a path.
    "breachmap-audit" = jsonencode({
      Version = "2012-10-17"
      Statement = [{
        Sid       = "Collector"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "sts:ExternalId" = var.collector_external_id } }
      }]
    })
  }
}

resource "aws_iam_role" "github" {
  for_each           = local.github_roles
  name               = each.key
  assume_role_policy = local.github_trust[each.key]
  tags               = each.value.tags
  permissions_boundary = (
    each.key == "deploy-boundary" ? aws_iam_policy.s3_read_only_boundary.arn : null
  )
  depends_on = [aws_iam_openid_connect_provider.github]
}

# Roles trusted by other roles reference ci-bootstrap's ARN; IAM resolves the
# ARN to a principal id when the policy is saved, so ci-bootstrap must exist first.
resource "aws_iam_role" "other" {
  for_each           = local.other_trust
  name               = each.key
  assume_role_policy = each.value
  depends_on         = [aws_iam_role.github, aws_iam_openid_connect_provider.kind]
}

resource "aws_iam_role_policy" "inline" {
  for_each   = local.inline_policy_list
  name       = each.value.name
  role       = each.value.role
  policy     = each.value.policy
  depends_on = [aws_iam_role.github, aws_iam_role.other]
}

resource "aws_iam_role_policy_attachment" "org_wildcard_customer_data" {
  role       = aws_iam_role.github["deploy-org-wildcard"].name
  policy_arn = aws_iam_policy.customer_data_read.arn
}

resource "aws_iam_role_policy_attachment" "audit_security_audit" {
  role       = aws_iam_role.other["breachmap-audit"].name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}
