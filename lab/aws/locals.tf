locals {
  github_host     = "token.actions.githubusercontent.com"
  github_provider = "arn:aws:iam::${var.account_id}:oidc-provider/${local.github_host}"
  kind_host       = "oidc.lab.local/kind"
  kind_provider   = "arn:aws:iam::${var.account_id}:oidc-provider/${local.kind_host}"

  customer_bucket = "acme-customer-data${var.bucket_suffix}"
  static_bucket   = "acme-static-site${var.bucket_suffix}"
  bucket_arn      = "arn:aws:s3:::${local.customer_bucket}"
  objects_arn     = "${local.bucket_arn}/*"

  role_arn = { for name in [
    "deploy-aud-only", "deploy-scoped", "deploy-org-wildcard", "deploy-prod-env",
    "deploy-scp-blocked", "deploy-boundary", "ci-legacy-reader", "ci-bootstrap",
    "admin-breakglass", "locked-role", "secrets-reader", "irsa-app", "deploy-ip-locked",
    "breachmap-audit",
  ] : name => "arn:aws:iam::${var.account_id}:role/${name}" }

  # Trust policy for GitHub Actions with the given condition block.
  github_trust = {
    for name, condition in {
      "deploy-aud-only" = {
        StringEquals = { "${local.github_host}:aud" = "sts.amazonaws.com" }
      }
      "deploy-scoped" = {
        StringEquals = {
          "${local.github_host}:aud" = "sts.amazonaws.com"
          "${local.github_host}:sub" = "repo:${var.github_org}/app:ref:refs/heads/main"
        }
      }
      "deploy-org-wildcard" = {
        StringEquals = { "${local.github_host}:aud" = "sts.amazonaws.com" }
        StringLike   = { "${local.github_host}:sub" = "repo:${var.github_org}/*" }
      }
      "deploy-prod-env" = {
        StringEquals = {
          "${local.github_host}:aud" = "sts.amazonaws.com"
          "${local.github_host}:sub" = "repo:${var.github_org}/app:environment:prod"
        }
      }
      "deploy-scp-blocked" = {
        StringEquals = { "${local.github_host}:aud" = "sts.amazonaws.com" }
      }
      "deploy-boundary" = {
        StringEquals = { "${local.github_host}:aud" = "sts.amazonaws.com" }
      }
      "ci-legacy-reader" = {
        StringEquals = { "${local.github_host}:aud" = "sts.amazonaws.com" }
      }
      "ci-bootstrap" = {
        StringEquals = { "${local.github_host}:aud" = "sts.amazonaws.com" }
      }
      "secrets-reader" = {
        StringEquals = {
          "${local.github_host}:aud" = "sts.amazonaws.com"
          "${local.github_host}:sub" = "repo:${var.github_org}/app:ref:refs/heads/main"
        }
      }
      "deploy-ip-locked" = {
        StringEquals = {
          "${local.github_host}:aud" = "sts.amazonaws.com"
          "${local.github_host}:sub" = "repo:${var.github_org}/app:ref:refs/heads/main"
        }
        IpAddress = { "aws:SourceIp" = "203.0.113.0/24" }
      }
      } : name => jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Sid       = "GitHubOIDC"
          Effect    = "Allow"
          Principal = { Federated = local.github_provider }
          Action    = "sts:AssumeRoleWithWebIdentity"
          Condition = condition
        }]
    })
  }
}
