output "github_oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.github.arn
}

output "role_arns" {
  value = { for name, arn in local.role_arn : name => arn }
}

output "customer_data_bucket" {
  value = aws_s3_bucket.customer_data.bucket
}

output "collector_role_arn" {
  description = "Assume this (with the external ID) to run the collector against the lab."
  value       = aws_iam_role.other["breachmap-audit"].arn
}
