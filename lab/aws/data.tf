resource "aws_s3_bucket" "customer_data" {
  bucket = local.customer_bucket
  tags   = { classification = "customer-data", crown-jewel = "true" }
}

resource "aws_s3_bucket_public_access_block" "customer_data" {
  bucket                  = aws_s3_bucket.customer_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "customer_data" {
  bucket = aws_s3_bucket.customer_data.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PartnerRead"
        Effect    = "Allow"
        Principal = { AWS = ["arn:aws:iam::${var.partner_account_id}:role/partner-reader", "arn:aws:iam::${var.partner_account_id}:role/partner-noidentity"] }
        Action    = "s3:GetObject"
        Resource  = local.objects_arn
      },
      {
        Sid       = "DenyLegacyReaders"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = local.objects_arn
        Condition = {
          ArnNotLike = {
            "aws:PrincipalArn" = [
              "arn:aws:iam::${var.account_id}:role/deploy-*",
              local.role_arn["admin-breakglass"],
              local.role_arn["locked-role"],
              "arn:aws:iam::${var.partner_account_id}:role/partner-*",
            ]
          }
        }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.customer_data]
}

resource "aws_s3_bucket" "static_site" {
  bucket = local.static_bucket
}

resource "aws_kms_key" "prod_data" {
  description             = "breachmap lab: prod data key (crown jewel)"
  deletion_window_in_days = 7
  tags                    = { crown-jewel = "true" }
  policy = jsonencode({
    Version   = "2012-10-17"
    Id        = "prod-data"
    Statement = [{ Sid = "EnableIamPolicies", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Action = "kms:*", Resource = "*" }]
  })
}

resource "aws_kms_key" "secrets" {
  description             = "breachmap lab: key for Secrets Manager"
  deletion_window_in_days = 7
  policy = jsonencode({
    Version   = "2012-10-17"
    Id        = "secrets"
    Statement = [{ Sid = "EnableIamPolicies", Effect = "Allow", Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }, Action = "kms:*", Resource = "*" }]
  })
}

resource "aws_secretsmanager_secret" "prod_db" {
  name                    = "prod/db-credentials"
  kms_key_id              = aws_kms_key.secrets.arn
  recovery_window_in_days = 0
  tags                    = { crown-jewel = "true" }
}

resource "aws_secretsmanager_secret_version" "prod_db" {
  secret_id     = aws_secretsmanager_secret.prod_db.id
  secret_string = jsonencode({ username = "app", password = "lab-only-not-a-real-secret" })
}
