resource "aws_iam_policy" "customer_data_read" {
  name = "CustomerDataRead"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "ListBucket", Effect = "Allow", Action = "s3:ListBucket", Resource = local.bucket_arn },
      { Sid = "ReadObjects", Effect = "Allow", Action = "s3:GetObject", Resource = local.objects_arn },
    ]
  })
}

resource "aws_iam_policy" "s3_read_only_boundary" {
  name = "S3ReadOnlyBoundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Sid = "S3ReadOnly", Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket"], Resource = "*" },
    ]
  })
}

locals {
  read_customer_data = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Sid = "ReadCustomerData", Effect = "Allow", Action = "s3:GetObject", Resource = local.objects_arn }]
  })
}
