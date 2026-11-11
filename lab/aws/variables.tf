variable "region" {
  description = "Region for the regional resources (S3, KMS, Secrets Manager). IAM is global."
  type        = string
  default     = "us-east-1"
}

variable "account_id" {
  description = "The lab account id. Passed explicitly so plan works offline without a data source."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account id."
  }
}

variable "partner_account_id" {
  description = "A second account trusted by the bucket policy. Does not need to exist for the plan; the partner roles live in the fixture only."
  type        = string
  default     = "222222222222"
}

variable "github_org" {
  description = "GitHub org or user that owns the lab repositories (acme in the fixture)."
  type        = string
  default     = "acme"
}

variable "budget_alert_email" {
  description = "Where AWS Budgets sends the alarm when the lab passes the spend threshold."
  type        = string
}

variable "budget_limit_usd" {
  description = "Monthly spend that triggers the alarm."
  type        = number
  default     = 5
}

variable "bucket_suffix" {
  description = "S3 bucket names are global; append something unique to the fixture's bucket names."
  type        = string
  default     = ""
}

variable "collector_external_id" {
  description = "External ID the Breachmap collector must present to assume the read-only role."
  type        = string
  default     = "breachmap-lab"
  sensitive   = true
}

variable "offline_plan" {
  description = "Plan without an AWS account (dummy credentials). Must be false for apply."
  type        = bool
  default     = false
}
