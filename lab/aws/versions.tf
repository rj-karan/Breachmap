terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # offline_plan lets CI and laptops run `terraform plan` with dummy
  # credentials and no AWS account. Never set it for apply.
  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan

  # Every resource the lab creates carries this tag. Replay and teardown are
  # fenced on it, and it is the first thing to check if something looks like
  # it leaked outside the lab.
  default_tags {
    tags = {
      breachmap-lab = "true"
      project       = "breachmap"
      fixture       = "v1-oidc"
    }
  }
}
