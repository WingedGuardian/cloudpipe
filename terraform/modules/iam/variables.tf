variable "environment" {}
variable "region" {}
variable "account_id" {}
variable "state_bucket" {}
variable "asset_bucket" {}
variable "log_group_arn" {}

variable "github_org" {
  description = "limits OIDC trust to this org--without it, any GitHub repo could assume the role"
}

variable "github_repo" {}
