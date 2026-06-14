variable "environment" { type = string }
variable "region" { type = string }
variable "account_id" { type = string }
variable "state_bucket" { type = string }
variable "asset_bucket" { type = string }
variable "log_group_arn" { type = string }

variable "github_org" {
  type        = string
  description = "limits OIDC trust to this org--without it, any GitHub repo could assume the role"
}

variable "github_repo" { type = string }
