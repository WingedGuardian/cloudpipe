variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" { type = string }

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "azs" {
  description = "at least 2 for ALB, 3 for production RDS"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "github_org" {
  type        = string
  description = "GitHub org/user for OIDC trust--only this org can assume CI roles"
}

variable "github_repo" {
  type    = string
  default = "cloudpipe"
}

variable "container_image" {
  type        = string
  description = "ECR image URI or local image tag for the app container"
}
