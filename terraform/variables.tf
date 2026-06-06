variable "region" {
  default = "us-east-1"
}

variable "environment" {}

variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "azs" {
  description = "at least 2 for ALB, 3 for production RDS"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "github_org" {
  description = "GitHub org/user for OIDC trust--only this org can assume CI roles"
}

variable "github_repo" {
  default = "cloudpipe"
}

variable "container_image" {
  description = "ECR image URI or local image tag for the app container"
}
