variable "environment" {}
variable "region" {}
variable "vpc_id" {}
variable "public_subnet_ids" { type = list(string) }
variable "private_subnet_ids" { type = list(string) }
variable "task_role_arn" {}
variable "execution_role_arn" {}
variable "db_endpoint" {}
variable "db_secret_arn" {}
variable "container_image" {}
