terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "cloudpipe-tfstate"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cloudpipe-tfstate-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "cloudpipe"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "networking" {
  source = "./modules/networking"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
  azs         = var.azs
}

module "iam" {
  source = "./modules/iam"

  environment   = var.environment
  region        = var.region
  account_id    = data.aws_caller_identity.current.account_id
  state_bucket  = "cloudpipe-tfstate"
  asset_bucket  = module.storage.bucket_arn
  log_group_arn = module.compute.log_group_arn
  github_org    = var.github_org
  github_repo   = var.github_repo
}

module "storage" {
  source = "./modules/storage"

  environment = var.environment
}

module "database" {
  source = "./modules/database"

  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  app_sg_id          = module.compute.app_sg_id
}

module "compute" {
  source = "./modules/compute"

  environment        = var.environment
  region             = var.region
  vpc_id             = module.networking.vpc_id
  public_subnet_ids  = module.networking.public_subnet_ids
  private_subnet_ids = module.networking.private_subnet_ids
  task_role_arn      = module.iam.task_role_arn
  execution_role_arn = module.iam.execution_role_arn
  db_endpoint        = module.database.endpoint
  db_secret_arn      = module.database.secret_arn
  container_image    = var.container_image
}

data "aws_caller_identity" "current" {}
