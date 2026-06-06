# IAM module--the security showcase
# Three roles, strict separation: CI plan (read-only), CI apply (write), task (minimal)
# OIDC federation means no stored AWS credentials in GitHub

# ──────────────────────────────────────────────
# GitHub OIDC provider--one per account, shared across repos
# ──────────────────────────────────────────────

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  # AWS stopped validating OIDC thumbprints for GitHub in June 2023.
  # Terraform still requires a value--this is a no-op placeholder.
  thumbprint_list = ["ffffffffffffffffffffffffffffffffffffffff"]
}

locals {
  oidc_arn      = aws_iam_openid_connect_provider.github.arn
  repo_wildcard = "repo:${var.github_org}/${var.github_repo}:*"
  repo_main     = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"
  name_prefix   = "cloudpipe-${var.environment}"
}

# ──────────────────────────────────────────────
# CI Plan role--read-only, runs on every PR
# ──────────────────────────────────────────────

resource "aws_iam_role" "ci_plan" {
  name = "${local.name_prefix}-ci-plan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.oidc_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        # any branch can plan (read-only), apply locks to main ref via StringEquals--that's the actual security boundary
        # any branch/PR can plan
        StringLike = {
          "token.actions.githubusercontent.com:sub" = local.repo_wildcard
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_plan" {
  name = "plan-readonly"
  role = aws_iam_role.ci_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateRead"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
        ]
        Resource = [
          "arn:aws:s3:::${var.state_bucket}",
          "arn:aws:s3:::${var.state_bucket}/*",
        ]
      },
      {
        Sid    = "StateLockRead"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/cloudpipe-tfstate-lock"
      },
      {
        Sid    = "InfraReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ecs:Describe*",
          "ecs:List*",
          "rds:Describe*",
          "s3:GetBucket*",
          "s3:ListBucket",
          "elasticloadbalancing:Describe*",
          "logs:Describe*",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "secretsmanager:DescribeSecret",
        ]
        Resource = "*"
      },
      {
        Sid      = "StsIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

# ──────────────────────────────────────────────
# CI Apply role--write access, only from main branch
# ──────────────────────────────────────────────

resource "aws_iam_role" "ci_apply" {
  name = "${local.name_prefix}-ci-apply"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.oidc_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          # only main branch can apply--this is the critical security boundary
          "token.actions.githubusercontent.com:sub" = local.repo_main
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "ci_apply" {
  name = "apply-scoped"
  role = aws_iam_role.ci_apply.id

  # split into service-specific statements. IAM is global (region condition
  # doesn't apply), so it gets its own statement scoped to cloudpipe-* roles.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "TerraformStateWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
        ]
        Resource = [
          "arn:aws:s3:::${var.state_bucket}",
          "arn:aws:s3:::${var.state_bucket}/*",
        ]
      },
      {
        Sid    = "StateLockWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
        ]
        Resource = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/cloudpipe-tfstate-lock"
      },
      {
        Sid    = "InfraManageRegional"
        Effect = "Allow"
        Action = [
          "ec2:*",
          "ecs:*",
          "rds:*",
          "s3:*",
          "elasticloadbalancing:*",
          "logs:*",
          "secretsmanager:*",
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = var.region
          }
        }
      },
      {
        # IAM is global--region condition doesn't apply, so scope to
        # cloudpipe roles and the OIDC provider instead
        Sid    = "IAMManageScoped"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:PassRole",
          "iam:CreateOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider",
        ]
        Resource = [
          "arn:aws:iam::${var.account_id}:role/${local.name_prefix}-*",
          "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com",
        ]
      },
      {
        Sid      = "StsIdentity"
        Effect   = "Allow"
        Action   = "sts:GetCallerIdentity"
        Resource = "*"
      },
    ]
  })
}

# ──────────────────────────────────────────────
# ECS task execution role--pulls images, writes logs
# ──────────────────────────────────────────────

resource "aws_iam_role" "execution" {
  name = "${local.name_prefix}-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_base" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "secretsmanager:GetSecretValue"
      Resource = [
        "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:cloudpipe/${var.environment}/*",
        "arn:aws:secretsmanager:${var.region}:${var.account_id}:secret:rds!*"
      ]
    }]
  })
}

# ──────────────────────────────────────────────
# ECS task role--what the running container can do
# ──────────────────────────────────────────────
# This is intentionally minimal. The container only needs to
# read/write its own S3 bucket and push logs.

resource "aws_iam_role" "task" {
  name = "${local.name_prefix}-ecs-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "task" {
  name = "app-permissions"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AssetBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
        ]
        Resource = "${var.asset_bucket}/*"
      },
      {
        Sid    = "AppLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${var.log_group_arn}:*"
      },
    ]
  })
}
