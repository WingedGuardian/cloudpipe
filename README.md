# CloudPipe

Terraform CI/CD pipeline with an AI analysis engine that scores IAM blast radius, flags policy violations, and estimates cost delta on every PR--before anything touches AWS.

## Pipeline

`validate → plan → analyze → gate → apply`

On every PR: fmt/validate/tflint runs first, Checkov uploads findings to the GitHub Security tab as SARIF, then an OIDC-authenticated plan runs against a read-only role. InfraScope picks up the plan JSON and produces a security score. Critical findings block merge. On merge to main, a separate write role runs `terraform apply`.

## InfraScope

The differentiator. InfraScope decomposes IAM policies deterministically--action classification, Parliament lint, privilege escalation path analysis, cost delta via Infracost--then runs a weighted 5-dimension formula to produce a 0–100 security score. The LLM component writes the narrative explanation; it doesn't make the scoring decisions. Scoring is reproducible and auditable.

## PR Comment

Every analyzed PR gets a collapsible comment: score at the top, then sections for IAM findings, policy violations, and cost delta. Critical findings surface inline--not buried in a log. If nothing interesting happened, the comment says so and stays out of the way.

## IAM Security

No stored AWS credentials anywhere. Three OIDC-federated roles with hard separation:

- **`ci-plan`**--read-only (Describe\*, state read). Runs on every PR.
- **`ci-apply`**--write access, scoped to `cloudpipe-*` resources, region-locked. Main branch only.
- **`ecs-task`**--one S3 bucket, one Secrets Manager secret, CloudWatch logs. Nothing else.

`ci-apply` is constrained to 17 actions. No wildcards on write operations. The role boundary is defined in Terraform so it's auditable and version-controlled alongside the infrastructure it governs.

## Setup

You need:

- **GitHub secrets**: `AWS_ACCOUNT_ID`, plus OIDC trust already configured in your account
- **State backend**: run `cd terraform/bootstrap && terraform apply` once to create the S3 bucket and DynamoDB lock table
- **Infracost** (optional): add `INFRACOST_API_KEY` secret for cost delta; pipeline degrades gracefully without it

```bash
# bootstrap state (one-time)
cd terraform/bootstrap && terraform init && terraform apply

# run InfraScope locally against a plan
cd terraform/environments/dev
terraform plan -out=tfplan && terraform show -json tfplan > plan.json
python -m infrascope.analyzer plan.json
```

AWS costs ~$65/mo when deployed (NAT gateway dominates). Run `terraform destroy` after demos--at rest the bill is $0.
