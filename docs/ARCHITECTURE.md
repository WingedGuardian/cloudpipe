# Architecture

## Overview

CloudPipe is a CI/CD pipeline with an embedded security analysis engine (InfraScope). The pipeline runs in GitHub Actions; InfraScope runs as a Python package within the pipeline.

## Pipeline Flow

```
Developer pushes Terraform changes
    │
    ├─ [PR event] terraform-ci.yml
    │   ├─ validate job:   fmt check, validate, tflint
    │   ├─ security-scan:  checkov → SARIF → GitHub Security tab
    │   ├─ plan job:       OIDC auth → terraform plan → JSON artifact
    │   └─ infrascope job: downloads plan → runs analysis → posts PR comment
    │
    └─ [push to main] terraform-cd.yml
        └─ apply job:     OIDC auth (write role) → terraform apply → drift baseline
```

## InfraScope Analysis Pipeline

InfraScope processes a Terraform plan JSON through four analysis modules, then combines results into a security score:

```
plan.json
    │
    ├─ plan_parser.py          Extract IAM roles, policies, resource changes
    │   └─ Output: list[IAMRole], list[ResourceChange]
    │
    ├─ iam_blast_radius.py     Classify each IAM action by attack category
    │   ├─ Action categories: data_exfil, priv_escalation,
    │   │                     lateral_movement, destruction, logging
    │   ├─ Severity adjusted by resource scope (wildcard amplifies, ARN reduces)
    │   └─ Output: list[RoleBlastRadius]
    │
    ├─ policy_lint.py          Parliament grammar checks + custom rules
    │   ├─ parliament: malformed policies, known bad patterns
    │   ├─ custom: unconstrained PassRole, wildcard-on-wildcard, sensitive unscoped
    │   └─ Output: list[PolicyFinding]
    │
    ├─ cost_analysis.py        Infracost JSON or plan-based estimation
    │   └─ Output: CostSummary
    │
    ├─ security_score.py       Deterministic weighted scoring
    │   ├─ Dimensions: iam (30%), network (25%), encryption (20%),
    │   │              logging (15%), compliance (10%)
    │   └─ Output: SecurityScore (0-100, grade A-F, pass/fail)
    │
    └─ analyzer.py             Orchestrator
        ├─ Optional: Bedrock Claude narrative (graceful degradation)
        └─ pr_comment.py → collapsible GitHub PR comment
```

The AI narrative is optional. All analysis and scoring is deterministic. The LLM adds human-readable summaries; it doesn't make pass/fail decisions.

## OIDC Authentication

No stored AWS credentials. Each workflow run gets short-lived tokens via OIDC federation:

```
GitHub Actions runner
    │ OIDC token (contains repo, branch, event info)
    ▼
AWS STS AssumeRoleWithWebIdentity
    │ Condition: token.actions.githubusercontent.com:sub must match
    │            repo:WingedGuardian/cloudpipe:* (plan) or
    │            repo:WingedGuardian/cloudpipe:ref:refs/heads/main (apply)
    ▼
Short-lived AWS credentials (15min-1hr)
```

The plan role cannot modify any resources. The apply role can only be assumed from the main branch.

## Infrastructure

CloudPipe deploys an ECS Fargate service with supporting infrastructure:

- **Networking**: VPC, 2 public subnets (ALB), 2 private subnets (ECS, RDS), single NAT
- **Compute**: ECS cluster, Fargate service, ALB, CloudWatch logs
- **Database**: RDS Postgres (t4g.micro, encrypted, private subnet)
- **Storage**: S3 bucket (versioned, encrypted, public access blocked)
- **IAM**: 4 roles (ci-plan, ci-apply, ecs-execution, ecs-task)

The deployed service is minimal. The infrastructure provides a rich IAM surface for InfraScope to analyze.

## Design Decisions

**Why GitHub Actions (not Jenkins/GitLab CI)?** Free for public repos, first-class OIDC support, tight PR integration for InfraScope comments. Public repos get more recruiter traffic than private links.

**Why separate plan/apply roles?** The plan role having write access is a common misconfiguration. Separating them is the entire point of the security model.

**Why deterministic scoring + optional LLM?** The security gate must be reliable. An LLM hallucinating "this is fine" shouldn't pass a PR with `iam:*` on `*`. Deterministic first, AI narrative second.

**Why Parliament (unmaintained) + custom rules?** Parliament catches policy grammar issues that custom rules miss. Custom rules catch security patterns that Parliament doesn't cover. Together they're more comprehensive than either alone. Parliament works fine despite no recent releases.

**Why single NAT gateway?** $32/month per NAT. Production would use one per AZ for HA. This is a demo--saving money on infrastructure that isn't the point of the project.
