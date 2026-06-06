# Security Model

## Threat Assumptions

The pipeline protects against two scenarios:
1. **Accidental overpermission**--developer adds `s3:*` instead of `s3:GetObject` on one bucket
2. **Privilege escalation via IAM**--`iam:PassRole` or `iam:CreateAccessKey` without conditions opens a lateral movement path

It does NOT protect against a compromised GitHub Actions runner or AWS account-level compromise. Those require different controls (runner hardening, AWS Organizations SCPs).

## OIDC Federation

Zero stored credentials. The OIDC trust chain:

```
GitHub OIDC Provider (token.actions.githubusercontent.com)
    │
    ├─ ci-plan role
    │   Trust: repo:WingedGuardian/cloudpipe:* (any branch)
    │   Permissions: Describe*, state read, IAM policy read
    │
    └─ ci-apply role
        Trust: repo:WingedGuardian/cloudpipe:ref:refs/heads/main
        Permissions: Full infra management, region-locked to us-east-1
```

**Why this matters**: Traditional CI stores AWS access keys as GitHub secrets. Those keys are long-lived, shared across all workflow runs, and a single leak exposes the entire account. OIDC tokens are scoped to a single workflow run, expire in minutes, and the trust policy restricts which repos and branches can assume each role.

## IAM Role Separation

| Role | Can create resources? | Can read state? | Can modify IAM? | When assumed |
|------|-----------------------|-----------------|-----------------|--------------|
| ci-plan | No | Yes (read-only) | No (read-only) | Every PR |
| ci-apply | Yes (region-locked) | Yes | Yes (region-locked) | Main branch push |
| ecs-execution | No | No | No | ECS task startup |
| ecs-task | No | No | No | Container runtime |

The task role is the smallest: one S3 bucket, one Secrets Manager secret, CloudWatch logs. If the container is compromised, the attacker can read/write assets in one bucket and see one database password. They cannot read other buckets, assume other roles, or move laterally.

## InfraScope Security Checks

### Blast Radius Classification

Every IAM action is classified into an attack category:

| Category | Example actions | What an attacker could do |
|----------|----------------|--------------------------|
| data_exfil | s3:GetObject, rds:*, secretsmanager:GetSecretValue | Read sensitive data |
| priv_escalation | iam:PassRole, iam:CreateAccessKey, iam:AttachRolePolicy | Gain higher privileges |
| lateral_movement | ec2:RunInstances, ecs:RunTask, lambda:InvokeFunction | Move to other services |
| destruction | s3:DeleteBucket, rds:DeleteDBInstance | Destroy resources |

Severity is adjusted by resource scope: `s3:GetObject` on `*` is high; on `arn:aws:s3:::my-bucket/*` is medium.

### Custom Policy Rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| unconstrained-passrole | Critical | iam:PassRole without Condition |
| wildcard-action-resource | Critical | Service:* on Resource * |
| sensitive-unscoped | High | Data actions (s3, secrets) on all resources |

### Security Posture Score

Weighted across 5 dimensions:

| Dimension | Weight | What it measures |
|-----------|--------|-----------------|
| IAM | 30% | Blast radius findings, policy violations |
| Network | 25% | Open security groups, public-facing resources |
| Encryption | 20% | Storage encryption, transit encryption |
| Logging | 15% | CloudWatch log groups present |
| Compliance | 10% | Parliament policy grammar findings |

Threshold: 70/100 to pass. Critical findings auto-fail regardless of score.
