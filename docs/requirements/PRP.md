# Product Requirements--CloudPipe CI/CD + InfraScope

## Goal

**Deliverable:** CI/CD pipeline with AI-powered infrastructure security analysis for Terraform PRs.

**Business value:** DevSecOps pipeline engineering: the system that prevents bad infrastructure from reaching production. Shows IAM expertise, Terraform CI/CD patterns, and infrastructure-specific AI integration.

**Pipeline behavior:**
- Developer opens PR with Terraform changes
- Pipeline validates, scans, plans, and runs InfraScope analysis
- InfraScope posts collapsible PR comment with blast radius, policy findings, cost delta, and security score
- Critical findings block merge; score below threshold blocks merge
- On merge to main, separate write role applies changes
- Weekly drift detection opens GitHub issues on state divergence

**Success criteria:**
- InfraScope correctly identifies overpermissive policies in test fixtures
- Clean plans pass with score >= 70; overpermissive plans fail with critical findings
- `ruff check . && pytest -v` clean
- `terraform validate` passes for all environments
- GitHub Actions workflows have valid syntax
- OIDC: no stored AWS credentials anywhere

## Context

**Patterns followed:**
- OIDC federation for GitHub Actions (no stored keys)
- Separate plan/apply IAM roles (least privilege per stage)
- Deterministic analysis first, AI narrative second (reliability over cleverness)
- Parliament + custom rules (complementary coverage)
- Collapsible PR comments (dense information, scannable)
- SARIF upload for Checkov (findings in GitHub Security tab)

**External constraints:**
- Parliament: last release 2023, functional but unmaintained
- Infracost: free tier, fallback to plan-based estimation
- Bedrock Claude: optional AI narrative, graceful degradation
- GitHub Actions: free for public repos, OIDC support built-in

## Data Model

**Input:** Terraform plan JSON (`terraform show -json`)

**InfraScope data types:**

| Type | Key fields | Purpose |
|------|-----------|---------|
| IAMRole | name, trust_policy, statements | Extracted from plan |
| PolicyStatement | effect, actions, resources, conditions | Individual policy statements |
| ActionClassification | action, category, severity, resource_scope | Blast radius result |
| RoleBlastRadius | role, classifications, overall_severity | Per-role analysis |
| PolicyFinding | rule, severity, detail, recommendation | Lint results |
| CostSummary | total_monthly, delta_monthly, top_drivers | Cost analysis |
| SecurityScore | overall (0-100), grade (A-F), passed, breakdown | Final score |

## Task Sequence

1. **Project structure**--git init, pyproject.toml, Makefile, .gitignore
2. **Terraform bootstrap**--S3 + DynamoDB for remote state
3. **Terraform modules**--networking, compute, database, storage, iam
4. **Container**--minimal FastAPI service + Dockerfile
5. **GitHub Actions: CI**--validate, scan, plan, InfraScope
6. **GitHub Actions: CD**--apply on merge, drift baseline
7. **GitHub Actions: drift**--weekly detection, auto-issue on divergence
8. **InfraScope: plan parser**--extract IAM roles and resource changes
9. **InfraScope: blast radius**--action classification + severity scoring
10. **InfraScope: policy lint**--Parliament + custom rules
11. **InfraScope: cost analysis**--Infracost parsing + plan estimation
12. **InfraScope: security score**--weighted 5-dimension scoring
13. **InfraScope: PR comment**--collapsible markdown formatter
14. **InfraScope: analyzer**--orchestrator with AI narrative (optional)
15. **Test fixtures**--overpermissive + clean plan JSONs
16. **Tests**--blast radius, policy lint, security score, cost analysis
17. **Docs**--README, ARCHITECTURE.md, SECURITY.md
18. **Code review + code-voice audit**

## Validation Strategy

**Level 1--Lint (every save):**
- `ruff check .`--Python lint
- `terraform validate`--HCL syntax

**Level 2--Unit tests (every commit):**
- Blast radius: overpermissive → critical, clean → low/medium, no escalation
- Policy lint: catches wildcards, PassRole, has recommendations
- Security score: overpermissive fails, clean passes, weights sum to 1
- Cost: detects resources, sorted, all new

**Level 3--Integration (with GitHub Actions):**
- Push PR → pipeline runs → InfraScope comment appears
- Fix issues → re-push → score improves
- Merge → apply succeeds → drift baseline saved
- Weekly cron → drift check runs (no drift = no issue)

## Anti-Patterns Avoided

- OIDC federation instead of stored AWS credentials
- Plan and apply use separate IAM roles
- Pass/fail decisions are deterministic; the LLM writes the narrative, not the verdict
- Tests run against plan JSON fixtures, not mock AWS
- Automated scoring gates plus human review
- Remote S3 backend with DynamoDB locking for state
