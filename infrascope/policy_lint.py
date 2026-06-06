"""Policy linting via parliament + custom rules.

Parliament does the heavy lifting (AWS policy grammar validation).
Custom rules augmenting parliament: wildcard resources, sensitive action combinations.
"""
import json
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class PolicyFinding:
    rule: str
    severity: str  # critical, high, medium, low
    resource_address: str
    detail: str
    recommendation: str


def lint_plan_policies(plan: dict) -> list[PolicyFinding]:
    """Run parliament + custom rules against all IAM policies in the plan."""
    findings = []

    for rc in plan.get("resource_changes", []):
        if rc["type"] not in ("aws_iam_role_policy", "aws_iam_policy"):
            continue
        if rc["change"]["actions"] == ["delete"]:
            continue

        after = rc["change"].get("after", {}) or {}
        policy_str = after.get("policy", "{}")
        if isinstance(policy_str, dict):
            doc = policy_str
        else:
            try:
                doc = json.loads(policy_str)
            except (json.JSONDecodeError, TypeError):
                continue

        addr = rc["address"]
        findings.extend(_run_parliament(doc, addr))
        findings.extend(_custom_rules(doc, addr))

    return findings


def _run_parliament(doc: dict, addr: str) -> list[PolicyFinding]:
    """Parliament catches malformed policies and known bad patterns."""
    results = []
    try:
        import parliament
        policy = parliament.policy(doc)
        policy.analyze()
        for finding in policy.findings:
            # parliament severity is CRITICAL/HIGH/MEDIUM/LOW/INFO
            sev = str(finding.severity).lower()
            if sev == "info":
                continue
            results.append(PolicyFinding(
                rule=f"parliament:{finding.issue}",
                severity=sev,
                resource_address=addr,
                detail=str(finding.detail),
                recommendation=str(finding.fix),
            ))
    except ImportError:
        log.warning("parliament not installed, skipping policy grammar checks")
    except Exception as e:
        log.warning("parliament error on %s: %s", addr, e)
    return results


def _custom_rules(doc: dict, addr: str) -> list[PolicyFinding]:
    """Checks parliament doesn't cover: wildcards, dangerous combos, missing conditions."""
    findings = []

    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        # PassRole without a condition key is an escalation path parliament doesn't flag
        # rule: iam:PassRole without condition is always a finding
        if "iam:PassRole" in actions and not stmt.get("Condition"):
            findings.append(PolicyFinding(
                rule="custom:unconstrained-passrole",
                severity="critical",
                resource_address=addr,
                detail=(
                    "iam:PassRole without Condition allows privilege escalation "
                    "to any role the service can assume"
                ),
                recommendation="Add Condition restricting iam:PassedToService or target role ARN",
            ))

        # rule: wildcard actions on wildcard resources
        wildcard_actions = [a for a in actions if a.endswith(":*") or a == "*"]
        wildcard_resources = "*" in resources
        if wildcard_actions and wildcard_resources:
            findings.append(PolicyFinding(
                rule="custom:wildcard-action-resource",
                severity="critical",
                resource_address=addr,
                detail=(
                    f"Wildcard actions ({', '.join(wildcard_actions)}) "
                    "on Resource '*'--unrestricted access"
                ),
                recommendation="Scope to specific operations and resource ARNs",
            ))

        # rule: data-sensitive actions without resource scoping
        sensitive = {"s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                     "secretsmanager:GetSecretValue", "rds:*"}
        matched = set(actions) & sensitive
        if matched and wildcard_resources:
            findings.append(PolicyFinding(
                rule="custom:sensitive-unscoped",
                severity="high",
                resource_address=addr,
                detail=f"Sensitive actions ({', '.join(matched)}) on all resources",
                recommendation="Restrict Resource to specific bucket ARNs or secret ARNs",
            ))

    return findings
