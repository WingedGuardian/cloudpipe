"""Deterministic IAM action classifier. Scores severity without LLM calls."""
from dataclasses import dataclass

from .plan_parser import IAMRole

# action prefix → (category, base_severity)
# not exhaustive--unknown actions default to "other" / medium
ACTION_CATEGORIES = {
    # data exfiltration
    "s3:GetObject":           ("data_exfil", "high"),
    "s3:ListBucket":          ("data_exfil", "medium"),
    "s3:*":                   ("data_exfil", "critical"),
    "rds:*":                  ("data_exfil", "critical"),
    "secretsmanager:GetSecretValue": ("data_exfil", "high"),
    "dynamodb:GetItem":       ("data_exfil", "medium"),
    "dynamodb:Scan":          ("data_exfil", "high"),
    "dynamodb:*":             ("data_exfil", "critical"),
    # privilege escalation
    "iam:PassRole":           ("priv_escalation", "critical"),
    "iam:CreateRole":         ("priv_escalation", "critical"),
    "iam:AttachRolePolicy":   ("priv_escalation", "critical"),
    "iam:PutRolePolicy":      ("priv_escalation", "critical"),
    "iam:CreateUser":         ("priv_escalation", "high"),
    "iam:CreateAccessKey":    ("priv_escalation", "critical"),
    "iam:*":                  ("priv_escalation", "critical"),
    "sts:AssumeRole":         ("priv_escalation", "high"),
    # lateral movement
    "ec2:RunInstances":       ("lateral_movement", "high"),
    "ec2:*":                  ("lateral_movement", "critical"),
    "ecs:RunTask":            ("lateral_movement", "high"),
    "lambda:InvokeFunction":  ("lateral_movement", "medium"),
    "lambda:*":               ("lateral_movement", "critical"),
    # resource destruction
    "s3:DeleteObject":        ("destruction", "high"),
    "s3:DeleteBucket":        ("destruction", "critical"),
    "rds:DeleteDBInstance":   ("destruction", "critical"),
    "ec2:TerminateInstances": ("destruction", "high"),
    # logging/monitoring
    "logs:CreateLogStream":   ("logging", "low"),
    "logs:PutLogEvents":      ("logging", "low"),
    "logs:Describe*":         ("read_only", "low"),
    "cloudwatch:PutMetricData": ("logging", "low"),
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class ActionClassification:
    action: str
    category: str
    severity: str
    resource_scope: str  # specific ARN or "*"


@dataclass
class RoleBlastRadius:
    role: IAMRole
    classifications: list[ActionClassification]
    overall_severity: str
    categories: dict[str, int]  # category → count of actions
    wildcard_actions: list[str]


def analyze_role(role: IAMRole) -> RoleBlastRadius:
    """Classify every action in a role's policies."""
    classifications = []
    categories: dict[str, int] = {}
    wildcards = []

    for stmt in role.statements:
        if stmt.effect != "Allow":
            continue
        for action in stmt.actions:
            cat, sev = _classify_action(action)
            resource_scope = _summarize_resources(stmt.resources)
            # wildcard resources amplify severity, scoped resources reduce it
            if resource_scope == "*" and sev != "critical":
                sev = _bump_severity(sev)
            elif resource_scope != "*" and sev not in ("low", "critical"):
                sev = _reduce_severity(sev)

            classifications.append(ActionClassification(
                action=action,
                category=cat,
                severity=sev,
                resource_scope=resource_scope,
            ))
            categories[cat] = categories.get(cat, 0) + 1

            if action.endswith("*"):
                wildcards.append(action)

    max_sev = max(
        (SEVERITY_RANK.get(c.severity, 0) for c in classifications),
        default=0,
    )
    overall = next(
        (k for k, v in SEVERITY_RANK.items() if v == max_sev), "low"
    )

    return RoleBlastRadius(
        role=role,
        classifications=classifications,
        overall_severity=overall,
        categories=categories,
        wildcard_actions=wildcards,
    )


def _classify_action(action: str) -> tuple[str, str]:
    # exact match first
    if action in ACTION_CATEGORIES:
        return ACTION_CATEGORIES[action]
    # check for service:* wildcard pattern
    if action.endswith(":*"):
        service = action.split(":")[0]
        # look up service-level wildcard
        wildcard_key = f"{service}:*"
        if wildcard_key in ACTION_CATEGORIES:
            return ACTION_CATEGORIES[wildcard_key]
    # unknown action in a known service--can't determine specific risk
    return "other", "medium"


def _summarize_resources(resources: list[str]) -> str:
    if not resources or resources == ["*"]:
        return "*"
    if len(resources) == 1:
        return resources[0]
    return f"{len(resources)} specific ARNs"


def _bump_severity(sev: str) -> str:
    rank = SEVERITY_RANK.get(sev, 1)
    bumped = min(rank + 1, 4)
    return next(k for k, v in SEVERITY_RANK.items() if v == bumped)


def _reduce_severity(sev: str) -> str:
    rank = SEVERITY_RANK.get(sev, 1)
    reduced = max(rank - 1, 1)
    return next(k for k, v in SEVERITY_RANK.items() if v == reduced)
