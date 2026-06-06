"""Deterministic security posture score from all analysis results.

Weighted across 5 dimensions. The score is computed without any LLM calls.
Pure formula applied to the structured findings from other modules.
"""
from dataclasses import dataclass

from .iam_blast_radius import RoleBlastRadius
from .policy_lint import PolicyFinding

# weights sum to 1.0
WEIGHTS = {
    "iam": 0.30,
    "network": 0.25,
    "encryption": 0.20,
    "logging": 0.15,
    "compliance": 0.10,
}

SEVERITY_DEDUCTIONS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


@dataclass
class ScoreBreakdown:
    dimension: str
    score: int  # 0-100
    weight: float
    deductions: list[str]


@dataclass
class SecurityScore:
    overall: int  # 0-100
    grade: str    # A-F
    passed: bool  # meets threshold
    breakdown: list[ScoreBreakdown]
    critical_count: int
    high_count: int


def compute_score(
    blast_results: list[RoleBlastRadius],
    policy_findings: list[PolicyFinding],
    resource_changes: list | None = None,
    threshold: int = 70,
) -> SecurityScore:
    """Compute overall security posture score."""
    iam_score, iam_deductions = _score_iam(blast_results, policy_findings)
    network_score, net_deductions = _score_network(resource_changes or [])
    encryption_score, enc_deductions = _score_encryption(resource_changes or [])
    logging_score, log_deductions = _score_logging(resource_changes or [])
    compliance_score, comp_deductions = _score_compliance(policy_findings)

    breakdown = [
        ScoreBreakdown("iam", iam_score, WEIGHTS["iam"], iam_deductions),
        ScoreBreakdown("network", network_score, WEIGHTS["network"], net_deductions),
        ScoreBreakdown("encryption", encryption_score, WEIGHTS["encryption"], enc_deductions),
        ScoreBreakdown("logging", logging_score, WEIGHTS["logging"], log_deductions),
        ScoreBreakdown("compliance", compliance_score, WEIGHTS["compliance"], comp_deductions),
    ]

    overall = round(sum(b.score * b.weight for b in breakdown))

    crit_count = sum(1 for f in policy_findings if f.severity == "critical")
    crit_count += sum(1 for br in blast_results if br.overall_severity == "critical")
    high_count = sum(1 for f in policy_findings if f.severity == "high")

    return SecurityScore(
        overall=overall,
        grade=_grade(overall),
        # the score that blocks a PR is pure arithmetic--LLM can't hallucinate a 70 into a 90
        passed=overall >= threshold and crit_count == 0,
        breakdown=breakdown,
        critical_count=crit_count,
        high_count=high_count,
    )


def _score_iam(
    blasts: list[RoleBlastRadius], findings: list[PolicyFinding],
) -> tuple[int, list[str]]:
    score = 100
    deductions = []

    for br in blasts:
        for wc in br.wildcard_actions:
            penalty = SEVERITY_DEDUCTIONS["critical"]
            score -= penalty
            deductions.append(f"-{penalty}: wildcard action {wc} on {br.role.name}")

    for f in findings:
        penalty = SEVERITY_DEDUCTIONS.get(f.severity, 5)
        score -= penalty
        deductions.append(f"-{penalty}: {f.rule} ({f.severity})")

    return max(0, score), deductions


def _score_network(changes: list) -> tuple[int, list[str]]:
    """Check for public-facing resources and open security groups."""
    score = 100
    deductions = []

    for rc in changes:
        after = rc.after or {} if hasattr(rc, 'after') else {}

        # open security group ingress
        if rc.type == "aws_security_group" and after:
            for ingress in after.get("ingress", []):
                cidrs = ingress.get("cidr_blocks", [])
                port = ingress.get("from_port")
                if "0.0.0.0/0" in cidrs and port not in (80, 443):
                    deductions.append(f"-15: port {port} open to 0.0.0.0/0")
                    score -= 15

        # public subnet with map_public_ip
        if rc.type == "aws_subnet" and after.get("map_public_ip_on_launch"):
            pass  # expected for ALB subnets, not a deduction

    return max(0, score), deductions


def _score_encryption(changes: list) -> tuple[int, list[str]]:
    score = 100
    deductions = []

    for rc in changes:
        after = rc.after or {} if hasattr(rc, 'after') else {}

        if rc.type == "aws_db_instance" and not after.get("storage_encrypted"):
            deductions.append("-25: RDS instance without encryption at rest")
            score -= 25

        if rc.type == "aws_s3_bucket":
            # we check for encryption config resource separately
            pass

    return max(0, score), deductions


def _score_logging(changes: list) -> tuple[int, list[str]]:
    score = 100
    deductions = []
    has_log_group = any(
        rc.type == "aws_cloudwatch_log_group"
        for rc in changes
        if hasattr(rc, 'type')
    )
    if changes and not has_log_group:
        deductions.append("-20: no CloudWatch log group defined")
        score -= 20

    return max(0, score), deductions


def _score_compliance(findings: list[PolicyFinding]) -> tuple[int, list[str]]:
    """Compliance is driven by policy findings--more findings, lower score."""
    score = 100
    deductions = []
    for f in findings:
        if f.rule.startswith("parliament:"):
            penalty = SEVERITY_DEDUCTIONS.get(f.severity, 5)
            score -= penalty
            deductions.append(f"-{penalty}: parliament finding ({f.severity})")
    return max(0, score), deductions


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
