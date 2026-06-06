"""Main orchestrator--ties plan parsing, blast radius, policy lint, cost, and scoring together."""
import argparse
import json
import logging
import sys

from . import cost_analysis, iam_blast_radius, plan_parser, policy_lint, security_score
from .pr_comment import format_comment, post_comment

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)


def analyze(plan_path: str, infracost_path: str | None = None) -> dict:
    """Run the full analysis pipeline. Returns structured results."""
    plan = plan_parser.load_plan(plan_path)

    # IAM blast radius
    roles = plan_parser.extract_iam_roles(plan)
    blast_results = [iam_blast_radius.analyze_role(r) for r in roles]

    # policy linting
    findings = policy_lint.lint_plan_policies(plan)

    # cost
    cost = None
    if infracost_path:
        cost = cost_analysis.parse_infracost(infracost_path)
    if not cost:
        cost = cost_analysis.estimate_from_plan(plan)

    # resource changes for network/encryption scoring
    changes = plan_parser.extract_resource_changes(plan)

    # security score
    score = security_score.compute_score(
        blast_results, findings, changes, threshold=70,
    )

    # try AI narrative--graceful degradation if unavailable
    narrative = _generate_narrative(blast_results, findings, score)

    return {
        "score": score,
        "blast_results": blast_results,
        "findings": findings,
        "cost": cost,
        "narrative": narrative,
    }


def _generate_narrative(blast_results, findings, score) -> str | None:
    """LLM-generated summary. Falls back gracefully if Bedrock is unavailable."""
    try:
        import boto3
        client = boto3.client("bedrock-runtime", region_name="us-east-1")

        prompt = _build_narrative_prompt(blast_results, findings, score)
        response = client.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 500,
                "messages": [{"role": "user", "content": prompt}],
            }),
            contentType="application/json",
        )
        result = json.loads(response["body"].read())
        return result["content"][0]["text"]
    except Exception as e:
        # AI narrative is optional--deterministic analysis is the core value
        log.info("AI narrative unavailable (%s), using deterministic results only", e)
        return None


def _build_narrative_prompt(blast_results, findings, score) -> str:
    """Build prompt for LLM narrative generation."""
    parts = ["Summarize this infrastructure security analysis in 3-4 sentences for a PR reviewer:"]
    parts.append(f"\nSecurity Score: {score.overall}/100 ({score.grade})")
    parts.append(f"Critical findings: {score.critical_count}, High: {score.high_count}")

    if blast_results:
        parts.append("\nIAM Roles analyzed:")
        for br in blast_results:
            wc_count = len(br.wildcard_actions)
            parts.append(f"- {br.role.name}: {br.overall_severity}, {wc_count} wildcard actions")
            if br.wildcard_actions:
                parts.append(f"  Wildcards: {', '.join(br.wildcard_actions)}")

    if findings:
        parts.append(f"\n{len(findings)} policy findings:")
        for f in findings[:5]:
            parts.append(f"- [{f.severity}] {f.rule}: {f.detail}")

    parts.append("\nBe specific about what an attacker could do. No filler.")
    parts.append("State the risk and the fix.")
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="InfraScope--Terraform plan security analysis")
    parser.add_argument("plan", help="path to terraform plan JSON")
    parser.add_argument("--infracost", help="path to infracost output JSON")
    parser.add_argument("--pr-comment", action="store_true", help="post results as PR comment")
    parser.add_argument("--repo", help="GitHub repo (owner/name) for PR comment")
    parser.add_argument("--pr", type=int, help="PR number for comment")
    parser.add_argument("--threshold", type=int, default=70, help="pass/fail score threshold")
    args = parser.parse_args()

    results = analyze(args.plan, args.infracost)
    comment = format_comment(
        results["score"],
        results["blast_results"],
        results["findings"],
        results["cost"],
        results["narrative"],
    )

    if args.pr_comment and args.repo and args.pr:
        post_comment(comment, args.repo, args.pr)
    else:
        print(comment)

    if not results["score"].passed:
        log.warning("InfraScope: FAILED (score %d, threshold %d)",
                     results["score"].overall, args.threshold)
        sys.exit(1)


if __name__ == "__main__":
    main()
