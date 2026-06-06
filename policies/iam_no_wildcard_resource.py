"""Custom Checkov policy: flag IAM policies that use Resource '*' with sensitive actions.

Run with: checkov -d terraform/ --external-checks-dir policies/
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

SENSITIVE_PREFIXES = ("s3:", "iam:", "rds:", "secretsmanager:", "dynamodb:")


class IAMNoWildcardResource(BaseResourceCheck):
    def __init__(self):
        name = "IAM policy should not use Resource '*' with sensitive actions"
        id = "CLOUDPIPE_IAM_001"
        supported = ["aws_iam_role_policy", "aws_iam_policy"]
        categories = [CheckCategories.IAM]
        super().__init__(
            name=name, id=id, categories=categories,
            supported_resource_types=supported,
        )

    def scan_resource_conf(self, conf):
        policy = conf.get("policy", [{}])
        if isinstance(policy, list):
            policy = policy[0] if policy else {}
        if isinstance(policy, str):
            import json
            try:
                policy = json.loads(policy)
            except (json.JSONDecodeError, TypeError):
                return CheckResult.UNKNOWN

        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            has_sensitive = any(
                a.startswith(prefix) for a in actions for prefix in SENSITIVE_PREFIXES
            )
            has_wildcard = "*" in resources

            if has_sensitive and has_wildcard:
                return CheckResult.FAILED

        return CheckResult.PASSED


check = IAMNoWildcardResource()
