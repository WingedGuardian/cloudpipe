"""Extract IAM policies, resources, and cost-relevant changes from terraform plan JSON."""
import json
from dataclasses import dataclass, field


@dataclass
class PolicyStatement:
    effect: str
    actions: list[str]
    resources: list[str]
    conditions: dict = field(default_factory=dict)


@dataclass
class IAMRole:
    name: str
    arn_pattern: str
    trust_policy: list[dict]
    statements: list[PolicyStatement]
    resource_address: str


@dataclass
class ResourceChange:
    address: str
    type: str
    name: str
    action: str  # create, update, delete, no-op
    before: dict | None
    after: dict | None


def load_plan(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def extract_iam_roles(plan: dict) -> list[IAMRole]:
    """Pull all IAM roles and their inline policies from the plan."""
    roles = {}
    changes = plan.get("resource_changes", [])

    # first pass: collect roles
    for rc in changes:
        if rc["type"] == "aws_iam_role" and rc["change"]["actions"] != ["delete"]:
            after = rc["change"].get("after", {}) or {}
            name = after.get("name", rc["address"])
            trust = _parse_policy_doc(after.get("assume_role_policy", "{}"))
            roles[rc["address"]] = IAMRole(
                name=name,
                arn_pattern=f"arn:aws:iam::*:role/{name}",
                trust_policy=trust.get("Statement", []),
                statements=[],
                resource_address=rc["address"],
            )

    # second pass: attach inline policies to their roles
    for rc in changes:
        if rc["type"] == "aws_iam_role_policy" and rc["change"]["actions"] != ["delete"]:
            after = rc["change"].get("after", {}) or {}
            role_addr = _find_role_ref(rc, changes)
            if role_addr and role_addr in roles:
                doc = _parse_policy_doc(after.get("policy", "{}"))
                for stmt in doc.get("Statement", []):
                    roles[role_addr].statements.append(PolicyStatement(
                        effect=stmt.get("Effect", "Allow"),
                        actions=_ensure_list(stmt.get("Action", [])),
                        resources=_ensure_list(stmt.get("Resource", [])),
                        conditions=stmt.get("Condition", {}),
                    ))

    return list(roles.values())


def extract_resource_changes(plan: dict) -> list[ResourceChange]:
    """All resource changes in the plan."""
    results = []
    for rc in plan.get("resource_changes", []):
        change = rc.get("change", {})
        actions = change.get("actions", [])
        # terraform uses lists like ["create"], ["update"], ["delete"], ["no-op"]
        action = actions[0] if actions else "no-op"
        if action == "no-op":
            continue
        results.append(ResourceChange(
            address=rc["address"],
            type=rc["type"],
            name=rc.get("name", ""),
            action=action,
            before=change.get("before"),
            after=change.get("after"),
        ))
    return results


def _parse_policy_doc(raw: str) -> dict:
    if not raw or raw == "{}":
        return {}
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _ensure_list(val) -> list:
    if isinstance(val, str):
        return [val]
    return list(val) if val else []


def _find_role_ref(policy_rc: dict, all_changes: list[dict]) -> str | None:
    """Best-effort: match policy to role via the role field in after config."""
    after = policy_rc.get("change", {}).get("after", {}) or {}
    role_id = after.get("role")
    if not role_id:
        return None
    # role_id is the role's name--find the role resource with that name
    for rc in all_changes:
        if rc["type"] == "aws_iam_role":
            rc_after = rc.get("change", {}).get("after", {}) or {}
            if rc_after.get("name") == role_id:
                return rc["address"]
    return None
