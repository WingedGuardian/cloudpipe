"""Parse Infracost JSON output and summarize cost changes.

Infracost runs separately (in the workflow or locally) and produces
a JSON breakdown.
"""
import json
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class CostItem:
    resource_name: str
    resource_type: str
    monthly_cost: float
    is_new: bool


@dataclass
class CostSummary:
    total_monthly: float
    delta_monthly: float  # positive = cost increase
    items: list[CostItem]
    top_drivers: list[CostItem]  # sorted by cost, top 5


def parse_infracost(path: str) -> CostSummary | None:
    """Parse infracost output JSON. Returns None if file missing or unparseable."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.warning("infracost output not available: %s", e)
        return None

    items = []
    total = 0.0
    prev_total = 0.0

    for project in data.get("projects", []):
        prev_total += float(project.get("pastBreakdown", {}).get("totalMonthlyCost", 0) or 0)

        for resource in project.get("breakdown", {}).get("resources", []):
            cost = float(resource.get("monthlyCost", 0) or 0)
            if cost == 0:
                continue
            items.append(CostItem(
                resource_name=resource.get("name", "unknown"),
                resource_type=resource.get("resourceType", "unknown"),
                monthly_cost=cost,
                is_new=resource.get("metadata", {}).get("isNew", False),
            ))
            total += cost

    items.sort(key=lambda x: x.monthly_cost, reverse=True)

    return CostSummary(
        total_monthly=total,
        delta_monthly=total - prev_total,
        items=items,
        top_drivers=items[:5],
    )


def estimate_from_plan(plan: dict) -> CostSummary:
    """Rough cost estimates from plan JSON when Infracost isn't available.

    These are ballpark figures based on common resource types. Good enough
    for the demo, but Infracost is the real source of truth.
    """
    # rough monthly costs for common resources in us-east-1
    cost_map = {
        "aws_nat_gateway": 32.40,
        "aws_db_instance": 12.41,  # db.t4g.micro
        "aws_lb": 16.20,          # ALB base cost
        "aws_ecs_service": 0,     # Fargate cost is per-task, hard to estimate from plan
        "aws_eip": 3.65,
    }

    items = []
    for rc in plan.get("resource_changes", []):
        if rc["change"]["actions"] == ["delete"]:
            continue
        rtype = rc["type"]
        if rtype in cost_map and cost_map[rtype] > 0:
            items.append(CostItem(
                resource_name=rc["address"],
                resource_type=rtype,
                monthly_cost=cost_map[rtype],
                is_new="create" in rc["change"]["actions"],
            ))

    total = sum(i.monthly_cost for i in items)
    items.sort(key=lambda x: x.monthly_cost, reverse=True)

    return CostSummary(
        total_monthly=total,
        delta_monthly=total,  # assume all new when estimating from plan
        items=items,
        top_drivers=items[:5],
    )
