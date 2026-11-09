"""Capability scopes and the authorisation chokepoint (notebook Step 10.2).

One declarative `ToolScope` per tool, one `authorize()` that every secure tool calls
before its body runs. No model is consulted, so no prompt can change the outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .context import SecurityContext
from .data import ShopData, is_first_party


@dataclass(frozen=True)
class ToolScope:
    """Permission for one tool. Default deny: a tool with no entry has no access."""

    requires_auth: str = "email_verified"
    requires_ownership: bool = False
    high_impact: bool = False
    allowed_fields: tuple[str, ...] | None = None
    first_party_only: bool = False
    max_risk_score: int = 100


@dataclass(frozen=True)
class AuthDecision:
    allowed: bool
    reason: str
    requires_human: bool = False


def build_tool_scopes(policy: dict[str, Any]) -> dict[str, ToolScope]:
    risk_ceiling = int(policy["high_risk_score_threshold"])
    return {
        "get_customer_secure": ToolScope(
            requires_auth="email_verified",
            requires_ownership=True,
            allowed_fields=("customer_id", "first_name", "last_name",
                            "loyalty_tier", "account_status", "account_since"),
        ),
        "get_order_secure": ToolScope(
            requires_auth="email_verified",
            requires_ownership=True,
            allowed_fields=("order_id", "product", "status", "amount_usd", "delivery_date",
                            "refund_status", "delivery_exception", "seller_id"),
        ),
        "search_knowledge_base_secure": ToolScope(requires_auth="unverified"),
        "update_customer_secure": ToolScope(
            requires_auth=policy["min_auth_level_for_profile_update"],
            requires_ownership=True,
            high_impact=True,
            max_risk_score=risk_ceiling,
        ),
        "issue_refund_secure": ToolScope(
            requires_auth=policy["min_auth_level_for_refund"],
            requires_ownership=True,
            high_impact=True,
            first_party_only=True,
            max_risk_score=risk_ceiling,
        ),
        "send_email_secure": ToolScope(requires_auth="email_verified", requires_ownership=True),
    }


def authorize(
    ctx: SecurityContext | None,
    scopes: dict[str, ToolScope],
    data: ShopData,
    tool_name: str,
    target_kind: str | None = None,
    target_id: str | None = None,
) -> AuthDecision:
    """Run the checks in a fixed order and return the first refusal, or an allow."""
    if ctx is None:
        return AuthDecision(False, "no active session - agent is unbound")

    scope = scopes.get(tool_name)
    if scope is None:
        return AuthDecision(False, f"'{tool_name}' has no declared scope (default deny)")

    if ctx.account_status != "active":
        return AuthDecision(False, f"account {ctx.customer_id} is '{ctx.account_status}' - "
                                   "self-service disabled, route to Tier-2")

    if not ctx.at_least(scope.requires_auth):
        return AuthDecision(False, f"requires auth level '{scope.requires_auth}', "
                                   f"session has '{ctx.auth_level}'")

    if ctx.risk_score > scope.max_risk_score:
        return AuthDecision(False, f"caller risk score {ctx.risk_score} exceeds limit "
                                   f"{scope.max_risk_score} for this tool ({ctx.flag_reason})")

    if scope.requires_ownership and target_id is not None:
        owner = data.owner_of(target_kind, target_id)
        if owner is None:
            return AuthDecision(False, f"{target_kind} {target_id} not found")
        if owner != ctx.customer_id:
            return AuthDecision(False, f"{target_kind} {target_id} belongs to {owner}, caller is "
                                       f"{ctx.customer_id} - cross-account access denied")

    if scope.first_party_only and target_kind == "order" and target_id is not None:
        order = data.order(target_id)
        if order is not None and not is_first_party(order["seller_id"]):
            return AuthDecision(False, f"order {target_id} is fulfilled by {order['seller_id']} - "
                                       "marketplace orders must be settled by the seller")

    return AuthDecision(True, "authorised", requires_human=scope.high_impact)
