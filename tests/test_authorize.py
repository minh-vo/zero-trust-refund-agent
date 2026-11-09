"""authorize() and the per-session tools: identity, ownership, tiers, minimisation."""

import json

import pytest

from shopease_agent.context import UnknownSessionError, start_session
from shopease_agent.data import load_data
from shopease_agent.scopes import authorize


@pytest.fixture
def svc(make_svc):
    return make_svc()


def test_unknown_session_fails_closed():
    with pytest.raises(UnknownSessionError):
        start_session(load_data(), "SESS-9999")


def test_own_order_is_allowed(svc):
    ctx = start_session(svc.data, "SESS-1001")
    assert authorize(ctx, svc.scopes, svc.data, "get_order_secure", "order", "O1002").allowed


def test_cross_account_read_is_denied(svc, tools_for):
    """Attack 8.1: Liam (C1002) asks for Noah's (C1004) laptop order."""
    _, t = tools_for(svc)
    out = t["get_order_secure"].invoke({"order_id": "O1004"})
    assert out.startswith("DENIED")
    assert "belongs to C1004" in out
    assert svc.effects.records_read == []


def test_tool_without_scope_is_denied(svc):
    ctx = start_session(svc.data, "SESS-1001")
    d = authorize(ctx, svc.scopes, svc.data, "delete_everything")
    assert not d.allowed and "default deny" in d.reason


def test_marketplace_order_cannot_be_refunded(svc, tools_for):
    """O1082 is the caller's own order, but MKT-8802 settles it, not ShopEase."""
    _, t = tools_for(svc)
    out = t["issue_refund_secure"].invoke({"order_id": "O1082", "amount_usd": 219})
    assert "marketplace orders must be settled by the seller" in out


def test_profile_update_needs_mfa(svc, tools_for):
    """Attack 6.2's bundled address change: the session is only email_verified."""
    _, t = tools_for(svc, "SESS-1001")
    out = t["update_customer_secure"].invoke({"field": "shipping_address", "new_value": "x"})
    assert "requires auth level 'mfa'" in out
    assert svc.effects.profile_writes == []


def test_restricted_high_risk_account_is_blocked(svc, tools_for):
    _, t = tools_for(svc, "SESS-1004")  # C1019, restricted, risk 95
    out = t["get_customer_secure"].invoke({"customer_id": "C1019"})
    assert "self-service disabled" in out or "requires auth level" in out


def test_customer_lookup_never_returns_pii(svc, tools_for):
    _, t = tools_for(svc)
    payload = json.loads(t["get_customer_secure"].invoke({"customer_id": "C1002"}))
    for field in ("email", "phone", "shipping_address", "billing_zip"):
        assert field not in payload


def test_email_recipient_comes_from_session(svc, tools_for):
    _, t = tools_for(svc)
    assert "to_email" not in t["send_email_secure"].args
    t["send_email_secure"].invoke({"subject": "hi", "body": "b"})
    assert svc.effects.emails_sent[0]["to"] == "liam.chen@example.com"
