"""Tamper-evident log, human approval, and the tool-chaining sequence rule."""

from shopease_agent.audit import AuditLog
from shopease_agent.hitl import ApprovalQueue, ApprovalRequest


def test_clean_chain_verifies():
    log = AuditLog()
    for i in range(5):
        log.append("event", {"i": i})
    assert log.verify() == (True, None)


def test_editing_an_entry_is_detected_at_that_entry():
    log = AuditLog()
    for amt in (34.50, 160.00, 150.00):
        log.append("issue_refund", {"amount_usd": amt})
    log.entries[1]["detail"]["amount_usd"] = 1.00  # make the loss reconcile
    assert log.verify() == (False, 1)


def test_deleting_an_entry_is_detected():
    log = AuditLog()
    for i in range(3):
        log.append("event", {"i": i})
    del log.entries[1]
    assert log.verify() == (False, 1)


def test_default_reviewer_denies():
    q = ApprovalQueue()
    assert q.request(ApprovalRequest("issue_refund", {}, "", "S", "C")) is False


def test_broken_reviewer_fails_closed():
    def broken(_):
        raise RuntimeError("review service down")

    assert ApprovalQueue(broken).request(ApprovalRequest("t", {}, "", "S", "C")) is False


def test_auto_deny_means_no_money_moves(make_svc, tools_for):
    svc = make_svc("atomic")
    _, t = tools_for(svc, "SESS-1003")  # Lucas, desk lamp
    out = t["issue_refund_secure"].invoke({"order_id": "O1010", "amount_usd": 34.50})
    assert out.startswith("NOT PROCESSED")
    assert svc.effects.refunds == []


def test_legit_refund_goes_through_with_a_reviewer(make_svc, tools_for, approve):
    svc = make_svc("atomic", approver=approve)
    _, t = tools_for(svc, "SESS-1003")
    out = t["issue_refund_secure"].invoke({"order_id": "O1010", "amount_usd": 34.50})
    assert out.startswith("Refund of $34.50 approved")
    assert svc.audit.of_type("issue_refund")


def test_refund_then_address_change_is_flagged_for_the_reviewer(make_svc, tools_for, approve):
    """Attack 8.3 with an MFA caller, so auth tiering is not what catches it."""
    svc = make_svc("atomic", approver=approve)
    _, t = tools_for(svc, "SESS-1002")
    t["issue_refund_secure"].invoke({"order_id": "O1004", "amount_usd": 200})
    t["update_customer_secure"].invoke({"field": "shipping_address",
                                        "new_value": "802 Dockside Row"})
    notes = [i.risk_note for i in svc.hitl.items]
    assert notes[0] == ""
    assert "FRAUD PATTERN" in notes[1] and "delivery-interception" in notes[1]
