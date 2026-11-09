from __future__ import annotations

import pytest

from shopease_agent.context import start_session
from shopease_agent.hitl import auto_approve
from shopease_agent.services import build_services
from shopease_agent.tools import make_secure_tools


@pytest.fixture
def make_svc(tmp_path):
    """Build fresh services; the SQLite ledger lives in this test's tmp dir."""
    counter = iter(range(1000))

    def _make(ledger: str = "atomic", approver=None, **kw):
        kwargs = {"db_path": tmp_path / f"ledger-{next(counter)}.db", **kw}
        if approver is not None:
            kwargs["approver"] = approver
        return build_services(ledger, **kwargs)

    return _make


@pytest.fixture
def tools_for():
    def _tools(svc, session_id="SESS-1001"):
        ctx = start_session(svc.data, session_id)
        return ctx, {t.name: t for t in make_secure_tools(ctx, svc)}

    return _tools


@pytest.fixture
def approve():
    return auto_approve
