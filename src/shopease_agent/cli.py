"""Command line entry point: `shopease <command>`."""

from __future__ import annotations

import argparse
import os
import sys


def _race_demo(_: argparse.Namespace) -> int:
    from .race import run_refund_race
    from .services import build_services

    print("Attack 8.4: two $230 refunds on O1041 at the same moment.")
    print("O1041 is a $612 espresso machine with $180 already refunded, so $432 is left.")
    print("Each request alone is fine. Together they are $460.\n")
    for kind in ("memory", "atomic"):
        svc = build_services(kind)
        result = run_refund_race(svc)
        intact, bad = svc.audit.verify()
        print(result.summary())
        print(f"  audit chain intact: {intact}" + ("" if intact else f" (first bad entry #{bad})"))
        print()
    return 0


def _gates(args: argparse.Namespace) -> int:
    from .attacks import print_scorecard, replay_gates

    ledgers = ["memory", "atomic"] if args.ledger == "both" else [args.ledger]
    names = {"memory": "Secure agent, notebook ledger", "atomic": "Secure agent, atomic ledger"}
    for kind in ledgers:
        print_scorecard(replay_gates(kind), names[kind])
    return 0


def _need_key() -> bool:
    if os.getenv("ANTHROPIC_API_KEY"):
        return True
    print("ANTHROPIC_API_KEY is not set. Copy .env.example to .env and fill it in, or export it.\n"
          "`shopease race-demo` and `shopease gates` work without a key.", file=sys.stderr)
    return False


def _attacks(args: argparse.Namespace) -> int:
    if not _need_key():
        return 2
    if args.agent == "baseline":
        _run_baseline_suite()
    else:
        from .attacks import run_live_suite

        run_live_suite(args.ledger)
    return 0


def _run_baseline_suite() -> None:
    from .attacks import (
        ATTACK_A1,
        ATTACK_C1,
        CHAIN_TURNS,
        DRIFT_TURNS,
        POLICY_QUERY,
        SPLIT_TURNS,
    )
    from .baseline import BASELINE_SYSTEM_PROMPT, build_baseline_world, make_baseline_tools
    from .config import DATA_DIR, POLICY_PDF_RAG_POISONED
    from .corpus import build_vectorstore
    from .graph import build_agent_graph
    from .llm import make_llm
    from .runner import Conversation, baseline_guard

    llm = make_llm()
    world = build_baseline_world()
    app = build_agent_graph(llm, make_baseline_tools(world), BASELINE_SYSTEM_PROMPT)

    def convo(label: str, turns: list[str]) -> None:
        c = Conversation(app, label, baseline_guard)
        for t in turns:
            c.say(t)

    convo("6.1 canonical injection", [ATTACK_A1])
    convo("6.2 multi-turn drift", DRIFT_TURNS)
    world.knowledge = build_vectorstore(DATA_DIR / POLICY_PDF_RAG_POISONED)
    convo("7.1 poisoned policy", [POLICY_QUERY])
    convo("8.1 cross-account", [ATTACK_C1])
    convo("8.2 refund splitting", SPLIT_TURNS)
    convo("8.3 tool chaining", CHAIN_TURNS)
    print("\nBASELINE STATE")
    print("  refunds        :", world.refunds)
    print("  profile writes :", world.profile_writes)
    print("  foreign reads  :", [r for r in world.records_read if r["owner"] != "C1002"])


def _chat(args: argparse.Namespace) -> int:
    if not _need_key():
        return 2
    from .context import start_session
    from .graph import build_agent_graph
    from .hitl import interactive
    from .llm import make_llm
    from .runner import Conversation, make_secure_guard
    from .services import build_services
    from .tools import SECURE_SYSTEM_PROMPT, make_secure_tools

    svc = build_services(args.ledger, approver=interactive, with_knowledge=True,
                         fresh_db=False)
    ctx = start_session(svc.data, args.session)
    app = build_agent_graph(make_llm(), make_secure_tools(ctx, svc), SECURE_SYSTEM_PROMPT)
    convo = Conversation(app, f"chat as {ctx.customer_id} ({ctx.auth_level})",
                         make_secure_guard(svc.audit))
    print(f"Bound to {ctx.session_id} -> {ctx.customer_id}. Empty line to quit.")
    while True:
        try:
            text = input("\nyou> ").strip()
        except EOFError:
            break
        if not text:
            break
        convo.say(text)
    print("audit chain intact:", svc.audit.verify()[0])
    return 0


def _load_dotenv() -> None:
    """Read KEY=VALUE lines from .env at the project root. Real env vars win."""
    from .config import PROJECT_ROOT

    path = PROJECT_ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            if value.strip():
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main(argv: list[str] | None = None) -> int:
    _load_dotenv()
    parser = argparse.ArgumentParser(prog="shopease", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("race-demo", help="attack 8.4 on both ledgers (offline)").set_defaults(fn=_race_demo)

    g = sub.add_parser("gates", help="replay every attack straight at the gates (offline)")
    g.add_argument("--ledger", choices=["memory", "atomic", "both"], default="both")
    g.set_defaults(fn=_gates)

    a = sub.add_parser("attacks", help="replay the attacks as conversations with Claude")
    a.add_argument("--agent", choices=["baseline", "secure"], default="secure")
    a.add_argument("--ledger", choices=["memory", "atomic"], default="atomic")
    a.set_defaults(fn=_attacks)

    c = sub.add_parser("chat", help="talk to the secure agent; you are the human reviewer")
    c.add_argument("--session", default="SESS-1001")
    c.add_argument("--ledger", choices=["memory", "atomic"], default="atomic")
    c.set_defaults(fn=_chat)

    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
