"""Minimal command-line interface to exercise the authentication core.

Examples:
    python -m authcore.cli --db a.json add-user alice pw
    python -m authcore.cli --db a.json login    alice pw
    python -m authcore.cli --db a.json check    at_...
    python -m authcore.cli --db a.json refresh  rf_...
    python -m authcore.cli --db a.json logout   at_...
    python -m authcore.cli --db a.json disable  alice
    python -m authcore.cli --db a.json events

Exit code 0 means allowed; non-zero means rejected. The error type (never a
generic network failure) is printed to stderr.
"""

from __future__ import annotations

import argparse
import json
import sys

from .errors import AuthError
from .service import AuthService


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authcore")
    parser.add_argument("--db", default="authcore.json")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("add-user").add_argument("args", nargs=2)
    sub.add_parser("login").add_argument("args", nargs=2)
    for name in ("check", "refresh", "logout"):
        sub.add_parser(name).add_argument("args", nargs=1)
    sub.add_parser("disable").add_argument("args", nargs=1)
    sub.add_parser("events")
    ns = parser.parse_args(argv)

    svc = AuthService(ns.db)
    args = getattr(ns, "args", [])
    try:
        if ns.cmd == "add-user":
            svc.create_user(args[0], args[1])
            print(json.dumps({"ok": True, "created": args[0]}, ensure_ascii=False))
        elif ns.cmd == "login":
            b = svc.login(args[0], args[1])
            print(json.dumps({"ok": True, "access_token": b.access_token,
                             "refresh_token": b.refresh_token,
                             "family": b.family}, ensure_ascii=False))
        elif ns.cmd == "check":
            print(json.dumps({"ok": True, "username": svc.check_access(args[0])},
                             ensure_ascii=False))
        elif ns.cmd == "refresh":
            b = svc.refresh(args[0])
            print(json.dumps({"ok": True, "access_token": b.access_token,
                             "refresh_token": b.refresh_token,
                             "family": b.family}, ensure_ascii=False))
        elif ns.cmd == "logout":
            svc.logout(args[0])
            print(json.dumps({"ok": True, "logged_out": True}, ensure_ascii=False))
        elif ns.cmd == "disable":
            svc.disable_user(args[0])
            print(json.dumps({"ok": True, "disabled": args[0]}, ensure_ascii=False))
        elif ns.cmd == "events":
            print(json.dumps(svc.list_reuse_events(), ensure_ascii=False, indent=1))
    except AuthError as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__,
                          "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
