"""Minimal command-line interface to exercise the authentication core.

Examples:
    python -m authcore.cli --db a.json add-user alice pw
    python -m authcore.cli --db a.json login    alice pw --device-id phone-1 --device-name 手机
    python -m authcore.cli --db a.json check    at_...
    python -m authcore.cli --db a.json refresh  rf_...
    python -m authcore.cli --db a.json logout   at_...
    python -m authcore.cli --db a.json devices  alice
    python -m authcore.cli --db a.json freeze   alice phone-1
    python -m authcore.cli --db a.json rollover alice phone-1 [--name 新手机]
    python -m authcore.cli --db a.json freeze-compromised alice phone-1
    python -m authcore.cli --db a.json unfreeze alice phone-1
    python -m authcore.cli --db a.json lineage  alice phone-1
    python -m authcore.cli --db a.json rename-device alice phone-1 新手机
    python -m authcore.cli --db a.json disable  alice
    python -m authcore.cli --db a.json enable   alice
    python -m authcore.cli --db a.json events
    python -m authcore.cli --db a.json activity [alice]

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
    login_p = sub.add_parser("login")
    login_p.add_argument("args", nargs=2)
    login_p.add_argument("--device-id", default=None)
    login_p.add_argument("--device-name", default=None)
    for name in ("check", "refresh", "logout"):
        sub.add_parser(name).add_argument("args", nargs=1)
    sub.add_parser("disable").add_argument("args", nargs=1)
    sub.add_parser("enable").add_argument("args", nargs=1)
    sub.add_parser("devices").add_argument("args", nargs=1)
    sub.add_parser("freeze").add_argument("args", nargs=2)
    rollover_p = sub.add_parser("rollover")
    rollover_p.add_argument("args", nargs=2)
    rollover_p.add_argument("--name", default=None)
    sub.add_parser("freeze-compromised").add_argument("args", nargs=2)
    sub.add_parser("unfreeze").add_argument("args", nargs=2)
    sub.add_parser("lineage").add_argument("args", nargs=2)
    sub.add_parser("rename-device").add_argument("args", nargs=3)
    sub.add_parser("events")
    sub.add_parser("activity").add_argument("args", nargs="?")
    ns = parser.parse_args(argv)

    svc = AuthService(ns.db)
    args = getattr(ns, "args", [])
    try:
        if ns.cmd == "add-user":
            svc.create_user(args[0], args[1])
            print(json.dumps({"ok": True, "created": args[0]}, ensure_ascii=False))
        elif ns.cmd == "login":
            b = svc.login(args[0], args[1], device_id=ns.device_id,
                          device_name=ns.device_name)
            print(json.dumps({"ok": True, "access_token": b.access_token,
                             "refresh_token": b.refresh_token,
                             "family": b.family, "session_id": b.session_id,
                             "device_id": b.device_id}, ensure_ascii=False))
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
        elif ns.cmd == "enable":
            svc.enable_user(args[0])
            print(json.dumps({"ok": True, "enabled": args[0]}, ensure_ascii=False))
        elif ns.cmd == "devices":
            print(json.dumps(svc.list_devices(args[0]), ensure_ascii=False, indent=1))
        elif ns.cmd == "freeze":
            frozen = svc.logout_device(args[0], args[1])
            print(json.dumps({"ok": True, "frozen_chains": frozen},
                             ensure_ascii=False))
        elif ns.cmd == "rollover":
            result = svc.rollover_device(args[0], args[1], new_name=ns.name)
            print(json.dumps({
                "ok": True,
                "access_token": result.bundle.access_token,
                "refresh_token": result.bundle.refresh_token,
                "family": result.bundle.family,
                "device_id": result.device_id,
                "generation": result.generation,
                "superseded_sessions": list(result.superseded_sessions),
                "rule": result.rule,
            }, ensure_ascii=False))
        elif ns.cmd == "freeze-compromised":
            revoked = svc.freeze_device_compromised(args[0], args[1])
            print(json.dumps({"ok": True, "revoked_chains": revoked,
                              "device_frozen": True}, ensure_ascii=False))
        elif ns.cmd == "unfreeze":
            svc.unfreeze_device(args[0], args[1])
            print(json.dumps({"ok": True, "unfrozen": args[1],
                              "old_generations_stay_revoked": True},
                             ensure_ascii=False))
        elif ns.cmd == "lineage":
            print(json.dumps(svc.device_lineage(args[0], args[1]),
                             ensure_ascii=False, indent=1))
        elif ns.cmd == "rename-device":
            svc.rename_device(args[0], args[1], args[2])
            print(json.dumps({"ok": True, "renamed": args[1]}, ensure_ascii=False))
        elif ns.cmd == "events":
            print(json.dumps(svc.list_reuse_events(), ensure_ascii=False, indent=1))
        elif ns.cmd == "activity":
            print(json.dumps(svc.export_device_activity(args[0] if args else None),
                             ensure_ascii=False, indent=1))
    except AuthError as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__,
                          "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
