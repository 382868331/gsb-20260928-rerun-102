#!/usr/bin/env python3
"""End-to-end demonstration of the authentication core.

Runs with the standard library only:

    python3 demo.py

Scenario: fictional-user login, concurrent renewal (one credential, many
threads), old-credential replay with the audit record, distinct handling of
expired/revoked/malformed credentials, and a fresh-process restart check that
proves revocation persists on disk.
"""

import os
import shutil
import sys
import tempfile
import threading
import time

from auth_core.errors import (
    AccountDisabledError,
    AccessTokenExpiredError,
    AuthError,
    InvalidCredentialsError,
    InvalidTokenError,
    RefreshTokenExpiredError,
    RevokedError,
    TokenFormatError,
    TokenReuseError,
)
from auth_core.seed import build_service
from auth_core.service import AuthService


def describe(exc):
    """Classify a refusal explicitly instead of masking it as a network error."""
    mapping = {
        InvalidCredentialsError: "REFUSED: invalid username or password",
        TokenFormatError: "REFUSED: malformed credential format",
        InvalidTokenError: "REFUSED: unrecognized credential",
        AccessTokenExpiredError: "REFUSED: access credential expired",
        RefreshTokenExpiredError: "REFUSED: renewal credential expired",
        TokenReuseError: "REFUSED: renewal replay detected, session revoked",
        AccountDisabledError: "REFUSED: account disabled",
        RevokedError: "REFUSED: credential revoked",
    }
    for error_type, text in mapping.items():
        if isinstance(exc, error_type):
            return text
    return f"UNEXPECTED ERROR: {exc!r}"


def expect_failure(label, fn):
    try:
        fn()
    except AuthError as exc:
        print(f"    {label}: {describe(exc)} ({type(exc).__name__})")
        return exc
    raise AssertionError(f"{label} should have failed")


def main():
    workdir = tempfile.mkdtemp(prefix="auth-demo-")
    store_path = os.path.join(workdir, "auth-state.json")
    print(f"state file: {store_path}")

    # Short lifetimes so expiry is demonstrable in seconds.
    auth = build_service(store_path, access_ttl=2, refresh_ttl=60)
    print("1) seeded fictional users: ada.lovelace, alan.turing, grace.hopper")

    print("2) login with a fictional local test user")
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")
    print(f"    family={tokens.family_id[:8]}... access and renewal credentials issued")
    principal = auth.verify_access_token(tokens.access_token)
    assert principal.username == "ada.lovelace"
    print("    access credential verified")
    expect_failure("wrong password", lambda: auth.login("ada.lovelace", "nope"))

    print("3) concurrent renewal with the same one-time credential")
    outcomes = []
    barrier = threading.Barrier(5)

    def worker():
        barrier.wait()
        try:
            outcome = auth.refresh(tokens.refresh_token)
            outcomes.append(("success", outcome))
        except AuthError as exc:
            outcomes.append(("failure", exc))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    successes = [outcome for outcome in outcomes if outcome[0] == "success"]
    replays = [outcome for outcome in outcomes if outcome[0] == "failure"]
    print(f"    {len(successes)} success(es), {len(replays)} rejection(s)")
    assert len(successes) == 1, "renewal credential may succeed exactly once"
    rotated = successes[0][1]
    assert isinstance(replays[0][1], TokenReuseError)
    print("    losing threads got TokenReuseError, not two valid chains")

    print("4) old credential replay (serial) and audit record")
    replay_error = expect_failure(
        "replay original credential",
        lambda: auth.refresh(tokens.refresh_token),
    )
    expect_failure(
        "new credential from the loser race is also dead",
        lambda: auth.refresh(rotated.refresh_token),
    )
    records = auth.list_reuse_records(username="ada.lovelace")
    print(f"    {len(records)} reuse record(s); raw credential is never stored")
    for record in records:
        print(
            f"      id={record['id']} reason={record['reason']} "
            f"digest={record['credential_digest'][:12]}..."
        )
    assert all("refresh_token" not in str(record) for record in records)
    matching = [record for record in records if record["id"] == replay_error.record_id]
    assert len(matching) == 1
    assert matching[0]["reason"] == "replayed_after_rotation"

    print("5) expiry, revocation and malformed credentials are distinguished")
    short_lived = AuthService(store_path, access_ttl=1, refresh_ttl=1)
    short = short_lived.login("grace.hopper", "Fiction!Grace-2026")
    time.sleep(2.2)
    expect_failure("expired access", lambda: short_lived.verify_access_token(short.access_token))
    expect_failure("expired renewal", lambda: short_lived.refresh(short.refresh_token))

    alan = auth.login("alan.turing", "Fiction!Alan-2026")
    auth.disable_user("alan.turing")
    expect_failure("access after disable", lambda: auth.verify_access_token(alan.access_token))
    expect_failure("renew after disable", lambda: auth.refresh(alan.refresh_token))
    expect_failure("login while disabled", lambda: auth.login("alan.turing", "Fiction!Alan-2026"))

    expect_failure("garbage credential", lambda: auth.verify_access_token("not-a-token"))
    ada2 = auth.login("ada.lovelace", "Fiction!Ada-2026")
    expect_failure(
        "wrong-type credential (renewal as access)",
        lambda: auth.verify_access_token(ada2.refresh_token),
    )

    print("6) logout revocation with a fresh session")
    auth.logout(ada2.refresh_token)
    expect_failure("access after logout", lambda: auth.verify_access_token(ada2.access_token))
    expect_failure("renew after logout", lambda: auth.refresh(ada2.refresh_token))

    print("7) restart check: brand-new AuthService over the same files")
    reloaded = AuthService(store_path)
    expect_failure("access survives restart as revoked", lambda: reloaded.verify_access_token(ada2.access_token))
    expect_failure("replay survives restart", lambda: reloaded.refresh(tokens.refresh_token))
    persistent_records = reloaded.list_reuse_records(username="ada.lovelace")
    assert len(persistent_records) >= 2
    print(f"    {len(persistent_records)} reuse records still queryable after restart")

    shutil.rmtree(workdir, ignore_errors=True)
    print("\nAll demo checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
