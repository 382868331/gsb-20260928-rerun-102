import json
import os
import subprocess
import sys
import threading
import time

import pytest

from auth_core.errors import (
    AuthError,
    AccountDisabledError,
    AccessTokenExpiredError,
    InvalidCredentialsError,
    InvalidTokenError,
    RefreshTokenExpiredError,
    RevokedError,
    TokenFormatError,
    TokenReuseError,
)
from auth_core.seed import build_service
from auth_core.service import AuthService
from auth_core.tokens import hash_token, token_kind


def test_login_and_access_token_verify(auth):
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")
    principal = auth.verify_access_token(tokens.access_token)
    assert principal.username == "ada.lovelace"
    assert principal.family_id == tokens.family_id


@pytest.mark.parametrize(
    "username,password,error",
    [
        ("ada.lovelace", "wrong", InvalidCredentialsError),
        ("nobody", "whatever", InvalidCredentialsError),
        ("alan.turing", "", InvalidCredentialsError),
    ],
)
def test_login_failures_are_specific(auth, username, password, error):
    with pytest.raises(error):
        auth.login(username, password)


def test_refresh_token_rotates_exactly_once(auth):
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")
    rotated = auth.refresh(tokens.refresh_token)
    assert rotated.family_id == tokens.family_id
    assert rotated.refresh_token != tokens.refresh_token
    assert rotated.access_token != tokens.access_token
    # New pair works.
    assert auth.verify_access_token(rotated.access_token).username == "ada.lovelace"
    # Old refresh token is now replay: family revoked.
    with pytest.raises(TokenReuseError):
        auth.refresh(tokens.refresh_token)
    # Even the current refresh token is dead because the family was revoked.
    with pytest.raises(TokenReuseError):
        auth.refresh(rotated.refresh_token)
    # Access tokens are revoked with the family.
    with pytest.raises(TokenReuseError):
        auth.verify_access_token(rotated.access_token)


def test_concurrent_refresh_single_winner(auth):
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        try:
            results.append(("ok", auth.refresh(tokens.refresh_token)))
        except AuthError as exc:  # noqa: F401
            results.append(("fail", exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "fail"]
    assert len(winners) == 1
    assert all(isinstance(exc, TokenReuseError) for _, exc in losers)


def test_concurrent_refresh_from_separate_processes(store_path):
    build_service(store_path)  # seed
    auth = AuthService(store_path)
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")

    worker_code = r"""
import sys
sys.path.insert(0, "__ROOT__")
from auth_core.service import AuthService
from auth_core.errors import TokenReuseError
auth = AuthService("__STORE__")
try:
    rotated = auth.refresh("__TOKEN__")
    print("OK:" + rotated.refresh_token)
except TokenReuseError as exc:
    print("REUSE:%s" % exc.record_id)
"""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    worker_code = (
        worker_code.replace("__ROOT__", root)
        .replace("__STORE__", store_path)
        .replace("__TOKEN__", tokens.refresh_token)
    )

    import subprocess

    procs = [
        subprocess.Popen(
            [sys.executable, "-c", worker_code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    outputs = []
    for proc in procs:
        stdout, stderr = proc.communicate()
        outputs.append(stdout.strip())
        assert proc.returncode == 0, stderr

    ok = [line for line in outputs if line.startswith("OK:")]
    reuse = [line for line in outputs if line.startswith("REUSE:")]
    assert len(ok) == 1, outputs
    assert len(reuse) == 3, outputs


def test_replay_recorded_without_raw_credential(auth, store_path):
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")
    auth.refresh(tokens.refresh_token)  # legitimate one-time rotation
    with pytest.raises(TokenReuseError):
        auth.refresh(tokens.refresh_token)
    with pytest.raises(TokenReuseError) as exc_info:
        auth.refresh(tokens.refresh_token)
    records = auth.list_reuse_records()
    assert len(records) == 2
    record = records[-1]
    assert record["id"] == exc_info.value.record_id
    assert record["username"] == "ada.lovelace"
    assert record["family_id"] == tokens.family_id
    assert record["credential_digest"] == hash_token(tokens.refresh_token)
    assert record["credential_kind"] == "refresh"
    # Raw credential must never appear in the on-disk state.
    with open(store_path, encoding="utf-8") as handle:
        raw_state = handle.read()
    assert tokens.refresh_token not in raw_state
    assert tokens.access_token not in raw_state
    state = json.loads(raw_state)
    assert all("raw" not in key for key in state["reuse_records"][0])


def test_logout_revokes_session_and_persists(store_path):
    auth = build_service(store_path)
    tokens = auth.login("grace.hopper", "Fiction!Grace-2026")
    auth.logout(tokens.refresh_token)
    with pytest.raises(RevokedError):
        auth.verify_access_token(tokens.access_token)
    with pytest.raises(RevokedError):
        auth.refresh(tokens.refresh_token)
    # Idempotent logout.
    auth.logout(tokens.refresh_token)
    # Restart: revocation is durable.
    reloaded = AuthService(store_path)
    with pytest.raises(RevokedError):
        reloaded.verify_access_token(tokens.access_token)


def test_account_disable_revokes_all_sessions_and_persists(store_path):
    auth = build_service(store_path)
    first = auth.login("alan.turing", "Fiction!Alan-2026")
    rotated = auth.refresh(first.refresh_token)
    second = auth.login("alan.turing", "Fiction!Alan-2026")
    auth.disable_user("alan.turing")
    for tokens in (first, rotated, second):
        with pytest.raises((AccountDisabledError, TokenReuseError)):
            auth.verify_access_token(tokens.access_token)
    with pytest.raises(AccountDisabledError):
        auth.refresh(second.refresh_token)
    with pytest.raises(AccountDisabledError):
        auth.login("alan.turing", "Fiction!Alan-2026")

    reloaded = AuthService(store_path)
    with pytest.raises(AccountDisabledError):
        reloaded.verify_access_token(second.access_token)


def test_expired_access_and_refresh_distinguished(short_auth):
    tokens = short_auth.login("ada.lovelace", "Fiction!Ada-2026")
    time.sleep(1.2)
    with pytest.raises(AccessTokenExpiredError):
        short_auth.verify_access_token(tokens.access_token)
    with pytest.raises(RefreshTokenExpiredError):
        short_auth.refresh(tokens.refresh_token)


def test_malformed_and_unknown_credentials_distinguished(auth):
    with pytest.raises(TokenFormatError):
        token_kind("garbage")
    with pytest.raises(TokenFormatError):
        auth.verify_access_token("act_differentprefix")
    with pytest.raises(TokenFormatError):
        auth.verify_access_token("rft_" + "A" * 52)
    from auth_core.tokens import mint_access_token

    with pytest.raises(InvalidTokenError):
        auth.verify_access_token(mint_access_token())
    from auth_core.tokens import mint_refresh_token

    with pytest.raises(InvalidTokenError):
        auth.refresh(mint_refresh_token())


def test_only_hashes_are_persisted(auth, store_path, tokens=None):
    tokens = auth.login("ada.lovelace", "Fiction!Ada-2026")
    with open(store_path, encoding="utf-8") as handle:
        state_text = handle.read()
    assert tokens.access_token not in state_text
    assert tokens.refresh_token not in state_text
    state = json.loads(state_text)
    assert hash_token(tokens.access_token) in state["access_tokens"]


def test_reuse_records_filterable(auth):
    ada = auth.login("ada.lovelace", "Fiction!Ada-2026")
    grace = auth.login("grace.hopper", "Fiction!Grace-2026")
    auth.refresh(ada.refresh_token)
    auth.refresh(grace.refresh_token)
    with pytest.raises(TokenReuseError):
        auth.refresh(ada.refresh_token)
    with pytest.raises(TokenReuseError):
        auth.refresh(grace.refresh_token)
    assert len(auth.list_reuse_records(username="ada.lovelace")) == 1
    assert len(auth.list_reuse_records(family_id=grace.family_id)) == 1
    assert len(auth.list_reuse_records()) == 2
