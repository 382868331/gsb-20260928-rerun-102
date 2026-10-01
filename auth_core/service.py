"""Authentication core: login, access-credential checks, one-time renewal.

Renewal credentials rotate inside a *family* (one login session). A refresh
credential succeeds at most once. Presenting an already-rotated credential is
reuse and revokes the whole family. All revocation state is persisted, so it
survives process restart.
"""

from dataclasses import dataclass

from .errors import (
    AccountDisabledError,
    AccessTokenExpiredError,
    InvalidCredentialsError,
    InvalidTokenError,
    RefreshTokenExpiredError,
    RevokedError,
    TokenFormatError,
    TokenReuseError,
)
from .store import FileStore, now
from .tokens import (
    hash_password,
    hash_token,
    mint_access_token,
    mint_refresh_token,
    token_kind,
    verify_password,
)

DEFAULT_ACCESS_TTL_SECONDS = 15 * 60
DEFAULT_REFRESH_TTL_SECONDS = 7 * 24 * 60 * 60

REASON_LOGOUT = "logout"
REASON_ACCOUNT_DISABLED = "account_disabled"
REASON_REFRESH_REUSE = "refresh_reuse"


@dataclass(frozen=True)
class IssuedTokens:
    username: str
    family_id: str
    access_token: str
    refresh_token: str
    access_expires_at: int
    refresh_expires_at: int


@dataclass(frozen=True)
class Principal:
    username: str
    family_id: str
    session_id: str
    access_token_hash: str
    expires_at: int


class AuthService:
    def __init__(
        self,
        store,
        access_ttl=DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl=DEFAULT_REFRESH_TTL_SECONDS,
    ):
        if isinstance(store, str):
            store = FileStore(store)
        self.store = store
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl

    # ------------------------------------------------------------------ users

    def create_user(self, username, password):
        with self.store.mutate() as state:
            if username in state["users"]:
                raise ValueError(f"user already exists: {username}")
            state["users"][username] = {
                "password": hash_password(password),
                "enabled": True,
                "created_at": now(),
            }

    def disable_user(self, username):
        """Disable the account and revoke every surviving session/family."""
        with self.store.mutate() as state:
            user = state["users"].get(username)
            if user is None:
                raise KeyError(f"unknown user: {username}")
            user["enabled"] = False
            for family in state["families"].values():
                if family["username"] == username and family["status"] == "active":
                    self._revoke_family(state, family["family_id"], REASON_ACCOUNT_DISABLED)

    def enable_user(self, username):
        with self.store.mutate() as state:
            user = state["users"].get(username)
            if user is None:
                raise KeyError(f"unknown user: {username}")
            user["enabled"] = True

    def is_enabled(self, username):
        with self.store.read() as state:
            user = state["users"].get(username)
            return bool(user and user["enabled"])

    # ------------------------------------------------------------------ login

    def login(self, username, password):
        with self.store.mutate() as state:
            user = state["users"].get(username)
            if user is None or not verify_password(password, user["password"]):
                raise InvalidCredentialsError("invalid username or password")
            if not user["enabled"]:
                raise AccountDisabledError(f"account disabled: {username}")
            import uuid

            family_id = uuid.uuid4().hex
            return self._issue_family(state, username, family_id)

    def _issue_family(self, state, username, family_id):
        issued_at = now()
        access_raw = mint_access_token()
        refresh_raw = mint_refresh_token()
        access_hash = hash_token(access_raw)
        refresh_hash = hash_token(refresh_raw)
        access_expires = issued_at + self.access_ttl
        refresh_expires = issued_at + self.refresh_ttl

        state["families"][family_id] = {
            "family_id": family_id,
            "session_id": family_id,
            "username": username,
            "status": "active",
            "created_at": issued_at,
            "current_refresh_hash": refresh_hash,
            "revoked_at": None,
            "revocation_reason": None,
        }
        state["access_tokens"][access_hash] = {
            "username": username,
            "family_id": family_id,
            "status": "active",
            "issued_at": issued_at,
            "expires_at": access_expires,
            "revoked_at": None,
            "revocation_reason": None,
        }
        state["refresh_tokens"][refresh_hash] = {
            "username": username,
            "family_id": family_id,
            "status": "active",
            "issued_at": issued_at,
            "expires_at": refresh_expires,
            "rotated_at": None,
            "revoked_at": None,
            "revocation_reason": None,
        }
        return IssuedTokens(
            username=username,
            family_id=family_id,
            access_token=access_raw,
            refresh_token=refresh_raw,
            access_expires_at=access_expires,
            refresh_expires_at=refresh_expires,
        )

    # ----------------------------------------------------------- verification

    def verify_access_token(self, token):
        kind = token_kind(token)
        if kind != "access":
            raise TokenFormatError("expected an access credential, got a renewal credential")
        digest = hash_token(token)
        with self.store.read() as state:
            record = state["access_tokens"].get(digest)
            if record is None:
                raise InvalidTokenError("unrecognized access credential")
            user = state["users"].get(record["username"])
            if user is not None and not user["enabled"]:
                raise AccountDisabledError(f"account disabled: {record['username']}")
            if record["status"] != "active":
                raise self._revocation_error(record, state)
            if record["expires_at"] <= now():
                raise AccessTokenExpiredError("access credential has expired")
            return Principal(
                username=record["username"],
                family_id=record["family_id"],
                session_id=record["family_id"],
                access_token_hash=digest,
                expires_at=record["expires_at"],
            )

    @staticmethod
    def _revocation_error(record, state):
        reason = record.get("revocation_reason")
        if reason == REASON_ACCOUNT_DISABLED:
            return AccountDisabledError("account has been disabled")
        if reason == REASON_REFRESH_REUSE:
            family_id = record["family_id"]
            latest = AuthService._latest_record(state, family_id)
            return TokenReuseError(
                "session revoked because a rotated renewal credential was replayed",
                record_id=latest["id"] if latest else None,
            )
        if reason == REASON_LOGOUT:
            return RevokedError("credential revoked by logout")
        return RevokedError("credential has been revoked")

    @staticmethod
    def _latest_record(state, family_id):
        records = [r for r in state["reuse_records"] if r["family_id"] == family_id]
        return records[-1] if records else None

    # -------------------------------------------------------------- renewal

    def refresh(self, refresh_token):
        """Rotate a renewal credential exactly once.

        Replaying a rotated (or already-revoked) credential revokes the entire
        family and raises a distinct TokenReuseError/RevokedError.
        """
        kind = token_kind(refresh_token)
        if kind != "refresh":
            raise TokenFormatError("expected a renewal credential, got an access credential")
        digest = hash_token(refresh_token)
        with self.store.mutate() as state:
            record = state["refresh_tokens"].get(digest)
            if record is None:
                raise InvalidTokenError("unrecognized renewal credential")

            family = state["families"].get(record["family_id"])
            username = record["username"]
            user = state["users"].get(username)
            if user is not None and not user["enabled"]:
                self._record_reuse(
                    state,
                    username=username,
                    family_id=record["family_id"],
                    digest=digest,
                    reason="use_after_account_disabled",
                )
                raise AccountDisabledError(f"account disabled: {username}")

            if record["status"] == "rotated":
                self._revoke_family(state, record["family_id"], REASON_REFRESH_REUSE)
                saved = self._record_reuse(
                    state,
                    username=username,
                    family_id=record["family_id"],
                    digest=digest,
                    reason="replayed_after_rotation",
                )
                raise TokenReuseError(
                    "renewal credential was already used; whole session revoked",
                    record_id=saved["id"],
                )

            if record["status"] == "revoked":
                reason = family["revocation_reason"] if family else record.get("revocation_reason")
                self._record_reuse(
                    state,
                    username=username,
                    family_id=record["family_id"],
                    digest=digest,
                    reason="use_after_revocation",
                )
                if reason == REASON_REFRESH_REUSE:
                    latest = self._latest_record(state, record["family_id"])
                    raise TokenReuseError(
                        "renewal credential belongs to a revoked session (reuse detected)",
                        record_id=latest["id"] if latest else None,
                    )
                if reason == REASON_ACCOUNT_DISABLED:
                    raise AccountDisabledError("account has been disabled")
                raise RevokedError("renewal credential revoked by logout")

            if record["expires_at"] <= now():
                raise RefreshTokenExpiredError("renewal credential has expired")

            # Active credential: rotate it and mint the next pair in-place,
            # all under the same lock, so concurrent refreshes cannot fork the
            # family into two independent valid chains.
            record["status"] = "rotated"
            record["rotated_at"] = now()
            issued_at = now()
            access_raw = mint_access_token()
            refresh_raw = mint_refresh_token()
            access_hash = hash_token(access_raw)
            new_refresh_hash = hash_token(refresh_raw)
            access_expires = issued_at + self.access_ttl
            refresh_expires = issued_at + self.refresh_ttl

            state["access_tokens"][access_hash] = {
                "username": username,
                "family_id": record["family_id"],
                "status": "active",
                "issued_at": issued_at,
                "expires_at": access_expires,
                "revoked_at": None,
                "revocation_reason": None,
            }
            state["refresh_tokens"][new_refresh_hash] = {
                "username": username,
                "family_id": record["family_id"],
                "status": "active",
                "issued_at": issued_at,
                "expires_at": refresh_expires,
                "rotated_at": None,
                "revoked_at": None,
                "revocation_reason": None,
            }
            family["current_refresh_hash"] = new_refresh_hash
            return IssuedTokens(
                username=username,
                family_id=record["family_id"],
                access_token=access_raw,
                refresh_token=refresh_raw,
                access_expires_at=access_expires,
                refresh_expires_at=refresh_expires,
            )

    # ------------------------------------------------------------- revocation

    def logout(self, refresh_token):
        """Revoke the session/family identified by a renewal credential."""
        kind = token_kind(refresh_token)
        if kind != "refresh":
            raise TokenFormatError("logout requires a renewal credential")
        digest = hash_token(refresh_token)
        with self.store.mutate() as state:
            record = state["refresh_tokens"].get(digest)
            if record is None:
                raise InvalidTokenError("unrecognized renewal credential")
            family = state["families"][record["family_id"]]
            if family["status"] != "active":
                return  # already revoked; logout is idempotent
            self._revoke_family(state, family["family_id"], REASON_LOGOUT)

    def _revoke_family(self, state, family_id, reason):
        family = state["families"].get(family_id)
        if family is None:
            return
        family["status"] = "revoked"
        family["revoked_at"] = now()
        family["revocation_reason"] = reason
        family["current_refresh_hash"] = None
        family["status"] = "revoked"
        family["revoked_at"] = now()
        family["revocation_reason"] = reason
        family["current_refresh_hash"] = None
        for section in (state["access_tokens"], state["refresh_tokens"]):
            for record in section.values():
                if (
                    record["family_id"] == family_id
                    and record["status"] == "active"
                ):
                    record["status"] = "revoked"
                    record["revoked_at"] = now()
                    record["revocation_reason"] = reason

    # ----------------------------------------------------------- reuse audit

    def _record_reuse(self, state, username, family_id, digest, reason):
        record = {
            "id": state["next_record_id"],
            "recorded_at": now(),
            "username": username,
            "family_id": family_id,
            "credential_kind": "refresh",
            # SHA-256 digest only; the raw credential is never stored/logged.
            "credential_digest": digest,
            "reason": reason,
        }
        state["next_record_id"] += 1
        state["reuse_records"].append(record)
        return record

    def list_reuse_records(self, username=None, family_id=None):
        with self.store.read() as state:
            records = list(state["reuse_records"])
        if username is not None:
            records = [r for r in records if r["username"] == username]
        if family_id is not None:
            records = [r for r in records if r["family_id"] == family_id]
        return records
