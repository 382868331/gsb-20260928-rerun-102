from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import (
    AccountDisabledError,
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
    TokenExpiredError,
    TokenReuseDetectedError,
    TokenRevokedError,
)
from .store import Store

TOKEN_RE = re.compile(r"^(at|rf)_[A-Za-z0-9_-]{32,128}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def hash_credential(raw: str) -> str:
    """SHA-256 hex digest. Used for tokens; the raw value is never stored."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_password(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 password verifier."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)


@dataclass(frozen=True)
class TokenBundle:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    family: str
    session_id: int = 0


class AuthService:
    def __init__(
        self,
        db_path: str = "authcore.json",
        access_ttl: timedelta = timedelta(minutes=15),
        refresh_ttl: timedelta = timedelta(days=7),
    ):
        self.store = Store(db_path)
        self.access_ttl = access_ttl
        self.refresh_ttl = refresh_ttl

    # ---- users -----------------------------------------------------------

    def create_user(self, username: str, password: str) -> None:
        salt = secrets.token_bytes(16)
        verifier = salt.hex() + "$" + hash_password(password, salt).hex()
        with self.store.transaction() as data:
            if username in data["users"]:
                raise ValueError(f"user already exists: {username}")
            data["users"][username] = {
                "pwd_hash": verifier,
                "disabled": False,
                "created_at": _now().isoformat(),
            }

    def disable_user(self, username: str) -> None:
        """Deactivate the account and revoke every session it owns."""
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            user["disabled"] = True
            for session in data["sessions"].values():
                if session["username"] == username and not session["revoked"]:
                    self._revoke_session(data, session["id"], "account disabled")
                    self._record_activity(
                        data, "revoke", session, detail="account disabled"
                    )

    def enable_user(self, username: str) -> None:
        """Reactivate a disabled account.

        Previously revoked sessions stay revoked (they are never resurrected);
        the user must log in again, which creates fresh devices/chains.
        """
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            user["disabled"] = False

    # ---- login / logout --------------------------------------------------

    def login(
        self,
        username: str,
        password: str,
        device_id: str = "default",
        device_name: str | None = None,
    ) -> TokenBundle:
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown username")
            salt_hex, digest_hex = user["pwd_hash"].split("$", 1)
            expected = bytes.fromhex(digest_hex)
            given = hash_password(password, bytes.fromhex(salt_hex))
            if not hmac.compare_digest(expected, given):
                raise InvalidCredentialsError("password mismatch")
            if user["disabled"]:
                raise AccountDisabledError("account is disabled")
            label = device_name or device_id
            data["devices"].setdefault(username, {})[device_id] = label
            bundle = self._issue_bundle(data, username, device_id, label)
            session = data["sessions"][str(bundle.session_id)]
            self._record_activity(
                data, "login", session, detail="device login"
            )
            return bundle

    def rename_device(self, username: str, device_id: str, new_name: str) -> None:
        """Update the display name of a device.

        Only the device registry and the live sessions are relabelled; past
        audit/activity records keep the device id and the name snapshot that
        was captured when each event occurred, so attribution never changes.
        """
        with self.store.transaction() as data:
            if username not in data["users"]:
                raise InvalidCredentialsError("unknown user")
            devices = data["devices"].setdefault(username, {})
            if device_id not in devices:
                raise InvalidTokenError("unknown device for this user")
            devices[device_id] = new_name
            for session in data["sessions"].values():
                if session["username"] == username and session.get("device_id") == device_id:
                    session["device_name"] = new_name

    def logout(self, access_token: str) -> None:
        """Revoke the session backing this access token (and its refresh chain)."""
        self._check_shape(access_token, expect_prefix="at_")
        th = hash_credential(access_token)
        with self.store.transaction() as data:
            at = data["access"].get(th)
            if at is None:
                raise InvalidTokenError("unknown access token")
            session = data["sessions"][str(at["session_id"])]
            self._revoke_session(data, at["session_id"], "user logout")
            self._record_activity(data, "revoke", session, detail="user logout")

    def logout_device(self, username: str, device_id: str) -> int:
        """Revoke every session owned by one device; other devices stay live."""
        revoked = 0
        with self.store.transaction() as data:
            if username not in data["users"]:
                raise InvalidCredentialsError("unknown user")
            for session in data["sessions"].values():
                if (
                    session["username"] == username
                    and session.get("device_id") == device_id
                    and not session["revoked"]
                ):
                    self._revoke_session(data, session["id"], "device logout")
                    self._record_activity(
                        data, "revoke", session, detail="device logout"
                    )
                    revoked += 1
        return revoked

    # ---- access check ----------------------------------------------------

    def check_access(self, access_token: str) -> str:
        """Return the owning username when the credential is usable, else raise."""
        self._check_shape(access_token, expect_prefix="at_")
        th = hash_credential(access_token)
        with self.store.connect() as data:
            at = data["access"].get(th)
            if at is None:
                raise InvalidTokenError("unknown access token")
            session = data["sessions"][str(at["session_id"])]
            user = data["users"].get(session["username"])
            if user is not None and user["disabled"]:
                raise AccountDisabledError("account is disabled")
            if at["revoked"] or session["revoked"]:
                raise TokenRevokedError("credential or session revoked")
            if _now() >= datetime.fromisoformat(at["expires_at"]):
                raise TokenExpiredError("access token expired")
            return session["username"]

    # ---- refresh rotation -----------------------------------------------

    def refresh(self, refresh_token: str) -> TokenBundle:
        """Rotate a refresh credential exactly once.

        Concurrent calls on the same credential are serialized by an
        exclusive file lock: the winner rotates it, every loser observes the
        consumed credential, the reuse is recorded, and the whole family is
        revoked. Two unrelated valid chains can therefore never be issued.
        """
        self._check_shape(refresh_token, expect_prefix="rf_")
        th = hash_credential(refresh_token)
        pending_error: Exception | None = None
        bundle: TokenBundle | None = None
        with self.store.transaction() as data:
            cred = data["refresh"].get(th)
            if cred is None:
                raise InvalidTokenError("unknown refresh token")
            session = data["sessions"][str(cred["session_id"])]
            username = session["username"]
            user = data["users"].get(username)

            def record_reuse(detail: str) -> None:
                data["reuse"].append(
                    {
                        "observed_at": _now().isoformat(),
                        "family": cred["family"],
                        "session_id": cred["session_id"],
                        "username": username,
                        "device_id": session.get("device_id", "default"),
                        "device_name": session.get(
                            "device_name", session.get("device_id", "default")
                        ),
                        "credential_id": cred["id"],
                        "presented_hash": th,
                        "detail": detail,
                    }
                )
                self._record_activity(
                    data, "reject", session, credential_hash=th, detail=detail
                )

            if user is not None and user["disabled"]:
                record_reuse("use after account disabled")
                self._revoke_session(data, cred["session_id"], "account disabled")
                pending_error = AccountDisabledError("account is disabled")

            if pending_error is None and _now() >= datetime.fromisoformat(cred["expires_at"]):
                raise TokenExpiredError("refresh token expired")

            if pending_error is None and cred["used"]:
                # Replay of an already consumed credential => break the chain.
                record_reuse("replay of consumed refresh credential")
                self._revoke_session(data, cred["session_id"], "refresh reuse detected")
                pending_error = TokenReuseDetectedError(
                    "refresh credential was already used; "
                    f"family {cred['family']} frozen "
                    f"(device={session.get('device_id')}, "
                    f"session={cred['session_id']})"
                )

            if pending_error is None and (cred["revoked"] or session["revoked"]):
                record_reuse("use of revoked refresh credential")
                self._revoke_session(data, cred["session_id"], "revoked credential used")
                pending_error = TokenRevokedError("refresh credential revoked")

            if pending_error is None:
                now = _now()
                new_access = "at_" + secrets.token_urlsafe(32)
                new_refresh = "rf_" + secrets.token_urlsafe(32)
                session_id = cred["session_id"]
                family = cred["family"]
                data["seq"] += 1
                new_id = data["seq"]
                data["access"][hash_credential(new_access)] = {
                    "session_id": session_id,
                    "issued_at": now.isoformat(),
                    "expires_at": (now + self.access_ttl).isoformat(),
                    "revoked": False,
                }
                data["refresh"][hash_credential(new_refresh)] = {
                    "id": new_id,
                    "session_id": session_id,
                    "family": family,
                    "predecessor": cred["id"],
                    "issued_at": now.isoformat(),
                    "expires_at": (now + self.refresh_ttl).isoformat(),
                    "used": False,
                    "used_at": None,
                    "revoked": False,
                }
                cred["used"] = True
                cred["used_at"] = now.isoformat()
                cred["replaced_by"] = new_id
                bundle = TokenBundle(
                    access_token=new_access,
                    refresh_token=new_refresh,
                    access_expires_at=now + self.access_ttl,
                    refresh_expires_at=now + self.refresh_ttl,
                    family=family,
                    session_id=session_id,
                )
                self._record_activity(
                    data, "refresh", session, credential_hash=th,
                    detail="refresh rotation",
                )
        if pending_error is not None:
            raise pending_error
        assert bundle is not None
        return bundle

    # ---- reuse audit -----------------------------------------------------

    def list_reuse_events(self, family: str | None = None) -> list[dict]:
        """Query credential-reuse records. Raw credentials are never returned."""
        with self.store.connect() as data:
            events = data["reuse"]
            if family is not None:
                events = [e for e in events if e["family"] == family]
            return [dict(e) for e in events]

    # ---- device & activity views ------------------------------------------

    def list_devices(self, username: str) -> list[dict]:
        """List every session of a user grouped by login device.

        The display name is resolved through the device registry, so a rename
        is reflected here while historical audit records stay untouched.
        """
        with self.store.connect() as data:
            if username not in data["users"]:
                raise InvalidCredentialsError("unknown user")
            registry = data["devices"].get(username, {})
            devices: dict[str, dict] = {}
            for session in data["sessions"].values():
                if session["username"] != username:
                    continue
                device_id = session.get("device_id", "default")
                entry = devices.setdefault(
                    device_id,
                    {
                        "device_id": device_id,
                        "device_name": registry.get(
                            device_id, session.get("device_name", device_id)
                        ),
                        "sessions": [],
                    },
                )
                entry["sessions"].append(
                    {
                        "session_id": session["id"],
                        "family": session["family"],
                        "created_at": session["created_at"],
                        "revoked": session["revoked"],
                        "revoke_reason": session["revoke_reason"],
                    }
                )
            return list(devices.values())

    def list_activity(
        self,
        username: str | None = None,
        device_id: str | None = None,
        kind: str | None = None,
    ) -> list[dict]:
        """Export the device activity log.

        Events distinguish actual logins, refresh rotations, revocations and
        rejected attempts. Only SHA-256 hashes of presented credentials are
        stored, never the raw credentials, so the export is safe to share.
        """
        with self.store.connect() as data:
            events = data["activity"]
            if username is not None:
                events = [e for e in events if e["username"] == username]
            if device_id is not None:
                events = [e for e in events if e["device_id"] == device_id]
            if kind is not None:
                events = [e for e in events if e["kind"] == kind]
            return [dict(e) for e in events]

    # ---- internals -------------------------------------------------------

    @staticmethod
    def _check_shape(token: str, expect_prefix: str) -> None:
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            raise MalformedTokenError("credential is not a well-formed token")
        if not token.startswith(expect_prefix):
            raise MalformedTokenError(
                f"expected a {expect_prefix.rstrip('_')} credential"
            )

    @staticmethod
    def _record_activity(
        data: dict,
        kind: str,
        session: dict,
        credential_hash: str | None = None,
        detail: str = "",
    ) -> None:
        """Append one audit event. Never stores raw credentials."""
        data["activity"].append(
            {
                "observed_at": _now().isoformat(),
                "kind": kind,
                "username": session["username"],
                "device_id": session.get("device_id", "default"),
                "device_name": session.get(
                    "device_name", session.get("device_id", "default")
                ),
                "session_id": session["id"],
                "family": session["family"],
                "credential_hash": credential_hash,
                "detail": detail,
            }
        )

    def _issue_bundle(
        self,
        data: dict,
        username: str,
        device_id: str = "default",
        device_name: str | None = None,
    ) -> TokenBundle:
        now = _now()
        family = secrets.token_hex(16)
        access = "at_" + secrets.token_urlsafe(32)
        refresh = "rf_" + secrets.token_urlsafe(32)
        data["seq"] += 1
        session_id = data["seq"]
        data["sessions"][str(session_id)] = {
            "id": session_id,
            "username": username,
            "device_id": device_id,
            "device_name": device_name or device_id,
            "family": family,
            "created_at": now.isoformat(),
            "revoked": False,
            "revoke_reason": None,
        }
        data["access"][hash_credential(access)] = {
            "session_id": session_id,
            "issued_at": now.isoformat(),
            "expires_at": (now + self.access_ttl).isoformat(),
            "revoked": False,
        }
        data["seq"] += 1
        cred_id = data["seq"]
        data["refresh"][hash_credential(refresh)] = {
            "id": cred_id,
            "session_id": session_id,
            "family": family,
            "predecessor": None,
            "issued_at": now.isoformat(),
            "expires_at": (now + self.refresh_ttl).isoformat(),
            "used": False,
            "used_at": None,
            "revoked": False,
        }
        return TokenBundle(
            access_token=access,
            refresh_token=refresh,
            access_expires_at=now + self.access_ttl,
            refresh_expires_at=now + self.refresh_ttl,
            family=family,
            session_id=session_id,
        )

    @staticmethod
    def _revoke_session(data: dict, session_id: int, reason: str) -> None:
        session = data["sessions"].get(str(session_id))
        if session is not None:
            session["revoked"] = True
            session["revoke_reason"] = reason
        for at in data["access"].values():
            if at["session_id"] == session_id:
                at["revoked"] = True
        for rf in data["refresh"].values():
            if rf["session_id"] == session_id:
                rf["revoked"] = True
