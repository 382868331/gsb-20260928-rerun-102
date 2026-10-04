from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import (
    AccountDisabledError,
    ChainSupersededError,
    ChainWoundDownError,
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
    TokenExpiredError,
    TokenReuseDetectedError,
    TokenRevokedError,
)
from .store import Store

TOKEN_RE = re.compile(r"^(at|rf)_[A-Za-z0-9_-]{32,128}$")

# Decision rule announced before a planned rotation takes effect. Every
# in-flight request from the old chain is judged by this fixed rule, never by
# how late it happens to arrive.
ROTATION_RULE = (
    "planned rotation: new refresh family becomes active; the old chain can "
    "no longer create renewals; old access credentials already issued stay "
    "usable until the wind-down deadline; requests arriving afterwards are "
    "denied; the new chain is never fused by late old-chain requests"
)


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
    session_id: int
    device_id: str


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
                "devices": {},
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
                    self._record(
                        data, "revoke", session,
                        detail="account disabled; session revoked",
                    )

    def enable_user(self, username: str) -> None:
        """Reactivate a disabled account.

        Sessions revoked by the disable stay revoked; the user must log in
        again from each device.
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
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> TokenBundle:
        """Start a new session bound to a login device.

        ``device_id`` is the stable identity of the device; every refresh of
        the resulting chain keeps that identity. ``device_name`` is a
        display label that can be renamed later without touching the audit
        attribution of events that already happened.
        """
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
            device_id = device_id or ("dev_" + secrets.token_hex(8))
            device_name = device_name or device_id
            devices = user.setdefault("devices", {})
            if device_id not in devices:
                devices[device_id] = {
                    "name": device_name,
                    "first_seen_at": _now().isoformat(),
                }
            device = devices[device_id]
            lineage = device.get("lineage_id")
            if lineage is None:
                lineage = "lin_" + secrets.token_hex(12)
                device["lineage_id"] = lineage
            # A re-login (after logout, freeze or account re-enable) attaches
            # to the most recent chain of the device so the lineage survives
            # across every kind of interruption.
            predecessor = device.get("last_chain_session")
            bundle = self._issue_bundle(
                data, username, device_id,
                lineage_id=lineage, generation=device.get("generation", 0),
            )
            new_session = data["sessions"][str(bundle.session_id)]
            new_session["predecessor_session"] = predecessor
            device["last_chain_session"] = bundle.session_id
            session = data["sessions"][str(bundle.session_id)]
            self._record(data, "login", session, detail="device login")
            return bundle

    def logout(self, access_token: str) -> None:
        """Revoke the session backing this access token (and its refresh chain)."""
        self._check_shape(access_token, expect_prefix="at_")
        th = hash_credential(access_token)
        with self.store.transaction() as data:
            at = data["access"].get(th)
            if at is None:
                raise InvalidTokenError("unknown access token")
            self._revoke_session(data, at["session_id"], "user logout")
            session = data["sessions"][str(at["session_id"])]
            self._record(data, "revoke", session, detail="user logout")

    def logout_device(self, username: str, device_id: str) -> int:
        """Freeze every active session chain of one device only.

        Other devices of the same account keep their sessions. Returns the
        number of session chains that were revoked.
        """
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            frozen = 0
            for session in data["sessions"].values():
                if (
                    session["username"] == username
                    and session.get("device_id") == device_id
                    and not session["revoked"]
                ):
                    self._revoke_session(data, session["id"], "device frozen by user")
                    self._record(
                        data, "revoke", session,
                        detail="device chain frozen by user",
                    )
                    frozen += 1
            return frozen

    # ---- credential rotation -------------------------------------------

    def rotate_device_credentials(
        self,
        username: str,
        device_id: str,
        password: str,
        device_name: str | None = None,
        winddown: timedelta | None = None,
    ) -> dict:
        """Plan-driven credential rotation for one device.

        A brand-new login chain (new family) is issued for the same device,
        so the device keeps one continuous activity attribution. Every
        currently active chain of the device retires under the rule shown
        ahead of the rotation (``ROTATION_RULE``): its refresh credentials
        can no longer create renewals, while access credentials already in
        flight stay usable until ``winddown_until``. Retiring is not a
        reuse fuse, so a late request from the old chain can never freeze
        the new chain.

        Returns the new bundle plus the rule and the wind-down deadline so
        callers can display the exact acceptance rule before old requests
        settle.
        """
        winddown = self.access_ttl if winddown is None else winddown
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown username")
            salt_hex, digest_hex = user["pwd_hash"].split("$", 1)
            given = hash_password(password, bytes.fromhex(salt_hex))
            if not hmac.compare_digest(bytes.fromhex(digest_hex), given):
                raise InvalidCredentialsError("password mismatch")
            if user["disabled"]:
                raise AccountDisabledError("account is disabled")
            devices = user.setdefault("devices", {})
            if device_id not in devices:
                raise InvalidTokenError("unknown device for this user")
            if device_name is not None:
                devices[device_id]["name"] = device_name

            lineage = devices[device_id].setdefault(
                "lineage_id", "lin_" + secrets.token_hex(12)
            )
            generation = devices[device_id].get("generation", 0) + 1
            rotation_id = "rot_" + secrets.token_hex(8)
            now = _now()
            winddown_until = now + winddown

            retired = []
            for session in data["sessions"].values():
                if (
                    session["username"] == username
                    and session.get("device_id") == device_id
                    and not session["revoked"]
                    and not session.get("retired")
                ):
                    session["retired"] = True
                    session["retired_reason"] = "planned rotation"
                    session["winddown_until"] = winddown_until.isoformat()
                    session["rotation_id"] = rotation_id
                    for rf in data["refresh"].values():
                        if rf["session_id"] == session["id"] and not rf["used"]:
                            rf["revoked"] = True
                    retired.append(session["id"])
                    self._record(
                        data, "rotate", session,
                        detail=(
                            "planned rotation " + rotation_id
                            + "; old chain retired; " + ROTATION_RULE
                        ),
                        rotation_id=rotation_id,
                        generation=generation,
                        winddown_until=winddown_until.isoformat(),
                    )

            bundle = self._issue_bundle(
                data, username, device_id,
                lineage_id=lineage, generation=generation,
            )
            new_session = data["sessions"][str(bundle.session_id)]
            new_session["predecessor_session"] = retired[-1] if retired else (
                devices[device_id].get("last_chain_session")
            )
            for old_id in retired:
                data["sessions"][str(old_id)]["replaced_by_session"] = bundle.session_id
            devices[device_id]["generation"] = generation
            devices[device_id]["last_chain_session"] = bundle.session_id
            devices[device_id]["last_rotation_id"] = rotation_id
            self._record(
                data, "login", new_session,
                detail="new login chain after planned rotation " + rotation_id,
                rotation_id=rotation_id,
                generation=generation,
                winddown_until=winddown_until.isoformat(),
            )
            return {
                "bundle": bundle,
                "lineage_id": lineage,
                "generation": generation,
                "rotation_id": rotation_id,
                "retired_sessions": retired,
                "winddown_until": winddown_until,
                "rule": ROTATION_RULE,
            }

    def emergency_freeze_device(
        self, username: str, device_id: str, reason: str = "suspected leak"
    ) -> dict:
        """Immediate freeze used when credentials may be compromised.

        Unlike a planned rotation this grants no wind-down: every chain the
        device ever started that is not already hard-revoked is revoked now,
        including old chains merely living out a rotation window, and all
        unfinished authorizations (access + refresh credentials) die. The
        device must authenticate again to obtain a chain; other devices are
        untouched. Re-enabling the account later never revives these chains.
        """
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            device = user.setdefault("devices", {}).get(device_id)
            if device is None:
                raise InvalidTokenError("unknown device for this user")
            incident_id = "frz_" + secrets.token_hex(8)
            revoked_active = 0
            revoked_winddown = 0
            for session in data["sessions"].values():
                if (
                    session["username"] != username
                    or session.get("device_id") != device_id
                    or session["revoked"]
                ):
                    continue
                was_retired = bool(session.get("retired"))
                session["retired"] = True
                session["winddown_until"] = None
                self._revoke_session(
                    data, session["id"],
                    f"emergency device freeze ({reason})",
                )
                self._record(
                    data, "revoke", session,
                    detail=(
                        "emergency freeze " + incident_id + ": " + reason
                        + "; all unfinished device authorizations revoked"
                        + (
                            "; outstanding wind-down cancelled"
                            if was_retired else ""
                        )
                    ),
                    rotation_id=incident_id,
                )
                if was_retired:
                    revoked_winddown += 1
                else:
                    revoked_active += 1
            return {
                "incident_id": incident_id,
                "revoked_active_chains": revoked_active,
                "cancelled_winddown_chains": revoked_winddown,
                "scope": "device only; other devices unaffected",
            }

    def device_lineage(self, username: str, device_id: str) -> dict:
        """Reconstruct every login identity one device has ever used.

        Survives save/reopen: chains are linked in chronological order with
        their state, deny reasons and the scope still valid for chains in a
        wind-down window. No raw credentials appear anywhere in the result.
        """
        with self.store.connect() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            device = user.get("devices", {}).get(device_id)
            if device is None:
                raise InvalidTokenError("unknown device for this user")
            now = _now()
            chains = []
            for session in data["sessions"].values():
                if (
                    session["username"] != username
                    or session.get("device_id") != device_id
                ):
                    continue
                winddown_until = session.get("winddown_until")
                in_window = (
                    session.get("retired")
                    and not session["revoked"]
                    and winddown_until is not None
                    and now < datetime.fromisoformat(winddown_until)
                )
                if session["revoked"]:
                    state = "revoked"
                elif in_window:
                    state = "winding_down"
                elif session.get("retired"):
                    state = "retired"
                else:
                    state = "active"
                chains.append({
                    "session_id": session["id"],
                    "family": session["family"],
                    "generation": session.get("generation", 0),
                    "state": state,
                    "revoke_reason": session["revoke_reason"],
                    "retired_reason": session.get("retired_reason"),
                    "winddown_until": winddown_until if in_window else None,
                    "valid_scope": (
                        "already-issued access credentials only; no renewals"
                        if in_window else None
                    ),
                    "predecessor_session": session.get("predecessor_session"),
                    "replaced_by_session": session.get("replaced_by_session"),
                    "rotation_id": session.get("rotation_id"),
                    "created_at": session["created_at"],
                })
            chains.sort(key=lambda row: row["session_id"])
            denies = []
            for event in data.get("activity", []):
                if (
                    event.get("kind") == "deny"
                    and event.get("username") == username
                    and event.get("device_id") == device_id
                ):
                    denies.append({
                        "observed_at": event["observed_at"],
                        "session_id": event["session_id"],
                        "family": event["family"],
                        "detail": event["detail"],
                    })
            return {
                "username": username,
                "device_id": device_id,
                "device_name": device.get("name"),
                "lineage_id": device.get("lineage_id"),
                "generation": device.get("generation", 0),
                "chains": chains,
                "denies": denies,
            }

    def rename_device(self, username: str, device_id: str, new_name: str) -> None:
        """Rename a device. Past audit events keep their original attribution."""
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            device = user.setdefault("devices", {}).get(device_id)
            if device is None:
                raise InvalidTokenError("unknown device for this user")
            device["name"] = new_name

    def list_devices(self, username: str) -> list[dict]:
        """List the user's login devices and the state of each session chain."""
        with self.store.connect() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            devices = user.get("devices", {})
            out = []
            for session in data["sessions"].values():
                if session["username"] != username:
                    continue
                device_id = session.get("device_id")
                out.append(
                    {
                        "session_id": session["id"],
                        "family": session["family"],
                        "device_id": device_id,
                        "device_name": devices.get(device_id, {}).get(
                            "name", session.get("device_name")
                        ),
                        "created_at": session["created_at"],
                        "active": not session["revoked"],
                        "revoke_reason": session["revoke_reason"],
                        "retired": session.get("retired", False),
                        "winddown_until": session.get("winddown_until"),
                        "lineage_id": session.get("lineage_id"),
                        "generation": session.get("generation", 0),
                    }
                )
            out.sort(key=lambda row: row["session_id"])
            return out

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
            if session.get("retired"):
                # Planned rotation: the pre-announced rule accepts this
                # already-issued access credential only until the wind-down
                # deadline, and never touches the device's newer chain.
                deadline = session.get("winddown_until")
                if deadline is None or _now() >= datetime.fromisoformat(deadline):
                    raise ChainWoundDownError(
                        "old-chain request settled after the announced "
                        "wind-down deadline; renew the device's current chain"
                    )
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
                        "credential_id": cred["id"],
                        "presented_hash": th,
                        "detail": detail,
                    }
                )
                self._record(
                    data, "deny", session, detail=detail, presented_hash=th
                )

            def chain_label() -> str:
                return (
                    f"family={cred['family']} session={cred['session_id']} "
                    f"device={session.get('device_id')}"
                )

            if user is not None and user["disabled"]:
                record_reuse("use after account disabled")
                self._revoke_session(data, cred["session_id"], "account disabled")
                pending_error = AccountDisabledError("account is disabled")

            if pending_error is None and _now() >= datetime.fromisoformat(cred["expires_at"]):
                raise TokenExpiredError("refresh token expired")

            if pending_error is None and session.get("retired") and not session["revoked"]:
                # Planned rotation rule, fixed before the request was sent:
                # an old chain cannot create a renewal anymore. The request
                # is recorded for the reuse audit, but retiring is not a
                # fuse, so the successor chain of the same device survives.
                record_reuse(
                    "renewal attempted on chain retired by planned rotation"
                )
                pending_error = ChainSupersededError(
                    "chain retired by planned device rotation; new renewals "
                    "are refused; " + chain_label()
                )

            if pending_error is None and cred["used"]:
                # Replay of an already consumed credential => break the chain.
                record_reuse("replay of consumed refresh credential")
                self._revoke_session(data, cred["session_id"], "refresh reuse detected")
                pending_error = TokenReuseDetectedError(
                    "refresh credential was already used; froze chain "
                    + chain_label()
                )

            if pending_error is None and (cred["revoked"] or session["revoked"]):
                record_reuse("use of revoked refresh credential")
                pending_error = TokenRevokedError(
                    "refresh credential revoked; chain " + chain_label()
                )

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
                    device_id=session.get("device_id"),
                )
                self._record(
                    data, "refresh", session,
                    detail="rotated refresh credential; device identity kept",
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

    def export_device_activity(
        self, username: str | None = None, device_id: str | None = None
    ) -> list[dict]:
        """Export the device activity log without any raw credentials.

        Each record is one of login / refresh / revoke / deny and carries
        the device attribution as it was when the event happened (later
        renames do not rewrite history).
        """
        with self.store.connect() as data:
            events = data.get("activity", [])
            if username is not None:
                events = [e for e in events if e["username"] == username]
            if device_id is not None:
                events = [e for e in events if e["device_id"] == device_id]
            return [dict(e) for e in events]

    # ---- internals -------------------------------------------------------

    @staticmethod
    def _record(
        data: dict,
        kind: str,
        session: dict,
        detail: str,
        presented_hash: str | None = None,
        rotation_id: str | None = None,
        generation: int | None = None,
        winddown_until: str | None = None,
    ) -> None:
        """Append a device activity record. Never stores raw credentials."""
        record = {
                "observed_at": _now().isoformat(),
                "kind": kind,
                "username": session["username"],
                "session_id": session["id"],
                "family": session["family"],
                "device_id": session.get("device_id"),
                "device_name": session.get("device_name"),
                "lineage_id": session.get("lineage_id"),
                "generation": session.get("generation"),
                "detail": detail,
                "presented_hash": presented_hash,
            }
        if rotation_id is not None:
            record["rotation_id"] = rotation_id
        if generation is not None:
            record["generation"] = generation
        if winddown_until is not None:
            record["winddown_until"] = winddown_until
        data.setdefault("activity", []).append(record)

    @staticmethod
    def _check_shape(token: str, expect_prefix: str) -> None:
        if not isinstance(token, str) or not TOKEN_RE.match(token):
            raise MalformedTokenError("credential is not a well-formed token")
        if not token.startswith(expect_prefix):
            raise MalformedTokenError(
                f"expected a {expect_prefix.rstrip('_')} credential"
            )

    def _issue_bundle(
        self,
        data: dict,
        username: str,
        device_id: str | None = None,
        lineage_id: str | None = None,
        generation: int = 0,
    ) -> TokenBundle:
        now = _now()
        family = secrets.token_hex(16)
        access = "at_" + secrets.token_urlsafe(32)
        refresh = "rf_" + secrets.token_urlsafe(32)
        data["seq"] += 1
        session_id = data["seq"]
        device_name = None
        if device_id is not None:
            device_name = (
                data["users"][username].get("devices", {})
                .get(device_id, {})
                .get("name", device_id)
            )
        data["sessions"][str(session_id)] = {
            "id": session_id,
            "username": username,
            "family": family,
            "device_id": device_id,
            "device_name": device_name,
            "lineage_id": lineage_id,
            "generation": generation,
            "predecessor_session": None,
            "replaced_by_session": None,
            "created_at": now.isoformat(),
            "revoked": False,
            "revoke_reason": None,
            # A planned rotation retires the chain without hard-revoking it:
            # the wind-down window keeps already-issued access credentials
            # usable, but the chain can never produce another renewal.
            "retired": False,
            "retired_reason": None,
            "winddown_until": None,
            "rotation_id": None,
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
            device_id=device_id,
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
