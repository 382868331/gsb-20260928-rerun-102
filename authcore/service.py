from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .errors import (
    AccountDisabledError,
    AuthError,
    CredentialSupersededError,
    DeviceFrozenError,
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
    RolloverPlanError,
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
    session_id: int
    device_id: str
    generation: int = 1


@dataclass(frozen=True)
class RolloverResult:
    """Outcome of a planned device credential rollover."""

    bundle: TokenBundle
    device_id: str
    generation: int
    superseded_sessions: tuple[int, ...]
    rule: str


WIND_DOWN_RULE = (
    "planned rollover wind-down: retired generations can no longer create "
    "refresh rotations; access tokens already issued stay usable until they "
    "expire or the device is frozen/the account is disabled"
)

EMERGENCY_FREEZE_PRIORITY_RULE = (
    "emergency freeze takes priority over any rollover plan: a "
    "suspected-compromise device is blocked immediately, even when that "
    "makes the plan's minimum available device count unreachable; the "
    "shortfall is reported, never silently covered by freezing other devices"
)


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
            device = devices.get(device_id)
            if device is None:
                device = {
                    "name": device_name,
                    "first_seen_at": _now().isoformat(),
                    "generation": 0,
                    "frozen": False,
                    "frozen_at": None,
                }
                devices[device_id] = device
            device.setdefault("generation", 0)
            device.setdefault("frozen", False)
            device.setdefault("frozen_at", None)
            if device.get("frozen"):
                raise DeviceFrozenError(
                    f"device {device_id} is frozen after a suspected "
                    "compromise; it must be unfrozen before it can log in again"
                )
            login_generation = device["generation"] + 1
            device["generation"] = login_generation
            bundle = self._issue_bundle(
                data, username, device_id, generation=login_generation
            )
            session = data["sessions"][str(bundle.session_id)]
            self._record(
                data, "login", session,
                detail=f"device login; credential generation {bundle.generation}",
                generation=bundle.generation,
            )
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

    # ---- controlled credential rollover ---------------------------------

    def rollover_device(
        self, username: str, device_id: str, new_name: str | None = None
    ) -> RolloverResult:
        """Planned credential rollover for one device.

        A fresh login chain (new family) becomes the active generation of the
        *same* device, so device attribution is preserved. Every previously
        active chain of that device is marked ``superseded``: its refresh
        credentials can no longer create rotations (they fail as
        CredentialSupersededError, never as a reuse break, so a late old
        request cannot freeze the new chain), while access tokens that were
        already issued remain usable until they expire. Emergency freeze or
        account disable can still cut that wind-down short.
        """
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            if user["disabled"]:
                raise AccountDisabledError("account is disabled")
            return self._rollover_device_locked(
                data, username, device_id, new_name=new_name
            )

    def _rollover_device_locked(
        self,
        data: dict,
        username: str,
        device_id: str,
        new_name: str | None = None,
        context: str | None = None,
    ) -> RolloverResult:
        """Locked-body of a planned rollover. Caller holds the transaction
        and has already verified the account exists and is enabled."""
        user = data["users"][username]
        device = user.setdefault("devices", {}).get(device_id)
        if device is None:
            raise InvalidTokenError("unknown device for this user")
        device.setdefault("generation", 0)
        device.setdefault("frozen", False)
        if device.get("frozen"):
            raise DeviceFrozenError(
                f"device {device_id} is frozen; unfreeze it before a "
                "planned rollover"
            )
        if new_name is not None:
            device["name"] = new_name
        now = _now()
        old_sessions: list[int] = []
        for session in data["sessions"].values():
            if (
                session["username"] == username
                and session.get("device_id") == device_id
                and not session["revoked"]
            ):
                old_sessions.append(session["id"])
                session["superseded"] = True
                session["superseded_at"] = now.isoformat()
                session.setdefault("generation", 1)
                for rf in data["refresh"].values():
                    if (
                        rf["session_id"] == session["id"]
                        and not rf["used"]
                    ):
                        rf["superseded"] = True
        old_generation = device["generation"]
        new_generation = max(device["generation"], 0) + 1
        device["generation"] = new_generation
        bundle = self._issue_bundle(
            data, username, device_id, generation=new_generation
        )
        session = data["sessions"][str(bundle.session_id)]
        detail = (
            f"planned rollover generation {old_generation} -> "
            f"{new_generation}; {len(old_sessions)} prior chain(s) "
            "retired; " + WIND_DOWN_RULE
        )
        if context:
            detail += "; " + context
        self._record(
            data, "rollover", session,
            detail=detail,
            generation=new_generation,
            superseded_sessions=list(old_sessions),
            rule=WIND_DOWN_RULE,
        )
        return RolloverResult(
            bundle=bundle,
            device_id=device_id,
            generation=new_generation,
            superseded_sessions=tuple(old_sessions),
            rule=WIND_DOWN_RULE,
        )

    def freeze_device_compromised(
        self, username: str, device_id: str
    ) -> int:
        """Emergency freeze for a suspected-compromise device.

        Unlike a planned rollover this revokes *all* outstanding authorization
        of the device, including wind-down access tokens left by an earlier
        rollover, of every generation. Other devices are untouched. The device
        is additionally marked frozen so it cannot log in until unfrozen.
        Returns the number of session chains revoked.
        """
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            device = user.setdefault("devices", {}).get(device_id)
            if device is None:
                raise InvalidTokenError("unknown device for this user")
            device.setdefault("generation", 0)
            frozen = 0
            for session in data["sessions"].values():
                if (
                    session["username"] == username
                    and session.get("device_id") == device_id
                ):
                    if not session["revoked"]:
                        self._revoke_session(
                            data, session["id"],
                            "emergency freeze: suspected credential compromise",
                        )
                        frozen += 1
                    self._record(
                        data, "revoke", session,
                        detail=(
                            "emergency freeze; all generations revoked "
                            "including rollover wind-down access"
                        ),
                        generation=session.get("generation"),
                    )
            device["frozen"] = True
            device["frozen_at"] = _now().isoformat()
            return frozen

    def unfreeze_device(self, username: str, device_id: str) -> None:
        """Clear an emergency freeze.

        Revoked generations are not resurrected; the device must log in (or
        run a planned rollover) to receive a new chain.
        """
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            device = user.setdefault("devices", {}).get(device_id)
            if device is None:
                raise InvalidTokenError("unknown device for this user")
            device["frozen"] = False
            device["frozen_at"] = None

    def device_lineage(self, username: str, device_id: str) -> dict:
        """Return the full generation lineage of one device.

        Includes the displayed rollover rule and, for every login identity the
        device has ever held, the revocation/retirement reason and the scope
        still valid (wind-down access until expiry, or a live refresh chain).
        """
        with self.store.connect() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            device = user.get("devices", {}).get(device_id)
            if device is None:
                raise InvalidTokenError("unknown device for this user")
            now = _now()
            generations = []
            for session in data["sessions"].values():
                if (
                    session["username"] != username
                    or session.get("device_id") != device_id
                ):
                    continue
                wind_down = False
                if session.get("superseded") and not session["revoked"]:
                    wind_down = any(
                        not at["revoked"]
                        and now < datetime.fromisoformat(at["expires_at"])
                        for at in data["access"].values()
                        if at["session_id"] == session["id"]
                    )
                generations.append(
                    {
                        "generation": session.get("generation", 1),
                        "session_id": session["id"],
                        "family": session["family"],
                        "superseded": bool(session.get("superseded")),
                        "revoked": session["revoked"],
                        "revoke_reason": session["revoke_reason"],
                        "refresh_chain_active": (
                            not session["revoked"]
                            and not session.get("superseded")
                        ),
                        "wind_down_access_valid": wind_down,
                    }
                )
            generations.sort(key=lambda row: (row["generation"], row["session_id"]))
            return {
                "device_id": device_id,
                "device_name": device["name"],
                "current_generation": device.get("generation", 0),
                "frozen": device.get("frozen", False),
                "frozen_at": device.get("frozen_at"),
                "rollover_rule": WIND_DOWN_RULE,
                "generations": generations,
            }

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
                        "generation": session.get("generation", 1),
                        "created_at": session["created_at"],
                        "active": not session["revoked"],
                        "superseded": bool(session.get("superseded")),
                        "frozen": bool(
                            devices.get(device_id, {}).get("frozen", False)
                        ),
                        "revoke_reason": session["revoke_reason"],
                    }
                )
            out.sort(key=lambda row: row["session_id"])
            return out

    # ---- staged multi-device rollover plans -----------------------------

    @staticmethod
    def _device_availability(
        data: dict, username: str, device_id: str
    ) -> tuple[str, list[int]]:
        """Classify one device for plan simulation/execution.

        Returns `(status, live_session_ids)` where status is one of:
        `ready` (live refresh chain, can roll over now), `offline`
        (known device without a live chain), `frozen` (emergency freeze --
        blocked with priority), `unknown` (never registered).
        """
        user = data["users"][username]
        device = user.get("devices", {}).get(device_id)
        if device is None:
            return "unknown", []
        if device.get("frozen"):
            return "frozen", []
        live = [
            s["id"]
            for s in data["sessions"].values()
            if s["username"] == username
            and s.get("device_id") == device_id
            and not s["revoked"]
            and not s.get("superseded")
        ]
        return ("ready" if live else "offline"), live

    def create_rollover_plan(
        self,
        username: str,
        device_ids: list[str],
        min_available: int,
        wind_down_deadline: datetime | str | None = None,
    ) -> dict:
        """Declare and *simulate* a staged rollover plan for a device set.

        Nothing is rolled over here. The admin declares the minimum number
        of devices that must stay available (`min_available`) and the
        acceptable deadline for old-generation requests to finish winding
        down. The system simulates the rollover order and splits the ready
        devices into batches sized so that even losing a whole batch keeps
        availability at or above `min_available` whenever that is
        achievable. Devices under an emergency freeze are excluded with
        priority and any resulting shortfall is explained in the
        simulation. Only a batch that is later explicitly approved *and*
        still satisfies the conditions at execution time takes effect.
        """
        if isinstance(wind_down_deadline, str):
            wind_down_deadline = datetime.fromisoformat(wind_down_deadline)
        deduped: list[str] = []
        duplicates: list[str] = []
        for device_id in device_ids:
            (duplicates if device_id in deduped else deduped).append(device_id)
        if not deduped:
            raise RolloverPlanError("a rollover plan needs at least one device")
        if not 0 <= min_available <= len(deduped):
            raise RolloverPlanError(
                f"min_available must be between 0 and {len(deduped)} "
                "(the number of distinct devices in the plan)"
            )
        with self.store.transaction() as data:
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            statuses = {
                d: self._device_availability(data, username, d)[0]
                for d in deduped
            }
            ready = [d for d in deduped if statuses[d] == "ready"]
            excluded = {d: s for d, s in statuses.items() if s != "ready"}
            # Batch sizing: a failed device is never auto-frozen to protect
            # the count, so the worst case is losing a whole batch. Keep
            # batches small enough that ready - batch_size >= min_available
            # whenever possible; otherwise flag the residual risk.
            slack = len(ready) - min_available
            batch_size = max(1, min(len(ready), slack)) if slack > 0 else 1
            batches = []
            for index in range(0, len(ready), batch_size):
                chunk = ready[index:index + batch_size]
                batches.append(
                    {
                        "index": len(batches),
                        "device_ids": chunk,
                        "status": "simulated",
                        "approved_at": None,
                        "executed_at": None,
                        "results": None,
                    }
                )
            risk_note = None
            if slack <= 0 and ready:
                risk_note = (
                    "ready devices do not exceed min_available; any single "
                    "device failure during execution will cause a shortfall "
                    "that is reported, never covered by freezing others"
                )
            # Wind-down projection: old requests finish when the last
            # already-issued access token of the set expires.
            expiries = [
                datetime.fromisoformat(at["expires_at"])
                for at in data["access"].values()
                if data["sessions"][str(at["session_id"])]["username"]
                == username
                and data["sessions"][str(at["session_id"])].get("device_id")
                in deduped
                and not at["revoked"]
            ]
            wind_down_finished_by = (
                max(expiries).isoformat() if expiries else None
            )
            within_deadline = None
            if wind_down_deadline is not None:
                within_deadline = (
                    wind_down_finished_by is None
                    or datetime.fromisoformat(wind_down_finished_by)
                    <= wind_down_deadline
                )
            gap = self._plan_gap(len(ready), min_available, excluded)
            data["plan_seq"] += 1
            plan = {
                "id": f"plan_{data['plan_seq']}",
                "username": username,
                "device_ids": deduped,
                "duplicates_ignored": duplicates,
                "min_available": min_available,
                "wind_down_deadline": (
                    wind_down_deadline.isoformat()
                    if wind_down_deadline is not None
                    else None
                ),
                "created_at": _now().isoformat(),
                "simulation": {
                    "device_status": statuses,
                    "ready": ready,
                    "excluded": excluded,
                    "risk_note": risk_note,
                    "wind_down_finished_by": wind_down_finished_by,
                    "wind_down_within_deadline": within_deadline,
                    "availability_gap": gap,
                },
                "batches": batches,
                "status": "simulated",
            }
            data["plans"][plan["id"]] = plan
            return self._plan_view(data, plan)

    @staticmethod
    def _plan_gap(
        available: int, min_available: int, excluded: dict[str, str]
    ) -> str | None:
        """Explain a shortfall against min_available, or None if satisfied."""
        if available >= min_available:
            return None
        reasons = ", ".join(
            f"{device} ({status})" for device, status in sorted(excluded.items())
        ) or "none"
        return (
            f"availability shortfall: {available} of required "
            f"{min_available} device(s) available; missing "
            f"{min_available - available}; excluded devices: {reasons}; "
            + EMERGENCY_FREEZE_PRIORITY_RULE
        )

    def _plan_view(self, data: dict, plan: dict) -> dict:
        """Plan snapshot with *current* availability and gap re-evaluated."""
        statuses = {
            d: self._device_availability(data, plan["username"], d)[0]
            for d in plan["device_ids"]
        }
        available = sum(1 for s in statuses.values() if s == "ready")
        excluded = {d: s for d, s in statuses.items() if s != "ready"}
        view = dict(plan)
        view["batches"] = [dict(b) for b in plan["batches"]]
        view["current_availability"] = {
            "available": available,
            "min_available": plan["min_available"],
            "device_status": statuses,
            "gap": self._plan_gap(available, plan["min_available"], excluded),
        }
        return view

    def get_rollover_plan(self, plan_id: str) -> dict:
        """Return the plan with its live feasibility/authorization scope."""
        with self.store.connect() as data:
            plan = data["plans"].get(plan_id)
            if plan is None:
                raise RolloverPlanError(f"unknown rollover plan: {plan_id}")
            return self._plan_view(data, plan)

    def approve_rollover_batch(self, plan_id: str, batch_index: int) -> dict:
        """Explicitly approve one simulated batch. Approval alone changes
        no credentials; it only permits a later execution re-check."""
        with self.store.transaction() as data:
            plan, batch = self._load_batch(data, plan_id, batch_index)
            if batch["status"] == "executed":
                raise RolloverPlanError(
                    f"batch {batch_index} of {plan_id} was already executed; "
                    "re-submitting it is rejected"
                )
            if batch["status"] == "approved":
                raise RolloverPlanError(
                    f"batch {batch_index} of {plan_id} is already approved"
                )
            batch["status"] = "approved"
            batch["approved_at"] = _now().isoformat()
            plan["status"] = "approved"
            return self._plan_view(data, plan)

    def execute_rollover_batch(self, plan_id: str, batch_index: int) -> dict:
        """Execute one explicitly approved batch, re-validating conditions.

        Every device is re-checked at execution time: an emergency-frozen
        device is blocked with priority (never rolled over), an offline
        device (no live chain) is skipped, and a per-device failure is
        recorded in the batch result -- it never causes other devices to be
        frozen to protect the plan count. If availability afterwards falls
        below the declared minimum, the gap is explained in the result.
        """
        with self.store.transaction() as data:
            plan, batch = self._load_batch(data, plan_id, batch_index)
            username = plan["username"]
            user = data["users"].get(username)
            if user is None:
                raise InvalidCredentialsError("unknown user")
            if user["disabled"]:
                raise AccountDisabledError(
                    "account is disabled; approved batch cannot execute"
                )
            if batch["status"] == "simulated":
                raise RolloverPlanError(
                    f"batch {batch_index} of {plan_id} was never approved; "
                    "only an explicitly approved batch can take effect"
                )
            if batch["status"] == "executed":
                raise RolloverPlanError(
                    f"batch {batch_index} of {plan_id} was already executed; "
                    "repeated submission does not roll devices over twice"
                )
            results = []
            for device_id in batch["device_ids"]:
                status, _ = self._device_availability(data, username, device_id)
                if status != "ready":
                    detail = (
                        EMERGENCY_FREEZE_PRIORITY_RULE
                        if status == "frozen"
                        else f"device is {status}; skipped by plan execution"
                    )
                    results.append(
                        {
                            "device_id": device_id,
                            "outcome": (
                                "blocked" if status == "frozen" else "skipped"
                            ),
                            "reason": status,
                            "detail": detail,
                            "generation": None,
                        }
                    )
                    continue
                try:
                    rolled = self._rollover_device_locked(
                        data, username, device_id,
                        context=f"staged plan {plan_id} batch {batch_index}",
                    )
                except AuthError as exc:
                    results.append(
                        {
                            "device_id": device_id,
                            "outcome": "failed",
                            "reason": type(exc).__name__,
                            "detail": (
                                f"{exc}; other devices are NOT frozen to "
                                "protect the plan count"
                            ),
                            "generation": None,
                        }
                    )
                    continue
                results.append(
                    {
                        "device_id": device_id,
                        "outcome": "rolled_over",
                        "reason": None,
                        "detail": WIND_DOWN_RULE,
                        "generation": rolled.generation,
                    }
                )
            batch["status"] = "executed"
            batch["executed_at"] = _now().isoformat()
            batch["results"] = results
            plan["status"] = (
                "completed"
                if all(b["status"] == "executed" for b in plan["batches"])
                else "in_progress"
            )
            view = self._plan_view(data, plan)
            view["batch_result"] = {
                "batch_index": batch_index,
                "results": results,
                "availability_gap": view["current_availability"]["gap"],
            }
            return view

    @staticmethod
    def _load_batch(
        data: dict, plan_id: str, batch_index: int
    ) -> tuple[dict, dict]:
        plan = data["plans"].get(plan_id)
        if plan is None:
            raise RolloverPlanError(f"unknown rollover plan: {plan_id}")
        for batch in plan["batches"]:
            if batch["index"] == batch_index:
                return plan, batch
        raise RolloverPlanError(
            f"plan {plan_id} has no batch {batch_index}"
        )

    # ---- access check ----------------------------------------------------

    def check_access(self, access_token: str) -> str:
        """Return the owning username when the credential is usable, else raise."""
        return self.check_access_detail(access_token)["username"]

    def check_access_detail(self, access_token: str) -> dict:
        """Like check_access but returns the explicit decision basis.

        Decisions:
          * ``active``: current generation with a live refresh chain;
          * ``wind_down``: generation retired by a planned rollover -- the
            already-issued access token stays usable until expiry, but it can
            never create a new refresh;
          * ``frozen``: emergency device freeze / explicit revocation;
          * ``disabled`` / ``expired``: account or lifetime ended.
        """
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
            device = (user or {}).get("devices", {}).get(
                session.get("device_id")
            )
            if device is not None and device.get("frozen"):
                raise DeviceFrozenError(
                    f"device {session.get('device_id')} is frozen after a "
                    "suspected compromise"
                )
            if at["revoked"] or session["revoked"]:
                raise TokenRevokedError("credential or session revoked")
            if _now() >= datetime.fromisoformat(at["expires_at"]):
                raise TokenExpiredError("access token expired")
            decision = "wind_down" if session.get("superseded") else "active"
            return {
                "username": session["username"],
                "device_id": session.get("device_id"),
                "generation": session.get("generation", 1),
                "decision": decision,
                "rule": WIND_DOWN_RULE if decision == "wind_down" else None,
            }

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

            # Planned rollover: the whole old generation was retired. This is a
            # policy rejection shown to clients in advance (WIND_DOWN_RULE),
            # not a reuse break: it neither revokes the wind-down access of
            # the old chain nor touches the new chain of the same device.
            if pending_error is None and (
                session.get("superseded") or cred.get("superseded")
            ):
                detail = (
                    f"refresh from retired credential generation "
                    f"{session.get('generation', 1)}; " + WIND_DOWN_RULE
                )
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
                    data, "deny", session,
                    detail=detail, presented_hash=th,
                    generation=session.get("generation", 1),
                    decision="rollover_wind_down",
                )
                pending_error = CredentialSupersededError(
                    "credential generation retired by planned rollover; "
                    "no new refresh can be created, but issued access tokens "
                    "remain valid until expiry; " + chain_label()
                )

            if pending_error is None:
                device = (user or {}).get("devices", {}).get(
                    session.get("device_id")
                )
                if device is not None and device.get("frozen"):
                    record_reuse(
                        "use after emergency device freeze; all generations "
                        "of this device revoked"
                    )
                    pending_error = DeviceFrozenError(
                        "device frozen after suspected compromise; all its "
                        "pending authorization is revoked; " + chain_label()
                    )

            if pending_error is None and _now() >= datetime.fromisoformat(cred["expires_at"]):
                raise TokenExpiredError("refresh token expired")

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
                    generation=session.get("generation", 1),
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
        generation: int | None = None,
        decision: str | None = None,
        superseded_sessions: list[int] | None = None,
        rule: str | None = None,
    ) -> None:
        """Append a device activity record. Never stores raw credentials."""
        data.setdefault("activity", []).append(
            {
                "observed_at": _now().isoformat(),
                "kind": kind,
                "username": session["username"],
                "session_id": session["id"],
                "family": session["family"],
                "device_id": session.get("device_id"),
                "device_name": session.get("device_name"),
                "generation": (
                    generation
                    if generation is not None
                    else session.get("generation")
                ),
                "detail": detail,
                "presented_hash": presented_hash,
                "decision": decision,
                "superseded_sessions": superseded_sessions,
                "rule": rule,
            }
        )

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
        generation: int = 1,
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
            "generation": generation,
            "created_at": now.isoformat(),
            "revoked": False,
            "revoke_reason": None,
            "superseded": False,
            "superseded_at": None,
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
            generation=generation,
        )

    @staticmethod
    def _revoke_session(data: dict, session_id: int, reason: str) -> None:
        session = data["sessions"].get(str(session_id))
        if session is not None:
            session["revoked"] = True
            # Keep the first decisive revocation reason (e.g. an emergency
            # freeze); a later replay must not rewrite why the chain ended.
            if not session.get("revoke_reason"):
                session["revoke_reason"] = reason
        for at in data["access"].values():
            if at["session_id"] == session_id:
                at["revoked"] = True
        for rf in data["refresh"].values():
            if rf["session_id"] == session_id:
                rf["revoked"] = True
