from __future__ import annotations

import threading
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from authcore.service import hash_credential
from authcore import (
    AccountDisabledError,
    ChainSupersededError,
    ChainWoundDownError,
    AuthService,
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
    TokenExpiredError,
    TokenReuseDetectedError,
    TokenRevokedError,
)


class AuthCoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        self.svc.create_user("alice", "correct horse battery staple")
        self.svc.create_user("bob", "hunter2")

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, device_id, device_name=None):
        return self.svc.login(
            "alice", "correct horse battery staple",
            device_id=device_id, device_name=device_name,
        )

    def rotate(self, device_id, winddown=timedelta(seconds=5)):
        return self.svc.rotate_device_credentials(
            "alice", device_id, "correct horse battery staple",
            winddown=winddown,
        )

    def test_login_and_access_check(self):
        bundle = self.svc.login("alice", "correct horse battery staple")
        self.assertEqual(self.svc.check_access(bundle.access_token), "alice")
        with self.assertRaises(InvalidCredentialsError):
            self.svc.login("alice", "wrong")
        with self.assertRaises(InvalidCredentialsError):
            self.svc.login("nobody", "whatever")

    def test_refresh_succeeds_exactly_once_and_chains(self):
        first = self.svc.login("bob", "hunter2")
        rotated = self.svc.refresh(first.refresh_token)
        self.assertEqual(rotated.family, first.family)
        self.assertEqual(self.svc.check_access(rotated.access_token), "bob")
        # Old access still works until it expires; the old refresh is consumed.
        with self.assertRaises(TokenReuseDetectedError):
            self.svc.refresh(first.refresh_token)
        # The chain continued by the rotated token is now broken by the replay
        # (the whole family was revoked), i.e. no second valid branch.
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(rotated.refresh_token)
        events = self.svc.list_reuse_events(first.family)
        self.assertEqual(events[0]["detail"], "replay of consumed refresh credential")
        self.assertTrue(len(events) >= 1)

    def test_sequential_refresh_chain_keeps_working(self):
        first = self.svc.login("bob", "hunter2")
        second = self.svc.refresh(first.refresh_token)
        third = self.svc.refresh(second.refresh_token)
        self.assertEqual(first.family, second.family, third.family)
        self.assertEqual(self.svc.check_access(third.access_token), "bob")
        # Old credential never works again, but no replay occurred yet =>
        # the fresh chain head is still usable.
        with self.assertRaises(TokenReuseDetectedError):
            self.svc.refresh(second.refresh_token)
        # Family is revoked only after the actual replay.
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(third.refresh_token)

    def test_concurrent_refresh_only_one_winner(self):
        bundle = self.svc.login("alice", "correct horse battery staple")
        results: list[object] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(4)

        def attempt() -> None:
            try:
                barrier.wait()
                results.append(self.svc.refresh(bundle.refresh_token))
            except BaseException as exc:  # noqa: BLE001 - capture all
                errors.append(exc)

        threads = [threading.Thread(target=attempt) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        success = [r for r in results if r is not None]
        self.assertEqual(len(success), 1)
        self.assertTrue(all(isinstance(e, TokenReuseDetectedError) for e in errors))
        # Newly issued credential is unusable because the family was revoked.
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(success[0].refresh_token)
        self.assertGreaterEqual(len(self.svc.list_reuse_events(bundle.family)), 3)

    def test_logout_revokes_family_persists_across_restart(self):
        bundle = self.svc.login("bob", "hunter2")
        self.svc.logout(bundle.access_token)
        with self.assertRaises(TokenRevokedError):
            self.svc.check_access(bundle.access_token)
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(bundle.refresh_token)
        # Fresh process: reopen the same database file.
        restarted = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        with self.assertRaises(TokenRevokedError):
            restarted.check_access(bundle.access_token)

    def test_disabled_user_blocks_login_and_revokes_sessions_after_restart(self):
        bundle = self.svc.login("alice", "correct horse battery staple")
        self.svc.disable_user("alice")
        with self.assertRaises(AccountDisabledError):
            self.svc.check_access(bundle.access_token)
        with self.assertRaises(AccountDisabledError):
            self.svc.refresh(bundle.refresh_token)
        with self.assertRaises(AccountDisabledError):
            self.svc.login("alice", "correct horse battery staple")
        restarted = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        with self.assertRaises(AccountDisabledError):
            restarted.login("alice", "correct horse battery staple")

    def test_expiry_is_distinct_error(self):
        short = AuthService(str(Path(self.tmp.name) / "short.db"),
                            timedelta(milliseconds=1), timedelta(milliseconds=1))
        short.create_user("carol", "pw")
        bundle = short.login("carol", "pw")
        threading.Event().wait(0.05)
        with self.assertRaises(TokenExpiredError):
            short.check_access(bundle.access_token)
        with self.assertRaises(TokenExpiredError):
            short.refresh(bundle.refresh_token)

    def test_malformed_and_unknown_tokens_are_distinct(self):
        for bad in ("", "garbage", "at_!!!", "rf_short", None, 123, b"at_x"):
            with self.assertRaises(MalformedTokenError):
                self.svc.check_access(bad)  # type: ignore[arg-type]
        with self.assertRaises(MalformedTokenError):
            # well-formed token but wrong type for the operation.
            self.svc.refresh("at_" + "a" * 43)
        with self.assertRaises(InvalidTokenError):
            self.svc.check_access("at_" + "b" * 43)
        with self.assertRaises(InvalidTokenError):
            self.svc.refresh("rf_" + "c" * 43)

    def test_raw_credentials_never_stored(self):
        bundle = self.svc.login("alice", "correct horse battery staple")
        self.svc.refresh(bundle.refresh_token)
        with self.assertRaises(TokenReuseDetectedError):
            self.svc.refresh(bundle.refresh_token)
        on_disk = Path(self.db).read_text(encoding="utf-8")
        self.assertNotIn(bundle.access_token, on_disk)
        self.assertNotIn(bundle.refresh_token, on_disk)
        event = self.svc.list_reuse_events()[0]
        self.assertEqual(event["presented_hash"], hash_credential(bundle.refresh_token))
        self.assertNotIn("password", repr(event))


class DeviceSessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        self.svc.create_user("alice", "pw-alice")

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, device_id, name):
        return self.svc.login("alice", "pw-alice",
                              device_id=device_id, device_name=name)

    def test_refresh_keeps_device_identity(self):
        phone = self.login("phone-1", "小手机")
        rotated = self.svc.refresh(phone.refresh_token)
        self.assertEqual(rotated.device_id, "phone-1")
        self.assertEqual(rotated.session_id, phone.session_id)
        devices = self.svc.list_devices("alice")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["device_name"], "小手机")
        self.assertTrue(devices[0]["active"])

    def test_freeze_one_device_keeps_others(self):
        phone = self.login("phone-1", "小手机")
        laptop = self.login("laptop-1", "旧电脑")
        frozen = self.svc.logout_device("alice", "phone-1")
        self.assertEqual(frozen, 1)
        with self.assertRaises(TokenRevokedError):
            self.svc.check_access(phone.access_token)
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(phone.refresh_token)
        # The other device is untouched and can still refresh.
        self.assertEqual(self.svc.check_access(laptop.access_token), "alice")
        rotated = self.svc.refresh(laptop.refresh_token)
        self.assertEqual(rotated.device_id, "laptop-1")
        states = {d["device_id"]: d["active"]
                  for d in self.svc.list_devices("alice")}
        self.assertEqual(states, {"phone-1": False, "laptop-1": True})

    def test_reuse_freezes_old_chain_not_relogin(self):
        # Old refresh credential races with a fresh login on the same device.
        old = self.login("phone-1", "小手机")
        rotated = self.svc.refresh(old.refresh_token)
        fresh = self.login("phone-1", "小手机")  # user logs in again
        with self.assertRaises(TokenReuseDetectedError) as ctx:
            self.svc.refresh(old.refresh_token)  # replay of the old chain
        message = str(ctx.exception)
        self.assertIn(old.family, message)
        self.assertIn(str(old.session_id), message)
        # Only the stale chain is frozen; the newer login survives.
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(rotated.refresh_token)
        self.assertEqual(self.svc.check_access(fresh.access_token), "alice")
        self.assertEqual(self.svc.refresh(fresh.refresh_token).device_id, "phone-1")
        devices = self.svc.list_devices("alice")
        by_session = {d["session_id"]: d["active"] for d in devices}
        self.assertFalse(by_session[old.session_id])
        self.assertTrue(by_session[fresh.session_id])

    def test_disable_ends_all_devices_and_enable_allows_relogin(self):
        phone = self.login("phone-1", "小手机")
        laptop = self.login("laptop-1", "旧电脑")
        self.svc.disable_user("alice")
        for bundle in (phone, laptop):
            with self.assertRaises(AccountDisabledError):
                self.svc.check_access(bundle.access_token)
        self.assertFalse(any(d["active"] for d in self.svc.list_devices("alice")))
        self.svc.enable_user("alice")
        # Old chains stay revoked after re-enabling; a new login works.
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(phone.refresh_token)
        again = self.login("phone-1", "小手机")
        self.assertEqual(self.svc.check_access(again.access_token), "alice")

    def test_rename_device_keeps_audit_attribution(self):
        phone = self.login("phone-1", "小手机")
        self.svc.refresh(phone.refresh_token)
        self.svc.rename_device("alice", "phone-1", "新手机")
        # Listing shows the new name...
        self.assertEqual(self.svc.list_devices("alice")[0]["device_name"], "新手机")
        # ...but earlier audit records still carry the original name.
        activity = self.svc.export_device_activity("alice", "phone-1")
        kinds = [e["kind"] for e in activity]
        self.assertEqual(kinds, ["login", "refresh"])
        self.assertTrue(all(e["device_name"] == "小手机" for e in activity))
        self.assertTrue(all(e["device_id"] == "phone-1" for e in activity))

    def test_activity_export_distinguishes_kinds_and_hides_secrets(self):
        phone = self.login("phone-1", "小手机")
        rotated = self.svc.refresh(phone.refresh_token)
        with self.assertRaises(TokenReuseDetectedError):
            self.svc.refresh(phone.refresh_token)
        laptop = self.login("laptop-1", "旧电脑")
        self.assertEqual(self.svc.logout_device("alice", "laptop-1"), 1)
        activity = self.svc.export_device_activity("alice")
        kinds = [e["kind"] for e in activity]
        self.assertEqual(kinds, ["login", "refresh", "deny", "login", "revoke"])
        laptop_events = self.svc.export_device_activity("alice", "laptop-1")
        self.assertEqual([e["kind"] for e in laptop_events], ["login", "revoke"])
        blob = repr(activity)
        self.assertNotIn(phone.refresh_token, blob)
        self.assertNotIn(rotated.refresh_token, blob)
        self.assertNotIn(phone.access_token, blob)
        self.assertNotIn(laptop.refresh_token, blob)
        deny = activity[2]
        self.assertEqual(deny["presented_hash"],
                         hash_credential(phone.refresh_token))

    def test_concurrent_refresh_across_devices(self):
        bundles = [self.login("dev-%d" % i, "设备%d" % i) for i in range(3)]
        barrier = threading.Barrier(len(bundles))
        outcomes = []

        def rotate(bundle):
            barrier.wait()
            try:
                outcomes.append(self.svc.refresh(bundle.refresh_token))
            except BaseException as exc:  # noqa: BLE001
                outcomes.append(exc)

        threads = [threading.Thread(target=rotate, args=(b,)) for b in bundles]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Distinct devices have independent chains: all three rotations win.
        self.assertTrue(all(not isinstance(o, BaseException) for o in outcomes))
        self.assertEqual({o.device_id for o in outcomes},
                        {"dev-0", "dev-1", "dev-2"})


class RotationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        self.svc.create_user("alice", "pw-alice")

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, device_id, device_name=None):
        return self.svc.login("alice", "pw-alice",
                              device_id=device_id, device_name=device_name)

    def rotate(self, device_id, winddown=timedelta(seconds=5)):
        return self.svc.rotate_device_credentials(
            "alice", device_id, "pw-alice", winddown=winddown,
        )

    def test_planned_rotation_keeps_lineage_and_winddown_rule(self):
        old = self.login("phone", "旧手机")
        result = self.rotate("phone")
        new = result["bundle"]
        self.assertEqual(new.device_id, "phone")
        self.assertNotEqual(new.family, old.family)
        from authcore.service import ROTATION_RULE
        self.assertEqual(result["rule"], ROTATION_RULE)
        self.assertEqual(result["retired_sessions"], [old.session_id])
        self.assertEqual(self.svc.check_access(old.access_token), "alice")
        with self.assertRaises(ChainSupersededError):
            self.svc.refresh(old.refresh_token)
        rotated = self.svc.refresh(new.refresh_token)
        self.assertEqual(self.svc.check_access(rotated.access_token), "alice")

    def test_old_request_out_of_order_after_winddown_is_denied_not_frozen(self):
        old = self.login("phone")
        result = self.rotate("phone", winddown=timedelta(milliseconds=50))
        new = result["bundle"]
        import time
        time.sleep(0.08)
        with self.assertRaises(ChainWoundDownError):
            self.svc.check_access(old.access_token)
        self.assertEqual(self.svc.check_access(new.access_token), "alice")

    def test_consecutive_rotations_link_all_generations(self):
        first = self.login("phone")
        r1 = self.rotate("phone")
        r2 = self.rotate("phone")
        self.assertEqual(r1["generation"], 1)
        self.assertEqual(r2["generation"], 2)
        self.assertEqual(r1["lineage_id"], r2["lineage_id"])
        with self.assertRaises(ChainSupersededError):
            self.svc.refresh(first.refresh_token)
        with self.assertRaises(ChainSupersededError):
            self.svc.refresh(r1["bundle"].refresh_token)
        newest = self.svc.refresh(r2["bundle"].refresh_token)
        self.assertEqual(newest.device_id, "phone")
        lineage = self.svc.device_lineage("alice", "phone")
        states = [(c["generation"], c["state"]) for c in lineage["chains"]]
        self.assertEqual([s for _, s in states],
                         ["winding_down", "winding_down", "active"])
        self.assertTrue(all(c["family"] for c in lineage["chains"]))

    def test_concurrent_refresh_on_same_chain_after_rotation(self):
        old = self.login("phone")
        new = self.rotate("phone")["bundle"]
        barrier = threading.Barrier(4)
        outcomes = []

        def attempt(token, expect_old):
            barrier.wait()
            try:
                outcomes.append((expect_old, self.svc.refresh(token)))
            except BaseException as exc:  # noqa: BLE001
                outcomes.append((expect_old, exc))

        threads = [
            threading.Thread(target=attempt, args=(old.refresh_token, True))
            for _ in range(3)
        ] + [threading.Thread(target=attempt, args=(new.refresh_token, False))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        old_outcomes = [o for is_old, o in outcomes if is_old]
        new_outcomes = [o for is_old, o in outcomes if not is_old]
        self.assertEqual(len(old_outcomes), 3)
        self.assertTrue(all(isinstance(o, ChainSupersededError) for o in old_outcomes))
        self.assertEqual(len(new_outcomes), 1)
        self.assertFalse(isinstance(new_outcomes[0], BaseException))

    def test_emergency_freeze_revokes_unfinished_and_keeps_other_devices(self):
        phone_old = self.login("phone")
        result = self.rotate("phone")
        phone_new = result["bundle"]
        watch = self.login("watch", "手表")
        report = self.svc.emergency_freeze_device("alice", "phone")
        self.assertEqual(report["cancelled_winddown_chains"], 1)
        self.assertEqual(report["revoked_active_chains"], 1)
        for token in (phone_old.access_token, phone_new.access_token):
            with self.assertRaises(TokenRevokedError):
                self.svc.check_access(token)
        for token in (phone_old.refresh_token, phone_new.refresh_token):
            with self.assertRaises(TokenRevokedError):
                self.svc.refresh(token)
        self.assertEqual(self.svc.check_access(watch.access_token), "alice")
        self.assertEqual(self.svc.refresh(watch.refresh_token).device_id, "watch")

    def test_rotation_reuse_and_disable_interleave_scope(self):
        phone = self.login("phone")
        rotated = self.rotate("phone")["bundle"]
        watch = self.login("watch")
        with self.assertRaises(ChainSupersededError):
            self.svc.refresh(phone.refresh_token)
        self.assertEqual(self.svc.check_access(rotated.access_token), "alice")
        self.svc.disable_user("alice")
        for bundle in (phone, rotated, watch):
            with self.assertRaises((AccountDisabledError, TokenRevokedError)):
                self.svc.check_access(bundle.access_token)
        self.svc.enable_user("alice")
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(rotated.refresh_token)
        relogin = self.login("phone")
        self.assertEqual(self.svc.check_access(relogin.access_token), "alice")
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(rotated.refresh_token)

    def test_lineage_persists_with_denies_and_scopes_after_reopen(self):
        old = self.login("phone", "手机")
        rotated = self.rotate("phone")["bundle"]
        with self.assertRaises(ChainSupersededError):
            self.svc.refresh(old.refresh_token)
        reopened = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        lineage = reopened.device_lineage("alice", "phone")
        self.assertEqual(len(lineage["chains"]), 2)
        self.assertEqual(lineage["chains"][0]["state"], "winding_down")
        self.assertEqual(
            lineage["chains"][0]["valid_scope"],
            "already-issued access credentials only; no renewals",
        )
        self.assertEqual(lineage["chains"][1]["state"], "active")
        self.assertTrue(
            lineage["denies"][0]["detail"].startswith("renewal attempted on chain")
        )
        self.assertEqual(lineage["chains"][1]["family"], rotated.family)
        for event in reopened.export_device_activity("alice", "phone"):
            self.assertNotIn("refresh_token", event)
            self.assertNotIn("access_token", event)
            self.assertEqual(event["device_id"], "phone")


if __name__ == "__main__":
    unittest.main()
