from __future__ import annotations

import threading
import unittest
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from authcore.service import hash_credential
from authcore import (
    AccountDisabledError,
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
    """Per-device session management with multiple fictional devices."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        self.svc.create_user("alice", "correct horse battery staple")

    def tearDown(self):
        self.tmp.cleanup()

    def _login_two_devices(self):
        phone = self.svc.login("alice", "correct horse battery staple",
                               device_id="phone-1", device_name="小手机")
        laptop = self.svc.login("alice", "correct horse battery staple",
                                device_id="laptop-1", device_name="工作电脑")
        return phone, laptop

    def test_refresh_keeps_device_identity(self):
        phone, _ = self._login_two_devices()
        rotated = self.svc.refresh(phone.refresh_token)
        devices = self.svc.list_devices("alice")
        phone_entry = next(d for d in devices if d["device_id"] == "phone-1")
        self.assertEqual(phone_entry["device_name"], "小手机")
        self.assertEqual(len(phone_entry["sessions"]), 1)
        self.assertEqual(phone_entry["sessions"][0]["family"], rotated.family)

    def test_single_device_logout_leaves_other_devices(self):
        phone, laptop = self._login_two_devices()
        self.assertEqual(self.svc.logout_device("alice", "phone-1"), 1)
        with self.assertRaises(TokenRevokedError):
            self.svc.check_access(phone.access_token)
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(phone.refresh_token)
        # The other device is untouched and can still refresh.
        self.assertEqual(self.svc.check_access(laptop.access_token), "alice")
        rotated = self.svc.refresh(laptop.refresh_token)
        self.assertEqual(rotated.family, laptop.family)

    def test_reuse_freezes_only_the_leaked_chain_not_relogin(self):
        phone, _ = self._login_two_devices()
        rotated = self.svc.refresh(phone.refresh_token)
        # Attacker replays the old credential after the legit rotation.
        with self.assertRaises(TokenReuseDetectedError) as ctx:
            self.svc.refresh(phone.refresh_token)
        self.assertIn(phone.family, str(ctx.exception))
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(rotated.refresh_token)
        # A fresh login on the same device creates a new, unaffected chain.
        relogin = self.svc.login("alice", "correct horse battery staple",
                                 device_id="phone-1", device_name="小手机")
        self.assertNotEqual(relogin.family, phone.family)
        self.assertEqual(self.svc.check_access(relogin.access_token), "alice")
        again = self.svc.refresh(relogin.refresh_token)
        self.assertEqual(again.family, relogin.family)
        # The frozen chain is identifiable in the reuse audit.
        events = self.svc.list_reuse_events(phone.family)
        self.assertEqual(events[0]["device_id"], "phone-1")
        self.assertEqual(events[0]["family"], phone.family)

    def test_concurrent_refresh_freezes_only_that_device(self):
        phone, laptop = self._login_two_devices()
        barrier = threading.Barrier(4)
        errors: list[BaseException] = []

        def attempt() -> None:
            try:
                barrier.wait()
                self.svc.refresh(phone.refresh_token)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=attempt) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(any(isinstance(e, TokenReuseDetectedError) for e in errors))
        # Only the phone chain was frozen; the laptop session is still valid.
        self.assertEqual(self.svc.check_access(laptop.access_token), "alice")
        self.svc.refresh(laptop.refresh_token)

    def test_disable_revokes_all_devices_and_enable_allows_relogin(self):
        phone, laptop = self._login_two_devices()
        self.svc.disable_user("alice")
        for bundle in (phone, laptop):
            with self.assertRaises(AccountDisabledError):
                self.svc.check_access(bundle.access_token)
        devices = self.svc.list_devices("alice")
        self.assertTrue(
            all(s["revoked"] for d in devices for s in d["sessions"])
        )
        # Re-enable: old sessions stay revoked, new logins work again.
        self.svc.enable_user("alice")
        with self.assertRaises(TokenRevokedError):
            self.svc.check_access(phone.access_token)
        fresh = self.svc.login("alice", "correct horse battery staple",
                               device_id="tablet-1", device_name="平板")
        self.assertEqual(self.svc.check_access(fresh.access_token), "alice")
        devices = self.svc.list_devices("alice")
        self.assertEqual({d["device_id"] for d in devices},
                         {"phone-1", "laptop-1", "tablet-1"})

    def test_activity_log_distinguishes_kinds_and_hides_raw_credentials(self):
        phone, _ = self._login_two_devices()
        rotated = self.svc.refresh(phone.refresh_token)
        with self.assertRaises(TokenReuseDetectedError):
            self.svc.refresh(phone.refresh_token)
        self.svc.logout_device("alice", "laptop-1")

        kinds = [e["kind"] for e in self.svc.list_activity(username="alice")]
        for expected in ("login", "refresh", "reject", "revoke"):
            self.assertIn(expected, kinds)
        # Filters work per device and per kind.
        phone_events = self.svc.list_activity(username="alice",
                                              device_id="phone-1")
        self.assertTrue(all(e["device_id"] == "phone-1" for e in phone_events))
        refreshes = self.svc.list_activity(username="alice", kind="refresh")
        self.assertEqual(len(refreshes), 1)
        self.assertEqual(refreshes[0]["credential_hash"],
                         hash_credential(phone.refresh_token))
        # The export never contains raw credentials.
        export = repr(self.svc.list_activity())
        self.assertNotIn(phone.refresh_token, export)
        self.assertNotIn(rotated.refresh_token, export)
        self.assertNotIn(phone.access_token, export)

    def test_rename_device_keeps_audit_attribution(self):
        phone, _ = self._login_two_devices()
        self.svc.refresh(phone.refresh_token)
        before = self.svc.list_activity(username="alice", device_id="phone-1")
        self.svc.rename_device("alice", "phone-1", "新手机")
        after = self.svc.list_activity(username="alice", device_id="phone-1")
        # Historical events are untouched: same id, same name snapshot.
        self.assertEqual(before, after)
        self.assertTrue(all(e["device_name"] == "小手机" for e in after))
        # The live device list shows the new name.
        devices = self.svc.list_devices("alice")
        entry = next(d for d in devices if d["device_id"] == "phone-1")
        self.assertEqual(entry["device_name"], "新手机")


if __name__ == "__main__":
    unittest.main()
