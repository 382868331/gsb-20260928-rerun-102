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


class DeviceRolloverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(seconds=20),
                               timedelta(seconds=60))
        self.svc.create_user("alice", "pw-alice")
        self.svc.create_user("bob", "pw-bob")

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, user, password, device_id, name=None):
        return self.svc.login(user, password, device_id=device_id,
                              device_name=name)

    def test_planned_rollover_retires_old_chain_keeps_wind_down(self):
        old = self.login("alice", "pw-alice", "phone-1", "手机")
        result = self.svc.rollover_device("alice", "phone-1")
        new = result.bundle
        self.assertEqual(new.device_id, "phone-1")
        self.assertEqual(new.generation, 2)
        self.assertEqual(result.superseded_sessions, (old.session_id,))
        self.assertNotEqual(old.family, new.family)
        # Old refresh credential can never start a new rotation...
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(old.refresh_token)
        # ...and arriving late a second time still gets the same policy
        # decision, never a reuse circuit break that touches the new chain.
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(old.refresh_token)
        # Already-issued old access token keeps working (wind-down scope).
        detail = self.svc.check_access_detail(old.access_token)
        self.assertEqual(detail["decision"], "wind_down")
        self.assertEqual(detail["generation"], 1)
        # The new chain is fully alive and can rotate normally.
        rotated_new = self.svc.refresh(new.refresh_token)
        self.assertEqual(self.svc.check_access(new.access_token), "alice")
        self.assertEqual(self.svc.check_access(rotated_new.access_token),
                         "alice")
        self.assertEqual(rotated_new.generation, 2)

    def test_successive_rollovers_form_lineage_and_current_only_refreshes(self):
        gen1 = self.login("alice", "pw-alice", "phone-1", "手机")
        gen2 = self.svc.rollover_device("alice", "phone-1").bundle
        gen3 = self.svc.rollover_device("alice", "phone-1",
                                        new_name="新手机").bundle
        self.assertEqual((gen1.generation, gen2.generation, gen3.generation),
                         (1, 2, 3))
        for retired in (gen1, gen2):
            with self.assertRaises(CredentialSupersededError):
                self.svc.refresh(retired.refresh_token)
        detail1 = self.svc.check_access_detail(gen1.access_token)
        detail2 = self.svc.check_access_detail(gen2.access_token)
        self.assertEqual(detail1["decision"], "wind_down")
        self.assertEqual(detail2["decision"], "wind_down")
        self.assertEqual(self.svc.check_access_detail(gen3.access_token)[
                             "decision"], "active")
        lineage = self.svc.device_lineage("alice", "phone-1")
        self.assertEqual(lineage["device_name"], "新手机")
        self.assertEqual(lineage["current_generation"], 3)
        self.assertFalse(lineage["frozen"])
        self.assertEqual([g["generation"] for g in lineage["generations"]],
                         [1, 2, 3])
        self.assertTrue(lineage["generations"][0]["wind_down_access_valid"])
        self.assertTrue(lineage["generations"][2]["refresh_chain_active"])
        self.assertIn("wind-down", lineage["rollover_rule"])

    def test_concurrent_rollover_and_old_refresh_does_not_freeze_new_chain(self):
        old = self.login("alice", "pw-alice", "phone-1", "手机")
        outcomes = []
        barrier = threading.Barrier(3)

        def late_refresh():
            barrier.wait()
            try:
                outcomes.append(("old", self.svc.refresh(old.refresh_token)))
            except BaseException as exc:  # noqa: BLE001
                outcomes.append(("old", exc))

        def do_rollover():
            barrier.wait()
            try:
                outcomes.append(("rollover",
                                 self.svc.rollover_device("alice", "phone-1")))
            except BaseException as exc:  # noqa: BLE001
                outcomes.append(("rollover", exc))

        threads = [threading.Thread(target=late_refresh),
                   threading.Thread(target=late_refresh),
                   threading.Thread(target=do_rollover)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        rollover = next(o for label, o in outcomes if label == "rollover")
        self.assertNotIsInstance(rollover, BaseException)
        old_results = [o for label, o in outcomes if label == "old"]
        # Whether the old request landed before or after the rollover, exactly
        # one outcome is possible: either a normal single-use rotation (it was
        # the live chain at commit time), or the rollover policy rejection.
        # Neither case leaves the new chain frozen.
        self.assertTrue(all(
            isinstance(o, CredentialSupersededError)
            or not isinstance(o, BaseException)
            for o in old_results
        ))
        if any(not isinstance(o, BaseException) for o in old_results):
            # The refresh won the race: its result is the retired chain now;
            # replaying it is still a policy rejection, and the new chain
            # after rollover stays usable.
            self.assertTrue(all(
                isinstance(o, CredentialSupersededError)
                or not isinstance(o, BaseException)
                for o in old_results
            ))
        new_bundle = rollover.bundle
        rotated = self.svc.refresh(new_bundle.refresh_token)
        self.assertEqual(self.svc.check_access(rotated.access_token), "alice")

    def test_out_of_order_old_requests_never_circuit_break(self):
        gen1 = self.login("alice", "pw-alice", "phone-1", "手机")
        mid = self.svc.refresh(gen1.refresh_token)
        gen2 = self.svc.rollover_device("alice", "phone-1").bundle
        # An even older credential returns later than a newer one.
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(mid.refresh_token)
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(gen1.refresh_token)
        # New chain works regardless of the arrival order of old responses.
        self.assertEqual(self.svc.check_access(gen2.access_token), "alice")
        # No reuse-style family break: deny records carry the rollover basis.
        denies = [
            e for e in self.svc.export_device_activity("alice", "phone-1")
            if e["kind"] == "deny"
        ]
        self.assertTrue(all(e["decision"] == "rollover_wind_down"
                            for e in denies))

    def test_emergency_freeze_revokes_all_generations_and_wind_down(self):
        gen1 = self.login("alice", "pw-alice", "phone-1", "手机")
        gen2 = self.svc.rollover_device("alice", "phone-1").bundle
        revoked = self.svc.freeze_device_compromised("alice", "phone-1")
        self.assertEqual(revoked, 2)
        # Current chain, wind-down access, and further logins are all cut.
        with self.assertRaises(DeviceFrozenError):
            self.svc.check_access(gen1.access_token)
        with self.assertRaises(DeviceFrozenError):
            self.svc.check_access(gen2.access_token)
        with self.assertRaises(DeviceFrozenError):
            self.svc.refresh(gen2.refresh_token)
        with self.assertRaises(DeviceFrozenError):
            self.svc.login("alice", "pw-alice", device_id="phone-1",
                           device_name="手机")
        # Other devices are not implicated.
        laptop = self.login("bob", "pw-bob", "laptop-1", "电脑")
        alice_laptop = self.login("alice", "pw-alice", "laptop-2", "电脑")
        self.assertEqual(self.svc.refresh(laptop.refresh_token).device_id,
                         "laptop-1")
        self.assertEqual(self.svc.check_access(alice_laptop.access_token),
                         "alice")
        # Unfreeze never resurrects old generations.
        self.svc.unfreeze_device("alice", "phone-1")
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(gen2.refresh_token)
        again = self.login("alice", "pw-alice", "phone-1", "新手机")
        self.assertEqual(again.generation, 3)
        self.assertEqual(self.svc.check_access(again.access_token), "alice")

    def test_rollover_then_account_disable_then_enable_scopes_revocation(self):
        phone = self.login("alice", "pw-alice", "phone-1", "手机")
        new_phone = self.svc.rollover_device("alice", "phone-1").bundle
        laptop = self.login("alice", "pw-alice", "laptop-1", "电脑")
        bob_phone = self.login("bob", "pw-bob", "phone-1", "手机")
        self.svc.disable_user("alice")
        # Every generation, including wind-down access, ends on disable.
        with self.assertRaises(AccountDisabledError):
            self.svc.check_access(phone.access_token)
        with self.assertRaises(AccountDisabledError):
            self.svc.check_access(new_phone.access_token)
        with self.assertRaises(AccountDisabledError):
            self.svc.refresh(phone.refresh_token)
        # Bob's identically named device is unaffected.
        self.assertEqual(self.svc.check_access(bob_phone.access_token), "bob")
        # Re-enable: old chains of every generation stay revoked.
        self.svc.enable_user("alice")
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(phone.refresh_token)
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(new_phone.refresh_token)
        lineage = self.svc.device_lineage("alice", "phone-1")
        self.assertFalse(any(g["refresh_chain_active"]
                             for g in lineage["generations"]))
        self.assertFalse(any(g["wind_down_access_valid"]
                             for g in lineage["generations"]))
        relogin = self.login("alice", "pw-alice", device_id="phone-1")
        self.assertEqual(relogin.generation, 3)

    def test_reuse_alert_after_rollover_scoped_and_persisted(self):
        gen1 = self.login("alice", "pw-alice", "phone-1", "手机")
        rotated_gen1 = self.svc.refresh(gen1.refresh_token)
        gen2 = self.svc.rollover_device("alice", "phone-1").bundle
        # Replayed consumed credentials of the retired generation arrive late.
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(rotated_gen1.refresh_token)
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(gen1.refresh_token)
        activity = self.svc.export_device_activity("alice", "phone-1")
        rollover_events = [e for e in activity if e["kind"] == "rollover"]
        self.assertEqual(len(rollover_events), 1)
        self.assertEqual(rollover_events[0]["superseded_sessions"],
                         [gen1.session_id])
        self.assertIsNotNone(rollover_events[0]["rule"])
        blob = repr(activity)
        for secret in (gen1.refresh_token, gen2.refresh_token,
                       rotated_gen1.access_token):
            self.assertNotIn(secret, blob)

        # Reopen the database: generations, reject reasons and surviving scope
        # still line up under the same device.
        restarted = AuthService(self.db, timedelta(seconds=20),
                                timedelta(seconds=60))
        lineage = restarted.device_lineage("alice", "phone-1")
        gens = {g["generation"]: g for g in lineage["generations"]}
        self.assertTrue(gens[1]["superseded"])
        self.assertTrue(gens[1]["wind_down_access_valid"])
        self.assertTrue(gens[2]["refresh_chain_active"])
        self.assertEqual(lineage["current_generation"], 2)
        self.assertEqual(restarted.check_access(gen1.access_token), "alice")
        with self.assertRaises(CredentialSupersededError):
            restarted.refresh(gen1.refresh_token)
        events = restarted.export_device_activity("alice", "phone-1")
        self.assertTrue(all("presented_hash" in e for e in events if e["kind"] == "deny"))
        self.assertTrue(all(e.get("raw_credential") is None for e in events))



class StagedRolloverPlanTest(unittest.TestCase):
    """Staged multi-device rollover plans: simulate, approve, execute."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(seconds=2), timedelta(seconds=10))
        self.svc.create_user("alice", "correct horse battery staple")
        self.bundles = {}
        for dev in ("dev-a", "dev-b", "dev-c", "dev-d"):
            self.bundles[dev] = self.svc.login(
                "alice", "correct horse battery staple",
                device_id=dev, device_name=dev,
            )

    def tearDown(self):
        self.tmp.cleanup()

    def _make_plan(self, devices, min_available):
        return self.svc.create_rollover_plan(
            "alice", devices, min_available=min_available
        )

    def test_two_consecutive_batches_execute_in_order(self):
        plan = self._make_plan(
            ["dev-a", "dev-b", "dev-c", "dev-d"], min_available=2
        )
        self.assertEqual(plan["status"], "simulated")
        self.assertEqual(len(plan["batches"]), 2)
        self.assertIsNone(plan["current_availability"]["gap"])
        # Simulation changed nothing: every device is still generation 1.
        for dev, bundle in self.bundles.items():
            self.assertEqual(
                self.svc.check_access_detail(bundle.access_token)["generation"], 1
            )
        # An unapproved batch cannot take effect.
        with self.assertRaises(RolloverPlanError):
            self.svc.execute_rollover_batch(plan["id"], 0)

        self.svc.approve_rollover_batch(plan["id"], 0)
        first = self.svc.execute_rollover_batch(plan["id"], 0)
        outcomes = {r["device_id"]: r["outcome"]
                    for r in first["batch_result"]["results"]}
        self.assertEqual(outcomes, {"dev-a": "rolled_over", "dev-b": "rolled_over"})
        self.assertEqual(first["status"], "in_progress")
        self.assertIsNone(first["batch_result"]["availability_gap"])

        self.svc.approve_rollover_batch(plan["id"], 1)
        second = self.svc.execute_rollover_batch(plan["id"], 1)
        self.assertEqual(second["status"], "completed")
        for dev in self.bundles:
            lineage = self.svc.device_lineage("alice", dev)
            self.assertEqual(lineage["current_generation"], 2)
        # Old-generation access tokens of the first batch keep winding down
        # undisturbed by the second batch's new generations.
        detail = self.svc.check_access_detail(self.bundles["dev-a"].access_token)
        self.assertEqual(detail["decision"], "wind_down")
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(self.bundles["dev-a"].refresh_token)

    def test_duplicate_device_and_repeated_submission_rejected(self):
        plan = self._make_plan(
            ["dev-a", "dev-b", "dev-a", "dev-a"], min_available=1
        )
        self.assertEqual(plan["device_ids"], ["dev-a", "dev-b"])
        self.assertEqual(plan["duplicates_ignored"], ["dev-a", "dev-a"])
        # ready(2) - min_available(1) bounds the batch size to one device.
        self.assertEqual(len(plan["batches"]), 2)
        with self.assertRaises(RolloverPlanError):
            self._make_plan(["dev-a"], min_available=2)

        self.svc.approve_rollover_batch(plan["id"], 0)
        with self.assertRaises(RolloverPlanError):
            self.svc.approve_rollover_batch(plan["id"], 0)
        self.svc.execute_rollover_batch(plan["id"], 0)
        with self.assertRaises(RolloverPlanError):
            self.svc.execute_rollover_batch(plan["id"], 0)
        # The repeated submissions did not roll anything twice.
        self.assertEqual(
            self.svc.device_lineage("alice", "dev-a")["current_generation"], 2
        )
        with self.assertRaises(RolloverPlanError):
            self.svc.get_rollover_plan("plan_999")

    def test_offline_device_skipped_without_freezing_others(self):
        # dev-c logged out before the plan: it is offline for planning and
        # never enters a batch.
        self.svc.logout_device("alice", "dev-c")
        plan = self._make_plan(["dev-a", "dev-c", "dev-b"], min_available=1)
        sim = plan["simulation"]
        self.assertEqual(sim["device_status"]["dev-c"], "offline")
        self.assertEqual(sim["ready"], ["dev-a", "dev-b"])
        self.assertEqual(len(plan["batches"]), 2)

        # dev-b goes offline *after* simulation but before its batch runs.
        self.svc.login("alice", "correct horse battery staple",
                       device_id="dev-c", device_name="dev-c")
        self.svc.approve_rollover_batch(plan["id"], 0)
        self.svc.approve_rollover_batch(plan["id"], 1)
        self.svc.logout_device("alice", "dev-b")
        result = self.svc.execute_rollover_batch(plan["id"], 0)
        outcomes = {r["device_id"]: r["outcome"]
                    for r in result["batch_result"]["results"]}
        self.assertEqual(outcomes["dev-a"], "rolled_over")
        result = self.svc.execute_rollover_batch(plan["id"], 1)
        outcomes = {r["device_id"]: r["outcome"]
                    for r in result["batch_result"]["results"]}
        self.assertEqual(outcomes["dev-b"], "skipped")
        # The offline device gained no new chain from the plan, and no
        # device was frozen to protect the plan count.
        self.assertEqual(
            self.svc.device_lineage("alice", "dev-b")["current_generation"], 1
        )
        lineage = self.svc.device_lineage("alice", "dev-a")
        self.assertFalse(lineage["frozen"])
        self.assertEqual(lineage["current_generation"], 2)
        # Availability is still satisfied by the other devices, so there is
        # no gap; dev-b is simply reported offline, never frozen.
        availability = result["current_availability"]
        self.assertIsNone(availability["gap"])
        self.assertEqual(availability["device_status"]["dev-b"], "offline")

    def test_emergency_freeze_blocks_device_and_explains_gap(self):
        plan = self._make_plan(["dev-a", "dev-b"], min_available=2)
        self.assertIsNotNone(plan["simulation"]["risk_note"])
        self.svc.approve_rollover_batch(plan["id"], 0)
        self.svc.approve_rollover_batch(plan["id"], 1)
        # Suspected leak between approval and execution: freeze wins.
        self.svc.freeze_device_compromised("alice", "dev-b")
        result = self.svc.execute_rollover_batch(plan["id"], 0)
        result = self.svc.execute_rollover_batch(plan["id"], 1)
        outcomes = {r["device_id"]: (r["outcome"], r["reason"])
                    for r in result["batch_result"]["results"]}
        self.assertEqual(outcomes["dev-b"], ("blocked", "frozen"))
        gap = result["batch_result"]["availability_gap"]
        self.assertIn("shortfall", gap)
        self.assertIn("dev-b", gap)
        # The frozen device kept no authorization of any generation, and
        # the gap is still visible when re-reading the plan afterwards.
        self.assertTrue(self.svc.device_lineage("alice", "dev-b")["frozen"])
        with self.assertRaises(DeviceFrozenError):
            self.svc.check_access(self.bundles["dev-b"].access_token)
        reread = self.svc.get_rollover_plan(plan["id"])
        self.assertIn("shortfall", reread["current_availability"]["gap"])

    def test_account_disable_between_approval_and_execution(self):
        plan = self._make_plan(["dev-a", "dev-b"], min_available=1)
        self.svc.approve_rollover_batch(plan["id"], 0)
        self.svc.disable_user("alice")
        with self.assertRaises(AccountDisabledError):
            self.svc.execute_rollover_batch(plan["id"], 0)
        # Nothing executed while disabled; the batch stays merely approved.
        view = self.svc.get_rollover_plan(plan["id"])
        self.assertEqual(view["batches"][0]["status"], "approved")
        for dev in ("dev-a", "dev-b"):
            self.assertEqual(
                self.svc.device_lineage("alice", dev)["current_generation"], 1
            )
        # Re-enabling does not resurrect chains, so devices are now offline
        # and execution skips them instead of minting fresh authorization.
        self.svc.enable_user("alice")
        self.svc.approve_rollover_batch(plan["id"], 1)
        first = self.svc.execute_rollover_batch(plan["id"], 0)
        second = self.svc.execute_rollover_batch(plan["id"], 1)
        outcomes = {
            r["device_id"]: r["outcome"]
            for r in (first["batch_result"]["results"]
                      + second["batch_result"]["results"])
        }
        self.assertEqual(outcomes, {"dev-a": "skipped", "dev-b": "skipped"})
        self.assertIsNotNone(second["batch_result"]["availability_gap"])

    def test_old_requests_scoped_to_own_generation_across_devices(self):
        plan = self._make_plan(["dev-a"], min_available=0)
        self.svc.approve_rollover_batch(plan["id"], 0)
        self.svc.execute_rollover_batch(plan["id"], 0)
        # dev-a's old request winds down by its own generation's rule...
        detail_a = self.svc.check_access_detail(self.bundles["dev-a"].access_token)
        self.assertEqual(detail_a["decision"], "wind_down")
        # ...while dev-b, untouched by the plan, keeps a fully active chain
        # and its requests are unaffected by dev-a's new generation.
        detail_b = self.svc.check_access_detail(self.bundles["dev-b"].access_token)
        self.assertEqual(detail_b["decision"], "active")
        rotated_b = self.svc.refresh(self.bundles["dev-b"].refresh_token)
        self.assertEqual(rotated_b.generation, 1)
        # dev-a's retired refresh is a policy rejection, not a reuse break:
        # dev-a's new chain and dev-b's chain both survive it.
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(self.bundles["dev-a"].refresh_token)
        self.assertEqual(
            self.svc.check_access(rotated_b.access_token), "alice"
        )
        lineage = self.svc.device_lineage("alice", "dev-a")
        gens = {g["generation"]: g for g in lineage["generations"]}
        self.assertTrue(gens[2]["refresh_chain_active"])

    def test_wind_down_deadline_reported_in_simulation(self):
        soon = (_dt_now() + timedelta(seconds=1)).isoformat()
        later = (_dt_now() + timedelta(hours=1)).isoformat()
        tight = self.svc.create_rollover_plan(
            "alice", ["dev-a"], min_available=0, wind_down_deadline=soon
        )
        self.assertFalse(tight["simulation"]["wind_down_within_deadline"])
        loose = self.svc.create_rollover_plan(
            "alice", ["dev-a"], min_available=0, wind_down_deadline=later
        )
        self.assertTrue(loose["simulation"]["wind_down_within_deadline"])
        self.assertIsNotNone(loose["simulation"]["wind_down_finished_by"])


def _dt_now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


if __name__ == "__main__":
    unittest.main()
