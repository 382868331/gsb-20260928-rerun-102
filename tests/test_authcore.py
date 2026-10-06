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
    DeviceOfflineError,
    DeviceFrozenError,
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
    PlanNotApprovedError,
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
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "auth.db")
        self.svc = AuthService(self.db, timedelta(hours=1), timedelta(hours=2))
        self.svc.create_user("alice", "pw-alice")

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, device_id):
        return self.svc.login(
            "alice", "pw-alice",
            device_id=device_id, device_name=device_id,
        )

    def test_two_approved_batches_recheck_conditions_and_keep_generations_apart(self):
        first = self.login("dev-1")
        second = self.login("dev-2")
        plan = self.svc.plan_device_rollover(
            "alice", [["dev-1"], ["dev-2"]], minimum_available=1,
            wind_down=timedelta(minutes=5),
        )
        self.assertTrue(plan["simulation"]["feasible"])
        restarted = AuthService(self.db, timedelta(hours=1), timedelta(hours=2))
        persisted_plan = restarted.get_rollover_plan(plan["id"])
        self.assertEqual(persisted_plan["batches"], [["dev-1"], ["dev-2"]])
        self.assertNotIn("access_token", repr(persisted_plan))
        self.assertEqual(
            [d["device_id"] for d in plan["simulation"]["batches"][0]["devices"]],
            ["dev-1"],
        )
        with self.assertRaises(PlanNotApprovedError):
            self.svc.execute_rollover_batch(plan["id"], 0)
        self.svc.approve_rollover_batches(plan["id"], [0])
        batch1 = self.svc.execute_rollover_batch(plan["id"], 0)
        self.assertEqual(batch1["shortfall"], 0)
        new_first = batch1["results"][0]
        self.assertEqual(new_first["status"], "rolled_over")
        self.assertEqual(new_first["generation"], 2)
        # Repeating the same approved batch is idempotent and cannot increment
        # the device generation a second time.
        repeated = self.svc.execute_rollover_batch(plan["id"], 0)
        self.assertEqual(repeated["results"][0]["status"], "skipped")
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(first.refresh_token)
        detail = self.svc.check_access_detail(first.access_token)
        self.assertEqual(detail["decision"], "wind_down")
        self.assertEqual(detail["generation"], 1)
        # The other device's old generation is untouched by the first batch.
        self.assertEqual(self.svc.check_access(second.access_token), "alice")
        self.assertEqual(self.svc.refresh(second.refresh_token).generation, 1)

        with self.assertRaises(PlanNotApprovedError):
            self.svc.execute_rollover_batch(plan["id"], 1)
        self.svc.approve_rollover_batches(plan["id"], [1])
        batch2 = self.svc.execute_rollover_batch(plan["id"], 1)
        self.assertEqual(batch2["results"][0]["generation"], 2)
        self.assertEqual(self.svc.get_rollover_plan(plan["id"])["status"],
                         "executed")
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(second.refresh_token)
        self.assertEqual(
            self.svc.check_access_detail(new_first["access_token"])[
                "generation"],
            2,
        )

    def test_duplicate_device_in_plan_is_rejected(self):
        self.login("dev-1")
        self.login("dev-2")
        with self.assertRaises(ValueError):
            self.svc.plan_device_rollover(
                "alice", [["dev-1"], ["dev-1", "dev-2"]], 1
            )

    def test_offline_device_fails_without_freezing_other_devices(self):
        online = self.login("online")
        offline = self.login("offline")
        self.svc.logout(offline.access_token)
        plan = self.svc.plan_device_rollover(
            "alice", [["online", "offline"]], minimum_available=1
        )
        simulated = {d["device_id"]: d for d in plan["simulation"]["batches"][0]["devices"]}
        self.assertFalse(simulated["offline"]["eligible"])
        self.assertIn("offline", simulated["offline"]["reason"])
        self.assertTrue(plan["simulation"]["feasible"])
        self.svc.approve_rollover_batches(plan["id"], [0])
        result = self.svc.execute_rollover_batch(plan["id"], 0)
        statuses = {r["device_id"]: r["status"] for r in result["results"]}
        self.assertEqual(statuses, {"online": "rolled_over", "offline": "failed"})
        self.assertIn("DeviceOfflineError", result["results"][1]["reason"])
        self.assertEqual(result["availability_gap"], ["offline"])
        self.assertEqual(result["shortfall"], 0)
        self.assertEqual(self.svc.check_access(online.access_token), "alice")
        with self.assertRaises(DeviceOfflineError):
            self.svc.rollover_device("alice", "offline")

    def test_account_disabled_between_simulation_and_execution_blocks_current_batch(self):
        first = self.login("dev-1")
        second = self.login("dev-2")
        plan = self.svc.plan_device_rollover(
            "alice", [["dev-1", "dev-2"]], minimum_available=1
        )
        self.svc.approve_rollover_batches(plan["id"], [0])
        self.svc.disable_user("alice")
        result = self.svc.execute_rollover_batch(plan["id"], 0)
        self.assertTrue(all(r["status"] == "failed" for r in result["results"]))
        self.assertEqual(result["shortfall"], 1)
        self.assertEqual(set(result["availability_gap"]), {"dev-1", "dev-2"})
        self.svc.enable_user("alice")
        # Disable permanently ended the old chains. Re-enabled devices must
        # establish fresh chains before the still-approved plan can act.
        relogged1 = self.login("dev-1")
        relogged2 = self.login("dev-2")
        result2 = self.svc.execute_rollover_batch(plan["id"], 0)
        self.assertTrue(all(r["status"] == "rolled_over"
                            for r in result2["results"]))
        with self.assertRaises(TokenRevokedError):
            self.svc.refresh(first.refresh_token)
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(relogged1.refresh_token)
        with self.assertRaises(CredentialSupersededError):
            self.svc.refresh(relogged2.refresh_token)
        self.assertEqual(relogged1.generation, 2)
        self.assertEqual(result2["results"][0]["generation"], 3)

    def test_emergency_freeze_takes_precedence_and_reports_gap(self):
        self.login("dev-1")
        second = self.login("dev-2")
        plan = self.svc.plan_device_rollover(
            "alice", [["dev-1"], ["dev-2"]], minimum_available=2
        )
        self.svc.approve_rollover_batches(plan["id"], [0, 1])
        first_result = self.svc.execute_rollover_batch(plan["id"], 0)
        new_first_token = first_result["results"][0]["access_token"]
        report = self.svc.freeze_device_compromised_report(
            "alice", "dev-1",
            managed_device_ids=["dev-1", "dev-2"],
            minimum_available=2,
        )
        self.assertTrue(report["device_frozen"])
        self.assertEqual(report["shortfall"], 1)
        self.assertEqual(report["availability_gap"], ["dev-1"])
        with self.assertRaises(DeviceFrozenError):
            self.svc.check_access(new_first_token)
        second_result = self.svc.execute_rollover_batch(plan["id"], 1)
        self.assertEqual(second_result["results"][0]["status"], "rolled_over")
        self.assertEqual(second_result["availability_gap"], ["dev-1"])
        self.assertEqual(second_result["shortfall"], 1)
        self.assertEqual(self.svc.check_access(second.access_token), "alice")

    def test_each_old_generation_uses_its_own_wind_down_rule(self):
        short_svc = AuthService(
            str(Path(self.tmp.name) / "short.db"),
            timedelta(hours=1), timedelta(hours=2),
        )
        short_svc.create_user("bob", "pw-bob")
        gen1a = short_svc.login("bob", "pw-bob", device_id="dev-1")
        gen1b = short_svc.login("bob", "pw-bob", device_id="dev-2")
        plan = short_svc.plan_device_rollover(
            "bob", [["dev-1"], ["dev-2"]], minimum_available=1,
            wind_down=timedelta(milliseconds=80),
        )
        short_svc.approve_rollover_batches(plan["id"], [0, 1])
        first = short_svc.execute_rollover_batch(plan["id"], 0)
        new1 = first["results"][0]
        threading.Event().wait(0.05)
        second = short_svc.execute_rollover_batch(plan["id"], 1)
        new2 = second["results"][0]
        threading.Event().wait(0.06)
        with self.assertRaises(CredentialSupersededError):
            short_svc.check_access(gen1a.access_token)
        # Device two retired later, so its own deadline is still open even
        # though device one's earlier generation has already closed.
        detail = short_svc.check_access_detail(gen1b.access_token)
        self.assertEqual(detail["generation"], 1)
        self.assertEqual(detail["decision"], "wind_down")
        self.assertEqual(
            short_svc.check_access_detail(new1["access_token"])["generation"],
            2,
        )
        self.assertEqual(
            short_svc.check_access_detail(new2["access_token"])["generation"],
            2,
        )


if __name__ == "__main__":
    unittest.main()
