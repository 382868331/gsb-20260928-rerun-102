"""End-to-end walkthrough of the authentication core with fictional users.

Run:  python run_demo.py
Uses a throwaway data directory, so it can be executed repeatedly.
"""

from __future__ import annotations

import shutil
import threading
from datetime import timedelta
from pathlib import Path

from authcore import (
    AccountDisabledError,
    AuthError,
    AuthService,
    CredentialSupersededError,
    DeviceFrozenError,
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
    PlanNotApprovedError,
    TokenExpiredError,
    TokenReuseDetectedError,
    TokenRevokedError,
)

DATA_DIR = Path("demo_data")
DB = DATA_DIR / "authcore.json"


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def expect(label: str, fn, *args, expected=()):
    try:
        result = fn(*args)
        print(f"[允许] {label}: {result!r}")
        return result
    except expected as exc:
        print(f"[拒绝] {label}: {type(exc).__name__} — {exc}")
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"[意外] {label}: {type(exc).__name__} — {exc}")
        raise


def main() -> None:
    if DATA_DIR.exists():
        shutil.rmtree(DATA_DIR)
    DATA_DIR.mkdir()

    # Short lifetimes keep the demo fast and let us show real expiry.
    svc = AuthService(str(DB), access_ttl=timedelta(seconds=2),
                      refresh_ttl=timedelta(seconds=30))
    svc.create_user("林小满", "Purple-Otter-721!")
    svc.create_user("赵远征", "Quiet-Fox-904!")
    print("已创建虚构用户: 林小满 / 赵远征")

    section("1. 登录与凭据检查")
    bundle = expect("正确密码登录", svc.login, "林小满", "Purple-Otter-721!")
    expect("错误密码登录", svc.login, "林小满", "wrong-password",
           expected=InvalidCredentialsError)
    expect("访问凭据检查", svc.check_access, bundle.access_token)
    expect("格式错误的访问凭据", svc.check_access, "at_!!!not-a-token",
           expected=MalformedTokenError)
    expect("格式正确但不存在的凭据", svc.check_access, "at_" + "z" * 43,
           expected=InvalidTokenError)
    expect("拿刷新凭据当访问凭据用", svc.check_access, bundle.refresh_token,
           expected=MalformedTokenError)

    section("2. 并发续期：4 个线程同时使用同一条续期凭据")
    barrier = threading.Barrier(4)
    outcomes: list[tuple[str, object]] = []

    def race(index: int) -> None:
        barrier.wait()
        try:
            outcomes.append((f"线程{index}", svc.refresh(bundle.refresh_token)))
        except AuthError as exc:
            outcomes.append((f"线程{index}", exc))

    threads = [threading.Thread(target=race, args=(i,)) for i in range(1, 5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    winners = [o for o in outcomes if not isinstance(o[1], AuthError)]
    print(f"成功续期的线程数: {len(winners)}（必须恰好为 1 个线程进入签发）")
    for name, outcome in outcomes:
        kind = "成功签发新链" if not isinstance(outcome, AuthError) else type(outcome).__name__
        print(f"  {name}: {kind}")
    rotated = winners[0][1]
    expect("赢家刚签发的访问凭据也被撤销（并发重放 => 整族熔断）",
           svc.check_access, rotated.access_token, expected=TokenRevokedError)
    expect("赢家的新续期凭据同样失效（无第二条有效链）",
           svc.refresh, rotated.refresh_token, expected=TokenRevokedError)

    section("3. 旧凭据重放与重用审计")
    expect("重放最初的续期凭据", svc.refresh, bundle.refresh_token,
           expected=TokenReuseDetectedError)
    events = svc.list_reuse_events()
    print(f"重用记录条数: {len(events)}（仅含 SHA-256 哈希，无原始凭据）")
    for event in events:
        print(f"  - {event['observed_at']} | {event['detail']} | "
              f"用户={event['username']} | hash={event['presented_hash'][:16]}…")
    raw_on_disk = DB.read_text(encoding="utf-8")
    assert bundle.refresh_token not in raw_on_disk
    assert rotated.refresh_token not in raw_on_disk
    print("已确认磁盘数据中不包含任何原始凭据明文")

    section("4. 退出登录撤销整条权限链")
    zb = expect("赵远征登录", svc.login, "赵远征", "Quiet-Fox-904!")
    expect("赵远征访问", svc.check_access, zb.access_token)
    svc.logout(zb.access_token)
    print("赵远征已退出登录")
    expect("退出后旧访问凭据", svc.check_access, zb.access_token,
           expected=TokenRevokedError)
    expect("退出后续期凭据", svc.refresh, zb.refresh_token,
           expected=TokenRevokedError)

    section("5. 账户停用")
    lb2 = expect("林小满重新登录", svc.login, "林小满", "Purple-Otter-721!")
    svc.disable_user("林小满")
    print("管理员已停用账户: 林小满")
    expect("停用后访问", svc.check_access, lb2.access_token,
           expected=AccountDisabledError)
    expect("停用后续期", svc.refresh, lb2.refresh_token,
           expected=AccountDisabledError)
    expect("停用后登录", svc.login, "林小满", "Purple-Otter-721!",
           expected=AccountDisabledError)

    section("6. 过期单独区分")
    ex = expect("赵远征登录（用于过期演示）", svc.login, "赵远征", "Quiet-Fox-904!")
    print("等待 2.5 秒让访问凭据过期（访问 TTL=2s）…")
    threading.Event().wait(2.5)
    expect("过期访问凭据", svc.check_access, ex.access_token,
           expected=TokenExpiredError)

    section("7. 模拟重启：重新打开同一份持久化文件")
    restarted = AuthService(str(DB), access_ttl=timedelta(seconds=2),
                            refresh_ttl=timedelta(seconds=30))
    expect("重启后已退出的凭据仍被撤销", restarted.check_access, zb.access_token,
           expected=TokenRevokedError)
    expect("重启后停用账户仍不能登录", restarted.login, "林小满",
           "Purple-Otter-721!", expected=AccountDisabledError)
    expect("重启后正常用户可登录", restarted.login, "赵远征", "Quiet-Fox-904!")
    print(f"重启后重用记录仍可查询: {len(restarted.list_reuse_events())} 条")

    section("8. 按登录设备管理会话")
    phone = svc.login("赵远征", "Quiet-Fox-904!",
                      device_id="phone-01", device_name="口袋手机")
    laptop = svc.login("赵远征", "Quiet-Fox-904!",
                       device_id="laptop-01", device_name="书房电脑")
    print("同一账户在两台虚构设备上登录: phone-01 / laptop-01")

    section("8a. 多台设备并发续期：各自独立的链，全部成功")
    barrier2 = threading.Barrier(2)
    results2: list[object] = []

    def rotate2(bundle):
        barrier2.wait()
        try:
            results2.append(svc.refresh(bundle.refresh_token))
        except AuthError as exc:
            results2.append(exc)

    ts = [threading.Thread(target=rotate2, args=(b,)) for b in (phone, laptop)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    print("两台设备的续期都成功（链互相独立）:",
          all(not isinstance(r, AuthError) for r in results2))
    by_device = {r.device_id: r for r in results2
                 if not isinstance(r, AuthError)}
    phone2, laptop2 = by_device["phone-01"], by_device["laptop-01"]

    section("8b. 怀疑手机泄露续期凭据：只冻结手机这条链")
    frozen = svc.logout_device("赵远征", "phone-01")
    print(f"已冻结 phone-01 的 {frozen} 条链，其他设备不受影响")
    expect("手机的新续期凭据", svc.refresh, phone2.refresh_token,
           expected=TokenRevokedError)
    expect("书房电脑继续续期", svc.refresh, laptop2.refresh_token)

    section("8c. 旧续期请求与重新登录交错：只熔断旧链")
    old = svc.login("赵远征", "Quiet-Fox-904!",
                    device_id="tablet-01", device_name="客厅平板")
    rotated_old = svc.refresh(old.refresh_token)
    fresh = svc.login("赵远征", "Quiet-Fox-904!",
                      device_id="tablet-01", device_name="客厅平板")
    expect("交错期间重放平板旧续期凭据", svc.refresh, old.refresh_token,
           expected=TokenReuseDetectedError)
    expect("旧链赢家凭据也被熔断", svc.refresh, rotated_old.refresh_token,
           expected=TokenRevokedError)
    expect("平板上后来重新登录的会话仍然有效", svc.check_access,
           fresh.access_token)

    section("8d. 设备重命名不改变既有审计归属")
    svc.rename_device("赵远征", "tablet-01", "卧室平板")
    for row in svc.list_devices("赵远征"):
        print(f"  设备 {row['device_id']}（{row['device_name']}） "
              f"session={row['session_id']} active={row['active']} "
              f"原因={row['revoke_reason']}")
    activity = svc.export_device_activity("赵远征", "tablet-01")
    print("平板（重命名后）的活动记录仍归属当时的设备名:")
    for event in activity:
        print(f"  - {event['kind']:7s} | 设备名快照={event['device_name']} | "
              f"{event['detail']}")

    section("8e. 账户停用结束全部设备，重开后需重新登录")
    svc.disable_user("赵远征")
    print("已停用 赵远征，全部设备会话同时结束:",
          all(not d["active"] for d in svc.list_devices("赵远征")))
    svc.enable_user("赵远征")
    svc.login("赵远征", "Quiet-Fox-904!", device_id="phone-02",
              device_name="新手机")
    print("已重开账户；旧链保持撤销，新手机重新登录后列表:",
          [(d["device_id"], d["active"]) for d in svc.list_devices("赵远征")])

    section("8f. 导出设备活动记录（不含原始凭据）")
    section("9. 设备凭据换代：计划换代与紧急冻结")

    section("9a. 连续两次计划换代：旧链收尾、新链续期")
    g1 = svc.login("赵远征", "Quiet-Fox-904!",
                   device_id="watch-01", device_name="运动手表")
    print(f"手表第 1 代登录身份: family={g1.family[:8]}… generation={g1.generation}")
    r1 = svc.rollover_device("赵远征", "watch-01")
    g2 = r1.bundle
    print(f"第 1 次换代 -> generation={r1.generation}，"
          f"已退休会话 {list(r1.superseded_sessions)}")
    print("事先显示的换代规则:", r1.rule)
    r2 = svc.rollover_device("赵远征", "watch-01", new_name="新运动手表")
    g3 = r2.bundle
    print(f"第 2 次换代 -> generation={r2.generation}")
    expect("第 1 代旧续期请求（在途返回晚了）", svc.refresh, g1.refresh_token,
           expected=CredentialSupersededError)
    expect("第 2 代旧续期请求", svc.refresh, g2.refresh_token,
           expected=CredentialSupersededError)
    old_access = expect("第 1 代旧访问凭据仍在收尾范围内",
                        svc.check_access_detail, g1.access_token)
    print(f"  旧访问决定依据: {old_access['decision']} "
          f"generation={old_access['generation']}")
    expect("第 3 代当前链正常续期", svc.refresh, g3.refresh_token)

    section("9b. 同设备并发：换代与旧续期请求抢锁")
    w1 = svc.login("赵远征", "Quiet-Fox-904!",
                   device_id="band-01", device_name="健康手环")
    race_outcomes: list[tuple[str, object]] = []
    barrier3 = threading.Barrier(3)

    def old_request() -> None:
        barrier3.wait()
        try:
            race_outcomes.append(("旧续期", svc.refresh(w1.refresh_token)))
        except AuthError as exc:
            race_outcomes.append(("旧续期", exc))

    def do_rollover() -> None:
        barrier3.wait()
        try:
            race_outcomes.append(("换代", svc.rollover_device(
                "赵远征", "band-01")))
        except AuthError as exc:
            race_outcomes.append(("换代", exc))

    t_old1 = threading.Thread(target=old_request)
    t_old2 = threading.Thread(target=old_request)
    t_roll = threading.Thread(target=do_rollover)
    for t in (t_old1, t_old2, t_roll):
        t.start()
    for t in (t_old1, t_old2, t_roll):
        t.join()
    for label, outcome in race_outcomes:
        print(f"  {label}: {type(outcome).__name__}")
    band_new = next(o.bundle for label, o in race_outcomes if label == "换代")
    expect("换代后的新链绝不会因旧请求晚到而被冻结",
           svc.refresh, band_new.refresh_token)

    section("9c. 旧请求乱序返回：先到新凭据、后到更老凭据")
    expect("更老的旧续期最后才返回", svc.refresh, w1.refresh_token,
           expected=CredentialSupersededError)
    expect("新链访问仍然有效", svc.check_access, band_new.access_token)

    section("9d. 怀疑泄露：紧急冻结撤销该设备全部未完成授权")
    revoked_all = svc.freeze_device_compromised("赵远征", "watch-01")
    print(f"紧急冻结手表，撤销历代链数: {revoked_all}（含换代收尾访问）")
    expect("第 1 代收尾访问也被撤销", svc.check_access, g1.access_token,
           expected=DeviceFrozenError)
    expect("第 3 代续期被撤销", svc.refresh, g3.refresh_token,
           expected=DeviceFrozenError)
    expect("冻结期间禁止该设备重新登录",
           lambda: svc.login("赵远征", "Quiet-Fox-904!",
                             device_id="watch-01",
                             device_name="新运动手表"),
           expected=DeviceFrozenError)
    print("其他设备不受牵连: 手环新链 ->",
          svc.check_access(band_new.access_token))

    section("9e. 解冻后重新登录：旧代不复活，继续向上编号")
    svc.unfreeze_device("赵远征", "watch-01")
    expect("解冻后第 3 代旧访问凭据仍撤销（冻结原由保留）",
           svc.check_access, g3.access_token,
           expected=TokenRevokedError)
    g4 = svc.login("赵远征", "Quiet-Fox-904!",
                   device_id="watch-01", device_name="新运动手表")
    print(f"重新登录获得 generation={g4.generation}（旧代不复活）")

    section("9f. 换代 / 重用告警 / 账户停用交错后的谱系")
    svc.disable_user("赵远征")
    svc.enable_user("赵远征")
    lineage = svc.device_lineage("赵远征", "watch-01")
    print(f"手表当前代际={lineage['current_generation']} "
          f"冻结标记={lineage['frozen']}")
    for gen in lineage["generations"]:
        print(f"  gen={gen['generation']} session={gen['session_id']} "
              f"superseded={gen['superseded']} revoked={gen['revoked']} "
              f"原因={gen['revoke_reason']} "
              f"收尾访问有效={gen['wind_down_access_valid']} "
              f"续期链活跃={gen['refresh_chain_active']}")

    section("9g. 保存重开后谱系仍可对应")
    reopened = AuthService(str(DB), access_ttl=timedelta(seconds=2),
                           refresh_ttl=timedelta(seconds=30))
    persisted = reopened.device_lineage("赵远征", "watch-01")
    print("重开后代际数:", len(persisted["generations"]),
          "当前代:", persisted["current_generation"])

    section("9h. 多设备分阶段换代：模拟、显式批准、重新校验")
    p1 = svc.login("赵远征", "Quiet-Fox-904!",
                   device_id="plan-phone", device_name="计划手机")
    p2 = svc.login("赵远征", "Quiet-Fox-904!",
                   device_id="plan-tablet", device_name="计划表")
    p3 = svc.login("赵远征", "Quiet-Fox-904!",
                   device_id="plan-laptop", device_name="计划电脑")
    staged = svc.plan_device_rollover(
        "赵远征",
        [["plan-phone"], ["plan-tablet", "plan-laptop"]],
        minimum_available=2,
        wind_down=timedelta(seconds=30),
    )
    print("计划", staged["id"], "模拟可行:", staged["simulation"]["feasible"])
    for batch in staged["simulation"]["batches"]:
        print("  批次", batch["batch_index"], "预计可用",
              batch["projected_available_count"], batch["projected_available_after"])
    expect("未批准先执行", svc.execute_rollover_batch, staged["id"], 0,
           expected=PlanNotApprovedError)
    svc.approve_rollover_batches(staged["id"], [0])
    first_batch = svc.execute_rollover_batch(staged["id"], 0)
    print("第 0 批执行结果:", [(r["device_id"], r["status"], r["generation"])
                              for r in first_batch["results"]])
    repeated = svc.execute_rollover_batch(staged["id"], 0)
    print("重复提交第 0 批:", [(r["device_id"], r["status"])
                              for r in repeated["results"]])
    expect("第 1 批未批准", svc.execute_rollover_batch, staged["id"], 1,
           expected=PlanNotApprovedError)
    svc.approve_rollover_batches(staged["id"], [1])
    second_batch = svc.execute_rollover_batch(staged["id"], 1)
    new_tablet = next(
        row for row in second_batch["results"]
        if row["device_id"] == "plan-tablet"
    )
    print("第 1 批执行结果:", [(r["device_id"], r["status"], r["generation"])
                              for r in second_batch["results"]])
    expect("第一批旧续期仅按其旧代收尾规则拒绝", svc.refresh, p1.refresh_token,
           expected=CredentialSupersededError)
    expect("其他设备旧访问仍按自己的代次收尾", svc.check_access, p2.access_token)

    section("9i. 紧急冻结优先阻断，并显式报告可用缺口")
    gap = svc.freeze_device_compromised_report(
        "赵远征", "plan-tablet",
        managed_device_ids=["plan-phone", "plan-tablet", "plan-laptop"],
        minimum_available=3,
    )
    print("冻结 plan-tablet 后缺口:", gap["shortfall"],
          "不可用设备:", gap["availability_gap"])
    expect("被怀疑设备的新代次也立即阻断", svc.check_access,
           new_tablet["access_token"], expected=DeviceFrozenError)

    section("10. 导出设备活动记录（不含原始凭据）")
    export = svc.export_device_activity("赵远征")
    kinds = {}
    for event in export:
        kinds[event["kind"]] = kinds.get(event["kind"], 0) + 1
    print(f"共 {len(export)} 条记录，按类型统计: {kinds}")
    blob = repr(export)
    for secret in (phone.refresh_token, laptop.refresh_token,
                   fresh.access_token, g1.refresh_token, g3.refresh_token):
        assert secret not in blob
    rollover_records = [e for e in export if e["kind"] == "rollover"]
    print(f"换代记录 {len(rollover_records)} 条，均只记设备/链关系与决定依据 "
          "(generation / superseded_sessions / rule)，无原始凭据")
    print("导出内容只含哈希与元数据，无任何原始凭据")

    print("\n全部场景走完：过期 / 撤销 / 停用 / 格式错误均为独立错误类型，"
          "没有伪装成网络失败。")


if __name__ == "__main__":
    main()
