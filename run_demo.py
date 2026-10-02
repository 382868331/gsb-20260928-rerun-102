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
    InvalidCredentialsError,
    InvalidTokenError,
    MalformedTokenError,
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

    section("8. 按登录设备管理会话（虚构设备）")
    dev = AuthService(str(DATA_DIR / "devices.json"),
                      access_ttl=timedelta(seconds=30),
                      refresh_ttl=timedelta(seconds=300))
    dev.create_user("陈默", "Silent-River-308!")
    phone = dev.login("陈默", "Silent-River-308!",
                      device_id="phone-01", device_name="旧手机")
    laptop = dev.login("陈默", "Silent-River-308!",
                       device_id="laptop-02", device_name="工作电脑")
    print("陈默已在 旧手机 / 工作电脑 两台虚构设备上登录")

    rotated = dev.refresh(phone.refresh_token)
    print("旧手机完成续期，仍归属 device_id=phone-01（身份沿用）")
    expect("旧手机上的旧续期凭据被重放（疑似泄露）", dev.refresh,
           phone.refresh_token, expected=TokenReuseDetectedError)
    frozen = dev.list_reuse_events(phone.family)[0]
    print(f"被冻结的链: family={frozen['family'][:12]}… "
          f"device={frozen['device_id']}（只冻结这一条链）")
    expect("工作电脑完全不受影响", dev.check_access, laptop.access_token)
    dev.refresh(laptop.refresh_token)
    print("工作电脑续期成功，确认单设备冻结不波及其他设备")

    relogin = dev.login("陈默", "Silent-River-308!",
                        device_id="phone-01", device_name="旧手机")
    expect("旧手机重新登录后的新链正常续期", dev.refresh,
           relogin.refresh_token)
    print("重新登录产生全新 family，未被旧链的熔断牵连")

    dev.rename_device("陈默", "phone-01", "新手机")
    entry = next(d for d in dev.list_devices("陈默")
                 if d["device_id"] == "phone-01")
    print(f"设备重命名后列表显示: {entry['device_name']}")
    history = dev.list_activity(username="陈默", device_id="phone-01")
    print(f"重命名前的审计记录仍归属旧名称 "
          f"'{history[0]['device_name']}'（审计归属不变）")

    dev.logout_device("陈默", "laptop-02")
    expect("工作电脑被单独退出", dev.check_access, laptop.access_token,
           expected=TokenRevokedError)
    expect("旧手机新链仍然有效", dev.check_access, relogin.access_token)

    activity = dev.list_activity(username="陈默")
    print(f"设备活动记录 {len(activity)} 条（可导出，不含原始凭据）:")
    for event in activity:
        print(f"  - {event['kind']:7s} | {event['device_id']:9s} | "
              f"{event['device_name']} | {event['detail']}")
    assert phone.refresh_token not in repr(activity)

    dev.disable_user("陈默")
    print("账户停用：全部设备会话同时结束")
    expect("停用后任何设备访问", dev.check_access, relogin.access_token,
           expected=AccountDisabledError)
    dev.enable_user("陈默")
    expect("重开账户后旧会话仍已撤销", dev.check_access,
           relogin.access_token, expected=TokenRevokedError)
    dev.login("陈默", "Silent-River-308!", device_id="tablet-03",
              device_name="平板")
    remaining = dev.list_devices("陈默")
    print("重开后设备列表: "
          + ", ".join(f"{d['device_name']}({len(d['sessions'])}个会话)"
                      for d in remaining))

    print("\n全部场景走完：过期 / 撤销 / 停用 / 格式错误均为独立错误类型，"
          "没有伪装成网络失败。")


if __name__ == "__main__":
    main()
