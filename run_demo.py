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

    print("\n全部场景走完：过期 / 撤销 / 停用 / 格式错误均为独立错误类型，"
          "没有伪装成网络失败。")


if __name__ == "__main__":
    main()
