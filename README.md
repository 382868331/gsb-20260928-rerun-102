# 身份认证实验核心（Auth Core）

纯 Python 标准库实现的本地身份认证核心，覆盖：

- 虚构本地测试用户登录（PBKDF2-SHA256 口令存储）；
- 不透明访问凭据（access token）校验；
- 不透明续期凭据（refresh token）轮换，**每条续期凭据只能成功使用一次**；
- 并发续期安全：同一条续期凭据被多个线程/进程同时使用时，恰有一个成功，
  其余立即触发整链（家族）撤销，不会产生两条互不相关的有效续期链；
- 旧凭据重放检测：重放已轮换/已撤销的续期凭据会撤销整个会话家族；
- 登出与账户停用撤销对应会话的全部访问/续期凭据，撤销状态落盘，
  **进程重启后仍有效**；
- 凭据重用可查询审计记录（`list_reuse_records`），记录中只有 SHA-256
  摘要、用户名、家族 ID、时间与原因，**绝不包含原始凭据**；
- 过期、撤销、账户停用、格式错误、无法识别分别抛出不同异常类型，
  调用方不会把各类拒绝误判成“网络失败”。

## 运行环境

- Python 3.14（仅标准库；运行环境无 sqlite3，因此使用 JSON 文件持久化）
- 测试需要 pytest

## 快速体验

```bash
python3 demo.py        # 端到端演示：登录/并发续期/重放/重启
python3 -m pytest tests/ -q
```

## 模块说明

- `auth_core/tokens.py`：令牌生成、格式校验、SHA-256 摘要与口令哈希。
  令牌形如 `act_<52字符base32>`（访问）与 `rft_<52字符base32>`（续期）。
- `auth_core/store.py`：JSON 文件存储，fcntl 跨进程排他锁 +
  临时文件 fsync + rename 原子替换；业务异常路径下的状态变更也会落盘。
- `auth_core/service.py`：`AuthService`，提供 `create_user`、`login`、
  `verify_access_token`、`refresh`、`logout`、`disable_user`、
  `enable_user`、`list_reuse_records`。
- `auth_core/seed.py`：三个虚构用户 `ada.lovelace` / `alan.turing` /
  `grace.hopper`（口令仅用于本地测试，见源码）。
- `demo.py`：完整故事线演示。
- `tests/test_auth_core.py`：含多线程与多子进程的并发续期测试。

## 异常分类

| 异常 | 含义 |
| --- | --- |
| `InvalidCredentialsError` | 用户名或口令错误 |
| `TokenFormatError` | 凭据格式错误（前缀/长度不合法、类型用错） |
| `InvalidTokenError` | 格式正确但服务端从未签发/已不认识 |
| `AccessTokenExpiredError` | 访问凭据过期 |
| `RefreshTokenExpiredError` | 续期凭据过期 |
| `TokenReuseError`（`RevokedError` 子类） | 续期凭据重放，整链撤销，携带审计记录 id |
| `RevokedError` | 登出等显式撤销 |
| `AccountDisabledError` | 账户已停用 |

## 存储内容

状态文件（默认由调用方指定路径）只包含：用户口令哈希、访问/续期凭据的
SHA-256 摘要及状态、续期家族状态、重用审计记录（同样只含摘要）。
任何原始令牌、原始口令都不会写入磁盘或日志。
