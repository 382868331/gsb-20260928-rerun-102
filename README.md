# 身份认证实验核心（authcore）

本地认证核心，仅依赖 Python 3 标准库，覆盖：

- 本地测试用户：PBKDF2-HMAC-SHA256 口令存储（200k 轮，每用户独立盐）。
- 登录：签发不透明访问凭据（`at_…`）与续期凭据（`rf_…`），数据库只存
  SHA-256 哈希，原始凭据永不落盘。
- 访问凭据检查：区分格式错误、未知凭据、过期、撤销、账户停用五种结果。
- 续期：旋转式（rotation），每条续期凭据只能成功使用一次；旧凭据与新凭据
  以 `predecessor/replaced_by` 串成单条链。
- 并发安全：续期在独占文件锁事务中执行，同一条凭据被多线程/多进程并发
  使用时只有一个请求能旋转；其余请求判定为重放，记录审计并撤销整个续期
  家族，因此不可能出现两条互不相关的有效续期链。
- 退出登录：撤销该会话全部访问与续期凭据。账户停用：撤销该用户全部会话，
  且禁止再次登录。状态持久化到 `authcore.json`（原子替换 + `fsync`），
  重启后仍然有效。
- 重用审计：`reuse` 表记录观察时间、家族、会话、用户、凭据序号、**所呈
  交凭据的 SHA-256 哈希**和原因；不含原始凭据，可通过 API 或 CLI 查询。

## 错误类型（不伪装成网络失败）

`MalformedTokenError`（格式错误）、`InvalidTokenError`（未知凭据）、
`TokenExpiredError`（过期）、`TokenRevokedError`（撤销）、
`TokenReuseDetectedError`（续期凭据重用，家族熔断）、
`AccountDisabledError`（账户停用）、`InvalidCredentialsError`（用户名/口令
错误），均继承自 `AuthError`。

## 使用

```bash
python -m unittest discover -s tests   # 8 个测试
python run_demo.py                      # 完整虚构用户演示

python -m authcore.cli --db demo.json add-user alice 'S3cret!'
python -m authcore.cli --db demo.json login    alice 'S3cret!'
python -m authcore.cli --db demo.json check    at_...
python -m authcore.cli --db demo.json refresh  rf_...
python -m authcore.cli --db demo.json logout   at_...
python -m authcore.cli --db demo.json disable  alice
python -m authcore.cli --db demo.json events
```

## 文件

- `authcore/service.py`：登录、检查、续期旋转、撤销与审计逻辑。
- `authcore/store.py`：带 `flock` 锁的 JSON 持久化（线程/进程安全）。
- `authcore/errors.py`：分类错误。
- `authcore/cli.py`：命令行入口。
- `tests/test_authcore.py`：含 4 线程并发续期、重放熔断、重启持久化等测试。
- `run_demo.py`：虚构用户全流程演示（中文输出）。
