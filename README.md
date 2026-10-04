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
- 按登录设备管理会话：登录可携带稳定的 `device_id` 与显示名，每次续期
  沿用该设备身份；`logout_device` 只冻结指定设备的会话链，不影响其他
  设备；账户停用仍同时结束全部会话，`enable_user` 重开后旧链保持撤销。
- 交错重放定位：旧续期请求与重新登录交错时，重用熔断只撤销被重放的
  那条链（错误信息注明 family / session / device），后来重新登录的
  会话不受影响。
- 设备活动导出：`activity` 表区分 `login` / `refresh` / `revoke` /
  `deny` / `rollover` 五类事件，只含哈希、设备与链的关系和决定依据；
  设备重命名只改显示名，不改既有审计记录中的设备归属快照。
- 受控设备凭据换代：`rollover_device` 执行**计划换代**，同一设备获得
  新的登录链（新 family、generation 加一，活动归属不变）；旧代被标记
  为 `superseded`——不能再创建新的续期（返回
  `CredentialSupersededError`，这是事先返回给客户端的换代策略拒绝，不是
  重放熔断），已经发出的访问凭据按 `WIND_DOWN_RULE` 在到期前继续有效。
  在途旧请求无论早晚到达、乱序到达都只按换代规则决定，旧代请求永远不
  会冻结新链。
- 紧急冻结：`freeze_device_compromised` 用于怀疑泄露，撤销该设备**历代**
  全部尚未完成的授权（含计划换代留下的收尾访问），并在解冻前禁止该设备
  重新登录；其他设备不受牵连。`unfreeze_device` 只解除冻结标记，旧代不
  复活，需重新登录或再次换代。`device_lineage` 可查看历代登录身份、
  撤销/退休原因与仍有效范围（`wind_down_access_valid` /
  `refresh_chain_active`），保存重开后仍然对应。

## 错误类型（不伪装成网络失败）

`MalformedTokenError`（格式错误）、`InvalidTokenError`（未知凭据）、
`TokenExpiredError`（过期）、`TokenRevokedError`（撤销）、
`TokenReuseDetectedError`（续期凭据重用，家族熔断）、
`CredentialSupersededError`（计划换代后旧代凭据的策略拒绝，不再续期、
保留收尾访问）、`DeviceFrozenError`（设备紧急冻结）、
`AccountDisabledError`（账户停用）、`InvalidCredentialsError`（用户名/口令
错误），均继承自 `AuthError`；前两者继承 `TokenRevokedError`。

## 使用

```bash
python -m unittest discover -s tests   # 23 个测试
python run_demo.py                      # 完整虚构用户演示

python -m authcore.cli --db demo.json add-user alice 'S3cret!'
python -m authcore.cli --db demo.json login    alice 'S3cret!' --device-id phone-1 --device-name 手机
python -m authcore.cli --db demo.json check    at_...
python -m authcore.cli --db demo.json refresh  rf_...
python -m authcore.cli --db demo.json logout   at_...
python -m authcore.cli --db demo.json devices  alice
python -m authcore.cli --db demo.json freeze   alice phone-1
python -m authcore.cli --db demo.json rollover alice phone-1 --name 新手机
python -m authcore.cli --db demo.json freeze-compromised alice phone-1
python -m authcore.cli --db demo.json unfreeze alice phone-1
python -m authcore.cli --db demo.json lineage  alice phone-1
python -m authcore.cli --db demo.json rename-device alice phone-1 新手机
python -m authcore.cli --db demo.json disable  alice
python -m authcore.cli --db demo.json enable   alice
python -m authcore.cli --db demo.json events
python -m authcore.cli --db demo.json activity [alice]
```

## 文件

- `authcore/service.py`：登录、检查、续期旋转、撤销与审计逻辑。
- `authcore/store.py`：带 `flock` 锁的 JSON 持久化（线程/进程安全）。
- `authcore/errors.py`：分类错误。
- `authcore/cli.py`：命令行入口。
- `tests/test_authcore.py`：含 4 线程并发续期、重放熔断、重启持久化、
  多设备并发续期、单设备冻结、交错重放定位、停用/重开、重命名审计归属，
  以及连续换代、换代/旧请求并发、旧请求乱序、紧急冻结、换代与停用交错、
  重开后历代谱系对应等测试。
- `run_demo.py`：虚构用户全流程演示（中文输出），含多设备管理与第 9 节
  设备凭据换代场景。
