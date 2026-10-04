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
  `deny` / `rotate` 五类事件，只含哈希与元数据；设备重命名只改显示名，
  不改既有审计记录中的设备归属快照。
- 设备凭据换代（rotation）：`rotate_device_credentials` 在同一设备上
  签发全新登录家族（新 `family`），旧链按换代前固定显示的规则收尾——
  旧续期凭据立刻不能再创建续期，已签发的旧访问凭据在收尾窗口
  （wind-down）内仍可用，窗口后到达的在途请求拒绝；旧链请求一律不触发
  家族熔断，因此迟到的旧响应绝不可能冻结新链。
- 计划换代 vs 怀疑泄露：`emergency_freeze_device` 立即撤销该设备全部
  未完成授权（包括尚在收尾窗口内的旧链与活动新链），无宽限；只影响
  该设备，其他设备与其他用户不受牵连。换代、重用告警与账户停用交错
  时最终撤销范围可查；账户重开不复活任何旧链，需重新登录，重新登录
  仍挂接同一设备谱系。
- 历代登录身份：每个设备有稳定 `lineage_id` 与递增 `generation`，链与
  链之间以 `predecessor_session / replaced_by_session` 串联；
  `device_lineage` 返回每代链的状态（active / winding_down / retired /
  revoked）、拒绝原因与仍有效范围（仅已签发的访问凭据、不能续期），
  持久化重开后仍一一对应。

## 错误类型（不伪装成网络失败）

`MalformedTokenError`（格式错误）、`InvalidTokenError`（未知凭据）、
`TokenExpiredError`（过期）、`TokenRevokedError`（撤销）、
`TokenReuseDetectedError`（续期凭据重用，家族熔断）、
`ChainSupersededError`（旧链已被计划换代取代，拒绝新续期但不熔断新链）、
`ChainWoundDownError`（旧链在途请求晚于收尾截止时间）、
`AccountDisabledError`（账户停用）、`InvalidCredentialsError`（用户名/口令
错误），均继承自 `AuthError`。

## 使用

```bash
python -m unittest discover -s tests   # 8 个测试
python run_demo.py                      # 完整虚构用户演示

python -m authcore.cli --db demo.json add-user alice 'S3cret!'
python -m authcore.cli --db demo.json login    alice 'S3cret!' --device-id phone-1 --device-name 手机
python -m authcore.cli --db demo.json check    at_...
python -m authcore.cli --db demo.json refresh  rf_...
python -m authcore.cli --db demo.json logout   at_...
python -m authcore.cli --db demo.json devices  alice
python -m authcore.cli --db demo.json freeze   alice phone-1
python -m authcore.cli --db demo.json rename-device alice phone-1 新手机
python -m authcore.cli --db demo.json rotate   alice phone-1 'S3cret!' --winddown-seconds 900
python -m authcore.cli --db demo.json freeze-emergency alice phone-1 --reason 'suspected leak'
python -m authcore.cli --db demo.json lineage  alice phone-1
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
  多设备并发续期、单设备冻结、交错重放定位、停用/重开、重命名审计
  归属，以及计划换代与收尾窗口、连续换代、旧请求乱序返回、同设备旧链
  并发续期、怀疑泄露立即冻结、换代/重用/停用交错撤销范围、重开后谱系
  还原等测试。
- `run_demo.py`：虚构用户全流程演示（中文输出），含多设备管理与设备
  凭据换代场景。
