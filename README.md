# 本地身份认证实验核心

这是一个 Go 实现的独立身份服务实验骨架，面向本机开发和后续应用接入。项目只使用程序生成的测试账户，不读取真实凭据；也不包含权限管理后台。

## 能力

- 本地账户登录：密码使用 PBKDF2-SHA256、每用户独立盐和恒定时间比较，明文密码不入库。
- 双令牌模型：短期访问令牌 + 较长寿命刷新令牌，访问令牌默认 2 分钟过期。
- 刷新令牌轮换：续期后旧访问令牌和旧刷新令牌同时失效，旧刷新凭据重放返回 401。
- 并发原子续期：同一旧刷新凭据的并发请求在互斥区原子消费，持久化完成后才返回成功。
- 服务端撤销：退出登录撤销当前会话；账户停用撤销该账户所有活动会话。
- 无认证缓存放行：鉴权与续期均查询当前权威存储索引，撤销后本地仍持有的令牌不能继续使用。
- 重启保持：账户、盐值哈希、会话状态、撤销原因和已用刷新凭据哈希通过原子替换写入 JSON 文件。
- 日志脱敏：只记录用户名和结果，密码、访问令牌、刷新令牌均以 redacted 或不出现的方式处理。

## 运行服务

```bash
go run ./cmd/idp -addr 127.0.0.1:8080 -data-dir ./data
```

首次启动会生成测试账户 `alice`。生成密码写入 `data/alice-test-password.txt`，文件权限为 0600；也可以用 `IDP_SEED_PASSWORD` 提供本地测试密码。状态文件是 `data/idp-state.json`，其中仅包含哈希、盐、过期时间和撤销状态。

## HTTP 接口

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"..."}'

curl -sS http://127.0.0.1:8080/v1/me \
  -H 'Authorization: Bearer ACCESS_TOKEN'

curl -sS -X POST http://127.0.0.1:8080/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"REFRESH_TOKEN"}'

curl -sS -X POST http://127.0.0.1:8080/v1/auth/logout \
  -H 'Authorization: Bearer ACCESS_TOKEN'
```

## 本地竞态与失效演示

演示程序用标准 `http.Client` 走完整 HTTP 请求处理链；在禁止绑定端口的环境中，传输层替换为进程内 RoundTripper，不影响 handler、鉴权和存储逻辑。

```bash
go run ./cmd/idp-demo
go test -race ./...
```

演示依次验证：登录、访问令牌过期、刷新轮换、旧刷新凭据重放、8 个并发续期仅 1 个成功、退出后缓存令牌失效、账户停用后全部会话失效，以及重新打开状态文件模拟重启后撤销仍有效。

## 边界

- 这是实验身份服务，不包含注册、权限、角色、管理后台或外部身份提供商。
- 令牌以 256 位随机数生成，存储中只保存 SHA-256 哈希；客户端必须妥善保存返回的明文令牌。
- 文件存储适合单实例本地实验；后续多应用共用时，应将 `internal/auth.Service` 的鉴权语义迁移到带事务和唯一约束的数据库实现。
