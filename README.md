# Keygate

Rust API key 管理与 Envoy 鉴权服务，使用 PostgreSQL 存储。

- Envoy 负责 OIDC 登录和组访问控制，Keygate 验证转发的 ID token。
- 应用共享；每个用户只能生成、查看和撤销自己的 key。创建应用不会获得管理其他用户 key 的权限，也不会自动添加 Envoy 路由。
- API key 使用系统安全随机源生成 256 位随机秘密，只显示一次，数据库只保存 SHA-256 摘要和归属信息。
- 鉴权服务可按节点部署，使用有界内存缓存。默认撤销延迟最多 30 秒；已建立的流不会被中断。

```text
浏览器 → Envoy OIDC / 组访问策略 → manager → PostgreSQL
客户端 → Envoy → 后端应用
           ↓ ext_authz
       authz（每节点）→ 内存缓存 → PostgreSQL
```

## 运行

需要 Rust 1.95 和 PostgreSQL。数据库连接通过 `KEYGATE_DATABASE_URL` 设置；生产连接建议使用 `sslmode=verify-full` 并配置可信 CA。

```sh
export KEYGATE_DATABASE_URL='postgres://keygate:REPLACE_PASSWORD@localhost/keygate'
umask 077
openssl rand -hex 32 > proxy-secret
cargo run -- --mode all --proxy-secret-file proxy-secret --trust-subject-header
```

以上是本地可信代理模式，请求需携带 `X-Keygate-Proxy-Secret` 和 `X-Keygate-Subject`。生产环境不要启用 `--trust-subject-header`，改用：

```text
KEYGATE_MODE=manager
KEYGATE_DATABASE_URL=<PostgreSQL manager 连接串>
KEYGATE_PUBLIC_ORIGIN=https://keys.example.com
KEYGATE_OIDC_ISSUER=https://id.example.com
KEYGATE_OIDC_AUDIENCE=<OIDC client ID>
KEYGATE_OIDC_JWKS_URL=<discovery 文档中的 jwks_uri>
KEYGATE_PROXY_SECRET_FILE=/credentials/proxy/credential
```

manager / all 模式启动时创建 `keygate_applications` 表；首次初始化应先启动单个 manager。authz 模式不执行 DDL，只需要连接权限、schema USAGE 和该表的 SELECT 权限。并发写入采用版本 CAS，冲突返回 409，刷新后重试。

[部署模板](deploy/workloads.yaml) 使用两个 Secret 保存 manager/authz 的数据库连接串。数据库需独立配置和备份；哈希存储不能替代数据库写权限保护。

## Envoy

[配置模板](deploy/envoy-gateway.yaml) 需要按实际 Envoy Gateway CRD 调整：

- 登录侧转发 `X-Keygate-ID-Token`，并覆盖注入 `X-Keygate-Proxy-Secret`。OIDC 组访问限制在 Envoy 配置，Keygate 不读取客户端组 header。
- API 路由固定请求 `/check/<应用 UUID>`；应用 ID 从 UI 获取，不接受客户端 header 决定鉴权范围。
- 客户端使用 `Authorization: Bearer <API key>`。只在该路由绑定的应用内匹配 key 摘要。
- authz 成功返回 `X-Auth-Request-User`、`X-Keygate-User-Id`（同一个用户 ID）、`X-Keygate-App`、`X-Keygate-Key-Id`。用户 ID 来自通过校验的 key 所有者，为 `usr_` 加 OIDC sub 的 SHA-256 摘要。
- `X-Auth-Request-User` 是 [OAuth2 Proxy 的常见约定](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/)，不是 HTTP 标准字段。Envoy 必须覆盖所有同名身份头，后端只允许 Envoy 访问。

每节点部署使用 DaemonSet 和 `internalTrafficPolicy: Local`，模板通过 Service ClusterIP 路由；按实际节点配置 toleration。默认缓存上限 1024 个应用，TTL 30 秒，可通过 `KEYGATE_CACHE_CAPACITY` / `KEYGATE_CACHE_TTL_SECONDS` 调整，TTL 为 0 时每次查库。故障不延长缓存期限，过期后查库失败则拒绝授权。

## API key 格式

```text
kg-<43 位 base64url 随机秘密>
```

总长 46 个 ASCII 字符；短前缀标明 Keygate API key，秘密部分是 32 字节安全随机数的无填充 base64url 编码。应用 ID 来自 Envoy 路由，用户和 key ID 从匹配摘要的存储记录确定，不嵌入 key。SHA-256 只用于存储完整 key 的摘要，不能拿时间戳或用户名做哈希来代替安全随机生成。这也不同于用户密码存储，用户密码应使用专门的密码 KDF。

这是存储和 key 格式的破坏性更新：已移除 OpenBao / SQLite，没有自动迁移旧数据，旧 `kgt_` 和 `keygate_api_v1_` key 不再接受。已有安装需要在 PostgreSQL 中重建应用和 key，并更新 Envoy 路由中的应用 UUID。修改 OIDC issuer 也需要规划用户身份迁移。

## 测试

```sh
cargo test-all
```

完整测试需要 Linux 和 Docker，会启动并清理独立 PostgreSQL、Envoy，不读取集群凭据。无需 Docker 的测试运行 `cargo test --locked`。

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
cargo coverage
```

CI 要求全部生产 Rust 源码（含 main.rs）行和函数覆盖率 100%；HTML 报告位于 `target/llvm-cov/html/index.html`。检查格式和 lint：`cargo fmt --check`、`cargo clippy --locked --all-targets -- -D warnings`。安全边界和测试范围见 [SECURITY.md](SECURITY.md)。
