# Keygate

Rust 编写的 API key 管理与 Envoy 鉴权服务。

- Web UI：通过 Envoy OIDC 登录，每个用户管理自己的应用和密钥。
- 长期 API key：生成时显示一次，可单独撤销；存储中只有 SHA-256 摘要。
- 鉴权服务：Envoy HTTP `ext_authz`，可按节点部署，使用有界内存缓存。
- 可插拔存储：OpenBao KV v2、SQLite；新增后端只需实现 `Store` trait。

```text
浏览器 → Envoy OIDC → manager → Store
客户端 → Envoy → 应用服务
           ↓ ext_authz
       authz（每节点）→ 内存缓存 → Store
```

## 测试

需要 Rust 1.95。完整测试需要 Linux、Docker；测试自行启动并清理独立的 OpenBao 和 Envoy，不访问集群凭据。

```sh
cargo test-all
```

包含管理 API、用户/应用隔离、JWT 校验、CSRF、存储 CAS、SQLite 持久化、节点缓存撤销、故障关闭，以及真实 OpenBao/Envoy 集成测试。首次运行会拉取测试镜像。只运行无需 Docker 的测试：`cargo test --locked`。

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

## 本地运行

同一进程运行管理端（8080）和鉴权端（8081），SQLite 保存到当前目录。默认仅监听回环地址。

```sh
umask 077
openssl rand -hex 32 > proxy-secret
cargo run -- --mode all --backend sqlite \
  --proxy-secret-file proxy-secret \
  --trust-subject-header
```

此模式用于本地测试可信代理身份。管理请求必须携带 `X-Keygate-Proxy-Secret` 和 `X-Keygate-Subject`，因此直接打开浏览器会得到 401。正常部署使用下面的 OIDC 配置，不启用 `--trust-subject-header`。

## Envoy 与 OIDC

Envoy 负责登录、Cookie 和刷新。Keygate 默认校验 Envoy 转发的 ID token：签名、issuer、audience、有效期和 `sub`。使用 ID token，不使用不保证为 JWT 的 access token。

管理端配置：

```text
KEYGATE_MODE=manager
KEYGATE_PUBLIC_ORIGIN=https://keys.example.com
KEYGATE_OIDC_ISSUER=https://id.example.com
KEYGATE_OIDC_AUDIENCE=<Pocket ID client ID>
KEYGATE_OIDC_JWKS_URL=<discovery 文档中的 jwks_uri>
KEYGATE_PROXY_SECRET_FILE=/credentials/proxy/credential
```

Envoy 的 OIDC `forwardIDToken.header` 设置为 `X-Keygate-ID-Token`，并用 credential injection 覆盖 `X-Keygate-Proxy-Secret`。后者至少 32 字节，服务端文件与 Envoy Secret 内容一致。管理服务不要直接暴露给客户端；网络策略只允许 Envoy。配置示例见 [deploy/envoy-gateway.yaml](deploy/envoy-gateway.yaml)。需要安装的 Envoy Gateway CRD 支持 `forwardIDToken`。

可信 subject 模式仅适用于已经验证身份、覆盖 subject 头的受控代理。默认 JWT 模式忽略客户端提供的 subject 头。单实例绑定一个 OIDC issuer；改变 issuer 会影响应用所有者身份，不能直接当作无状态配置切换。

用户通过 `sub` 拥有应用，不能访问其他用户的应用。允许哪些用户登录，由 Pocket ID 客户端访问策略决定。首版没有团队共享、管理员代管或用户自助接入路由。

## 存储后端

OpenBao 配置：

```text
KEYGATE_BACKEND=openbao
KEYGATE_BAO_ADDR=https://openbao.example.com
KEYGATE_BAO_MOUNT=kv
KEYGATE_BAO_PREFIX=keygate
KEYGATE_BAO_TOKEN_FILE=/credentials/bao/token
```

数据保存到 KV v2 的 `keygate/apps/<application UUID>`。每个应用一个文档，使用 CAS 防止并发创建/撤销覆盖。撤销保留记录，不删除源 secret。Token 文件每次请求重新读取，交给 OpenBao Agent 或其他凭据管理组件负责登录、续租和更新。服务不会创建或自动续租 OpenBao token。

manager 使用 [写入策略](deploy/openbao-manager.hcl)，authz 使用 [只读策略](deploy/openbao-authz.hcl)。不需要同步每个 API key 到 Kubernetes Secret。示例 token Secret 只用于服务访问 OpenBao，不能把客户端 key 放进去。

SQLite 适合同机运行或本地验证，**不能给不同节点各放一份 SQLite 当共享存储**。跨节点部署使用 OpenBao，或添加共享数据库后端。后端接口在 [src/store.rs](src/store.rs)：`get`、`list`、原子 `put(expected_version)`。插件为编译时 Rust 实现，不加载动态库。

## 按节点鉴权

运行 `keygate --mode authz --backend openbao`，或使用 [DaemonSet 模板](deploy/workloads.yaml)。每个 Envoy 所在节点都需要可用的 authz Pod，按实际节点 taint 添加 toleration。

每条应用路由把 ext_authz 路径固定成 `/check/<application UUID>`，服务兼容 Envoy 在其后附加原始路径。客户端仍发送标准 `Authorization: Bearer <key>`。成功返回 200 和应用/key ID；无效 key 返回 401，跨应用返回 403，存储错误返回 503。Envoy 必须 `failOpen: false`，不要把请求 body 发送给鉴权服务。服务不代理正文，因此支持 SSE/长响应。

新增应用需要一次路由绑定；之后创建、撤销、轮换该应用的 key 都在 UI 完成，无需改 YAML。用户自建的应用 UUID 不会自动获得现有 API 路由的权限。

DaemonSet 确保每节点有实例，但普通 Service backendRef 不保证命中本节点。模板用 `Backend` FQDN 访问 Service ClusterIP，配合 `internalTrafficPolicy: Local`；需启用 Envoy Gateway Backend 扩展，并在集群实际验证本节点路由。缺少本节点实例时拒绝请求，不回退到远端节点。

把 authz 的 `x-keygate-app`/`x-keygate-key-id` 作为可信身份时，Envoy 必须覆盖客户端同名头。codex-api 的内部凭据仍由 Envoy 注入独立请求头，禁止客户端绕过 Envoy 直连后端；不要提前覆盖供 ext_authz 校验的 Authorization。

## 缓存与限制

- 缓存应用的摘要记录，不保存明文 key；默认最多 1024 个应用。
- 默认固定 30 秒 TTL，命中不会延长。`KEYGATE_CACHE_TTL_SECONDS=0` 禁用，最大 300 秒。
- 撤销最迟在配置的缓存 TTL 后对新鉴权检查生效，不中断已经放行的流式请求。
- 后端不可用时，未过期缓存仍可使用；过期记录拒绝放行，不使用 stale fallback。
- 未找到的应用不做负缓存，新增 key 可能需要等待该应用已有缓存过期。
- 读取限时 5 秒，并发最多 32 个，等待最多 250 毫秒；入口仍应配置请求限流。
- JWKS 固定缓存 60 秒，密钥轮换须保留重叠窗口。
- 首版应用列表逐个读取，适合小规模部署；每应用最多 1000 条密钥记录（含撤销记录）。没有用量计费、审计后台或即时撤销广播。

`/healthz` 只表示进程存活，不表示存储/IdP 可用。部署文件是待替换参数的示例，不会自动部署，也不含实际凭据。

参考：[Envoy 外部鉴权](https://gateway.envoyproxy.io/docs/tasks/security/ext-auth/)、[OIDC API](https://gateway.envoyproxy.io/docs/api/extension_types/)、[OpenBao KV v2](https://openbao.org/docs/secrets/kv/kv-v2/)。
