# Keygate

Rust API key 管理与 Envoy 鉴权服务，使用 PostgreSQL 存储，管理页面使用 Svelte 和 TypeScript。

- Envoy 负责 OIDC 登录和组访问控制，Keygate 验证转发的 ID token。
- 应用由管理员在配置文件中定义，并由管理员配置对应的 Envoy 路由和自定义 API 访问规则。用户只能为已配置的应用生成、查看和撤销自己的 key，不能创建或修改应用。
- 新 API key 的 `kg-` 前缀后仅包含 46 个随机英文字母，使用系统安全随机源，随机熵至少为 256 位。密钥只显示一次，数据库只保存 SHA-256 摘要和归属信息。
- 鉴权服务可按节点部署，使用有界内存缓存。默认撤销延迟最多 30 秒；已建立的流不会被中断。

```text
浏览器 → Envoy OIDC / 组访问策略 → manager → PostgreSQL
客户端 → Envoy → 后端应用
           ↓ ext_authz
       authz（每节点）→ 内存缓存 → PostgreSQL
```

## 镜像

推送到 main 或在 Actions 手动运行工作流，测试通过后自动发布 Linux amd64 镜像，无需额外配置 PAT：

```sh
docker pull ghcr.io/reonokiy/keygate:latest
```

每次发布同时提供 `sha-<完整提交 SHA>` 标签，digest 记录在 Actions 发布任务摘要中。PR 仅运行测试，不发布镜像。

## 运行

从源码运行需要 Rust 1.95、Node.js 24（含 npm）和 PostgreSQL。先安装前端依赖、检查类型并构建页面，再编译运行 Rust 服务。数据库连接通过 `KEYGATE_DATABASE_URL` 设置；生产连接建议使用 `sslmode=verify-full` 并配置可信 CA。

```sh
npm --prefix web ci
npm --prefix web run check
npm --prefix web run build
export KEYGATE_DATABASE_URL='postgres://keygate:REPLACE_PASSWORD@localhost/keygate'
umask 077
openssl rand -hex 32 > proxy-secret
cargo run -- --mode all --config deploy/keygate.json --proxy-secret-file proxy-secret --trust-subject-header
```

Svelte / TypeScript 源码位于 `web/`，Vite 将页面构建为 `web/dist/index.html`、`app.js` 和 `style.css`，由 Rust 编译时嵌入并提供。`web/dist/` 不提交到版本库，因此首次运行 Cargo 构建、测试或 lint 前必须完成前端构建。修改前端后，重新运行 `npm --prefix web run check`、`npm --prefix web run build`，再重新编译并启动 Rust 服务。Docker 镜像构建和 CI 会自动执行前端检查与构建；运行已构建的镜像不需要 Node.js。

以上是本地可信代理模式，请求需携带 `X-Keygate-Proxy-Secret` 和 `X-Keygate-Subject`。生产环境不要启用 `--trust-subject-header`，改用：

```text
KEYGATE_MODE=manager
KEYGATE_CONFIG=/config/keygate.json
KEYGATE_DATABASE_URL=<PostgreSQL manager 连接串>
KEYGATE_PUBLIC_ORIGIN=https://keys.example.com
KEYGATE_OIDC_ISSUER=https://id.example.com
KEYGATE_OIDC_AUDIENCE=<OIDC client ID>
KEYGATE_OIDC_JWKS_URL=<discovery 文档中的 jwks_uri>
KEYGATE_PROXY_SECRET_FILE=/credentials/proxy/credential
```

manager / all 模式启动时创建 `keygate_applications` 表；首次初始化应先启动单个 manager。authz 模式不执行 DDL，只需要连接权限、schema USAGE 和该表的 SELECT 权限。并发写入采用版本 CAS，冲突返回 409，刷新后重试。

[部署模板](deploy/workloads.yaml) 使用两个 Secret 保存 manager/authz 的数据库连接串，并将同一个应用配置 ConfigMap 以只读方式挂载到两类进程。数据库需独立配置和备份；哈希存储不能替代数据库写权限保护。

## 管理员应用配置

所有运行模式（`manager`、`authz`、`all`）都必须通过 `--config <文件路径>` 或 `KEYGATE_CONFIG` 指定 JSON 配置文件。管理员维护应用 ID 和名称，例如 [deploy/keygate.json](deploy/keygate.json)：

```json
{
  "applications": [
    {
      "id": "11111111-1111-4111-8111-111111111111",
      "name": "Codex API"
    }
  ]
}
```

配置中的应用是唯一有效的应用目录。`GET /api/apps` 返回这些应用和当前用户的 key，即使应用还没有生成过 key；服务不提供创建应用的 API。`applications` 可以为空；重复或全零 UUID、无效名称、未知配置字段会导致启动失败。应用名称和 UUID 由配置决定，API key 仍保存在 PostgreSQL 中。

添加应用时，管理员还需在 Envoy 中设置对应的路由、HTTP 方法、路径及自定义 API 访问策略，并将鉴权路径绑定到同一个 UUID。Keygate 配置定义应用目录；网关配置定义 API 规则。应用配置本身不会创建 Envoy 路由，也不包含方法或路径规则。

配置仅在进程启动时读取。修改配置后，必须协调重启 manager 和全部 authz 实例，确保所有进程使用同一版本；仅更新 ConfigMap 不会生效。移除应用后，加载新配置的进程会拒绝该应用的密钥管理和鉴权，但不会删除数据库中的 key。修改名称时保留 UUID 可继续使用现有 key；重新加入旧 UUID 也会重新启用其尚未撤销的 key。若需彻底停用应用，应同时移除对应 Envoy 路由，并等待全部实例更新。

## Envoy

[配置模板](deploy/envoy-gateway.yaml) 需要按实际 Envoy Gateway CRD 调整：

- 登录侧转发 `X-Keygate-ID-Token`，并覆盖注入 `X-Keygate-Proxy-Secret`。OIDC 组访问限制在 Envoy 配置，Keygate 不读取客户端组 header。
- API 路由固定请求 `/check/<应用 UUID>`；应用 ID 必须与管理员配置文件中的 UUID 一致，不接受客户端 header 决定鉴权范围。
- 路由允许的 HTTP 方法、路径及自定义 API 策略由管理员在 Envoy 中设置；Keygate 验证 key 是否属于该路由绑定的已配置应用。
- 客户端使用 `Authorization: Bearer <API key>`。只在该路由绑定的应用内匹配 key 摘要。
- authz 成功返回 `X-Auth-Request-User`、`X-Keygate-User-Id`（同一个用户 ID）、`X-Keygate-App`、`X-Keygate-Key-Id`。用户 ID 来自通过校验的 key 所有者，为 `usr_` 加 OIDC sub 的 SHA-256 摘要。
- `X-Auth-Request-User` 是 [OAuth2 Proxy 的常见约定](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/)，不是 HTTP 标准字段。Envoy 必须覆盖所有同名身份头，后端只允许 Envoy 访问。

每节点部署使用 DaemonSet 和 `internalTrafficPolicy: Local`，模板通过 Service ClusterIP 路由；按实际节点配置 toleration。默认缓存上限 1024 个应用，TTL 30 秒，可通过 `KEYGATE_CACHE_CAPACITY` / `KEYGATE_CACHE_TTL_SECONDS` 调整，TTL 为 0 时每次查库。故障不延长缓存期限，过期后查库失败则拒绝授权。

管理页面的静态资源和 API 请求使用相对路径，支持子路径，例如 `/keys/`：代理应将 `/keys` 重定向到 `/keys/`，并在转发时去掉 `/keys` 前缀。OIDC 回调也应放在该子路径下；`KEYGATE_PUBLIC_ORIGIN` 仍填写域名 origin，不包含路径。生产页面由 Keygate 提供，无需单独部署前端服务器。

## API key 格式

```text
kg-<46 个随机英文字母 A-Z / a-z>
```

新 key 总长 49 个 ASCII 字符；固定前缀是 `kg-`，之后只包含大小写英文字母，不含数字、下划线或额外的连字符。秘密部分使用系统安全随机源 `OsRng`，从 52 个字母中均匀生成 46 个字符，约有 262 位随机熵。应用 ID 来自 Envoy 路由，用户和 key ID 从匹配摘要的存储记录确定，不嵌入 key。SHA-256 只用于存储完整 key 的摘要，不能拿时间戳或用户名做哈希来代替安全随机生成。这也不同于用户密码存储，用户密码应使用专门的密码 KDF。

已签发的 `kg-` 加 43 个规范无填充 base64url 字符的旧格式 key（总长 46 个字符，原始秘密为 32 字节）仍兼容：只要所属应用在配置中且 key 未撤销，现有 PostgreSQL 中保存的 key 无需重新生成。仅新签发的 key 使用上述纯字母秘密格式。

此前存储和 key 格式已有破坏性更新：已移除 OpenBao / SQLite，没有自动迁移旧数据，旧 `kgt_` 和 `keygate_api_v1_` key 不再接受。从这些旧版本升级时，需要在配置文件中定义应用、重新生成 key，并更新 Envoy 路由中的应用 UUID。已有 PostgreSQL 安装改用配置目录时，将原有应用 UUID 和名称写入配置即可保留现有 key；遗漏的应用将无法使用。修改 OIDC issuer 也需要规划用户身份迁移。

## 测试

```sh
npm --prefix web ci
npm --prefix web run check
npm --prefix web run build
npm exec --prefix web -- playwright install chromium
npm --prefix web test
cargo test-all
```

`npm --prefix web run check` 检查 Svelte 和 TypeScript，`npm --prefix web run build` 验证生产构建。`npm --prefix web test` 使用 Playwright 和 Chromium，针对生产页面构建及生产 CSP 运行浏览器冒烟测试，覆盖根路径、子路径、移动端视口、密钥生成与撤销、关闭后清除密钥、复制失败回退和错误显示。浏览器测试使用模拟 API，不验证真实 OIDC 登录或完整部署链路。CI 使用 `playwright install --with-deps chromium` 安装浏览器及系统依赖，然后运行前端测试。

Rust 完整测试需要 Linux 和 Docker，会启动并清理独立 PostgreSQL、Envoy，不读取集群凭据。完成前端构建后，无需 Docker 的 Rust 测试运行 `cargo test --locked`。

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
cargo coverage
```

CI 要求全部生产 Rust 源码（含 main.rs）行和函数覆盖率 100%；HTML 报告位于 `target/llvm-cov/html/index.html`。检查格式和 lint：`cargo fmt --check`、`cargo clippy --locked --all-targets -- -D warnings`。安全边界和测试范围见 [SECURITY.md](SECURITY.md)。
