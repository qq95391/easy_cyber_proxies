# Easy Proxies（二开版）

基于 [sing-box](https://github.com/SagerNet/sing-box) 的多协议代理池：一个共享入口 + 每节点独立端口同时提供服务，内置健康探测、三态熔断、调用方零感知改道、独立账号与分池、结构化分级日志与管理面板。

> 本仓库是 `jasonwong1991/easy_proxies` 的二开分支，在原版基础上重构了运行拓扑、验证模型、账号体系与可观测性。原版文档中的 `mode` 多选一、`pool.user_pools` 配置方式已在本分支废弃，详见[升级与破坏性变更](#升级与破坏性变更)。

---

## 特性

| 能力 | 说明 |
|---|---|
| **多协议** | VMess / VLESS / Trojan / Shadowsocks / Hysteria2 / TUIC / AnyTLS / SOCKS5 / HTTP(S)。`ssr://`、`hysteria://` 可被解析但不参与构建 |
| **双栈拓扑** | 共享 pool 入口（默认 2323）+ 每节点独立端口（默认 24000 起）同时启动，无需切换模式 |
| **零感知改道** | 拨号阶段失败自动换节点，全部改道在 `switch_budget`（默认 3s）内完成；超时才向调用方报错 |
| **三态熔断** | 每节点 Closed / Open / HalfOpen，连续失败达阈值后跳过，半开探测自动恢复 |
| **会话粘性** | `用户名.会话ID` 固定到单一上游节点，支持 TTL 与容量上限 |
| **独立账号** | 每用户独立凭据（bcrypt），一用户单池，支持启停、到期、会话/并发配额、凭据轮换，变更热生效 |
| **分层验证** | 后台 `generate_204` 保活；全维度严格验证（出口 IP / 匿名度 / 真实性 / MITM / 延迟 / 带宽）由人工按需触发 |
| **多来源接入** | 内联节点、`nodes.txt`、订阅、网络空间测绘（FOFA / Hunter / Quake / 自定义）、免费代理池（proxy_pool） |
| **节点管理** | WebUI 增删改、按协议动态表单、Clash YAML 批量导入 + 解析预览 + 事务式批量添加 |
| **可观测** | 改道数、切换耗时 P95/P99、感知失败率、重载断连；结构化日志支持级别/类别/关键字检索，并记录访问目标域名/IP |
| **管理面板** | 监控看板 / 用户与分池 / 会话路由 / 节点配置 / 诊断分析 / 控制台日志 / 系统设置 |

---

## 快速开始

### 前置条件

- Docker 24+ 与 Docker Compose v2
- 2 GB 以上可用内存（节点数多时按需增加）
- 需要拉取镜像与 Go 依赖的网络环境

### Docker Compose 部署

```bash
git clone <your-fork-url> easy_proxies
cd easy_proxies
cp .env.example .env      # 按需填写端口、面板密码、测绘密钥
docker compose up -d --build
```

启动后：

| 端口 | 用途 |
|---|---|
| `32323` → 容器 `2323` | 共享 pool 入口（HTTP + SOCKS5，同一端口多协议） |
| `9091` | 管理面板与 `/api/*` |
| `24000-24200` | 每节点独立端口，**默认不映射到宿主机**（容器内验证与管理面使用；需要宿主机直连时取消 `docker-compose.yml` 中该行的注释） |
| `5010` | 内置 `proxy_pool` 的 API（`/get/` `/all/` `/count/`） |

首次启动时：若 `data/config.yaml` 不存在，`entrypoint.sh` 会从镜像内 `config.example.yaml` 生成；`data/` 与 `logs/` 通过 volume 持久化。

### 本地构建（可选）

```bash
go build ./...
go test ./... -count=1
node --test scripts/test-ui.mjs    # 前端 fixture
```

要求 Go 1.26.10 及以上（见 `go.mod`）。

---

## 运行拓扑：固定双栈

```
客户端 ──► 共享入口 2323（HTTP/SOCKS5，池内调度）
        └► 节点端口 24000+（每节点一个，直连该节点）

两条路径同时存在，互不影响；共享入口仍走健康加权/会话粘性/熔断/改道。
```

- `mode` 字段已从配置移除，写了也会被忽略。
- 每个节点固定占用一个端口：节点数超过可用端口范围时启动会失败，需调大 `multi_port.base_port` 或减少节点。
- 共享入口是主链路；per-node 端口用于「指定出口」与严格验证，不需要时可不映射到宿主机。

---

## 配置说明

完整示例见 `config.example.yaml`，生产配置放在 `data/config.yaml`。

### 入口与端口

| 字段 | 默认 | 说明 |
|---|---|---|
| `listener.address` / `port` | `0.0.0.0:2323` | 共享入口，HTTP 与 SOCKS5 同端口 |
| `listener.username` / `password` | — | 兼容用的全局凭据；独立账号启用后仍可作为旧客户端凭据 |
| `multi_port.address` | `0.0.0.0` | per-node 监听地址 |
| `multi_port.base_port` | `24000` | per-node 起始端口，按节点数顺延 |
| `multi_port.username` / `password` | — | per-node 入口默认凭据 |

### 池调度与零感知

| 字段 | 默认 | 说明 |
|---|---|---|
| `pool.mode` | `sequential` | `sequential` / `random` / `balance` / `latency` |
| `pool.retry_enabled` / `retry_attempts` | `true` / `3` | 首次拨号失败后自动换节点重试 |
| `pool.failure_threshold` | `3` | 连续失败到该值进入黑名单 |
| `pool.blacklist_duration` | `24h` | 黑名单时长，可通过 API 手动释放 |
| `pool.transient_cooldown` | `60s` | 超时/重置/503 的短冷却 |
| `pool.rate_limit_cooldown` | `60s` | 429 限流的冷却 |
| `pool.switch_budget` | `3s` | **一次请求内所有改道的总预算** |
| `pool.dial_timeout` | 关闭 | 单次拨号超时，留空沿用调用方 context |
| `pool.health_interval` | `5m` | 后台 `generate_204` 探测周期 |
| `pool.enable_circuit_breaker` | `true` | 每节点三态熔断 |
| `pool.fallback` | `none` | 池内全不可用时：`none` / `default_pool` / `direct` |
| `pool.blacklist_failed_pin` | `true` | 会话绑定节点拨号失败时立即拉黑 |

> `fallback: direct` 会让流量**绕过代理、使用真实出口 IP**，仅在无可用节点时作为兜底。管理面板在选中该项时会显示红色警告。

### 会话路由与粘性

- 主入口支持 `用户名.会话ID` 形式固定上游节点：`http://wang.account01:1234@host:2323`。
- `sticky.session_enabled`（默认 `true`）、`session_ttl`（默认 `24h`）、`max_sessions`（默认 `10000`）。
- `sticky.enabled` / `port` 只控制旧的「来源 IP 粘性端口」，与命名会话相互独立。
- 已建立的连接不会迁移，已发送的请求不会因 HTTP 业务错误自动重放。

### 管理面板

| 字段 | 默认 | 说明 |
|---|---|---|
| `management.enabled` | `true` | 是否启用面板 |
| `management.listen` | `0.0.0.0:9091` | 面板与 API 监听地址 |
| `management.password` | 空 | 为空则不需要登录（**生产务必设置**） |
| `management.probe_target` | `http://cp.cloudflare.com/generate_204` | 健康探测目标 |

### 扩展来源与验证（`extension`）

默认全部关闭，需显式启用。

```yaml
extension:
  enabled: true
  outbound_proxy: "http://127.0.0.1:7897"   # 来源出站代理，留空直连
  cache_file: extension_nodes.txt

  mapping:            # 网络空间测绘：fofa / hunter / quake / 自定义 provider
    enabled: false
    interval: 6h
    presets:
      - platform: fofa
        enabled: true
        key_env: FOFA_KEY          # 只写环境变量名，明文放 .env
        query: 'protocol=="socks5" && country="CN"'
        size: 300

  freepool:           # 免费代理池：内置抓取器 或 外部 proxy_pool
    enabled: false
    interval: 10m
    external_api:
      enabled: true
      base_url: "http://proxy-pool:5010"   # 容器内用服务名，不要用宿主 IP
      get_path: "/get/"                    # 必须 /get/；/all/ 返回数组，当前解析器不支持
      batch: 20

  verification:       # 全维度严格验证（人工触发，不自动入池）
    enabled: true
    echo_ip_url: "https://httpbin.org/ip"
    min_score: 40
    timeout: 8s
    concurrency: 32
    retries: 3
    recheck_interval: 10m
    max_failures: 3
    authenticity:
      action: reject      # reject / mark / downgrade
    mitm:
      action: reject
```

### 节点来源

三种方式可混用：

1. `subscriptions:` 订阅链接（支持 http(s)、本地文件、`inline:<base64>`）
2. `nodes_file: nodes.txt` 每行一个 URI
3. `nodes:` 直接内联

支持的 URI 形式：

```
vmess://base64_json
vless://uuid@host:port?security=tls&type=ws&path=/x#name
trojan://password@host:port?sni=x#name
ss://base64(method:password)@host:port#name
hy2://password@host:port#name
tuic://uuid:password@host:443#name
anytls://password@host:443#name
socks5://[user:pass@]host:port#name
http(s)://[user:pass@]host:port#name
```

---

## 验证模型（重要）

| 层 | 触发 | 方式 | 是否影响入池 | 是否重载核心 |
|---|---|---|---|---|
| **L1 入池准入** | 添加/抓取 | `generate_204` 健康探测 | 不通过则不入池 | 新增节点需重载 |
| **L2 后台保活** | 周期 `health_interval` | `generate_204` | 连续失败按黑名单/冷却处理 | 否 |
| **L3 严格验证** | **人工触发** | 全维度评分（出口 IP、匿名度、真实性、MITM、延迟、带宽） | **默认只标记，不剔除** | 否 |

- L3 入口：诊断分析页「验证全部」/ 节点详情「严格验证」，或 `POST /api/nodes/verify`。
- 非 HTTP/SOCKS 协议通过 per-node 端口落地后验证；未分配端口时返回 `skipped`，不会伪造结果。
- 结果写入 `data/node_quality.json`，重启保留，可在诊断页点击行展开查看。

---

## 账号与分池

- 存储：`data/accounts.json`，**凭据只存 bcrypt 哈希**，不回显、不写日志、不入导出。
- 关系：**一用户单池**；用户不填分池则使用默认池（全部节点）。
- 热生效：增删改立即作用于新连接，不重建核心、不打断在途连接。
- 字段：`username`、`password`、`display_name`、`pool`、`enabled`、`expires_at`、`max_sessions`、`max_conns`、`note`、`credential_version`。
- 分池字段：`name`、`nodes[]`（留空 = 全部）、`fallback`（`none` / `default_pool` / `direct`）、`enabled`、`note`。
- 删除分池前需先迁移池内用户；删除用户不影响在途连接。

> 旧的 `pool.user_pools`（按用户名绑定节点子集、写入 `config.yaml`）**已停用**：`PUT /api/pool/user-pools` 返回 `410 Gone`，`GET` 返回空的弃用响应。请改用「用户与分池」页。

---

## 可观测性

### 指标

`GET /api/metrics?window=1m|5m|1h`，`GET /api/metrics/stream`（SSE）。

| 指标 | 含义 |
|---|---|
| `reroute_total` / `reroute_rate` | 改道次数 / 改道率（换到不同节点才计） |
| `reroute_avg_ms` / `reroute_p95_ms` / `reroute_p99_ms` | 切换耗时（只统计改道成功样本） |
| `client_visible_failure_rate` | 业务侧感知失败率（零感知核心验收指标） |
| `circuit_transitions` / `node_evictions` / `node_recoveries` | 熔断迁移、摘除、恢复 |
| `reload_disconnected_conns` | 重载导致的连接中断数（目标 0） |
| `degrades` / `queue_depth` | 降级次数、排队深度 |

面板提供 1m/5m/1h 窗口切换、改道趋势与耗时分布曲线、改道/熔断事件流。

### 日志

- 控制台日志页支持**级别（DEBUG/INFO/WARN/ERROR）+ 类别 + 关键字**检索。
- 类别：`refresh`（来源计数与准入原因）、`verify`（逐节点拒绝明细，默认 DEBUG）、`access`（访问目标）、`reroute`、`circuit`。
- 每次刷新固定输出一行 INFO 汇总：

```
[INFO][refresh] refresh done candidates=314 sources=fofa:300,free:15 admitted=2 admitted_by=fofa:2,free:0 deduped=1 rejected=score_below_min:180,timeout:90,mitm:25,authenticity:17
```

- 访问日志一条连接一行：客户端 IP、用户名/会话、目标域名或 IP:端口、协议、选中节点、结果、耗时。
- 缓冲区有界（约 2000 条）并滚动覆盖，不落盘；`log_level` 控制默认阈值。
- 日志中的 URL 会自动剥离 query（避免密钥泄露），但**目标域名按原样记录**。

---

## WebUI

| 页面 | 内容 |
|---|---|
| 监控看板 | 节点表（成功率、熔断状态、改道数、摘除/恢复）、零感知指标卡、事件流、曲线、节点删除/探测/拉黑 |
| 用户与分池 | 分池 CRUD、用户 CRUD（配额/到期/启停/改密）、变更审计 |
| 会话路由 | 命名会话绑定与释放、扩展来源访问记录；旧分池入口已迁移 |
| 节点配置 | 添加（URI / 按协议表单）、批量导入（Clash YAML / URL 列表 + 预览）、编辑、删除、重载核心 |
| 诊断分析 | 节点质量分析（点击行展开全维度结果）、严格验证、GeoIP/稳定性图表 |
| 控制台日志 | 结构化日志检索 + 原始控制台视图 |
| 系统设置 | 监听、池、零感知参数、GeoIP、订阅、日志等 |

---

## API 摘要

所有管理接口沿用面板登录鉴权（`/api/auth`）。

| 方法 | 路径 | 用途 |
|---|---|---|
| GET/POST | `/api/nodes/config` | 列出 / 新增节点 |
| PUT/DELETE | `/api/nodes/config/{name}` | 修改 / 删除节点 |
| POST | `/api/nodes/config/batch` | 批量添加（失败回滚） |
| POST | `/api/nodes/preview` | 解析 Clash YAML 或 URL 列表并预览去重结果 |
| GET | `/api/nodes/quality` | 严格验证质量档案 |
| POST | `/api/nodes/verify` | 触发严格验证（单节点 / 批量 / `{"all":true}`） |
| POST | `/api/nodes/probe-all` | 全量健康探测 |
| POST | `/api/nodes/{tag}/probe` | 单节点探测 |
| POST | `/api/nodes/{tag}/release` \| `/blacklist` | 手动解封 / 拉黑 |
| GET/POST/PUT/DELETE | `/api/accounts[/users\|/pools]` | 账号与分池 CRUD |
| GET | `/api/pool/user-pools` | 旧分池只读兼容（已弃用） |
| GET | `/api/metrics`、`/api/metrics/stream` | 指标快照 / SSE |
| GET | `/api/logs?level=&category=&q=` | 结构化日志 |
| GET | `/api/debug` | 诊断快照（含质量结果） |
| GET/PUT | `/api/settings` | 读取 / 保存核心设置（需重载生效） |
| POST | `/api/reload` | 重载核心 |
| GET | `/api/export` | 导出代理链接 |
| GET | `/api/ext/status` \| `/api/ext/config` \| `/api/ext/refresh` | 扩展来源状态 / 配置 / 手动刷新 |

---

## 常用运维

```bash
# 查看状态
docker compose ps
docker logs --tail 100 easy_proxies_ext

# 修改 pool/sticky/management 等核心设置后
# 面板点「重载核心」，或：
curl -X POST http://127.0.0.1:9091/api/reload

# 改 data/config.yaml 后同样需要重载
# 账号、分池、日志级别不需要重载
```

| 场景 | 是否重载 | 是否断连 |
|---|---|---|
| 账号 / 分池增删改 | 否 | 否 |
| 节点增删改 | 是（手动） | 是，在途连接会断 |
| 订阅刷新且节点集合不变 | 否（自动跳过） | 否 |
| 订阅刷新且节点集合变化 | 是 | 是 |
| 严格验证 / 健康探测 | 否 | 否 |
| 日志级别、面板设置 | 否 | 否 |

---

## 升级与破坏性变更

升级到本分支时请注意：

1. **`mode` 字段已移除**，固定双栈；旧配置里的 `mode:` 会被静默忽略。
2. **每个节点占用独立端口**（默认 24000 起），节点数超过端口范围会启动失败；宿主机默认不映射该范围。
3. **`pool.user_pools` 已停用**，`PUT` 返回 410；分池迁移到「用户与分池」页（`accounts.json`）。
4. **严格验证改为人工触发**，入池门槛仅为 `generate_204` 健康探测。
5. **删除订阅/扩展来源的节点不持久**，下次刷新会重新出现。
6. `pool.fallback: direct` 会使用真实出口 IP，请确认安全边界后再启用。

---

## 排障

| 现象 | 常见原因 |
|---|---|
| 免费池节点未入池 | `extension.freepool.enabled` 或 `external_api.enabled` 为 `false`；`base_url` 写成宿主 IP（容器内应为 `http://proxy-pool:5010`）；`get_path` 写成 `/all/`（当前只支持 `/get/`）；严格验证分数未达标 |
| 启动报 `config.nodes cannot be empty` | 没有任何可用节点，且 `pool.fallback` 不是 `direct` |
| 启动报端口分配失败 | 节点数超过 `multi_port.base_port` 起的可用端口范围 |
| 面板能打开但代理不可用 | 节点全部处于黑名单/冷却；查看 `/api/debug` 与「池内全不可用」日志 |
| 严格验证大量 `skipped` | 非 HTTP/SOCKS 协议需要 per-node 端口，检查双栈是否正常分配端口 |
| 订阅刷新后配置回退 | 订阅刷新会以订阅结果为准；需要固定的节点请用内联或 `nodes.txt` |

---

## 安全说明

- 面板密码为空时管理接口无鉴权，**生产环境必须设置 `management.password`**。
- 代理凭据与测绘 API Key 只通过 `.env` 注入，仓库与日志中不出现明文。
- `data/` 内含 `config.yaml`、`accounts.json`、`node_quality.json`、`nodes.txt`，请勿提交到版本库。
- 日志会记录访问目标域名（按设计不脱敏），敏感业务请自行评估。
- `skip_cert_verify: true` 会关闭上游证书校验，仅建议排障时临时使用。

---

## 开发与测试

```bash
gofmt -l internal cmd
go vet ./...
go test ./... -count=1
go test -race ./... -count=1          # 需要 C 编译器
node --test scripts/test-ui.mjs       # 前端 fixture（无需浏览器）
```

- 前端是单文件原生 JS（`internal/monitor/assets/index.html`），通过 `go:embed` 打包。
- 新增行为请先补合同测试，再改路由/刷新语义。

## 致谢

- [sing-box](https://github.com/SagerNet/sing-box)：代理内核
- [jasonwong1991/easy_proxies](https://github.com/jasonwong1991/easy_proxies)：原始项目
- [jhao104/proxy_pool](https://github.com/jhao104/proxy_pool)：免费代理池组件
