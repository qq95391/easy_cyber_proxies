# Easy Proxies（中文文档）

完整文档已合并到主 [README.md](README.md)，此处仅保留入口，避免两处内容不同步。

## 快速索引

| 想了解 | 跳转 |
|---|---|
| 项目特性总览 | [README.md · 特性](README.md#特性) |
| 部署与端口 | [README.md · 快速开始](README.md#快速开始) |
| 双栈拓扑（pool + 每节点端口） | [README.md · 运行拓扑](README.md#运行拓扑固定双栈) |
| 配置字段 | [README.md · 配置说明](README.md#配置说明) |
| 健康探测与严格验证 | [README.md · 验证模型](README.md#验证模型重要) |
| 账号与分池 | [README.md · 账号与分池](README.md#账号与分池) |
| 指标与日志 | [README.md · 可观测性](README.md#可观测性) |
| API | [README.md · API 摘要](README.md#api-摘要) |
| 升级注意事项 | [README.md · 升级与破坏性变更](README.md#升级与破坏性变更) |

## 三条最常被问到的事

1. 运行模式已固定为**双栈**，配置里的 `mode:` 会被忽略。
2. 旧的 `pool.user_pools` 已停用，分池改到面板「用户与分池」（`accounts.json`）。
3. 严格验证（出口 IP / 匿名度 / 真实性 / MITM）需**手动触发**；后台只做 `generate_204` 保活。
