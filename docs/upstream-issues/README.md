# 给上游的 issue 与工单

这些文件是**可直接粘贴的文本**，不是自动创建的对象。本仓库不向上游写入任何内容。

| 文件 | 用途 |
|---|---|
| `00-issue-body.md` | 合并 issue 正文：整体结论、分片索引、基线、必须先验证 |
| `shard-A-ledger.md` | 工单 A：账本、结算、守恒、证据闸门与重启 |
| `shard-B-consensus-identity.md` | 工单 B：共识、认证委员会、DID、消息安全（含 Critical） |
| `shard-C-plugins.md` | 工单 C：插件内核、分级、能力、生命周期 |
| `shard-D-sandbox.md` | 工单 D：沙箱后端、隔离边界、资源限制 |
| `shard-E-api-mcp.md` | 工单 E：REST/MCP、数值安全、NAT、纠删码 |
| `shard-F-node-runtime.md` | 工单 F：启动链、可达性、死策略、并发 |
| `shard-G-nonrust-docs.md` | 工单 G：非 Rust 面、文档、测试、跨语言 |

**使用方式**：把 `00-issue-body.md` 作为 issue 正文；若要拆分，按分片各开一条，并把工单文件的内容作为各自正文。工单内的相对链接在 GitHub 上需改为对应 issue 编号。

**一个刻意的取舍**：每张工单里，项目自己的发现**只按 ID 引用**（读者手上有原始报告），而外部核查的发现**给出全文**（读者从未见过）。这样既不重复转述、也不引入转录错误。
