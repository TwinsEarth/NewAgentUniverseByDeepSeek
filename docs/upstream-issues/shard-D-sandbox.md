# 工单 D：沙箱后端、隔离边界、资源限制与平台差异

> 对象：`TwinsEarth/agent-universe` v3.5.0（annotated tag → commit 001ab7f；gsn-core 0.3.50）
> 本文件为**可直接粘贴的 issue 正文**。全程只读核查，未对该仓库做任何写入。


**分片范围**：`sandbox/` 后端（process / docker / firecracker / k8s / wasm）、隔离边界、资源限制、所有权、平台差异

**目标版本**：见下方各条；对应自审 §7 的 v3.5.1 / v3.5.2 / v3.5.3 计划。

## 自审发现（按 ID 引用；详细描述见原报告分片表）

| ID | 级别 | 状态 | 要点 |
|---|---|---|---|
| D-1 | Medium | confirmed | waiver 的非空理由承诺进审计，但 AuditEntry 无 waiver 字段、create 记录点未传入（api.rs:97） |
| D-2 | Low | confirmed | Windows safe_join 不拦 drive-prefix/UNC 绝对路径（Linux 不受影响） |
| D-3 | Low | confirmed | ulimit/Job Object/超时/env 清除等真实强制缺少行为级测试 |
| D-4 | Low | confirmed | MCP stdio 使用裸 SandboxConfig::default()，致 sandbox_create 恒返回 422 |
| D-5 | Low | unverified | cfg.isolation 字段在代码中未见被消费，实际隔离选择是否受其控制待运行确认 |
| D-6 | Low | confirmed | NetworkGuard/ExecutionToken/SandboxIdentity 为无生产调用的死策略 |
| D-7 | Low | confirmed | 无 setuid 降权，「以非 root 运行」目前是部署假设而非代码强制 |
| D-8 | Low | confirmed | SandboxResult.cpu_time_ms 恒为 0，资源计量不可用 |

## 建议顺序

1. **D-1 优先**：豁免（waiver）是「无法强制的边界」的书面承认，而这份承认目前**没有落进审计记录**——豁免机制存在的意义就是留下可追溯的痕迹。补字段与传入点，并加一条证明豁免理由真的落进审计的测试。
2. **D-4 是外部用户直接可见的**：MCP stdio 用裸 `SandboxConfig::default()` 导致 `sandbox_create` **恒返回 422**——即该路径上的沙箱创建功能实际不可用。建议优先确认是配置缺失还是设计如此。
3. **D-5 需运行期验证**：`cfg.isolation` 是否真的被消费，决定隔离选择是否受配置控制。在未验证前不要假设它生效，也不要假设它失效。
4. **D-7 的措辞值得注意**：「以非 root 运行」目前是部署假设而非代码强制——建议在文档中明确这一区别，而不是让它读起来像已强制的性质。
5. D-2 / D-3 需 Windows 实机验证；D-6 / D-8 属收敛与计量项。

## 与其他工单的关系

- **工单 C**：C-003（sys.* 构建链校验）与本分片的信任根建立同源。
- **工单 F**：D-5 的验证依赖节点运行路径，建议与 F 分片的可达性核查一起做。
- **工单 G**：D-7 的「部署假设 vs 代码强制」区别应写进文档，属 G 的范围。

## 交付标准（适用于本工单全部条目）

- 类型化错误，不使用 `unwrap`/`expect`/`panic!`；
- 跨平台（Linux / macOS / Windows）兼容；
- CHANGELOG 记录；
- 行为变更必须补一条**在旧实现上会失败**的回归测试；
- 因资源不足无法运行的关卡，如实标注 NOT VERIFIED，不以静态阅读替代运行验证。
