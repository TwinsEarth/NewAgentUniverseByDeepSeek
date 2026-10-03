# 工单 F：节点启动链、子系统可达性与并发

> 对象：`TwinsEarth/agent-universe` v3.5.0（annotated tag → commit 001ab7f；gsn-core 0.3.50）
> 本文件为**可直接粘贴的 issue 正文**。全程只读核查，未对该仓库做任何写入。


**分片范围**：`node.rs` 启动链、子系统构造与可达性、死策略、并发与锁纪律

**目标版本**：见下方各条；对应自审 §7 的 v3.5.1 / v3.5.2 / v3.5.3 计划。

## 外部核查发现（本次新增，供参考）

### DOC-F1 · High（文档面）

**位置**：README、架构文档、发布说明中把这些库面模块描述为节点实际运行的能力

**现状**：自审 F-4 已确认：这批模块作为 `pub mod` 被导出，单看库面会认为节点运行着分布式拓扑、记忆网格与调度器；但在 `gsn-daemon` 的真实启动链上它们**不可达**。**本次外部核查从文档一侧独立得到同一结论**：`releases/v3.4.2.md` 的「16 文件 / 约 6,077 行」没有任何计数方式能得出（实测顶层 12/3,787、递归 18/7,018）。**两份独立报告在此互相印证，故这一类应视为已确认。**

**动作**：**本项不必在补丁版本强行接线。** 分两步：
① 在 README、架构文档与**每个模块头注释**中如实标注「库面 / 实验性，未在守护进程构造」；
② 在后续 minor 版本中决定「接线启用」还是「收敛删除」，并把该决定记为待决项——**避免长期保留两套实现**。

**验收标准**：① 文档不再把这些模块描述为节点实际运行的能力；② 每个模块头部有明确状态标注；③ 存在一个待决项记录「接线 or 删除」。

**建议版本**：v3.5.3

## 自审发现（按 ID 引用；详细描述见原报告分片表）

| ID | 级别 | 状态 | 要点 |
|---|---|---|---|
| F-1 | Medium | confirmed | mcp/server.rs McpServer 已完整定义但从不构造，活路径由 Bridge 直接分发 |
| F-2 | Medium | confirmed(DORMANT) | 已订阅 gsn/agents、gsn/tasks，但 Publish 无构造点、Received 落空分支，agent/task 发现实际未生效 |
| F-3 | Medium | confirmed | gsn mcp stdio 用 spawn() 而非 spawn_with_store，是无 SQLite、无恢复的断连市场 |
| F-4 | High（聚合） | confirmed | topology / scheduler / memory / swarm 纯算法 / mesh / nat 生产零构造（详见 4.2） |
| F-5 | Medium | unverified | POST /agents 直接 upsert_agent(hardcoded reputation 0.0) 与 market actor 双写竞争 |
| F-6 | Low | confirmed | 无后台 consensus/committee 循环，swarm/consensus.rs LightweightConsensus 零调用 |

## 建议顺序

1. **F-4 的文档面（DOC-F1）应优先于其代码面。** 代码面按自审建议「补丁版不必强行接线」；但**文档标注必须做**——它影响运维与评审的信任基础，而且成本极低。
2. **F-5（并发时序）为 unverified**：在实跑之前不要基于它做设计决定。它与「必须先验证」中的测试口径问题相关——并发问题最容易在实跑时才暴露。
3. 休眠子系统（F-1 ~ F-3）：请区分「有意的 feature 门」与「接线遗漏」。若是有意，建议在文档中写明开关名与默认值。
4. **本分片的正面结论值得记录**：唯一真实启动链、所有环境变量开关均被真实消费、生产路径无裸 `unwrap`、锁纪律干净（仅在 `spawn_blocking` 内持有、带毒化恢复、无锁序反转）。

## 与其他工单的关系

- **工单 G**：DOC-F1 是文档项，与 G 的文档清单同批处理。
- **工单 D**：D-5（cfg.isolation 是否被消费）依赖本分片的可达性结论。
- **工单 B**：**F-6 与 B-03 是同一条代码**——`swarm/consensus.rs` 的 `LightweightConsensus` 在 F 分片记为「无后台共识循环、零调用」，在 B 分片记为「权重自报、无去重验签、零生产调用」。**请合并处理，避免同一份代码被改两遍或两个人都以为对方在管。**
- **工单 C**：F 分片的死策略与 C-006 等确认(DEAD) 条目同类，建议统一收敛策略。
- **F-5 为 unverified**：REST 直写与 market actor 的快照双写竞争需实跑才能定性；在验证前不要基于它做设计决定。它与「必须先验证」中的测试口径问题相关。

## 交付标准（适用于本工单全部条目）

- 类型化错误，不使用 `unwrap`/`expect`/`panic!`；
- 跨平台（Linux / macOS / Windows）兼容；
- CHANGELOG 记录；
- 行为变更必须补一条**在旧实现上会失败**的回归测试；
- 因资源不足无法运行的关卡，如实标注 NOT VERIFIED，不以静态阅读替代运行验证。
