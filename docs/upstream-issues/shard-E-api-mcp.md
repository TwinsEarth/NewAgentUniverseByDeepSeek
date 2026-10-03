# 工单 E：REST / MCP、数值安全、NAT 与纠删码

> 对象：`TwinsEarth/agent-universe` v3.5.0（annotated tag → commit 001ab7f；gsn-core 0.3.50）
> 本文件为**可直接粘贴的 issue 正文**。全程只读核查，未对该仓库做任何写入。


**分片范围**：`api/rest.rs`、`node.rs` 的路由与鉴权、三种 MCP 传输、参数校验、数值安全、NAT stub、纠删码

**目标版本**：见下方各条；对应自审 §7 的 v3.5.1 / v3.5.2 / v3.5.3 计划。

## 自审发现（按 ID 引用；详细描述见原报告分片表）

| ID | 级别 | 状态 | 要点 |
|---|---|---|---|
| E-01 | Low | confirmed | Bearer token 比较为朴素 ==，非恒定时间（node.rs:911、sse.rs:51） |
| E-02 | Low | confirmed(死代码) | economy/reputation.rs apply_decay 在 halflife=0 时整数除零；生产可达性 unverified |
| E-03 | Low | confirmed(死代码) | pricing with_supply_demand 未做 is_finite 检查，NaN/Inf 可污染比较 |
| E-04 | Low | confirmed | market_tools.rs:184 round 参数按 number 处理、as u32 截断，1.5 静默退 0 |
| E-05 | Low | confirmed | get_money 保留 unwrap_or(Money::ZERO) 旧脚枪；当前被上游 schema 拦截，属纵深防御缺口 |

## 建议顺序

1. 本分片**无 Critical / High / Medium**：鉴权默认拒绝、参数统一校验、金额全类别拒绝与纠删码真实重建均成立。这是本次核查愿意明确记录的正向结论。
2. **E-01** 属标准加固：Bearer 比较改常量时间。注意同一模式在两个文件（`node.rs:911`、`sse.rs:51`），请一并修改，避免只改一处。
3. **E-02 ~ E-05** 建议按「当前是否可达」分档：可达的加固，不可达的收敛删除。**死代码里的除零与非有限数不算漏洞，但会在某次重构把它变活时成为漏洞**——这正是需要记录状态的理由。
4. **一处文档与代码的路径不一致**（`handle_plugin_api` 实际在 `node.rs:1299`，文档指向 `api/rest.rs`）已归入**工单 G**，因它是文档修正而非代码缺陷。若本分片负责 `node.rs`，请一并知悉。

## 与其他工单的关系

- **工单 G**：`handle_plugin_api` 的路径修正与本分片同文件，见工单 G。
- **工单 F**：E-02/E-03 的死代码可达性判定依赖启动链核查结论。

## 交付标准（适用于本工单全部条目）

- 类型化错误，不使用 `unwrap`/`expect`/`panic!`；
- 跨平台（Linux / macOS / Windows）兼容；
- CHANGELOG 记录；
- 行为变更必须补一条**在旧实现上会失败**的回归测试；
- 因资源不足无法运行的关卡，如实标注 NOT VERIFIED，不以静态阅读替代运行验证。
