# 工单 C：插件内核、分级、能力令牌与生命周期

> 对象：`TwinsEarth/agent-universe` v3.5.0（annotated tag → commit 001ab7f；gsn-core 0.3.50）
> 本文件为**可直接粘贴的 issue 正文**。全程只读核查，未对该仓库做任何写入。


**分片范围**：`plugin/` 内核、tier→runtime 绑定、能力令牌、生命周期状态机、黑名单、热更新、进程插件 outbox

**目标版本**：见下方各条；对应自审 §7 的 v3.5.1 / v3.5.2 / v3.5.3 计划。

## 外部核查发现（本次新增，供参考）

### DOC-C1 · 文档缺陷

**位置**：`releases/v3.4.2.md`：`gsn-core/src/plugin/` **16 文件 / 约 6,077 行**

**现状**：实测（`main` @ `5f29a92`）：**顶层 12 个 `.rs` / 3,787 行**；**递归 18 个 / 7,018 行**。**两种读法都对不上 16 / 6,077**——递归读法行数差 941，顶层读法差 4 个文件、2,290 行。

**动作**：改为**实测值 + 口径**，并把统计命令写进 CI 关卡：
```sh
find gsn-core/src/plugin -maxdepth 1 -name '*.rs' | wc -l
find gsn-core/src/plugin -name '*.rs' -exec cat {} + | wc -l
```
这样数字变化时是**关卡报警**，而不是**文档静默过期**。

**验收标准**：① 数字与实测一致且写明口径；② 统计命令可复现；③ 最好做成关卡。

**建议版本**：v3.5.3（快）

### DOC-C2 · 代码注释

**位置**：`plugin/bus.rs:467`

**现状**：派发注释仍写「**五道检查**」，而 `validate_sender` 已实现**七道**（`:389-465`；签名 `:441-446`、nonce 重放 `:448-463`；`MAX_SEEN_NONCES=1024` 在 `:100`）。

**动作**：改注释。

**验收标准**：注释与实现一致。**危险在于**：下一位读者会按注释以为少了两道检查，从而**重复实现已有保护**或**误判缺口**。

**建议版本**：v3.5.3（快）

## 自审发现（按 ID 引用；详细描述见原报告分片表）

| ID | 级别 | 状态 | 要点 |
|---|---|---|---|
| C-001 | Medium | confirmed | PluginLifecycle 状态机生产零构造，bus.set_state 无条件接受翻状态（隔离态可被翻回 Running） |
| C-002 | Medium | confirmed | 黑名单 DB 生产从不播种，安装期闸门对空表判定；file_appeal 为死代码 |
| C-003 | Medium | confirmed | com.twinsearth.sys.* 安装时无构建链校验，自签名清单可通过 |
| C-005 | Medium | confirmed | collect_outbox 无大小上限，host 先整文件 read_to_string 才逐消息校验，存在内存放大面 |
| C-004 | Low | confirmed | nonce 无 TTL，按字典序而非时间淘汰 |
| C-006 | Low | confirmed | outbox 单行畸形导致整次调用失败；非 UTF-8 会静默丢失整队列 |
| C-007 | Low | confirmed | 双缓冲 spawn 失败回滚分支无测试，swap 后步骤存在 desync 风险 |
| C-008 | Low | confirmed | start() 不复查黑名单；uninstall 泄漏 bus RouteEntry |
| C-009 | Low | confirmed | 限流槽在签名/nonce 校验之前消耗，可被未授权请求耗尽 |
| C-010 | Low | confirmed(info) | official root 从不下发，T1/T2 外部安装 fail-closed；Linux 上 T3 runtime 不可达 |

## 建议顺序

1. **C-001 / C-002 / C-003 是一类**：安全机制「写出来了，但生产路径上没接线」。请先确认每条是「接线」还是「明确标注为不生效」——**两者都可接受，只有「写了但没接线且无人知道」不可接受**。
2. C-001 的状态机翻转是最容易验证的一条，建议作为该类第一个。
3. C-005（outbox 内存放大）可独立修：改为逐行流式读取并在读入前限长。
4. C-009 属易修项，挪动消耗点即可。
5. C-010 标为 confirmed(info)：请确认「official root 从不下发」是有意设计还是未完成；若是有意，建议在文档中写明，否则外部读者会当成缺陷。
6. DOC-C1 / DOC-C2 与代码解耦，可立即做。

## 与其他工单的关系

- **工单 B**：C-004 与 B-05 是同一份 nonce 窗口代码，请合并修复。
- **工单 D**：C-003（构建链校验）与 D 分片的沙箱强制能力同属「信任根如何建立」。
- **工单 G**：DOC-C1 / DOC-C2 属文档项，若集中处理文档可移入 G。

## 交付标准（适用于本工单全部条目）

- 类型化错误，不使用 `unwrap`/`expect`/`panic!`；
- 跨平台（Linux / macOS / Windows）兼容；
- CHANGELOG 记录；
- 行为变更必须补一条**在旧实现上会失败**的回归测试；
- 因资源不足无法运行的关卡，如实标注 NOT VERIFIED，不以静态阅读替代运行验证。
