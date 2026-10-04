# v3.8 族自查 / Resource market self-audit

本文档是 **D-11 第 ③ 条**的交付物：v3.8.0…v3.8.9 十版的**每一条交付物都能被指到代码**。

**自查的规则**：每一项给出**文件与行号可核对的落点**，并**注明它是否真的被接线**。
**「写了」与「接线了」是两件事**，而这份文档的用处就在于把两者分开写。

---

## D-01 · 资源计量与商品化骨架 → v3.8.0

| 交付物 | 落点 | 接线 |
|---|---|---|
| 六类资源，各有单位 | `crates/nau-market/src/resource.rs` · `ResourceKind::ALL` / `unit()` | 插件操作 `kinds` |
| 单位不可混算 | 同文件 · `ResourceAmount::checked_add` | 编译期与运行期都被拒 |
| `Quota` 与 `ResourceAmount` 无转换 | 同文件 · 两者之间无 `From`/`as`/方法 | `fits_within` 返回 `bool` |
| 无跨类总分 | 同文件 · `ResourceBundle` 无 `total()` | — |

## D-02 · 能力核对 → v3.8.0

| 交付物 | 落点 | 接线 |
|---|---|---|
| 十个 0 命中名词**具名拒绝** | `crates/nau-plugins/src/plugins/resource.rs` · `REFUSED` | 插件操作 `refused`，部署检查断言 |

## D-03 · 注册与质押准入 → v3.8.1

| 交付物 | 落点 | 接线 |
|---|---|---|
| 门槛是**市场的**（读 `MarketConfig`） | `crates/nau-market/src/resource.rs` · `ResourceRegistry::from_config` | 插件操作 `register` / `admitted` |
| **不加 Tier / PluginState** | `crates/nau-plugin/tests/kernel_vocabulary.rs`（**内核自己的套件**） | — |
| 罚没额由**规则**算 | 同文件 · `ResourceRegistry::slash` | 插件操作 `slash`，部署检查断言 |

## D-04 · 时延感知匹配 → v3.8.2

| 交付物 | 落点 | 接线 |
|---|---|---|
| 时延**类别**（不是 `PriorityClass`） | `crates/nau-market/src/resource.rs` · `LatencyClass` | 插件操作 `match` |
| 「不该匹配」是**过滤**而非权重 | 同文件 · `ResourceDemand::admits` | 部署检查用**二十分之一价格**的容忍节点证明 |
| 复用**同一个评分公式** | `crates/nau-market/src/matching.rs` · `score_value`（`score_bid` 也调用它） | — |

## D-05 · 多轨定价 → v3.8.3

| 交付物 | 落点 | 接线 |
|---|---|---|
| **价格带条款、无裸数字字段** | `crates/nau-market/src/pricing.rs` · `Price`（无 amount 字段） | 插件操作 `price` |
| 四条轨道 | 同文件 · `Price::compute` | 部署检查重算总额 |
| **无浮点** | 同文件 · 整数基点 + `i128` 中间量 | — |

## D-06 · 快照商品化 → v3.8.4

| 交付物 | 落点 | 接线 |
|---|---|---|
| 内容寻址即「买到的是地址指的」 | `crates/nau-market/src/resource.rs` · `SnapshotAsset::snapshot` | 插件操作 `asset` |
| 版税**守恒**（不创造货币） | 同文件 · `settle_restore` + `RestoreSettlement::is_conserved` | 测试断言 `sum_of_balances` 与 `accounted_total` 不变 |
| **恢复的 PMB 审计记录** | `crates/nau-plugins/src/plugins/resource.rs` · 用**类型化变体**取规范能力名 | ⚠️ **部分**：记录被**产出**并返回，**未提交**——`SystemPlugin::handle` 拿不到 `&mut HostContext`，无法 `request_send`。**部署检查反过来断言 `record_filed: false`** |

## D-07 · 多维守恒 → v3.8.5

| 交付物 | 落点 | 接线 |
|---|---|---|
| 六类**各自**守恒 | `crates/nau-market/src/resource_ledger.rs` · `ResourceAudit`（**无总分**） | 插件操作 `resource-audit` |
| 越界**拒绝**而非饱和 | 同文件 · 全部 `checked_*`，文件内无 `saturating_add` 用于记账 | 部署检查断言拒绝 |
| 与 `nau-ledger` **互不干扰** | 同文件 · 两个类型两份状态 | 测试断言金额账本逐字段不变 |

## D-08 · 抽样验证 → v3.8.6

| 交付物 | 落点 | 接线 |
|---|---|---|
| 抽选**可复现**（SHA-256(种子‖0x1f‖交付)） | `crates/nau-market/src/sampling.rs` · `SamplingPlan::draws` | 插件操作 `sample` |
| **不可预测性** | ⚠️ **不提供**：种子是调用方的义务，模块**不生成**它 | 部署检查断言 `unpredictability` 以 `NOT provided here` 开头 |
| 抽中即触发**既有**争议流程 | 同文件 · `SamplingClaim`（**采样器无密钥**，不构造 `Dispute`） | ⚠️ **部分**：声明被产出，**提交需要持有密钥的当事人** |
| **PoCV** | **代码里 0 命中**（计划的「8 处」全在 `docs/`） | **未复用，也未声称复用** |

## D-09 · 多维信誉 → v3.8.7

| 交付物 | 落点 | 接线 |
|---|---|---|
| 第五维「资源真实性」 | `crates/nau-market/src/reputation.rs` · `Reputation::truthfulness` | 插件操作 `observe` |
| **不可自报** | 同文件 · 唯一写者 `record_resource_observation(&ResourceObservation)` | 部署检查断言答案里的 `cannot_self_report` |
| 接进既有复合分数 | 同文件 · `overall_bps`，权重 **30/15/25/10/20**（和为 10000，编译期断言顺序） | — |
| **改版前的锚定仍可验证** | 同文件 · 两个新字段带 `skip_serializing_if`（**逐字节测试**） | — |

## D-10 · 冷启动 → v3.8.8

| 交付物 | 落点 | 接线 |
|---|---|---|
| 起步上限（不是零） | `crates/nau-market/src/cold_start.rs` · `ColdStartPolicy` | 插件操作 `cold-start` |
| **自报完美不加分** | 同文件 · `assess` 只读 `observations` | 部署检查断言四维全满者与全新者逐字段相同 |
| **可复现** | 同文件 · 纯函数，无时钟无随机无状态 | 部署检查连调两次比对 |

## D-11 · 度量 → v3.8.9

| 交付物 | 落点 | 接线 |
|---|---|---|
| 指标**由状态导出**而非累积 | `crates/nau-market/src/metrics.rs` · `MarketMetrics::of` | 插件操作 `metrics` |
| **无跨类总分**；只有比率可比 | 同文件 · `KindMetrics` / `observation_coverage_bps` | 部署检查断言报告里那句话 |
| 数字**带五要素或标注为目标** | `metric-claims` 关卡（v3.5.9 建立） | **本仓文档**过关 |

---

## 这份自查**没有**覆盖的

**三项标注为「部分」的交付物是真实的缺口，不是措辞上的谨慎**：

1. **D-06 的 PMB 审计记录未被提交**（能力签名所限，见上）
2. **D-08 的争议未被提交**（`Dispute` 需要原告的公钥与签名，采样器没有）
3. **D-08 的不可预测性不由本模块提供**（种子是调用方的输入）

**而 `PoCV` 一行是这份文档里最该被读到的**：计划把它列为「8 处命中、应复用」，而**那 8 处全在文档里**。
**一份把计划里的数字当作事实引用的自查，会把这个错误复制下去**——所以这里给出的是检索结果。
