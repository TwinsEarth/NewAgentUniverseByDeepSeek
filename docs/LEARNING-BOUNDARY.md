# 持续学习边界 / The learning boundary — v3.9.9

**D1 + D2 的交付物**。本文档用与 `SETTLEMENT-NOUN-AUDIT.md` 相同的规格写成：
**每条结论都附可复跑的命令**，读者可以自己核对，而不必相信作者。

---

## 一句话结论

> **本仓库是「让学习可审计、可结算、可追责」的底座，不是学习算法本身。**
> **它提供经验的记录格式、信誉的度量维度、以及让不诚实付出代价的经济层——
> 而「从经验里更新策略」这件事，它不做，也没有声称做。**

---

## 一、D1：底座**存在**什么

| 组件 | 落点 | 实际提供的东西 |
|---|---|---|
| **经验记录** | `crates/nau-agent/src/experience.rs` | 经验的结构化记录类型 |
| **信誉五维** | `crates/nau-market/src/reputation.rs` | 第 5 维 **`truthfulness`**，权重 30/15/25/10/20 |
| **资源观测** | 同上 | `ResourceObservation`：把「承诺」与「实测」作对比的输入 |
| **涌现** | `crates/nau-plugins/src/plugins/` 的 `emergence` | Agent 群体层面的现象记录 |
| **Agent 议会** | 同上的 `agent-council` | 多 agent 决策的载体 |
| **群体** | 同上的 `swarm` | 多 agent 协作 |
| **技能** | 同上的 `skill` | 技能注册与版本 |
| **结算** | v3.9 全套（`settlement.rs` / `payment.rs`）| **让「说真话」有经济后果** |

**这些加起来的性质**：**学习所需的「记忆」与「问责」齐了** ✓

---

## 二、D1：底座**不存在**什么

### 可复跑的核对方法

```powershell
cd E:\DS\NewAgentUniverseByDeepSeek
$rs = Get-ChildItem "crates" -Recurse -File -Filter *.rs
foreach ($k in @("fn learn","fn evolve","self_evolve","continuous_learn","feedback_loop","fn adapt","policy_update","fn train")) {
  $n = ($rs | Select-String -Pattern $k -SimpleMatch -List | Measure-Object).Count
  "  {0,-20} 出现在 {1} 个文件里" -f $k, $n
}
```

### 实测结果

| 关键词 | 命中文件数 |
|---|---|
| `fn learn` | **0** |
| `fn evolve` | **0** |
| `self_evolve` | **0** |
| `continuous_learn` | **0** |
| `feedback_loop` | **0** |
| `policy_update` | **0** |
| `fn train` | **0** |
| `fn adapt` | **2** —— 见下 |

**关于 `fn adapt` 的 2 个文件，如实说明而不是把它抹掉**：这 4 行命中是

```
crates/nau-plugin/src/arbiter.rs:316   pub fn adapters(&self) -> &AdapterRegistry
crates/nau-plugin/src/hot.rs:105        fn adapt(&self, message: &PmbMessage) -> Result<PmbMessage>
crates/nau-plugin/src/hot.rs:133        fn adapt(&self, message: &PmbMessage) -> Result<PmbMessage>
```

第一处是 **`adapters`**（插件适配器注册表，恰好以 `fn adapt` 开头）；后两处是 **`hot.rs` 里把一条插件消息从旧 API 版本转换到新版本的 trait 方法**——
**那是插件热兼容的适配，不是学习**。

**写出来的理由**：一张声称「全是 0」的表如果漏掉唯一非零的那一行，就不是核对结果而是结论的宣传。
**这条边界的结论不依赖这个数字，但读者有权看到它。**

**所以**：

> **没有任何代码从经验里更新策略。**经验被**记录**、信誉被**度量**、不诚实被**罚没**——
> 而**「下一步该怎么做」的决定权不在本仓库**。

**这不是缺陷，是一条边界。** 把它写下来的理由和 `SETTLEMENT-NOUN-AUDIT.md` 相同：
**一个「有经验的记录」很容易被读成「会学习」，而那是两个不同的声明。**

---

## 三、D2：经验数据作为训练语料的边界

### 3.1 什么是**明确不说**的

> **本仓库不训练模型、不微调模型、不托管模型。**

### 可复跑的核对方法

```powershell
$rs = Get-ChildItem "crates" -Recurse -File -Filter *.rs
foreach ($k in @("training","train(","dataset","fine_tune","finetune","lora","gradient","loss_fn","backprop","transformer","neural")) {
  $n = ($rs | Select-String -Pattern $k -SimpleMatch | Measure-Object).Count
  "  {0,-14} {1,4} 处" -f $k, $n
}
```

### 实测结果

| 关键词 | 命中 |
|---|---|
| `training` / `train(` / `dataset` | **0** / **0** / **0** |
| `fine_tune` / `finetune` / `lora` | **0** |
| `gradient` / `loss_fn` / `backprop` | **0** |
| `transformer` / `neural` | **0** |
| `llm` | 53 —— **编排**（调用外部模型），非训练 |
| `checkpoint` | 28 —— **沙箱快照**，非模型检查点 |

**所以**：

> **本项目是把外部 LLM 当作被编排的部件，它自己不产生也不消费梯度。**

### 3.2 「经验数据能否当训练语料」——**这是你的决定，不是代码的决定**

**本仓库能说的只有三件事**，而**第三件是缺的**：

| # | 问题 | 现状 |
|---|---|---|
| 1 | **数据里有什么？** | ✅ **v3.9.5 已逐项列出**：`Exposure` 7 项（金额 / 付款方地址 / 收款方地址 / 任务 ID / **时间** / 争议方 / 交付摘要），并**同时列出 4 项不公开的**（任务内容 / 结果本身 / 当事方 DID / 彼此关联） |
| 2 | **私钥会不会进沙箱？** | ✅ **v3.9.4 用类型保证**：`PaymentRequest` **只有公开字段，没有一个放秘密的字段** |
| 3 | **经验数据能否用于训练？** | ❌ **本仓库没有声明。** |

### 3.3 第三件事为什么本仓库不该替你决定

> **「经验能不能当训练语料」是一个关于数据用途的决定，
> 而数据用途由数据主体与适用法律决定，不由代码库决定。**

**代码能做的是把事实摆出来**（上面第 1、2 条就是），**然后说清楚哪一条是空的**：

> **本仓库不限制、不标记、也不声明 `experience.rs` 记录的数据是否可以用于模型训练。
> 一个打算这样做的部署需要自己做出这个决定，并自己承担它。**

**这是「如实标注」，不是「已解决」。** 与 v3.9.8 的风险登记表把「监管不确定性」放进
**`accepted` 而非 `mitigated`** 是同一个手法 ✓

---

## 四、这张边界由**什么**守住

| 守住它的东西 | 检查什么 |
|---|---|
| `env-template` 关卡（**v3.9.9 新增**）| 本版新增的交付面关卡；与本主题相关的部分是它强制**每个被代码读取的环境变量都被记录**，从而让「文档漏掉一个关键开关」不再可能 |
| `metric-claims` 关卡（v3.5.9）| **本文档里的数字是否带五要素**——所以本文每个数字都注明了它是**实测的** |
| `economy-invariants` 关卡（v3.9.8）| 风险登记表**两张清单不相交**，且三条边界**具名** |
| `doc-counts` 关卡 | 文档声称的关卡数与脚本实际定义的一致 |
| `RESOURCE-MARKET-SELF-AUDIT.md` | D-06 / D-08 的三个 **PARTIAL** 被逐条标注 |

---

## 五、一句总括

> **这份文档回答的不是「它能不能学习」，而是「它已经提供了学习的哪些前提，以及哪些前提它不提供」。**
>
> **前一半让一个读代码的人知道从哪里接着做；后一半让一个读文档的人不会以为它已经做了。**
