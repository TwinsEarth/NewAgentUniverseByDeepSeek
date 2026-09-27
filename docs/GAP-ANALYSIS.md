# 查漏补缺分析 / Gap Analysis — upstream `agent-universe` v2.5.6 → NewAgentUniverseByDeepSeek V1.1.1

> **本文档是本项目的主要来源凭证。** 它逐条记录审计读到的**证据**（`文件:行号` + 原始代码）、
> 为什么该处是缺陷、以及重写后的对应处理。
>
> 审计对象：<https://github.com/TwinsEarth/agent-universe> `main`，版本 **v2.5.6**
> （Rust crate `gsn-core` `0.2.56`）。tarball 283 MB、**648 个文件**、Rust 15,735 行 /
> Python 934 行 / JavaScript 1,373 行 / Solidity 216 行 / 文档 23,039 行 / 论文 PDF 114 份。
>
> 许可证：MIT（`Copyright (c) 2026 Agent Universe Contributors`）。
> 来源与保留项的完整说明见 [`../ATTRIBUTION.md`](../ATTRIBUTION.md)。

---

## 0. 审计方法与可信度分级

| 手段 | 覆盖 |
|---|---|
| 全量读取源码 | 上表全部源码文件，逐行 |
| 本地执行 | `node js/test/test.js` → 12/12 通过；`node test/regression.js` → 14/14 通过；Python 包导入与行为探测 |
| 独立复现 | 用 Node/OpenSSL 的 Ed25519 独立复现上游钉住的跨语言向量，**逐字节命中** |
| 依赖源码核对 | `serde_json 1.0.151` / `zmij 1.0.23`（浮点输出格式） |
| **未能完成** | 上游 `gsn-core` 的 `cargo test` **未编译成功**：其依赖树（libp2p + rusqlite bundled + TLS）在 8 核 16 GB 机器上以 8 路并行 rustc 触发 `rustc-LLVM ERROR: out of memory` 与 `STATUS_STACK_BUFFER_OVERRUN`。因此对上游 Rust 运行时行为的判断均基于**源码阅读**，已在下文逐处标注；浮点格式的实际输出由依赖源码推断。 |

**本项目的验证是真实执行的**（见 §11），与上游形成对照：上游的旗舰承诺
「三端逐字节一致、可互验」在 CI 中**从未被执行**（原因见 §9.2）。

---

## 1. 结论摘要

| 严重度 | 数量 | 含义 |
|---|---|---|
| **严重 / Critical** | 12 | 直接破坏经济模型或信任模型，可被无权限的攻击者利用 |
| **高 / High** | 17 | 可利用、或破坏不变量、或使声明的能力实际不存在 |
| **中 / Medium** | 26 | 行为错误、panic 路径、静默数据丢失、资源耗尽 |
| **低 / Low** | 21 | 健壮性、可维护性、文档与实现不符 |
| **合计** | **76 条** | 每条均带 `文件:行号` 证据 |

三条**必须优先修复**、否则系统在安全意义上不成立的问题：

1. **BFT-lite 验收闸门完全由调用方控制。** 调用方通过查询串提供「赞成票数」和「委员会规模」，
   服务端据此**合成**委员与他们的票。任何客户端都能自我批准。
2. **货币是 `f64`，守恒用容差判定**（`.abs() < 0.001`），且结算在付款方余额不足时
   **凭空铸币**而不是拒绝。
3. **所有变更类接口都没有认证主体**，也没有状态前置条件；验收与匹配可反复重放以刷信誉。

---

## 2. 经济与结算 / Economy and settlement

### 2.1 【严重】货币使用 `f64`，守恒以容差判定

**证据** — `gsn-core/src/marketplace/settlement.rs`：

```rust
pub struct SettlementRecord { ... pub amount: f64, ... }          // :28
pub struct ConservationReport { ... pub total_budget: f64, ... }   // :37-40
pub struct SettlementEngine {
    balances: HashMap<String, f64>,                                // :47
    total_budget: f64, total_slashed: f64,                         // :53-54
    balance_sum: f64, total_paid_acc: f64,                         // :57-59
}
pub fn conservation_check(&self) -> ConservationReport {
    let conserved = (self.balance_sum - expected_sum).abs() < 0.001   // :173
        && self.total_paid_acc <= self.total_budget + 0.001;          // :174
```

**为什么是缺陷**：二进制浮点无法精确表示大多数十进制小数，反复 `+= / -=` 会累积误差。
一个「守恒到 0.001 以内」的账本**不是守恒的**：误差是真实的钱，会无界增长，
且可被有意引导。同样地 `payer_balance < actual_amount`（`:119`）在浮点下会在边界上
走向不同分支。容差还**与量级无关**：余额 ~10¹³ 时 f64 的 ULP 已达 ~0.002，
该比较落入噪声区间。JS 镜像实现用的是 `< 1e-9`（`js/lib/market.js:232`）——
两端相差**六个数量级**。

**重写处理**：`nau_core::domain::Money` 是**整数最小单位**（10⁻⁶，`Money(i64)`），
所有算术为 checked 运算并返回 `Result`；刻意**不实现** `Add`/`Sub` 运算符，
迫使调用方决定溢出语义。守恒为**精确相等**，全文无 epsilon。
测试 `Money` 的 `0.1 + 0.2 == 0.3` 精确成立，且拒绝 `1.0000001`、
指数记法与任何非数字输入。参见 `crates/nau-core/src/domain/money.rs`。

### 2.2 【严重】负数额度可被接受，且守恒检查看不出问题

**证据** — `settlement.rs:76-80` 与 `:148-160`：

```rust
pub fn deposit(&mut self, account: &str, amount: f64) {
    *self.balances.entry(account.to_string()).or_insert(0.0) += amount;
    self.total_budget += amount;      // 负数则总预算减少
    self.balance_sum += amount;       // 负数则系统总余额减少
}
pub fn slash(&mut self, account: &str, amount: f64) -> Result<f64, String> {
    let balance = self.balance(account);
    if balance < amount { return Err(...); }   // amount = -1000.0 时恒不成立
    *self.balances.entry(account.to_string()).or_insert(0.0) -= amount;  // 负数 → 加钱
    self.total_slashed += amount;                                        // 负数 → 减少罚没
    self.balance_sum -= amount;                                          // 负数 → 增加总余额
```

`deposit(-1000)` 与 `slash(-1000)` 都**通过守恒检查**，因为三个累加器始终被同时更新——
这是 §2.4 的结构性问题的直接后果。该路径经
`POST /api/v1/accounts/:acct/deposit` 无认证暴露（`api/rest.rs:240-249`），
且**仅在 `amount` 缺失时**返回 400，从不为负数返回 400。

**重写处理**：`nau-ledger` 的每个变更方法都拒绝非正数额度（`NauError::InvalidAmount`），
并有针对性测试。参见 `crates/nau-ledger/`（子代理产出，见 §11 验证记录）。

### 2.3 【严重】结算在付款方缺钱时凭空铸币

**证据** — `marketplace/mod.rs:352-355`：

```rust
// 确保付款方有余额
if self.settlement.balance(&payer) < amount {
    self.settlement.deposit(&payer, amount);
}
let paid = self.settlement.settle(task_id, &payer, &agent_id, amount,
                                  SettlementReason::Completed)?;
```

后果：`SettlementEngine::settle` 内部真正的余额不足护栏（`settlement.rs:119-124`，
上游有测试 `tests/v234_test.rs:401-406`）在真实路径上**永远不可达**。
`total_budget` 与 `balance_sum` 同时增加，因此守恒**仍报告 true**——
该不变量在结构上无法察觉此事。此外 `publish_task`（`mod.rs:158-165`）
既不托管资金也不检查需求方余额，而 JS SDK **确实**做了托管
（`js/lib/market.js:90-94`），`test/regression.js:140-146` 还据此断言了托管语义。
于是 Rust 实现与 JS 实现、与其自己的回归套件**三者语义不一致**。

**重写处理**：`Task` 发布即托管（`Ledger::escrow`），资金不足返回
`NauError::InsufficientBalance`，**绝不创建资金**；`release` 只能动用已托管的额度。

### 2.4 【高】O(1) 守恒检查是自指的，无法发现任何真实损坏

**证据** — `settlement.rs:171-183` 与 `:186-204`：

```rust
pub fn conservation_check(&self) -> ConservationReport {          // O(1)
    let expected_sum = self.total_budget - self.total_slashed;
    let conserved = (self.balance_sum - expected_sum).abs() < 0.001 && ...;
}
pub fn audit_full_scan(&self) -> ConservationReport {             // O(N)
    let balance_sum: f64 = self.balances.values().sum();          // 真正的重算
    ...
}
```

`conservation_check` 比较的是 `balance_sum`（增量维护）与 `total_budget - total_slashed`
（另两个由**同一批函数**增量维护的累加器）。生产路径上**从不**对
`balances` 求和；`audit_full_scan` 是唯一真正重算的路径，而它在
`gsn-core/src` 中**零调用点**（唯一调用者是 `settlement.rs:242` 的单元测试）。
因此该不变量退化为「三个总是一起更新的计数器仍然相等」，
无法发现错误账户写入、丢失更新或任何按账户的损坏。

上游 README（`:112`）与 `releases/v2.3.4.md:49` 却称其为 **CI 门禁**。

**重写处理**：保留 O(1) 面，但把 O(N) 审计提升为一等 API（`Ledger::audit`），
并写一个**证明该审计真的能失败**的测试：故意破坏一个账户余额，
断言 `conservation()` 仍说守恒而 `audit()` **报告差异**。
同时新增测试确保两条路径在长随机操作序列后一致。

### 2.5 【严重】所有变更类接口无授权、无状态前置条件

**证据**：

* `settle_task`（`mod.rs:332-400`）不检查调用者是否为需求方/所有者/任何人；
* `arbitrate`（`mod.rs:438-472`）不检查调用者是否为仲裁者，并对被告施加**任意**
  `slash_amount`；
* `open_dispute`（`mod.rs:405-435`）接受任意 `complainant` 字符串，无身份证明；
* `submit_result`（`mod.rs:280-299`）从不检查 `envelope.agent_id == task.owner`；
* `verify_result`（`mod.rs:302-327`）**没有任何状态前置条件**，无条件写入
  `Accepted`/`Rework`/`NoQuorum`；
* `grep -E 'authoriz|auth_token|api_key'` 在整个 `gsn-core/src` 中仅命中
  `deepseek/adapter.rs:23`（一个环境变量名）。

**重放放大**：先走完整个流程到 `Settled`，再调 `verify` → 任务被改回 `Accepted`，
再调 `settle` → 引擎的 `settled_tasks` 短路返回 `AlreadyPaid`/`0.0`（**钱是安全的**），
但 `mod.rs:365-392` 会**再跑一遍**：`rep.record_call(success, ratio)`、
`rep.reward_honesty()`、`agent.total_calls += 1`、重算 `success_rate`。
**可无限重复以免费刷信誉与诚实分。** 同一缺失的前置条件还允许把 `Slashed`
或 `Disputed` 的任务改写成 `Accepted`。

**重写处理**：每个带签名的领域结构（`Task`/`Bid`/`ResultEnvelope`/`Dispute`/
`DisputeOutcome`）都内嵌 `signer` + `signer_key` + `nonce` + `signed_at`
（+ 可选 `expires_at`），并实现 `Verifiable`：`verify()` 同时校验签名**与**
「DID 确实是该公钥的指纹」（`Did::matches_public_key`），
`verify_fresh(now)` 追加过期与时钟偏移检查。`NonceGuard` 拒绝 nonce 重用与回退。
`TaskState::transition` 是**完备的转移表**，非法转移返回
`NauError::InvalidTransition`。

### 2.6 【高】重复注册静默覆盖，同时重复存入质押

**证据** — `marketplace/mod.rs:116-148` 无 `contains_key` 检查：
`reputation_mgr.register_stake` **覆盖**质押记录（`reputation.rs:140-148`），
但 `settlement.deposit(&card.agent_id, card.stake)`（`:135`）**累加**余额，
技能索引还**追加**重复 id（`:138-143`），最后 `HashMap` 条目被替换（`:146`）。
上游测试 `v234_test.rs:103-111` 把此行为**记录为可接受**
（"重复注册会覆盖（HashMap 行为），但不报错"），而 JS SDK 会抛错
（`js/lib/market.js:64`），`test/regression.js:134-138`（REG-020）据以断言。
且 `stake = NaN` 能通过 `card.stake < self.min_stake`，因为 `NaN < 100.0` 为 `false`。

**重写处理**：`AgentCard::validate()` 检查全部不变量（名称非空且 ≤128、
技能非空且去重且小写、价格非负、SLA 的 bps ≤10000 且 `max_concurrency ≥ 1`、
质押为正、DID 与公钥绑定、`expires_at > signed_at`）；
重复注册在存储层按 DID 幂等（last-write-wins），不再重复计入资金。

### 2.7 【高】出价价格与支付额脱钩，出价 0 或负数是最优策略

**证据** — `mod.rs:251-255` 与 `:350`：

```rust
let cost_score = if bid.proposed_price > 0.0 { rep_score / bid.proposed_price }
                 else { rep_score };            // price <= 0 → 不惩罚
...
let amount = task.budget;                        // 支付额 = 预算，不是中标价
```

于是 `proposed_price = 0` 或负数**既赢得选择、又拿走全额预算**。
上游测试 `v234_test.rs:655-696` 把这一点**固化为期望行为**
（`proposed_price: 10.0`，`assert_eq!(paid, 50.0)`）。

**重写处理**：`Bid::validate_for(&task)` 拒绝非正价格与超出预算的价格；
结算额由中标价决定（预算为上限）。

### 2.8 【中】`SettlementReason` 的三个变体在真实路径上不可达

`DuplicateWork` 与 `Rejected`（`settlement.rs:17-19`）从未被生产代码传入——
`settle_task` 恒传 `Completed`（`mod.rs:362`）。`releases/v2.3.4.md:47`
承诺的「重复劳动→付0」「验收不通过→付0可罚没」在代码中不存在。

**重写处理**：结算原因由状态机与证据分级共同决定，
且 `EvidenceGrade::is_settlement_grade()` **真的**作为结算闸门被调用
（上游定义了它并注明「用于结算门禁」，却零调用点）。

---

## 3. 共识与验证 / Consensus and verification

### 3.1 【严重】验收委员会由调用方合成

**证据** — `api/market_actor.rs:360-386`：

```rust
MarketCommand::VerifyResult { task_id, approvals, committee_size, reply } => {
    let n = if committee_size > 0 { committee_size } else { 4 };
    let f = (n - 1) / 3;
    match QaCommittee::new(n, f) {
        Ok(mut committee) => {
            for i in 0..n {
                let did = format!("qa-{}", i);
                committee.add_member(did.clone());
                let vote = if i < approvals { QaVote::Stop } else { QaVote::Continue };
                let _ = committee.cast_vote(&did, vote);
            }
```

`approvals` 与 `committee_size` 是**客户端输入**，在 REST 层直接从查询串或请求体读取，
默认 3 与 4（`api/rest.rs:214-221`）：

```rust
let approvals = q.get("approvals")...unwrap_or(3);
let size = q.get("committee_size")....unwrap_or(4);
```

于是「委员会」由调用者提供的数字**现场合成**：调用者决定有多少席位、
谁坐这些席位（`qa-0`、`qa-1`… 这些字符串调用者同样能在脚本里造）、
以及多少票赞成。**调用者同时是委员、提案人与法定人数。**
`market_verify_result` 还**原样**暴露给 LLM 工具调用者
（`mcp/market_tools.rs:49-52`、`:91-95`），
`approvals`/`committee_size` 被文档化为可选参数。
任何客户端都能让任意存在的 `task_id` 返回 `accepted: true`。

**重写处理**：`nau-consensus::Vote` 是**带签名的 `Verifiable` 结构**，
携带 `voter` + `voter_key` + `nonce` + `signed_at`；`Committee::assign`
在构造时固定成员集合并**要求 `members.len() == n`**；
`cast()` 校验签名（`verify_fresh`）并拒绝非成员投票。
**不存在**任何能对未签名或调用方提供的票数进行统计的 API。

### 3.2 【高】`n` 是装饰性的

**证据** — `qa_committee.rs:68-76` 与 `:96-132`：

```rust
pub fn add_member(&mut self, did: String) {
    if self.members.len() < self.n as usize { self.members.push(...); }   // 超出静默丢弃
}
pub fn tally(&self) -> QaDecision {
    ...
    if self.members.iter().any(|m| m.equivocated) { return QaDecision::NoQuorum; }
    let quorum = 2 * self.f + 1;
```

`tally` 在 `members` 上统计而非在 `n` 上，且**没有任何地方断言 `members.len() == n`**。
以 `QaCommittee::new(3, 0)`（合法：`3 < 3·0+1 = 1` 为假）配 1 名成员投票，
即可用**单票**决定整轮。`n` 不具约束力。

**重写处理**：`Committee::assign` 强制 `members.len() == n` 且成员不重复，
否则 `NauError::Validation`。

### 3.3 【中】`3 * f + 1` 与 `2 * f + 1` 是未检查的 `u32` 运算

**证据** — `qa_committee.rs:53` `if n < 3 * f + 1`；`:118`、`:155` 重复 `2 * self.f + 1`。
`f > 1_431_655_765` 时 debug 下 panic、release 下**回绕**：
`f = 1_431_655_766` 使 `3f+1 ≡ 1 (mod 2³²)`，护栏 `n < 1` 对任何 `n` 为假，
于是构造出 `f` 荒谬、`quorum` 同样回绕的委员会。

**重写处理**：`VerificationPolicy::validate()` 与 `CommitteeSpec::new` 使用
`checked_mul`/`checked_add`，溢出返回错误。测试覆盖 `f` 接近 `u32::MAX`。

### 3.4 【高】承诺的 view change 不存在，`NoQuorum` 是吸收态

**文档承诺**：`qa_committee.rs:5`（"沉默 > f → NO_QUORUM + view_change"）、
`releases/v2.3.4.md:42,98`（"NO_QUORUM → VIEW_CHANGE → OPEN"）、`README.md:111`。

**代码事实**：`reset_votes()`（`qa_committee.rs:135-140`）是纯重置，
不递增 view/epoch、不改变成员、不记录发生过 view change，且**唯一调用者是测试**
（`v234_test.rs:342`）。`NoQuorum` 只映射到 `task.state = NoQuorum`（`mod.rs:321-323`），
**没有任何出边**；`TaskState::Running` 与 `Arbitration` 从未被赋值；
`Rework` 没有回到 `Matched`/`Running` 的路径。
另外，Python 参考实现所记载的 `safety_violation` / `conflicting_quorums` 触发条件
（`docs/papers/books/en/en-C2_Consensus and Security Governance.md:85,300`）
在 Rust 的 `QaDecision`（`qa_committee.rs:31-38`，仅 3 个变体、无 `reason`）中**完全丢失**。

**重写处理**：`TallyResult` 携带 `outcome`/`reason`/`quorum`/`accept`/`reject`/`silent`/
`equivocators`/`safety_violation`；协议同时达到两个法定人数时返回
`SafetyViolation` + `ConflictingQuorums`；`reset_for_next_round()` 递增轮次、
清空投票、**保留** equivocation 记录（避免 view change 洗白双投）。
`TaskState` 的转移表补上 `no_quorum → open` 与 `rework → running` 两条恢复边。

### 3.5 【中】equivocation 只留一个 bool，无法归责

`QaMember` 仅存 `equivocated: bool`（`qa_committee.rs:26`），
不记录是谁、也不记录冲突的两个决策，且没有轮次 id，
因此无法跨轮区分、无法处罚。

**重写处理**：`TallyResult::equivocators: Vec<Did>` 记录具体成员，并保留两票内容。

### 3.6 【中】Proof-of-Contribution 的验证既不认证也不唯一

**证据** — `proof/poc.rs:67-76`：

```rust
pub fn verify_contribution(&mut self, hash: &[u8; 32], verifier_did: String) -> bool {
    for record in &mut self.records {
        if &record.hash == hash {
            record.verifiers.push(verifier_did);        // 不查重
            record.verification_count += 1;
            return record.verification_count >= self.min_verifications;
        }
    }
    false
}
```

同一个主体可重复调用凑数；不检查验证者是否为贡献者本人；无签名校验；
`verification_count: u8` 溢出；`ContributionProof.signature`
（`economy/contribution.rs:16,90-92`）可设置却**从不验证**——
只有 `verify_hash()`（`:98-106`）重算公开字段的 SHA-256，除自洽外不证明任何事。

**重写处理**：验证者以带签名身份提交，去重且禁止自验；
`EvidenceGrade` 随结果流动并作为结算闸门。

---

## 4. 身份与签名 / Identity and signing

这是上游**最有价值**的部分，也是缺陷最集中的地方。

### 4.1 【严重】跨语言 `Receipt` 无法互验：浮点格式三方分歧

**证据** — `aca/receipt.rs:29-32` 的 `ResourceMetering` 含两个 `f64` 字段：

```rust
pub bandwidth_mb: f64,
pub energy_joules: f64,
```

三者对同一个值 `0.0` 的输出**互不相同**：

| 值 | Python `json.dumps` | JS `stableStringify` | Rust `serde_json` 1.0.151 + zmij |
|---|---|---|---|
| `1.0` | `1.0` | `1` | `1.0` |
| `-0.0` | `-0.0` | `0` | `0.0` |
| `1e21` | `1e+21` | `1e+21` | `1e21` |
| `1e-7` | `1e-07` | `1e-7` | `1e-7` |
| `1e16` | `1e+16` | `10000000000000000` | `10000000000000000` |
| `NaN` | `NaN`（非法 JSON） | `null` | `null` |

**三者在至少一行上互不相同。** 而 JS/Python 的 `build_receipt` 默认把
`bandwidth_mb`/`energy_joules` 设为「零值浮点」，于是同一份回执的规范字节不同，
**JS 或 Python 签发的 `Receipt` 无法被 Rust 的 `AcaProcessor` 验证，反之亦然**。
这是主路径（每次任务完成都走），不是边角。
上游唯一的向量（`cross_lang_signature.rs:13`）**不含任何浮点数**，所以 CI 看不见。

**重写处理**：规范载荷**拒绝一切浮点数**（`CanonicalError::NonIntegerNumber`），
货币与计量一律以整数最小单位或十进制字符串承载。
`conformance/vectors.json` 的 `rejections` 组把 `100.0`、`1.5`、`1e2` 钉为必须拒绝。

### 4.2 【严重】序列化失败时签名 `null`

**证据** — `aca/crypto.rs:19-25`：

```rust
pub fn canonical_payload<T: Serialize>(obj: &T) -> Vec<u8> {
    let mut v = serde_json::to_value(obj).unwrap_or(Value::Null);   // 失败 → Null
    if let Some(map) = v.as_object_mut() { map.remove("signature"); }
    serde_json::to_vec(&v).unwrap_or_default()                       // 失败 → 空
}
```

序列化失败会得到 `Value::Null`，于是 `sign_hex`（`:28-30`）**愉快地签下 4 字节
`null`**，且没有任何错误面可供诊断。

**重写处理**：`canonical_payload` 返回 `Result`；
`canonical_object` 额外要求根是 JSON 对象，否则 `RootNotObject`。
测试用一个 `Serialize` 恒失败的类型证明**不会**退化成 `null`。

### 4.3 【高】只移除顶层 `signature`，嵌套签名被外层覆盖

**证据**：`crypto.rs:21-23` 只在 `v.as_object_mut()` 上 `remove("signature")`，
即仅顶层。嵌套结构的内层 `signature` 会被外层签名覆盖。

**重写处理**：规范化的对象键过滤在**任意深度**生效，
并有专门测试与固定向量（`nested-signature-stripped-at-depth`）。

### 4.4 【高】键排序的跨语言分歧（astral 平面）

Python `sort_keys=True` 与 Rust `BTreeMap` 按 **Unicode 码点**排序；
JS 默认 `Array.prototype.sort()` 按 **UTF-16 码元**排序——
对 BMP 之外（U+10000+）的键，JS 会把 U+10000 排在 U+E000 **之前**，另两者相反。

**重写处理**：文档明确规定「按 Unicode 码点」，
JS SDK 必须使用显式的码点比较器；`conformance/vectors.json` 的
`astral-plane-key-ordering` 向量专门钉住此行为。

### 4.5 【高】接收到的规范字节被丢弃，签名实际覆盖的是「重新序列化」的结果

**证据**：验签调用 `canonical_payload(obj)`（`crypto.rs:44`），
其中 `obj` 是**本地反序列化后的结构体**，而非收到的原始字节。
任何接收端的字段默认值、类型强转、数值重规范化
（`message.rs:92-104` 的 `serde_json::from_value`）都会改变载荷并使验签失败；
对称地，发送方省略而接收方补默认值的字段，会验证到**不同的字节串**。

**重写处理**：契约明确为「签名覆盖规范形式」，并把
「新增字段必须同时更新规范规则版本」写入 `PROTOCOL_VERSION`（`nau/1`）的说明；
所有签名结构带 `nonce`/`signed_at`，`verify_fresh` 让时间语义显式可测。

### 4.6 【高】DID 指纹仅 64 位

**证据** — `identity/did.rs:13` `hex::encode(&hash[..8])`（Python `crypto.py:44`、
JS `aca.js:72` 相同）。64 位标识符的生日碰撞约 2³²，
有资源的攻击者可**研磨**出一个与受害者 DID 相同的 Ed25519 密钥；
`register_peer` 的「公钥↔DID」检查（`runtime.rs:176-185`）只证明发送方拥有
**某个**指纹相同的密钥，而非预期的那个。

**重写处理**：本项目保留 8 字节指纹以**兼容上游身份**
（`did:aip:` 前缀被 `Did::parse` 接受，且有测试证明上游向量可验证），
同时**新增**对弱公钥的拒绝：`PublicKey::from_hex` 调用
`VerifyingKey::is_weak()` 拒绝小阶点（含全零的恒等点编码）——
这是上游没有的加固。更宽的指纹规划记入 `docs/ARCHITECTURE.md` 的后续工作。

### 4.7 【严重】ACA 运行时零消费者、零测试；重放无保护

**证据**：`AcaProcessor` 在全仓仅出现于定义处（`runtime.rs:86,111`）与再导出
（`aca/mod.rs:22`）；`gsn-core/tests/*.rs` 中**没有任何**测试引用
`aca::runtime`、`process_message`、`execute_task` 或 `submit_review`。
同时 `runtime.rs:196-222` 校验发送方密钥与签名后**纯粹按 `msg_type` 分发**，
`msg.message_id`（`message.rs:45`）与 `msg.timestamp`（`:52`）**无人读取**，
不存在 seen 集合或 nonce。`handle_incoming_receipt`（`:379-427`）
也**不检查 `receipt.task_id` 是否对应本节点提案过的任务**，
每次重放都执行 `+60 Quality, +40 Availability`（`:412-413`）。
一份签名回执重放 100 次即可把对端推到信誉上限。

**重写处理**：`NonceGuard` + `verify_fresh` + 签名结构绑定 `task_id`；
`ResultEnvelope` 必须通过 `validate_for_settlement()` 才可释放付款。

### 4.8 【中】`SystemTime::now().duration_since(UNIX_EPOCH).unwrap()` 八处 panic 路径

**证据**：`envelope.rs:78-81`、`manifest.rs:92-95`、`message.rs:65-68`、
`receipt.rs:73-76`、`reputation.rs:50-53,81-84,95-98`。
时钟早于 1970 时，构造一条消息即 panic 而非返回错误。

**重写处理**：时间通过 `Clock` 端口注入（`SystemClock` 用 `unwrap_or(0)` 饱和，
不 panic；`ManualClock` 供确定性测试）。领域逻辑不再直接调用系统时间。

### 4.9 【低】非常量时间比较

`receipt.rs:103` `hasher.finalize().as_slice() == self.result_hash.as_slice()`；
JS `aca.js:238-242` 的提前返回字节循环；Python `aca.py:228-229` 的 list `==`。
比较的是**公开**哈希，实际风险低，但复用这些辅助函数做 MAC/密钥比较即引入时序侧信道。

**重写处理**：不在公开哈希上使用这些辅助函数作为安全边界的假设；
文档明确「比较公开摘要不构成安全边界」。

---

## 5. 网络、拓扑与中继 / Networking, topology, relay

### 5.1 【高】libp2p 传输层是真的，应用层数据面基本不存在

**是真的**：`net/peer.rs:108-186` 用 `SwarmBuilder` 构建了真实传输
（TCP+Noise+Yamux、QUIC、WebSocket、DNS）与真实行为
（Kademlia、GossipSub、Identify、RelayClient、AutoNAT、DCUtR、Ping），
`next_event` 真实轮询（`peer.rs:280-282`），`dht_put`/`dht_get`
真实调用 `put_record`/`get_record`（`peer.rs:221-237`）。
**这不是模拟。**

**但应用层缺失**（逐条证据）：

* **GossipSub 事件从不处理。** `PeerEvent::Gossipsub`（`peer.rs:42,55-59`）
  在 `process_swarm_event`（`node.rs:354-396`）与 `log_swarm_event`
  （`node.rs:513-528`）中**都没有 match 分支**；订阅了 `gsn/agents`、`gsn/tasks`
  两个主题（`node.rs:1193-1194`）却把收到的消息全部丢弃。
  且 `src/` 中**不存在**任何 `PeerCommand::Publish` 的生产者。
  所以「GossipSub 消息广播」没有任何活路径。
* **Kademlia 结果全部丢弃。** 只处理 `ConnectionClosed`、`OutgoingConnectionError`、
  `RelayClient`、`Identify`；`QueryResult`/`PutRecordOk`/`PutRecordErr`/`GetRecordOk`
  全部落入 `_ => {}`（`node.rs:394`）。于是 `POST /api/v1/agents` 返回
  `201 Created` 而对 DHT 写入是否到达任何对端**没有任何证据**。
* **DHT 从不 bootstrap，也不设 server mode。** `add_bootstrap`
  只做 `swarm.dial`（`peer.rs:215-218`），全仓无 `kad::Behaviour::bootstrap()` 调用；
  `mode::NodeMode::requires_dht_server()`（`mode/mod.rs:23`）**零调用点**。
* **DCUtR 从不驱动**，`PeerEvent::Dcutr` 只被 `eprintln!`（`node.rs:519`），
  且 `dcutr::Config` 保持默认（未配置 relay 服务器），**没有**调用
  `behaviour_mut().dcutr`。v2.5.4 发布说明所述的「自动协调同时打洞」无代码支撑。
* **没有 relay server（hop）。** 全仓未构造 `libp2p::relay::Behaviour`，
  因此节点**永远不能**为他人中继，与 relay 池叙事矛盾。
* **「续期」是拆建而非续期。** `node.rs:217-224` 每 80 秒对每条中继调用
  `listen_via_relay`，而该函数**先删除旧 listener** 再重新监听
  （`peer.rs:342-350`）。这是每 80 秒一次的连接扰动循环。

**同名的内存 mock 被 crate 根重新导出**，且集成测试对着 mock「证明」了联网：
`net/dht.rs:5-33` 的 `KademliaClient` 是本地 `HashMap`；
`net/gossip.rs:5-33` 的 `GossipSub` 是 `HashMap`；
`net/libp2p_node.rs:6-38` 的 `GsnNode` 是 `HashMap<String, AgentCard>`，
其模块头写着「libp2p 节点初始化（跨平台轻量版）」却**不构造任何 libp2p 对象**。
三者都在 `lib.rs:44` 被再导出；`tests/integration_test.rs:4-21` 的
`test_full_node_workflow` 正是对着这些 mock 断言「publish to DHT 成功」。

**重写处理**：不保留任何与网络服务同名的 mock；
`Transport` 是端口，`MemoryTransport` 名字显式表明是测试替身，
`TcpTransport` 是**真实 socket + 4 字节长度前缀分帧 + 帧长上限 + 读超时**，
并有双端点互发帧的集成测试。
libp2p 的替换理由与后续规划见 `docs/ARCHITECTURE.md` §0 与 `ATTRIBUTION.md` §2.3。

### 5.2 【高】`route_hops` 返回常量 7，「≤7 跳」不可反驳

**证据** — `topology/layer.rs:213-214`：

```rust
if self.node_group[from] == self.node_group[to] { return Some(1); }
// 跨房间：从本节点上行到 Lv7（≤7 层），再下行到目标房间
Some(Level::depth())          // 恒为 7
```

它对**每一对**跨房间节点返回常量 7，忽略两房间之间实际有多少层、
忽略 `reps`、忽略可达性；对不可达节点也**从不返回 `None`**。
两个房间、18 个节点的集群也报告 7 跳。
而测试 `route_hops_bounded_by_seven`（`layer.rs:278-287`）
断言 `== Some(7)`——**测试把常量固化成了「正确」。**

### 5.3 【中】Lv1 房间是团，边数测试不可能失败

`logical_edges`（`layer.rs:195-197`）对每个房间加 `n(n-1)/2`，
故 `edges ≈ N·fanout/2`；而测试断言
`edges < n*n/100` 且 `edges <= n*(9+10)*2`（`layer.rs:272-274`），
**没有做任何规模对照**（不比较 N 与 2N），`fanout` 还是常量，
因此任何「次 N²/100」的结构都能通过。该测试名为
`edges_are_linear_not_quadratic` 却不检验增长率。
更甚：三处文档对同一指标给出三种说法——
`layer.rs:8` 说 `O(N·fanout)`，`docs/design-v2.4.0-v2.4.1.md:88` 说 `O(N·fanout)`/「亚二次」，
`docs/architecture-v2.5.5.md:105` 说 `O(N·logN)`。

### 5.4 【中】分层拓扑不确定，`join` 是 O(depth·N)

`leaf_groups` 是 `HashMap`（`layer.rs:67`），而 `join` 用
「第一个未满的房间」(``:102-107``) 决定归属——**迭代顺序随机**，
于是房间归属、`logical_edges()` 与 `route_hops()` 在**不同运行之间可能不同**。
`promote()` 在**每次 `join`** 时被调用（`:120`）并遍历 `HashMap`
重新分桶（`:149-156`），因此 `join` 是 `O(depth·N)`，
整体构造为超线性——恰好是文档声称已消除的二次行为，
只是被搬进了构造器。`fanin_of`（`:168-176`）**漏掉上行边**，
其文档注释（`:167`）却声称包含父级代表，因此低估扇入。

**重写处理**：房间归属必须是节点 id 的**纯确定性函数**（哈希分桶，
与插入顺序无关）。验证方式：用 500 个 id 以**两种不同插入顺序**构建，
断言房间归属、边数、跳数**完全一致**。
`route_hops` 必须从实际树结构推导（绝不返回常量），未知节点返回 `None`。
并以「测量 `edges(2N)/edges(N) < 2.5`」证明次二次，
以「每个节点 `fanin ≤ fanout + 1`」证明扇入有界。

### 5.5 【中】中继池：容量是咨询性的，健康统计会被重置，探测记账会误杀健康节点

**证据** — `node.rs`：

* `auto_adopt_hop_relay` 先查 `cap.remaining <= 0`（`:298-301`）再插入（`:315`），
  **非原子**，且这是**唯一**会检查容量的插入路径；
  `ensure_channels`（`:404-444`）完全不检查容量与健康。
* `upsert_relay` 的 `ON CONFLICT` 会写入 `healthy = excluded.healthy`
  与 `fail_count = excluded.fail_count`（`persist.rs:249-250`），
  尽管注释声称「保留健康统计」（`:238`）——于是**已 dead 的中继可被复活**。
* `pending_probes: HashMap<PeerId, oneshot::Sender<...>>`（`node.rs:189`）
  在 `:616` 插入后**从不因超时或断连而移除**；
  对同一 `PeerId` 二次探测会**覆盖**第一个 sender，
  于是第一个调用者等满 15 秒超时（`:459`）后
  `mark_relay_failed`（`:468`）——**把探测记账造成的超时记为中继故障**，
  三轮就能把一个健康中继标记为 dead 并被 `delete_dead_relays` 删除。
* 每小时巡检（`:1208`）对不健康候选**串行**探测、每条 15 秒超时：
  按文档自述的池规模 3098（`docs/architecture-v2.5.5.md:208`），
  一轮需 ≥12.9 小时，**超过巡检周期**。

**重写处理**：容量在插入的同一个变更调用内强制
（`NauError::Conflict`）；健康与失败计数**只能**由显式
`record_failure`/`record_success` 改变，重新添加不会重置；
探测记账使重复探测返回错误而非静默驱逐；
选择顺序确定性（分类优先级 → `fail_count` → id，并有测试）。

### 5.6 【中】`nat` 模块返回硬编码结果，且测试固化了模拟

**证据** — `nat/mod.rs`：

```rust
pub fn gather_candidates(&mut self) -> Vec<IceCandidate> { self.local_candidates.clone() }  // :85-88 恒空
pub fn detect_nat_type(&mut self) -> NatType { NatType::PortRestrictedCone }                // :91-95 常量
pub fn connect(&mut self, peer_id: String, _remote: Vec<IceCandidate>) -> ConnectionState {
    let state = ConnectionState::Connected;                                                 // :101 无条件
```

`has_turn_relay` 是「字符串列表非空」（`:116-118`）。**上游自己的发布说明承认了这点**
（`releases/v2.5.4.md:106`：「原模拟 nat 模块（`src/nat/`）保留…真实穿透由 libp2p 层承载」）。
风险在于 `MeshNode::topology()`（`mesh/mesh.rs:133-144`）把 `nat_type`
与 `connection_count` 作为**测量值**暴露，而后者统计的是无条件 `Connected` 插入。

**重写处理**：不实现假的能力。拓扑与传输是真实端口；
「NAT 类型检测」在本版本中明确标注为**未实现**，
不出现在任何 API 返回值中（见 `docs/ARCHITECTURE.md` 的「明确未实现」清单）。
> **V1.1.1 更正**：本节原写「NAT 类型检测在本版本中明确标注为未实现」。
> 自 V1.1.1 起该条已不成立：`nau-net::stun`（RFC 5389 编解码）与 `nau-net::nat`
> （RFC 4787 映射/过滤分类）是真实实现并有 97 个 `nau-net` 测试通过，
> 其中该模块自身的测试发现并修复了 4 个协议缺陷。
> 但**仍然不宣称任何真实 NAT 类型**——分类真实 NAT 需要可达的公网 STUN 服务器，
> 不可达时返回 `Unknown` 而非猜测，这正是上游「返回硬编码常量」的相反做法。


### 5.7 【中】`MeshNode` 的嗅探是显式空操作，且无调用点

`LocalSniffer::scan` 只递增计数器（`discovery.rs:94-97`），
注释诚实写着「模拟：生产环境用 mDNS 或 UDP 广播」；
`MeshConfig.protocol_version` 停留在 `gsn/0.2.53`（`mesh/mesh.rs:33`）
而 Identify 宣告 `/gsn/0.2.56`（`peer.rs:155`）；
`grep` 确认 `MeshNode` 在 `mesh/mesh.rs` 之外**零调用点**，守护进程从不构造它。
`SessionRegistry` 的 `allocate_session` 也从不生成文档所称的「随机生成」code，
而是接受调用方提供的 code（`mesh.rs:71-73`）。

### 5.8 【中】`ModeController` / `NodeMode` 是惰性的

`mode::NodeMode::requires_dht_server()` 与 `max_storage_gb()`
（`mode/mod.rs:23-35`）在 `src/` 中**零调用点**；
`ModeController` 仅在 `tests/audit_test.rs:35` 被构造。
`node.rs:1141-1148` 计算 `NodeMode`、`node.rs:1192` 打印它、
`rest.rs` 把它放进 `NodeInfo`，**但从不据此门控任何行为**。

### 5.9 【低】启动时无条件拨打硬编码的第三方 IP

`node.rs:1076-1087` 有 10 个字面 IP，`node.rs:1099-1110` 有一个硬编码 seed relay
PeerId，`node.rs:1184-1188` **无条件拨打**，无白名单、无运营者退出开关。
这是烘焙进二进制的未认证对外联系清单。

**重写处理**：bootstrap 地址必须由配置/CLI 显式提供，默认**不**外联。

---

## 6. 存储与状态管理 / Storage and state

### 6.1 【严重】存储是只写不读的，账本从未持久化

**证据**：

* `storage/persist.rs` 只建 4 张表：`agents`（`:64`）、`tasks`（`:73`）、
  `kv_meta`（`:82`）、`relays`（`:88`）——
  **没有** balances / ledger / bids / disputes / reputation / settled_tasks 表。
* `load_agents`（`:132-152`）与 `load_tasks`（`:178-198`）在全仓**零调用点**；
  `upsert_task`（`:155-175`）同样零调用点。
* 唯一的持久化钩子在 `node.rs:1036-1056`，且**只**针对 agent 注册，
  并且是**重新解析原始 HTTP body** 来构造 `StoredAgent`——
  与 actor 校验并存储的内容**相互独立**，`skills` 有损 `join(",")`（`:1042`）、
  `reputation` 硬编码 `0.0`（`:1047`）、`created_at` 重新生成（`:1048`）。
* `run_daemon` 打开 store（`:1154`）并打印计数（`:1156-1160`），
  **但从不把任何状态载回** actor，而 actor 在 `api/market_actor.rs:169`
  以空 `AgentMarket` 启动。

**后果**：重启后 `conservation_check()` 返回 `0 = 0 − 0`、`conserved: true`
（`settlement.rs:171-183`），是一个**空洞的真**，而同时 API 却报告
从磁盘「恢复」了 N 个 agent。README（`:170`）称
「agents/tasks 通过 SQLite 真实落盘并在重启后恢复」——
对 `tasks` 是**假的**（从未持久化），对 `agents` 也是**假的**（写入但从不读取）。

**重写处理**：`Store` 端口显式包含 `load_agents`/`load_tasks`/`load_ledger`，
并有「drop 后重新 open，字段逐一相等」的测试；
追加日志对**被截断的末行**（模拟崩溃）容错跳过；
账本条目持久化并可重放；同一 id 后者覆盖前者且 `load_*` 只返回最新一条。

### 6.2 【中】`.lock().unwrap()` 18 处，一次 panic 毒化所有后续存储调用

`persist.rs:110,133,156,179,202,213,224,231,240,272,287,302,325,337,355,362,369,376`。
任何在持锁期间发生的 panic 都会使之后**每一次**存储调用 panic，
包括 swarm actor 任务内——而该任务的 `JoinHandle` 被丢弃（`node.rs:1195`），
于是 P2P 层永久死亡而 HTTP 仍返回 200。

**重写处理**：不使用会毒化的全局锁；`Store` 实现不 panic；
测试覆盖「损坏的尾巴」而非依赖未定义行为。

### 6.3 【中】守护进程的 accept 错误会终止整个进程

`node.rs:952` `let (mut stream, _remote) = listener.accept().await?;`——
一次 `EMFILE`/`ECONNABORTED` 即从 `run_daemon`（`:1225`）返回 `Err`，进程退出。

**重写处理**：accept 错误记录并继续；请求处理有超时与体积上限。

### 6.4 【中】HTTP 方法被绝大多数路由忽略

`api/rest.rs:158-188` 只有 `AgentsCollection` 与 `TasksCollection` 会分支 `method`，
其余目标**完全忽略方法**。可验证的后果：
`GET /api/v1/tasks/t1/settle` 会结算；
`GET /api/v1/disputes/d1/arbitrate` 会仲裁（且因无 body 使 `guilty` 默认 `false`，`:234`）。
变更状态的 `GET` 还违反 HTTP 缓存语义。

### 6.5 【中】HTTP 状态码由中文字符串子串决定

`api/rest.rs:37-44`：

```rust
Err(e) => {
    if e.contains("不存在") { Routed { status: 404, ... } }
    else { Routed { status: 422, ... } }
}
```

**这就是整个错误分类体系**：HTTP 状态取决于错误消息是否包含「不存在」这四个汉字。
任何未来改动都会静默重分类；一个恰好含该子串的校验错误会被变成 404；
且不存在任何机器可读错误码。

**重写处理**：`NauError` 是类型化的，映射到状态码由 `match` 决定，不做字符串匹配。

### 6.6 【低】`url_decode` 有 off-by-one 且有损解码

`api/rest.rs:69` `b'%' if i + 2 < bytes.len()` 要求两个十六进制位之后**还有**一个字符，
因此位于字符串末尾的 `%41` 不被解码；`:83` 的 `String::from_utf8_lossy`
把百分号编码的多字节 UTF-8 变成替换字符。

---

## 7. 记忆与模型适配 / Memory and LLM adapters

### 7.1 【中】「哈希链」用 `DefaultHasher`，且名字叫 `sha256_hex`

**证据** — `memory/layered.rs:78-86`：

```rust
fn sha256_hex(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    let mut h = DefaultHasher::new();
    input.hash(&mut h);
    format!("{:016x}", h.finish())      // 16 个十六进制字符 = 64 位
}
```

`handoff.rs:59-65` 内联了同样的东西。三个后果：
(a) 名字是**假的**；(b) 64 位非密码学摘要使针对审计轨迹的第二原像搜索**平凡可行**；
(c) `DefaultHasher` 明确**不保证跨 Rust 版本稳定**，
因此**审计轨迹在工具链升级后无法重新验证**。
此外两条链都只存摘要而**丢弃载荷**
（`layered.rs:61`、`handoff.rs:66`），所以轨迹**无法复现**。
两个模块的测试只断言 `!head_hash().is_empty()`（`layered.rs:109`）
与长度/计数（`handoff.rs:105-106`），**没有任何链路完整性或篡改检测测试**。
而 `sha2` 已经是该 crate 的依赖（`Cargo.toml:28`）。

**重写处理**：使用真实 `sha2::Sha256`，**同时存载荷**，
`HashChain::verify_chain()` 重算每一环并报出**首个**断裂的索引；
测试覆盖篡改任一载荷后验证失败且索引正确。

### 7.2 【中】「LRU」实为 LFU

`enhanced.rs:44-56` 以 `min_by_key(access_count)` 淘汰，
而 `access_count` 是**单调计数器**而非时间戳。
测试名 `lru_eviction_under_capacity`（`:102-112`）只区分「访问过一次」与「从未访问」。

**重写处理**：记录真实的 `last_used` 逻辑时钟并按最近最少使用淘汰；
测试设计为**在 LFU 规则下会失败**。

### 7.3 【中】防污染未被执行

`EnhancedMemory::shareable`（`enhanced.rs:76-78`）**没有调用者**；
`SwarmMemory::publish`（`shared_memory.rs:30-33`）接受任意调用方提供的 `weight`
（`shared_memory.rs:15`），`best_strategy` 取其最大值（`:40-44`）。
因此文档所称「只有高分经验才允许上群体库，防污染」在代码中**不存在**：
恶意或出错的发布者设 `weight = 1.0` 即可胜出。
并且 `best_strategy` 用 `partial_cmp(...).unwrap()`（`:43`），
`NaN` 权重即 panic——`collaboration/hetero_llm.rs:68,100` 同样如此。

**重写处理**：共享库拒绝**派生质量**低于阈值的经验；
质量由记录的成败次数**派生**，**不可由发布者提供**；
分数一律整数 bps，排序使用整数比较，不使用浮点 `partial_cmp`。

### 7.4 【中】`Flywheel::is_spinning` 是单调计数器上的闩锁

`flywheel.rs:37-47`：`is_spinning()` 是四个单调计数器的谓词，
一旦为真就**永远**为真（没有任何字段会减少），
且 `optimize_structure()`（`:37-39`）**不优化任何结构**，只递增计数。
没有任何接线把飞轮连到 `LayeredTopology`/`EnhancedMemory`/`AgentMemory`，
因此文档所述闭环（`flywheel.rs:5-6`）在代码中**没有因果路径**。
这是「把指标当成机制」的最清楚例子。

**重写处理**：不在本项目中断言一个无法执行的闭环；
`nau-agent` 的分层记忆有真实链路与可验证的 `verify_all()`。

### 7.5 【高】LLM 适配器吞掉 `Result`，并无检查索引

`.unwrap()` 出现在每个适配器的 `chat` 中
（`llm/adapter.rs:70,109,147,201,243`），而 `chat()` 返回 `LlmResult`（非 `Result`），
因此**任何提供方错误都是库函数中的无条件 panic**；
`resp.choices[0]`（`:72,203,245`）、`resp.candidates[0].content.parts[0]`（`:111`）、
`resp.content[0]`（`:149`）在响应为空数组时 panic——
真实提供方在内容过滤、空补全或仅返回工具调用时都会触发。
且全仓**没有任何 HTTP 客户端**（`Cargo.toml:25-63` 无 HTTP 依赖），
六个提供方全部是返回固定字符串的 `Mock*Client`；
`DeepSeekConfig.api_key_env`（`deepseek/adapter.rs:23`）被存储却**从不读取**。

**重写处理**：`LlmProvider` 端口的每个方法返回 `Result`；
提供方以数据描述（`ProviderProfile`：base_url、模型列表、上下文窗口、
密钥所在**环境变量名**），不含硬编码副作用客户端、不含密钥字面量；
测试用 `ScriptedProvider` 通过 `dyn LlmProvider` 调用。

### 7.6 【中】「网络分区检测」是查表

`llm/network.rs:281-303` 的 `probe_all` **不做任何 I/O**——
它评估与 `reachable_from` 相同的静态谓词（`:43-52`）然后把端点标记为 `Reachable`；
`EndpointHealth::{Failover, BlockedNoProxy}`（`:66-75`）**从未被赋值**；
代理 URL 是自述的占位符（`:182,190,198`），
而测试却断言「经该占位符可达」（`:334,353-357`）。
`downgrade_events: Vec<_>`（`:404`）无界增长。

**重写处理**：不在本版本中实现假的分区检测；
`ProviderProfile` 提供数据，健康判定留给调用方，
不在返回值中伪造可达性。

### 7.7 【低】`blind_attempt` 可能死循环

`swarm/memory.rs:156-170` 的拒绝采样
`while tried.contains(&pick)` 在 `budget >= choices` 时**永不终止**。
当前调用点都满足 `budget < choices`，属潜在挂起。

### 7.8 【低】纠删码无法恢复丢失的数据分片

`erasure/mod.rs:92-98` 的 `decode` 要求
`data_shards_available.len() >= self.data_shards`，随后只拼接数据分片（`:100-111`）——
SHA-256 校验分片（`:62-80`）**从不用于重建**。
因此尽管有 `ErasureCoder::new(4,2)` 与文档「丢失部分分片仍可恢复」（`:4`），
该结构实际是「分割 + 校验和」。
集成测试（`tests/integration_test.rs:93-102`）取 `shards[0..4]`（即 4 个数据分片）
来「模拟丢失 2 个分片」，因此**从未测试恢复**。

**重写处理**：本版本提供纠删码 API（`crates/nau-erasure`），且**行为与名字相符**——
任意 k 片可重建原始数据，穷举 504 个擦除子集验证，包含全部数据片丢失、仅剩校验片的场景。
上游的缺陷正是「名字与行为不符」：它构造了 SHA-256「校验片」但从不用于重建。
（**V1.1.1 更新**：本节原先写的是「本版本**不**提供纠删码 API」，已随 V1.1.1 实现更正。）
注意区分：**擦除**恢复已实现，**错误**纠正未实现（见 `docs/ARCHITECTURE.md` §7.1）。

---

## 8. MCP 协议 / MCP

### 8.1 【高】工具 schema 与分发是两份手工列表，且 schema 从不校验

`market_tools.rs:24-71` 声明 19 个工具（`RELEASES`/`releases/v2.3.6.md:11,41`
与 `market_tools.rs:3` 都写 18，**代码是 19**），
而 `MarketMcpBridge::call`（`:74-123`）是另一个手工 `match`。
所有参数读取都带宽松默认：`get_str` → `""`、`get_f64` → `0.0`、
`unwrap_or(3)`/`unwrap_or(4)`/`unwrap_or(false)`/`unwrap_or(10)`（`:75-79,92-99,107`）。
于是 `market_deposit` 传 `amount: "lots"` **静默存入 0**
并返回 `{"status":"deposited","amount":0.0,...}`；
`market_arbitrate` 传 `guilty: 1` **静默按不成立处理**。
`inputSchema` 从不被校验，且 `ToolParameter.enum_values`（`tool.rs:15`）**从未被填充**。

### 8.2 【高】调用方提供的阈值参数

`market_tools.rs:92-94`：

```rust
let approvals = args.get("approvals").and_then(|v| v.as_u64()).unwrap_or(3) as u32;
let size = args.get("committee_size").and_then(|v| v.as_u64()).unwrap_or(4) as u32;
self.market.verify_result(get_str("task_id"), approvals, size).await
```

**省略两个参数即得到满足法定人数的 3-of-4 裁决**，
即 §3.1 的攻击面在 MCP 侧同样开放（`verification.rs:120-126`
精心编码的 `n=3f+1` 不变量在这条路径上**从未被查阅**）。

### 8.3 【中】`id: null` 不可表示

`RequestId` 是 `Number(u64) | String`（`protocol.rs:9-14`），
因此解析错误与非法请求的响应使用 `RequestId::Number(0)`
（`stdio.rs:37,57`；`sse.rs:36,56`），而 JSON-RPC 规范要求 `"id": null`。
负数或小数 id 同样无法反序列化并被误报为 invalid-request。

### 8.4 【中】未知工具返回协议错误而非工具级失败

`server.rs:162-164` 返回 -32001；MCP 期望 `tools/call` 返回
带 `isError: true` 的**正常结果**。
（19 工具桥接层做对了，`market_tools.rs:111,121`；`McpServer` 没做对。）
于是**两个传输对同一输入给出不同答案**。

### 8.5 【中】无版本协商，且 `initialize` 前即可调用

`handle_initialize` 完全忽略 `req.params`（`server.rs:139-146`；
`stdio.rs:104-115`；`sse.rs:64-68`），恒答硬编码 `"2024-11-05"`，
从不拒绝不兼容的 `protocolVersion`，也没有
「未初始化」的 -32002 路径。

### 8.6 【中】SSE 不是可用的流

`handle_get`（`sse.rs:100-119`）返回一帧 `event: ready`、一行 `retry: 3000`，然后**关闭**：
无 `id:` 字段、无长连接、载荷是临时的自造字段。
而模块文档（`sse.rs:1-11`）描述「SSE 长连接」与服务端推送。
另外 `jsonrpc_response` 把**任何** JSON-RPC 错误映射为 HTTP 400（`sse.rs:121-128`），
并且从不读取 `Accept: text/event-stream`。

### 8.7 【低】能力结构体序列化出 `list_changed`

`protocol.rs:277-291` 的 `ToolsCapability{list_changed}` 等缺少 camelCase rename，
会序列化为 `list_changed`。活路径靠手写 JSON 字面量避开了它（`server.rs:125`、
`stdio.rs:105`），故为潜伏缺陷。

### 8.8 【严重】HTTP MCP 端点无认证且挂着动钱工具

`sse.rs:27` 的 `handle_post(body, market)` **不读任何 header/token/origin**，
直接分发到 `MarketMcpBridge::call`（`market_tools.rs:81-112`），
其中包含 `market_arbitrate`（可罚没质押）、`market_settle_task`、
`market_deposit`、`market_register_agent`。
而 `sse.rs:9-11` 的文档明确把它宣传为可远程接入
（「把 MCP server URL 指向 `http://<node>:4002/api/v1/mcp` 即可」）。
**任何能访问该端口的人都能提款/罚没账户。**

**重写处理**：工具 schema 与分发由**同一份定义**驱动（派生 schema + 校验 + 分发）；
类型错误与缺失必填返回 `-32602` 并指名参数；
阈值参数在本 crate 的工具面中**不存在**，
改为接受「带签名的票数组」并由服务端判定；
`RequestId` 含 `Null`；工具级失败返回 `isError: true`；
`initialize` 解析并回显受支持版本，未初始化请求返回 `-32002`。

---

## 9. SDK、合约、CI 与文档 / SDKs, contracts, CI, docs

### 9.1 【高】JS SDK 同时存在两套互不兼容的身份方案

`js/lib/keychain.js:26` → `did:au:<sha256(SPKI DER) 前32位十六进制>`（共 39 字符）；
`js/lib/aca.js:72` → `did:aip:<sha256(原始32字节公钥) 前8字节>`（共 24 字符）。
Python 与 Rust **只实现后者**。
于是**同一密钥对产生两个 DID**，且 `js/index.js:19`
的 `AgentUniverse` 门面**默认安装前者**（`js/index.d.ts:102` 也如此标注），
而 `buildManifest(u.identity, ...)` 会抛
`TypeError: identity.signInto is not a function`。
发布说明（`releases/v2.3.6.md:35`）确实声明旧 `Keypair` 仅为本地教学保留，
但门面仍把它作为默认身份交出。此外 `stableStringify`
对 `undefined` 会吐出裸标记 `undefined`
（实测 `{"a":undefined,"b":1}` 与 `{"a":[,1]}`，均为**非法 JSON**）、
对 `BigInt` 抛未捕获异常、对 `Date` 静默序列化为 `{}`
（载荷错误而签名「看起来」有效）。

### 9.2 【高】CI 静默跳过 11/17 个 Python 测试，且 clippy 从不拦截

**证据**：

* `ci.yml:64` 只安装 `pytest`，**从不安装 `cryptography`**；
  而 `aip-sdk-py/tests/test_crypto_aca.py:21-23` 有模块级
  `pytestmark = pytest.mark.skipif(not _HAVE_CRYPTO, ...)`，
  于是**整个文件（11 个测试，占 Python 套件 65%）每次 CI 都以 skipped 通过**。
  README（`:170`）与 `CHANGELOG.md:134` 宣称的「17 个 Python 测试」
  在 CI 中从未被真正执行。**仓库最核心的承诺（跨语言签名可互验）在 CI 中零覆盖。**
* `ci.yml:45`：`cargo clippy -- -D warnings 2>&1 || echo "clippy warnings tolerated"`
  ——`||` 保证恒为退出 0，`-D warnings` 纯属装饰。`:48` 同样处理 `gsn-daemon --help`。
* `ci.yml:3-7`：仅 `main` 分支；PR 指向其他分支或任何非 main 推送**零 CI**。
* `ci.yml:96-108`：合约「检查」只是 `grep -q "pragma solidity"` 与 `grep -q "contract "`，
  且目录缺失时走 `else` 分支打印警告**并通过**。
* **没有任何东西为发布把关**：`release.yml`、`publish.yml`、`client-build.yml`
  都在 `v*` 上独立触发，**没有 `needs:` 指向 CI**。
  `publish.yml:190-192` 会对一个从未测试过的 tag 执行 `npm publish`。
* `publish.yml:147-149` 授予 `id-token: write`（OIDC），
  却仍用长期 `NPM_TOKEN` PAT 发布（`:163-168,194`）——该权限未被使用。
* 所有 action 使用浮动主标签（`actions/checkout@v4`、
  `dtolnay/rust-toolchain@stable`、`softprops/action-gh-release@v2` 等），未按 SHA 固定。
* `dependabot.yml` 缺 `npm`（根、`/js`、`/client`、`/desktop`）
  与 `cargo`（`/client/src-tauri`、`/desktop/src-tauri`）条目：
  **实际发布的包与两个 Tauri Rust 外壳从不被扫描。**

### 9.3 【高】版本一致性已经漂移，且机制本身是漂移源

`docs/version-checklist.md` 是一份**手工维护**的登记表
（§1 列了 npm/JS 7 行、client 10 行、desktop 9 行、gsn-core 7 行、
Python **1** 行、CI 3 行），配 `scripts/bump-version.sh` 的 sed 规则。
审计发现**实际已漂移**：

| 文件:行 | 陈旧值 | 是否登记 | 是否被脚本修改 |
|---|---|---|---|
| `aip-sdk-py/aip/__init__.py:1`（docstring）与 `:31`（`__version__`） | `2.3.6` | **否** | **否** |
| `aip-sdk-py/aip/mcp_client.py:21`（`_SDK_VERSION`） | `2.3.6` | **否** | **否** |
| `aip-sdk-py/aip/aca.py:68`（`version=` 默认值） | `2.3.6` | **否** | **否** |
| `client/index.html:6`、`:13` | `v2.3.6` | **否** | **否** |
| `desktop/index.html:6`、`:13` | `v2.3.6` | **否** | **否** |
| `client/package.json:15`、`desktop/package.json:13`（依赖 pin） | `^2.3.4` | **否** | **否** |
| `desktop/README.md:3`（两处） | `v2.3.4` / `SDK@2.3.4` | **否**（§1 C 整节漏掉该文件） | **否** |
| `docs/architecture-v2.5.5.md:3` | `npm 2.5.5` | 不在范围 | 否 |

`scripts/bump-version.sh:19` 还把 GNU sed 的 BRE 扩展 `\+` 写进
`sed -i` 表达式，且**没有 `sed --version`/`gsed` 回退**，
而 `docs/version-checklist.md:132` 的 SOP 上下文会在 macOS 上执行它；
`sed` 无匹配时同样退出 0，因此**每一条失效规则都是静默的**，
脚本自身**不做任何自校验**（把校验推给人在 `:139-140` 手跑 grep）。
登记表自己的规则（`:161`「新增版本点…立即回到本登记表追加一行」）
正是没被遵守的那一条。

**重写处理**：版本有**唯一**机器可读来源（仓库根 `VERSION`），
Cargo 工作区、Python SDK 与 JS SDK 都**读取**它而非重述，
`crates/nau-core/tests/version_consistency.rs` 断言其一致，
并有一条断言「任何 crate 都不得声明字面版本」。

### 9.4 【严重】四个 Solidity 合约中三个不可部署

**`GovernorToken.sol`**：`delegateVotes` 执行 `votes[msg.sender] -= amount`（`:57`），
而 `votes` 在**合约任何地方都没有被递增过**（grep 确认只有 `:14` 声明与 `:57` 读取），
因此在 ^0.8 的检查算术下**任何非零调用都必然 revert**（Panic 0x11）——
治理代币唯一的治理原语完全不可用。`onlyOwner`（`:24-27`）声明后**从未应用于任何函数**，
`owner`（`:17`）无任何权限。`_transfer` 在每次首次收到余额时 `holders.push(to)`（`:66-68`），
而 `holders` **从不被任何函数读取**——无界、不可移除、不可读的状态膨胀。

**`AgentCardAnchor.sol`**：`anchor()`（`:19-28`）是 `external` 且**无任何认证**，
`anchors[cidHash] = Anchor({...anchorer: msg.sender})`（`:20-25`）
**无条件覆盖**已存在的锚定，因此任何人都能替换任何 agent 的链上清单锚并成为
被报告的 `anchorer`；而 `verify(cidHash)`（`:30-32`）仅返回 `anchoredAt > 0`，
只证明「有人锚过某个东西」，**从不校验调用者期望的 `agentDidHash`**。
`agentAnchors[msg.sender].push(cidHash)`（`:26`）无上限。

**`PoCVSettlement.sol`**（最严重）：

* `createTask`（`:29-42`）是 `payable` 却**从不读取 `msg.value`**，
  也不要求 `msg.value == rewardAmount`，因此可以创建
  `rewardAmount = type(uint256).max` 而**零资金**的任务，
  `settleTask` 随后尝试支付合约无法覆盖的金额（`:78-84`）→
  最后一个结算者 revert，**资金被永久锁定**（`require(success, "transfer failed")`）。
* `verifyTask`（`:55-61`）与 `disputeTask`（`:63-68`）**无任何访问控制**：
  任何地址都能把任何进行中的任务标记为 `Verified`（正是解锁全额支付的条件下）
  或强制进入 `Disputed`。
* `settleTask` 在**记账之前**执行外部 `call{value: payout}`（`:83`），
  而 `totalStaked[t.executor] -= t.stakeAmount` 在其后（`:85`）——
  check-effects-interactions 违背；文件中**没有任何 `nonReentrant`**。
  唯一阻止支付循环的是 `:76` 的状态写入，属「偶然的不变量」而非设计护栏。
* `acceptTask`（`:44-53`）不禁止 `msg.sender == t.requester`，
  因此需求方可自我接单 → 借助上一缺陷自我验证 → 提取资金。
* 争议中的任务仍全额支付执行者（`:79` 只门控**质押**的退还），
  **不存在任何罚没路径**——「PoCV」的争议解决在经济上无意义。
* 若无执行者时 `settleTask` 会把 `rewardAmount` 发给 `address(0)`（`:83`），
  永久销毁托管资金。

**`ReputationBridge.sol`**：`addVerifier`（`:30-32`）是 `onlyVerifier`，
因此**任何既有验证者都能无限铸造新验证者**，且无 owner、无上限、无移除函数；
`recordReputation`（`:34-40`）接受任意 `uint32` 而链下模型用 0–10000 bps
（`aip/models/models.py:24`）——**链上链下量纲不一致且双方都不强制**；
`snapshots[].push`（`:41-48`）无界；`ReputationUpdated`（`:19`，`:49` 发出）
只携带四个维度中的 `honesty` 一个，索引器无法重建快照；
`getLatestReputation` 对未知 DID **revert**（`:54`）而非返回零值。

**此外整个 `contracts/` 目录只有 4 个 `.sol` 文件**：
没有 `foundry.toml`、没有 `hardhat.config`、没有测试、没有部署脚本、
没有 OpenZeppelin、没有编译器版本 pin 之外的任何配置。

**重写处理**：四个合约全部重写——真实投票检查点与
`getPastVotes`；锚定**首写即不可变**且 `verify(cidHash, agentDidHash)` 校验两者；
`Settlement` 要求 `msg.value == rewardAmount`、验证者集合与法定人数、
状态先行后外呼 + `nonReentrant` + pull 支付、
禁止自我接单、争议可罚没；`ReputationRegistry` 为 owner-only 增删验证者并有上限、
bps 上限校验、按 epoch 幂等快照、事件携带全部维度。
配 Foundry 测试（每个缺陷一个以缺陷命名的失败优先测试）与 `Deploy.s.sol`。

### 9.5 【中】客户端与桌面端是 HTML 演示壳，且桌面端必然构建失败

两个应用的 Rust 侧合计**36 行、暴露 2 个命令**：
`client/src-tauri/src/lib.rs` 有 `get_platform()` 与
`get_sdk_version()`（返回硬编码 `"2.5.6"`）；
`desktop/.../lib.rs` 只有 `get_sdk_version()`，是前者真子集。
**两个前端都不调用 Rust 侧**（`grep invoke` 在
`client/src`、`desktop/src` 均无命中）；
`client/src/main.js:1` 直接从 npm 包 import `AgentMarket`，
在浏览器里跑内存市场模拟。并且：

* `desktop/src-tauri/tauri.conf.json:34-35` 需要 `icons/icon.icns` 与 `icons/icon.ico`，
  两者**都不存在**（目录只有 4 个 PNG），且被 `desktop/.gitignore:11-13` 显式忽略，
  因此 macOS/Windows 打包**必然失败**；而**没有任何 workflow 构建 `desktop/`**。
* 两个前端都有**运行时错误**：`client/src/main.js:71` 与
  `desktop/src/main.js:96` 读取 `c.totalPaid`，
  而 `conservationCheck()` 返回 `{conserved, balanceSum, totalSlashed, expected}`
  （`js/lib/market.js:231-236`）——**`totalPaid` 不存在**，两处都打印 `undefined`。
  `desktop/src/main.js:83-88` 在 try/catch 里期望第二次 `settle()` **抛错**，
  但 `settle()` 是**返回** `{paid:0, reason:'already_paid'}`（`js/lib/market.js:159-161`），
  因此桌面演示**每次都打印自己的假警报**「⚠️ 重复结算未被拦截!」。
* `desktop/src/main.js:8` 取到 `versionEl` 后**从不写入**，
  于是 `desktop/index.html:13` 永久显示陈旧的 `v2.3.6`。
* 两者都设 `"csp": null`（`tauri.conf.json:22`）且日志用 `innerHTML` 拼接
  （`client/src/main.js:18-20`），构成潜在 XSS 汇聚点。
* `client/platforms/ios.md:35` 与 `client/ios/README.md:6` 指向
  `client/src-tauri/gen/apple/`，该目录**不存在**（只有 `android/` 与 `schemas/`）。

**重写处理**：**放弃**两个客户端应用（理由与依据见 `ATTRIBUTION.md` §2.3
与本节），并在 `docs/ARCHITECTURE.md` 中记录该决定与重建所需工作，
而不是发布一个构建必然失败的 UI。

### 9.6 【中】文档与实现不符（12 处以上）

| 文档声明 | 代码事实 |
|---|---|
| `README.md:170` / `CHANGELOG.md:134`「17 个 Python 测试」 | CI 中 11 个被静默跳过（§9.2） |
| `README.md:170`「agents/tasks 通过 SQLite 真实落盘并在重启后恢复」 | `tasks` 从未持久化；`agents` 写入但**从不读取**（§6.1） |
| `README.md:276`「已发布版本 … 2.4.0 ~ 2.5.6」 | `docs/version-checklist.md:159` 称 v2.4.0–v2.5.4 **从未打 tag/发布** |
| `README.md:117-124`、`:319` 与 `docs/architecture-v2.5.5.md:92` 宣传四个智能合约与「Base/Arbitrum 主网」 | 四个合约均不可部署且无主网部署记录（§9.4） |
| `marketplace/task.rs:78`「六字段：goal/context/done/todo/trace/owner」 | `validate()`（`:113-140`）校验的是 `budget`/`required_skills`/`requester`，**从不校验 `done`/`trace`/`owner`** |
| `releases/v2.3.4.md:27`「技能过滤 → 信誉过滤 → 负载过滤 → 性价比排序」 | 只有技能查表（`mod.rs:175-184`）与比率排序（`:238-264`），**无信誉过滤、无负载项** |
| `releases/v2.3.4.md:28`「同性价比按负载低者优先」 | 严格 `>` 比较，**先到先得**（`mod.rs:260`） |
| `releases/v2.3.4.md:29`「支持质量门槛过滤低质投标」 | 不存在质量门槛 |
| `releases/v2.3.4.md:42,98`、`README.md:111`「view change」 | 不存在（§3.4） |
| `releases/v2.3.4.md:47`「重复劳动→付0」「验收不通过→付0可罚没」 | 两个枚举变体在生产路径上不可达（§2.8） |
| `releases/v2.3.4.md:54`「退出按规则退还」 | 无 unstake 路径；`StakeStatus::{Withdrawing,Withdrawn}`（`reputation.rs:98-101`）**从未被赋值** |
| `releases/v2.3.4.md:59-61`「争议与仲裁：基于 TraceLedger SHA-256 哈希链…只读仲裁」 | `DisputeCase`（`mod.rs:49-58`）无 trace 哈希、无 `TransferBundle` 引用、无证据台账写入；**crate 中不存在 `TraceLedger` 类型** |
| `releases/v2.3.4.md:15`「19 字段完整定义」 | 结构体有 **21** 个字段（`agent_card.rs:61-100`） |
| `docs/design-v2.4.0-v2.4.1.md:49,54` 与 `settlement.rs:169`/`README.md:112` 对守恒不变量给出**互相矛盾**的两个式子 | 代码实现的是后者（`balance_sum = total_budget − total_slashed`） |
| `docs/design-v2.4.0-v2.4.1.md:76`「守恒不变量 property test 1000 轮随机交易恒成立」 | **不存在 property test** |
| `marketplace/reputation.rs:4`「半衰期 90 天」 | 市场所用的信誉实现**没有时间输入**，不可能衰减；衰减只存在于**未被使用**的 `aca/reputation.rs:94-107` |
| `releases/v2.3.6.md:11,41`、`market_tools.rs:3`「18 个工具」 | `tool_definitions()` 返回 **19** 个 |
| `sse.rs:1-11,96-99`「SSE 长连接、服务端推送」 | `handle_get` 返回一帧后**关闭** |
| `aip/crypto.py:3-5` docstring 承诺未安装 `cryptography` 时「其余功能仍可正常使用」 | `verify_object` 在缺签名早退（`:105-107`）**之前**调用 `_require_crypto()`（`:104`），实测**抛 `RuntimeError`** |
| `js/test/test.js:2`「测试（8 项）」 | 文件声明 **12** 个测试 |
| `test/README.md:24` 称 REG-003 覆盖「两个 Cargo.lock」 | 代码只检查 client 的（`regression.js:69-76`），而登记表列了 3 处 |

### 9.7 【中】回归套件对着 JS 实现断言，却用来说明 Rust 实现

`test/regression.js` 的 REG-020/021/022/030/031（`:134-186`）
断言重复注册被拒、重复结算返回 `paid=0`、负数存款被拒、
`balanceSum == deposits − slashed`——但**全部跑在 `js/lib/market.js` 上**。
Rust 实现在其中三项上与 JS **不同**（§2.2 负数、§2.6 重复注册、§2.3 铸币），
且**根本没有托管**。因此绿色的回归套件对真正支撑守护进程的实现
**不提供任何保证**，而 `RELEASES.md:261` 与 `README.md:170` 却引用这些计数作为证据。

---

## 10. 未修复与明确放弃的范围 / Honest scope limits

诚实记录本版本**没有**做到的事，避免重演上游「文档承诺 > 代码事实」的问题：

1. **不实现 libp2p 网络栈。** 本版本提供 `Transport` 端口、
   真实 TCP 分帧传输与内存替身；Kademlia DHT、GossipSub、
   Circuit Relay v2、AutoNAT、DCUtR **均未实现**。
   上游的 libp2p 传输层是真的但其应用层数据面缺失（§5.1）；
   本版本选择**不宣称**这些能力，而不是宣称后留空。
2. **不实现 NAT 穿透。** 上游的 `nat` 模块返回硬编码结果（§5.6）。
   本版本不暴露 NAT 类型判定 API。
3. ~~**不实现纠删码。**~~ 上游的实现无法恢复丢失的数据分片（§7.8），
   **V1.1.1 起本版本提供该 API 且可真正恢复**：`crates/nau-erasure`，82 个单元测试 +
   9 个文档测试通过，穷举 504 个擦除子集（含仅剩校验片的情形）。**纠错**仍不在范围内。
4. **不实现可信执行环境（TEE）/ zkML 验证。** 上游的
   `tee_quote`/`zk_proof` 是不经校验的不透明字符串（§4）。
5. **不提供 GUI 客户端。** 见 §9.5 与 `ATTRIBUTION.md` §2.3。
6. **不实现链上结算的端到端联调。** 合约已重写并有 Foundry 测试，
   但本机无 Solidity 编译器，**本地未编译**（见 §11 验证记录）。
7. **不实现真实的 LLM HTTP 调用。** `LlmProvider` 是端口，
   提供方以数据描述（base_url / 模型 / 上下文窗口 / 密钥环境变量名），
   测试用脚本化提供方；真实 HTTP 客户端留给调用方注入。
8. ~~**不迁移上游的历史数据。**~~ 身份层兼容（§4.1 的向量已证明），
   但存储格式与账本语义不同——**V1.1.1 起提供迁移工具** `crates/nau-migrate`（65 个测试）：
   金额按**十进制文本逐字节**转换（绝不经过 `f64`，无法精确表示则类型化拒绝并指名文件与字段），
   上游 `did:aip:` 签名用本项目规范化规则逐条验证，语义差异一律转成显式 `Finding`
   而不是静默强制转换。限制：只读 JSON/JSONL，**没有数据库读取器**；
   上游确实有 SQLite，但只写不读（`load_*` 零调用点）且没有任何账本/余额表，
   因此 JSON 工件才是唯一有语义效力的数据。测试夹具为**按审计结果建模**，非真实抓取。
9. **信誉衰减未实现。** 上游文档承诺 90 天半衰期而其市场实现没有时间输入（§9.6）；
   本版本不宣称衰减，除非有测试支撑。

---

## 11. 本项目的验证记录 / Verification performed on this rewrite

| 验证项 | 命令 | 结果 |
|---|---|---|
| 规范载荷 / DID / 签名跨实现一致 | `cargo test -p nau-core` | 见下方记录 |
| 上游向量逐字节兼容 | `node conformance/generate.mjs` → `cargo test -p nau-core --test conformance` | 签名 `e14d3f9e…da0e` **命中** |
| 生成器可复现 | `git diff --exit-code conformance/vectors.json` | CI 门禁 |
| Python SDK | `python sdks/python/run_tests.py` | 见下方记录 |
| JS SDK | `node sdks/js/test/run.js` | 见下方记录 |
| 经济与共识不变量 | `cargo test -p nau-ledger -p nau-consensus` | 见下方记录 |
| 存储往返 | `cargo test -p nau-store` | 见下方记录 |
| 传输与拓扑 | `cargo test -p nau-net` | 见下方记录 |
| 记忆与 MCP | `cargo test -p nau-agent -p nau-mcp` | 见下方记录 |
| 合约 | `forge build && forge test` | **本地未执行**（无 Solidity 编译器），由 CI 执行 |

> **注**：上游在同类机器上**无法完成编译**
> （`rustc-LLVM ERROR: out of memory`）。本项目通过**依赖裁剪**
> （纯 Rust，无 C 工具链依赖，无 libp2p/rusqlite/TLS 栈）
> 与 `.cargo/config.toml` 中的 `jobs = 2`、`debug = 0`
> 使其可在 16 GB 机器上构建与测试。这是本项目首个可验证的优势：
> **它能被构建，因此它的测试能被执行。**

---

## 12. 分支、标签与 PR 审计 / Branch, tag and PR audit

审计要求覆盖**每一个分支**，而不只是默认分支。本节记录对上游仓库托管状态的实际查询结果。

### 12.1 审计快照的有效性

| 项 | 值 |
|---|---|
| 默认分支 | `main` |
| 我的审计快照 | `main` 的 tarball，`gsn-core` 版本 **0.2.56** |
| 查询时 `main` 上 `gsn-core/Cargo.toml` 的版本 | **0.2.56** |
| 结论 | **快照与查询时的 main 一致**，本文档的行号引用未因上游提交而失效 |

（上游在审计期间仍有推送：`pushed_at` 为 2026-09-27T01:14Z。版本号未变，
说明推送是文档/CI 层面的改动，未触及本文档引用的源码行。）

### 12.2 分支清单（6 个）

| 分支 | 类型 | 相对 `main` 的改动 | 是否影响本次审计 |
|---|---|---|---|
| `main` | 默认分支 | — | **已全量审计**（648 文件） |
| `feat/gsn-daemon-real-network` | 功能分支（PR #8） | **已于 2026-09-23 合并进 main** | **否**：内容已在 main 中，已覆盖 |
| `dependabot/cargo/gsn-core/ed25519-dalek-3.0.0` | 自动依赖升级（PR #12，**未合并**） | `gsn-core/Cargo.toml` + `Cargo.lock`（2 文件） | 否：未进入 main |
| `dependabot/cargo/gsn-core/libp2p-0.57.0` | 自动依赖升级（PR #10，**未合并**） | 同上（2 文件） | 否 |
| `dependabot/cargo/gsn-core/rand-0.10.3` | 自动依赖升级（PR #11，**未合并**） | 同上（2 文件） | 否 |
| `dependabot/github_actions/actions/setup-node-7` | 自动依赖升级（PR #9，**未合并**） | `ci.yml`、`client-build.yml`、`publish.yml`（3 文件） | 否 |

**关于 `feat/gsn-daemon-real-network` 的说明**：对该分支与 `main` 做 compare 时
GitHub 返回 **404「No common ancestor between main and feat/gsn-daemon-real-network」**，
即当前分支尖端与 `main` **没有共同祖先**——分支在合并后被重写（force-push/重建）过。
但 PR #8 的状态是 **merged（2026-09-23T07:35:13Z）**，
因此**其内容已经进入 main**，本文档对 main 的全量审计已经覆盖它。
该分支尖端如今已不含被合并的文件（例如 `gsn-core/src/node.rs` 在该 ref 上返回 404），
所以不再有「分支上有、main 上没有」的代码。

### 12.3 PR 清单（12 个）

| 状态 | 数量 | 内容 |
|---|---|---|
| merged | 1 | #8 功能分支（真实网络节点 + JS SDK） |
| closed（未合并） | 7 | 全部是 dependabot 依赖升级（#1–#7） |
| open | 4 | #9 `actions/setup-node` 4→7；#10 `libp2p` 0.54.1→0.57.0；#11 `rand` 0.8.8→0.10.3；#12 `ed25519-dalek` 2.2.0→3.0.0 |

**观察（对重写的直接影响）**：上游**实际使用**的版本是
`ed25519-dalek 2`、`rand 0.8`、`sha2 0.10`（`gsn-core/Cargo.toml:28,36,37`），
而其**打开**的 PR 想把它们升到 `ed25519-dalek 3`、`rand 0.10`、`sha2 0.11`——
都是 API 破坏性升级。本项目的依赖 pin 与上游**实际使用**的版本一致
（见 `Cargo.toml` 的 `[workspace.dependencies]`），
因此重写所对照的行为基线是明确的；同时本项目的依赖面**刻意更小**
（无 libp2p / rusqlite / TLS 栈），不会继承这批升级的迁移成本。

另外 8 个依赖升级 PR 中有 7 个被**关闭而非合并**，4 个仍然打开——
即上游的依赖面处于持续漂移状态，这与本文档 §9.2 记录的
「CI 不拦截任何东西」相互印证。

### 12.4 标签与发布（各 12 个）

最新为 **v2.5.6**，与本文档审计的版本一致。存在 v1.0.0、v2.0.0–v2.5.6 的标签，
其中 `docs/version-checklist.md:159` 自述 v2.4.0–v2.4.5 等**未打标签**，
而 `README.md:276` 却称「已发布 2.4.0 ~ 2.5.6」——该矛盾已在 §9.6 记录。

---

*本文档的所有 `文件:行号` 引用均指向上游 `TwinsEarth/agent-universe` v2.5.6 的 `main` 分支。*
*由于上游持续演进，行号可能随其提交而变化；引用时的源码片段已在此逐条摘录，可据此定位。*
*§12 补充了非默认分支、标签与 PR 的托管状态审计（查询时间：2026-09-27）。*
