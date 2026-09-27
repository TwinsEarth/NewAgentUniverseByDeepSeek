# 技术架构 / Architecture — NewAgentUniverseByDeepSeek V1.1.1

本文档说明系统结构、分层与依赖策略，以及**为什么**与上游 v2.5.6 的架构不同。
逐条缺陷证据见 [GAP-ANALYSIS.md](GAP-ANALYSIS.md)，来源与保留项见 [../ATTRIBUTION.md](../ATTRIBUTION.md)。

---

## 0. 架构原则

| 原则 | 上游 v2.5.6 | 本项目 |
|---|---|---|
| **依赖方向** | 单 crate、31 个顶层模块互相引用 | 单向依赖 DAG；`nau-core` 不依赖任何 crate |
| **纯逻辑与 I/O 分离** | 领域逻辑直接 `std::time::now()`、`unwrap()`、读写 SQLite | `nau-core` 无 I/O、无 async、`#![forbid(unsafe_code)]`；时间与存储都是注入的端口 |
| **失败即类型** | 大量 `Result<_, String>`、以及返回 `bool` 的验证函数 | 单一 `NauError` 分类；验证返回 `Result`，避免布尔被忽略 |
| **货币** | `f64` + 容差守恒 | `Money(i64)` 整数最小单位 + 精确相等 |
| **确定性** | `HashMap` 迭代序泄漏到 API 输出与拓扑 | 用户可见的序列一律 `BTreeMap`/显式排序 |
| **调试信息量** | 8 个 `SystemTime::…unwrap()` panic 路径 | `Clock` 端口；`SystemClock` 饱和不 panic |

**依赖裁剪的硬理由**：上游的依赖树包含 `libp2p 0.54` + `rusqlite(bundled)` + TLS 栈。
在 8 核 / 16 GB 机器上以 cargo 默认 8 路并行编译时，
本项目审计过程中**实际复现**了：

```
rustc-LLVM ERROR: out of memory
Allocation failed
process didn't exit successfully: rustc.exe ... (exit code: 0xc0000409, STATUS_STACK_BUFFER_OVERRUN)
```

即**上游无法在本机编译**，因此其测试也无法执行。本项目改为纯 Rust 依赖树
（无 C 工具链需求），并在 [`.cargo/config.toml`](../.cargo/config.toml)
设置 `jobs = 2`、`debug = 0`，使构建与测试可在 16 GB 机器上完成。
**能被构建，测试才能被信任**——这是本项目相对上游的第一个可验证差异。

---

## 1. 分层与 crate 图

```
                         ┌──────────────────────────────┐
                         │          nau-node            │  组合根
                         │  HTTP API · daemon · CLI     │
                         └───────┬──────────┬───────────┘
                                 │          │
              ┌──────────────────▼──┐   ┌───▼──────────────┐
              │     nau-market      │   │    nau-mcp       │
              │ 注册/匹配/生命周期   │   │ 工具协议/校验     │
              └──┬────────┬─────────┘   └───┬──────────────┘
                 │        │                 │
     ┌───────────▼──┐  ┌──▼───────────┐  ┌──▼──────────────┐
     │  nau-ledger  │  │ nau-consensus│  │   nau-agent     │
     │ 托管/罚没/守恒│  │ BFT-lite 投票 │  │ 记忆/LLM 端口    │
     └───────┬──────┘  └──────┬───────┘  └──┬──────────────┘
             │                │             │
             └────────┬───────┴─────────────┘
                      │
              ┌───────▼────────┐   ┌────────────────┐
              │    nau-store   │   │    nau-net     │
              │ 持久化端口      │   │ 传输/拓扑/中继  │
              └───────┬────────┘   └───────┬────────┘
                      └────────┬───────────┘
                               │
                      ┌────────▼────────┐
                      │    nau-core     │  ← 冻结契约
                      │ DID·规范JSON·Money│   无 I/O，无 async
                      └─────────────────┘
```

**端口 / 适配器（hexagonal）**：

| 端口 | 真实适配器 | 测试适配器 |
|---|---|---|
| `nau_store::Store` | `FileStore`（追加 JSONL + 原子快照） | `MemoryStore` |
| `nau_net::Transport` | `TcpTransport`（真实 socket，4 字节长度前缀分帧，帧长上限，读超时） | `MemoryTransport` |
| `nau_agent::LlmProvider` | 由调用方注入（`ProviderProfile` 描述端点/模型/上下文窗口） | `ScriptedProvider` |
| `nau_core::Clock` | `SystemClock` | `ManualClock` |

**命名纪律**：上游把三个内存 mock 命名为
`net/dht.rs::KademliaClient`、`net/gossip.rs::GossipSub`、`net/libp2p_node.rs::GsnNode`，
并在 `lib.rs:44` 从 crate 根再导出，于是集成测试对着 `HashMap`
「证明」了联网能力（GAP-ANALYSIS §5.1）。
本项目**禁止**测试替身与网络服务同名——`MemoryTransport` 的名字即表明它是替身。

---

## 2. 身份与规范签名（`nau-core`）

### 2.1 DID

```
did:nau:<SHA-256(原始 32 字节 Ed25519 公钥) 的前 8 字节，小写十六进制>
```

`Did::parse` **同时接受** `did:aip:`（上游前缀，常量 `DID_PREFIX_LEGACY`），
因此上游铸造的身份可迁移后继续验证。`Did::matches_public_key`
提供指纹绑定校验，`verify_payload_bound` 在验签时强制执行它——
**攻击者不能用自己的公钥冒用他人的 DID**。

`PublicKey::from_hex` 调用 `ed25519_dalek::VerifyingKey::is_weak()`
拒绝小阶点（含全零的恒等点编码）。这是上游没有的加固。

**已知限制（诚实记录）**：8 字节指纹意味着约 2³² 量级的生日碰撞可行性。
保留它是因为**兼容性优先**；比上游更宽的指纹（完整 SHA-256 + multibase）
列入后续工作，届时将需要一次显式的协议版本升级（`PROTOCOL_VERSION = "nau/1"`）。

### 2.2 规范载荷

完整规则见 [CONFORMANCE.md](CONFORMANCE.md)。要点：

1. 根必须是 JSON 对象；
2. **任意深度**删除 `signature` 键（上游只删顶层）；
3. 键按 **Unicode 码点**升序（JS 默认 `sort()` 按 UTF-16 码元，对星平面不一致）；
4. 无空白，分隔符恰为 `,` 与 `:`；
5. 字符串为原始 UTF-8，仅转义 `"`、`\` 与 7 个短控制转义，其他控制字符用**小写** `\u00xx`；
6. **数字必须是整数**，浮点/指数/越界一律拒绝；
7. 嵌套深度上限 64；
8. 序列化失败**报错**，绝不退化成签名 `null`。

### 2.3 签名结构

`Task` / `Bid` / `ResultEnvelope` / `Dispute` / `DisputeOutcome` / `AgentCard`
一律内嵌 `signer` + `signer_key` + `nonce` + `signed_at`（+ 可选 `expires_at`），
统一实现 `Verifiable`：

```rust
fn verify(&self) -> Result<()>                       // 签名 + DID↔公钥绑定
fn verify_fresh(&self, now: u64) -> Result<()>       // 再加过期与时钟偏移（±300s）
```

`NonceGuard` 按 DID 记录已见最大 nonce，拒绝重用与回退——**上游无任何 nonce**。
时间通过 `Clock` 注入，使过期语义可确定性测试。

---

## 3. 账本与守恒（`nau-ledger`）

* 金额是 `Money(i64)`，最小单位 10⁻⁶。**无浮点**、**无 epsilon**。
* 记账是双入式的：每个变更都产生一条 `LedgerEntry`，
  同时在同一方法内更新派生计数器（保证不变量由构造成立）。
* **托管**：`escrow(task, payer, amount)` 把预算锁进 `__escrow__:<task>` 命名空间账户；
  `release` 付款给执行者；`refund` 退回。余额不足返回 `InsufficientBalance`——
  **绝不创建资金**（上游在余额不足时 `deposit` 造钱）。
* **两个守恒视图**：
  * `conservation()` 是 O(1)，读增量计数器；
  * `audit()` 是 O(N)，**重新遍历每个账户并重算全部条目**。
  上游有等价的 `audit_full_scan` 但**零调用点**，且其 O(1) 检查比较的是
  「三个总是一起更新的计数器」，因此在结构上无法失败。
  本项目把 O(N) 审计提升为一等 API，并**用测试证明它能检测到 O(1) 检测不到的损坏**。
* 罚没只能作用于存在的余额，且非正数额度在任何变更方法上都被拒绝
  （上游接受负数：`deposit(-1000)` 会给账户**加钱**且守恒仍报 true）。

---

## 4. 共识（`nau-consensus`）

BFT-lite 的**参数与规则**取自上游（`n ≥ 3f+1`、`q = 2f+1`、
equivocation 整轮作废、`silence > f ⇒ NoQuorum`），但**认证与成员集是新增的**：

```rust
let spec = CommitteeSpec::new(3, 0)?;               // checked 算术
let mut committee = Committee::assign(spec, task_id, members)?;  // 强制 members.len() == n
for vote in signed_votes { committee.cast(vote, now)?; }         // 验签 + 成员资格
let tally = committee.tally();                                   // 带 reason/equivocators/safety_violation
```

修复的上游缺陷：

| 上游 | 本项目 |
|---|---|
| 调用方提供 `approvals`/`committee_size`，服务端合成委员与票 | 票是**签名的**；成员集在 `assign` 时固定 |
| `n` 无约束力；`new(3,0)` + 1 票即可决定 | 强制 `members.len() == n` 且去重 |
| `3*f+1` / `2*f+1` 未检查 `u32`，release 下回绕 | `checked_mul`/`checked_add` |
| 无 `safety_violation`（文档承诺但缺失） | 双方同时达到法定人数 ⇒ `SafetyViolation` + `ConflictingQuorums` |
| equivocation 只留 bool，无法归责 | `TallyResult::equivocators: Vec<Did>` |
| `reset_votes()` 无生产调用者，「view change」不存在 | `reset_for_next_round()` 递增轮次、清票、**保留** equivocation 记录 |

---

## 5. 市场（`nau-market`）

### 5.1 状态

单一 `Market` 独占全部状态（`BTreeMap`，保证输出顺序确定）。
上游的 actor 独占模型（`mpsc` + `oneshot`）是**正确的**，本项目保留该思想；
但上游的 `verify_result` 没有任何状态前置条件，且 `settle_task` 与
`arbitrate` 无授权，使 actor 的原子性无法阻止重放。

### 5.2 每个变更方法的六步纪律

1. **load** — 不存在返回 `NotFound`；
2. **authorize** — 验签 + DID↔公钥绑定；
3. **anti-replay** — `nonce` 必须严格递增；
4. **validate** — 实体自身不变量；
5. **transition** — 经 `TaskState::transition` 的完备转移表；
6. **mutate** — 与账本写入在同一次调用内完成，避免资金与状态漂移。

### 5.3 匹配（`matching.rs`）

分数是整数：`reputation_bps × 1e6 / price_minor`，再乘延迟惩罚（bps）。
延迟惩罚衡量的是**该 agent 自己承诺的 p95**——
上游用魔法常量 `2000.0` 作分母（`marketplace/mod.rs:368-370`），
使「承诺 200 ms」与「承诺 10 s」的 agent 被同等对待。

排序是**全序**：`(score desc, price asc, eta asc, did asc)`。
上游用严格 `>` 比较 `f64`，因此平局由**到达顺序**决定；
且出价 `≤ 0` 时评分退化为「仅信誉」，使零价出价**既中标又拿走全额预算**。

### 5.4 生命周期

```
Open ──match──▶ Matched ──start──▶ Running ──submit──▶ Submitted
                                                          │
                                                    verify (签名投票)
                                                          │
                    ┌─────────────────────────────────────┼──────────────┐
                    ▼                                     ▼              ▼
                 Accepted ──settle──▶ Settled          Rework        NoQuorum
                                                       │              │
                                                       ▼              ▼
                                                    Running         Open   ← 上游缺失的恢复边
```

`Accepted → Settled` 需要结果通过 `validate_for_settlement()`，
即**证据分级真的作为闸门**（上游定义了该谓词并注明「用于结算门禁」，却零调用点）。

### 5.5 信誉（`reputation.rs`）

四维、整数 bps、整数指数平滑（α = 1/10）。
上游有**三套**互不调和的信誉实现（权重分别是 0.35/0.20/0.30/0.15、
0.25/0.15/0.40/0.20，以及一个 `u16` 分数），其中只有一套接入匹配且**没有时间输入**，
却在文档里承诺 90 天半衰期；另外其 `reward_honesty()` 在每次结算时触发，
使诚实分在约 10 次任务后饱和——变成任务计数的函数而非行为的函数。

本项目：诚实分**只**因罚没与「无过错确认」而变动，结算**不会**抬升它；
失败调用不会抬高成功率（上游的成功率公式缺 `else` 分支，失败反而抬高记录值）。

---

## 6. 存储（`nau-store`）

`Store` 端口 + `FileStore`（追加 JSONL × 3 + `meta.json` 原子替换）与 `MemoryStore`。

* 每条记录带 `"v": 1` schema 标记；
* **被截断的末行**（模拟崩溃）在加载时跳过并告警，而不是让整个加载失败；
* 同一 id 后者覆盖前者，`load_*` 只返回最新一条；
* `compact()` 写临时文件 → fsync → rename，保证崩溃安全。

上游的存储是**只写不读**的：`load_agents`/`load_tasks`/`upsert_task`
在 `gsn-core/src` 中零调用点，账本表根本不存在；
唯一的持久化钩子重新解析原始 HTTP body，因此存储值与校验后的值会漂移
（`skills` 有损 `join(",")`、`reputation` 硬编码 `0.0`、`created_at` 重新生成）。
本项目要求「drop 后重新 open，字段逐一相等」的往返测试。

`Market::restore` 会**重放账本日志**（按 `EntryKind` 分派到公开 API），
使余额在重启后精确恢复——上游重启后 `conservation_check()` 返回
`0 = 0 − 0` 的**空洞真**，而 API 同时报告「已恢复 N 个 agent」。

---

## 7. 网络（`nau-net`）与「明确不实现」

提供：
* `Transport` 端口；`TcpTransport` 是**真实**的（bind/connect、4 字节大端长度前缀、
  8 MiB 帧长上限（超限报错而非分配）、读超时），并有双端点互发测试；
* `LayeredTopology` Lv1–Lv7：房间归属是节点 id 的**纯确定性函数**
  （与插入顺序无关）、`fanin_of` **包含上行边**、
  `route_hops` 从实际树结构推导（**绝不返回常量**）、未知节点返回 `None`；
  以「同一 id 集合两种插入顺序 ⇒ 完全相同的归属/边数/跳数」和
  「测量 `edges(2N)/edges(N)`」来验证，而不是上游那种不可能失败的
  `edges < n*n/100` 断言（GAP-ANALYSIS §5.2、§5.3）；
* `RelayPool`：容量在插入的同一调用内强制；健康与失败计数**只能**由
  `record_failure`/`record_success` 改变（上游重新添加会重置它们，使 dead 中继复活）；
  选择顺序确定（分类优先级 → `fail_count` → id）。

**不实现**（也不宣称）：Kademlia DHT、GossipSub、Circuit Relay v2、AutoNAT、DCUtR、
TEE/zkML 验证。（**V1.1.1 更新**：NAT 类型检测与纠删码已实现，见下节 §7.1；本节其余内容与 Kademlia/GossipSub/Relay v2/AutoNAT/DCUtR 仍成立。）理由与上游对应缺陷见 README 与 GAP-ANALYSIS §10。
### 7.1 V1.1.1 更新：上面这份「不实现」清单已部分过时

* **NAT 类型检测：已实现。** `nau-net::stun` 是真实的 RFC 5389 编解码器，
  `nau-net::nat` 实现 RFC 4787 的映射/过滤行为分类（纯函数 + `NatProbe` 端口）。
  对本地 STUN 服务器实测，`nau-net` 97 个测试通过。
  仍然**不宣称**真实 NAT 类型：那需要可达的公网 STUN 服务器，不可达时返回 `Unknown`。
* **纠删码：已实现且测试通过。** GF(256) 上的系统化 Reed-Solomon，采用生成多项式/余式构造，
  `cargo test -p nau-erasure` 82 个单元测试 + 9 个文档测试全部通过（穷举 504 个擦除子集）。
  **纠错不在实现范围内**：损坏但未被声明为丢失的分片会静默产生错误数据，需要上层校验和。
* **真实 LLM HTTP：已实现。** `nau-http` 提供真实 HTTP/1.1；`nau-agent` 的
  `HttpProvider` 按提供方形状构造请求并解析响应，空补全是类型化错误而非 panic。
  TLS 可编译但未经测试执行，未启用时不静默降级。
* **GUI：已实现浏览器客户端（端到端实测）**，Tauri 外壳仅源码。
* **libp2p 网络栈：已实现。** `crates/nau-libp2p` 把 TCP + Noise + Yamux + Kademlia +
  GossipSub + Circuit Relay v2 + AutoNAT + DCUtR 组合进真实 swarm，并适配到
  `nau_net::Transport` 端口；88 个测试通过，含真实多节点投递与 relay reservation。
  **DCUtR 打洞与 AutoNAT 可达性未验证**（环回场景下这类测试不测任何东西也会通过）。
  为守住 MSRV 1.85 裁掉 `dns/quic/tls/websocket`：**没有 QUIC、没有 DNS 解析**。
* **TEE/zkML：部分实现，且刻意标注边界。** `crates/nau-attest` 验证信封结构、固定根签名、
  nonce 绑定、新鲜度与 payload 绑定；**四种格式全部返回 `ChainNotImplemented`**，
  `HardwareAttested` 不可达。Merkle 包含证明真实，但**非零知识、不简洁、不证明计算正确**。
* **上游数据迁移：已实现。** `crates/nau-migrate`，65 个测试；金额按十进制文本精确转换，
  无法精确表示则拒绝；只读 JSON/JSONL，**没有数据库读取器**。
* **到此，§7 开头的「不实现」清单已全部清空。** 剩下的是各项**内部的**边界，
  例如没有证书链、没有证明系统、没有 QUIC/DNS、没有真实网络下的打洞验证——
  它们写在每项旁边，而不是汇总成一句「已实现」。



---

## 8. MCP（`nau-mcp`）

**单一事实来源**：每个工具只定义一次（名称、描述、带类型的参数列表、处理器），
JSON Schema **由该定义派生**，参数在分发前**按声明类型校验**，
失败返回 `-32602` 并指名参数。

上游 `market_tools.rs:24-71` 声明工具、`:74-123` 用另一个手工 `match` 分发，
两者可漂移且 schema 从不校验；所有参数读取都带宽松默认
（`unwrap_or(0.0)`/`unwrap_or("")`/`unwrap_or(false)`），
于是 `market_deposit(amount: "lots")` **静默存入 0**。

其它修复：`RequestId` 含 `Null`（上游用 `id: 0` 表示解析错误，违反 JSON-RPC）；
未知工具返回 `isError: true` 的**工具结果**而非协议错误；
`initialize` 解析并回显受支持版本，未初始化请求返回 `-32002`；
阈值类参数（`approvals`/`committee_size`）在本 crate 的工具面中**不存在**。

---

## 9. 版本一致性

版本有**唯一**机器可读来源：仓库根 `VERSION`。
Cargo 工作区、Python SDK（`sdks/python/nau_sdk/version.py`）与
JS SDK（`sdks/js/lib/version.js`）都**读取**它而非重述，
`crates/nau-core/tests/version_consistency.rs` 断言其一致，
并断言**任何 crate 都不得声明字面版本**。

上游用手工登记表 + `sed` 脚本管理 14 个以上的版本点，
审计发现实际已漂移 6 处（Python 三处、两个 `index.html`、`desktop/README.md`），
因为登记表本身漏掉了这些文件，且 `bump-version.sh` 的 `sed` 无匹配时静默退出 0。

---

## 10. 后续工作

1. 更宽的 DID 指纹（≥128 位）与对应的协议版本升级。
2. 真实传输适配器（若需 libp2p 互操作，作为 `Transport` 的独立适配器 crate，
   保持默认构建轻量）。
3. 账本日志的压缩与检查点（当前 `persist` 追加全部条目）。
4. 合约的链上部署与端到端联调（合约已重写并有 Foundry 测试，本机无编译器）。
5. SDK 的 REST/MCP 客户端与 `nau-node` 的契约测试（当前各自有 stub 服务器测试）。
