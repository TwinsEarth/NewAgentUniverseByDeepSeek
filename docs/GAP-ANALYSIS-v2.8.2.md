# v2.8.2 增量审计 / Gap Analysis — upstream `agent-universe` v2.8.2 → NewAgentUniverseByDeepSeek V1.2.3

本文是 [`GAP-ANALYSIS.md`](GAP-ANALYSIS.md)（对上游 **v2.5.6** 的 76 条缺陷审计）的**增量续篇**。
它只回答两个问题：

1. 上游从 v2.5.6 迭代到 **v2.8.2** 之后，那 76 条缺陷**是否真的修掉了**？
2. v2.8.2 新增的代码里，**新出现了什么**？

---

## 0. 方法与边界（先说清楚，因为它决定了结论的可信度）

| 项 | 值 |
|---|---|
| 审计对象 | `TwinsEarth/agent-universe` **v2.8.2**（根 `VERSION` = `2.8.2`，`gsn-core` = `0.2.82`） |
| 规模 | **675 文件 / 314.5 MB**；Rust **153 文件 / 21,530 行**（v2.5.6 时是 15 文件 / 15,735 行） |
| 方法 | **纯源码阅读 + 调用点 grep + 测试名映射** |
| 未做 | **没有编译、没有运行上游任何代码**。上游 `cargo test` 在本机无法编译（其依赖树 `libp2p 0.54 + rusqlite bundled + TLS` 在 8 核 / 16 GB 上 OOM，见 v2.5.6 审计 §0） |
| 因此 | 一切**运行时可观测**的结论都标注 `unverified`；其余结论都是对代码文本的判断，随附 `文件:行号` 供任何人复核 |

**本审计遵循两条自定规则，它们直接决定了很多条目的判定：**

* **「没有调用点的修复不算修复。」** 一个类型/函数只要在生产代码里零调用，它就没有改变任何行为。
* **「在修复前的代码上也能通过的测试，什么也没证明。」** 对每一条「已修复」声明，都检查那个被指名的测试是否真会在旧实现上失败。

---

## 1. 最值得记录的事实：上游把本项目的审计当成了修复路线图

`grep 'GAP §'` 在上游 `gsn-core/src` 中命中 **52 处**。上游的 `CHANGELOG.md` / `RELEASES.md` 逐条引用本审计的章节号：

| 上游版本 | 上游自述 | 引用 |
|---|---|---|
| v2.5.8 | 修复：精确整数账本（Money），根治 f64 跨语言守恒失效 | GAP §2.1–2.3 |
| v2.5.9 | 修复：认证式 BFT、可失败独立审计、重放保护 | GAP §2.4/§2.5/§3.1/§4.7 |
| v2.6.1 | 修复：账本落盘与重放恢复、MCP 参数校验 | GAP §6.1/§8.1 |
| v2.6.2 | 修复：版本唯一来源、合约可部署、纠删码真修与网络替身诚实化 | GAP §9.3/§9.4/§5 |
| v2.6.4 | 共识/身份签名加固：BFT checked 算术 + 规范签名 Result 化 + 时钟端口 + 弱公钥拒绝 | GAP §3.3/§3.6/§4.2–§4.9 |
| v2.6.7 | 记忆层加固：真 SHA-256 链存载荷 + 真 LRU + 派生质量防污染 + 盲猜死循环 | GAP §7.1–§7.4/§7.7 |
| v2.6.8 | MCP 认证闸门与 LLM 去 panic | GAP §7.5/§8.3/§8.4/§8.5/§8.8 |
| v2.6.9 | 文档/测试一致性：停止过度承诺 | GAP §5.1/§7.6/§8.6/§9.6/§9.7 |
| v2.7.2 | NAT 占位检测不再猜测类型 | GAP §5.6 |

**这使审计的性质发生了变化**：从「重新发现缺陷」变成「**核实修复声明是否成立**」。
而对声明的核实，结果比「是否修复」本身更有信息量——见下节。

---

## 2. 对 v2.5.6 缺陷的裁定（逐条）

裁定分四类：**已修** / **部分修复**（说明剩下什么）/ **未修** / **声明不被代码支持**。

### 2.1 判定为「真的修了」的（这些必须保住，不许回退）

| 缺陷 | v2.8.2 证据 |
|---|---|
| **f64 金额 + 容差守恒**（§2.1–2.3） | `marketplace/money.rs:21` `pub struct Money(pub i64)`（`#[serde(transparent)]`）；`settlement.rs:364-378` 全量重扫 + **精确相等** `sum == expected`；**无 `abs()`、无 epsilon、无 f64**。铸币路径全部封死（`mod.rs:214-230` 托管、`:168-184` 质押自付、`:626-633` 结算只从托管付款） |
| **无法失败的独立审计**（§2.4） | `settlement.rs:396-460` `independent_audit()` 只重放只追加日志，按账户比对**重放集与当前集的并集**，因此「自洽但未入账」的变动会被抓到 |
| **`route_hops` 常量 7**（§5.2） | `topology/layer.rs:154-178` 真实求 LCA，`Level::depth()` 只作循环上界；测试 `layer.rs:253-270` 断言 1/2/4/None |
| **边数测试不可能失败**（§5.3） | `layer.rs:217-230` 现在 10k vs 20k 对照，断言 `ratio < 2.5` |
| **房间分配不确定 / O(depth·N)**（§5.4） | `members: BTreeSet`、`room_of_rank = rank / fanout`、`join` 单次 `insert`；`layer.rs:232-251` 正序与逆序构建 500 个 id 断言结果相同 |
| **假 SHA-256 哈希链**（§7.1） | `memory/layered.rs:19-25` 真 SHA-256；载荷被保留（`:61`）；`:100-112` 重算整链并报出**首个**断链索引；对抗性测试 `layered.rs:142-151` 断言 `Err(1)` |
| **假 LRU（实为 LFU）**（§7.2） | `memory/enhanced.rs:57-71` 按 `last_used` 淘汰；测试 `enhanced.rs:119-140` 明写「在 LFU 规则下本测试会失败」 |
| **`blind_attempt` 死循环**（§7.7） | `swarm/memory.rs:161-171` 加入 `tried.len() >= choices` 逃逸与 `choices == 0` 早返回 |
| **纠删码真修**（§7.8） | `erasure/mod.rs:75-99` 真的调用 `self.rs.reconstruct(...)`，按 index 摆放存活分片、**数据片与校验片同等对待**，之后才取前 `data_shards` 拼接；依赖 `reed-solomon-erasure 6.0.0` 真实存在 |
| **网络替身诚实化**（§5.1 前半） | `GsnNode/KademliaClient/GossipSub` 三个旧名在整个 `src/`、`tests/`、`README.md`、`js/` 中**零命中**；替换为 `memory_node/memory_dht/memory_gossip`，每个文件首行写明「**这不是真实 Kademlia DHT / GossipSub / libp2p 节点**」 |
| **账本落盘与重放**（§6.1） | `storage/persist.rs:104-107` 建了 `ledger_entries` 表；`:393-401` 追加；`api/market_actor.rs:218-227` 启动时读回并 `restore`；`load_agents`/`load_tasks` 终于有真实调用点（`:230-245`）。锁毒化用 `unwrap_or_else(|e| e.into_inner())` 处理 |
| **MCP `id: null` / 未知工具 / 握手** | `protocol.rs:11-16` 加 `Null` 变体；未知工具返回 `isError: true`（`sse.rs:134-140`）；`-32002` + 握手状态（`server.rs:110-112,147-159`） |
| **MCP 动钱工具无认证**（§8.8） | `sse.rs:48-65` Bearer 校验；**未配置 token 时 15 个动钱/执行工具默认拒绝**（`sse.rs:106-120,168-187`）。这是真正的 fail-closed 默认值，应予肯定 |

### 2.2 判定为「**声明不被代码支持**」的（最重要的一类）

这类条目才是本次审计的主要产出：上游声称修了，代码没有。

| 上游声明 | 实际情况 | 证据 |
|---|---|---|
| v2.7.2「NAT 占位检测不再猜测类型」 | **只是把骗人的常量换成了诚实的常量**。`detect_nat_type` 返回 `Unknown`，但 `gather_candidates` 仍是「占位：不查询网卡/STUN」返回空列表，`connect` 仍无条件置 `Connected`，模块仍带 `#[allow(dead_code)]` **无任何调用点**。真正对外回答 NAT 的是 libp2p AutoNAT。而且守护进程的测试断言是 `assert!(!topo.nat_type.is_empty())`——**任何新的编造值都能通过** | `nat/mod.rs:98-117`、`nat/mod.rs:60`、`mesh/mesh.rs:263`、`net/peer.rs:440-446` |
| v2.6.2「纠删码真修……数据片丢失可靠校验片真实重建」 | **实现是真的，但被指名证明它的那个测试什么也没测**：`tests/v232_test.rs:382-396` 名为 `test_erasure_recover_from_parity`，注释写「所有 data shards 可用时可正常解码」，代码 `coder.decode(&shards, …)` **把 6 个分片全部交回**——正是 v2.5.6 被批评的那个手法，仍然存在、仍然绿。真正做恢复的测试在 `integration_test.rs:92-118`（真的丢掉 2 个数据片），却**没有被这条声明引用** | `CHANGELOG.md:200` vs `v232_test.rs:382-396` vs `integration_test.rs:92-118` |
| v2.6.4「时钟端口……消除八处 panic 路径」 | **至少十条仍在**，其中三条就在被点名的文件里：`marketplace/reputation.rs:226-231` 仍 `.unwrap()`；另有 `economy/reputation.rs:40,65,79,91`、`economy/contribution.rs:67`、`topology/neighbor.rs:33,51`、`swarm/consensus.rs:58`、`agent/task.rs:42`、`ffi/uniffi.rs:19` | 各处 |
| v2.6.4「弱公钥拒绝」 | `identity/did.rs:78-91 is_weak_pubkey` **零非测试调用点**。`register_agent` 不调它、`parse_committee_members` 不调它、`AcaProcessor::register_peer` 不调它 | grep 仅定义与其自身测试 |
| v2.6.4 §3.6「贡献验证带签名身份」 | 签名确实覆盖 `hash‖verifier_did`，但 **DID 没有绑定到公钥**：`verify_contribution_signed(hash, verifier_did, verifier_pubkey, sig)` 从不校验 `Did::fingerprint(pubkey) == verifier_did`（对比 `aca/runtime.rs:183-194` 就校验了）。于是一把密钥可用伪造的不同 DID 反复验证同一贡献，**绕过去重** | `proof/poc.rs:97-123` |
| v2.6.3「终局拒绝与重复劳动可达」 | 只有 `DuplicateWork` 可达（自动、内容哈希 `mod.rs:383-411`）。`reject_task` **零生产调用点**（REST 路由表无、`MarketCommand` 无、MCP 无），唯一调用者是 `tests/v234_test.rs:864`，因此 `SettlementReason::Rejected` 只能由库调用触达 | `mod.rs:533-553`、`rest.rs:325-345`、`market_actor.rs:100-156` |
| v2.6.6 「persist.rs 22 处 `.lock().unwrap()` 改 `into_inner()`」 | 改写是准确的，但 `into_inner()` 恢复意味着**毒化后继续使用可能处于半写状态的内部结构，且没有任何日志**——把 panic 换成了静默不一致 | `persist.rs:118` 等 |
| v2.6.0「证据分级结算闸门」 | 闸门存在，但 **`independent_audit` 的信任根（账本日志）没有任何完整性保护**（见 §3.1） | `settlement.rs:390-399` |

### 2.3 判定为「仍未修复」的

| 缺陷 | 现状 |
|---|---|
| **§5.5 中继池**：容量检查仍是「先读后写」且是唯一闸门；`ensure_channels` 完全不检查容量；**健康统计在重新添加时被覆盖**（`persist.rs:253-258` `ON CONFLICT … healthy = excluded.healthy, fail_count = excluded.fail_count`），`AddRelay` 以 `healthy: false, fail_count: 0` 重建 → **已死中继可被复活**；15 秒探测超时仍会被记为**中继故障** | `node.rs:663-671`、`persist.rs:247-258,341-358` |
| **§5.7 Mesh**：`LocalSniffer` 仍是空操作（`mesh/discovery.rs:93-97` 只 `scan_count += 1`）；`MeshNode` **零调用点**；会话 code 仍由**调用方提供**（`mesh/session.rs:51-55`），而文档说「随机生成」 | 各处 |
| **§5.8 `ModeController`/`NodeMode` 惰性** | `mode/mod.rs:51-54 switch_to` 无条件 `Ok(())`；`NodeMode` 在 `node.rs`/`rest.rs` 零使用——**运维选择的模式不控制任何东西** |
| **§5.9 硬编码第三方 bootstrap** | 从字面 IP 改为字面 `/dnsaddr/…`（`net/peer.rs:418-437`），**仍然无条件内建第三方联系人** |
| **§5.1 数据面**：`PeerEvent::Gossipsub` **仍无消费者**——变体定义在 `net/peer.rs:55-59`，守护进程事件分支（`node.rs:496-528`）从不处理它，gossip 消息被丢弃 | `node.rs:496-528` |
| **§7.3「不可由发布者谎报」** | 机制改为从成败次数派生质量（真的改了），**但次数本身仍由发布者提供**：`SharedEntry::new(agent_id, task_key, strategy, successes, failures)`，传 `(10_000, 0)` 就能赢 `max_by_key`。准确表述应是「不能谎报权重，仍可谎报结果」。且 `EnhancedMemory::shareable` 仍无调用点，防污染谓词与共享库**并未连接** | `shared_memory.rs:26-44,60-80` |
| **§9.6 信誉半衰期 90 天** | `marketplace/reputation.rs:4` 仍如此声明，而 `MarketReputation` **完全没有时间输入**（`:27-86`）；`StakeStatus::{Withdrawing, Withdrawn}` 全库零引用，**仍无退出/解押路径** |
| **§8.6 SSE 不是流** | 未修，仅新增了诚实注释（`sse.rs:7-10` 承认 `handle_get` 只发一帧） |
| **§8.7 `list_changed` 序列化** | `protocol.rs:293-296` 缺 camelCase rename，仍存在（潜伏） |

### 2.4 判定为「**部分修复**」的（剩下什么，逐条说清）

* **§2.5 调用方指定委员会 → 部分修复。** 服务端不再**合成**委员与票（`approvals`/`committee_size` 已删除），但**委员会成员及其公钥仍完全由请求体提供**：`api/rest.rs:405-431` 从 body 解 `{did, public_key}`，`qa_committee.rs:159-177 with_fixed_members` 唯一的校验是 `members.is_empty()`，然后 `let f = (n-1)/3;`。没有注册表、没有质押/信誉门槛、不检查成员是否为请求者本人、不校验 DID↔公钥绑定。于是「认证式」只意味着**已签名**，不意味着**已授权**：请求者自造 3–4 把密钥、贴上名字、给自己的任务签 Stop 票，服务端拿请求者自己的密钥验签通过。
  **上游自己的测试证明了缺陷而不是否认它**：`tests/v235_test.rs:186-202` 在客户端内 `Keypair::from_seed` 造出委员会，然后断言 `body["accepted"] == true`。
  并且 `mod.rs:462-468` 在 Stop 决策时把结果信封的 `evidence_grade` 提升为 `Verified`——**而那是 `settle_task` 的闸门**，所以自造的票可以直接解锁付款。
* **§4.1 跨语言浮点签名 → 部分修复（等于未修）。** `Money` 全程整数了，但 `aca/receipt.rs:26-33` **仍然持有 `bandwidth_mb: f64` / `energy_joules: f64`**，规范化（`aca/crypto.rs:46-50`）**不排除任何非整数**，主路径 `aca/runtime.rs:351-357` 用 `..default()` 把这两个 `0.0` 带进被签名的载荷。三端今天对同一个默认值就发出**不同字节**：Rust `0.0` / Python `0.0` / JS `0`。唯一的跨语言固定向量（`cross_lang_signature.rs:21-22`）**不含小数**，所以 CI 看不见——与 v2.5.6 §4.1 指出的盲区完全一致。
* **§6.1 存储只写不读 → 部分修复，但引入了更严重的新缺陷**（见 §3.1、§3.2）。

---

## 3. v2.8.2 新增代码里的**新缺陷**

这一节是本文相对 v2.5.6 审计的增量主体。**新代码带来了比它修掉的问题更严重的缺陷。**

### 3.1 【critical】账本日志没有任何完整性保护 → 让「守恒」与「独立审计」同时失效

上游的 `independent_audit` 明确声明它**只信任只追加、不可变的 `records`**（`marketplace/settlement.rs:390-399`）。然而这张表的定义是：

```sql
-- storage/persist.rs:104-107
(seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL)
```

**没有哈希链、没有签名、没有校验和、没有 SQLite trigger、没有约束。** 任何能写这个数据库文件的人（或任何未来的 bug）插入一行 `SettlementReason::Deposited`，`SettlementEngine::restore` 与 `independent_audit` **都会报告 `passed: true, conserved: true`**——凭空的货币被判定为守恒。

上游的审计测试改的是**内存里的余额表**（`settlement.rs:539-557`），**从不改持久化日志**，所以没有任何测试能发现这件事。

**与 V1.2.3 的关系**：这正是本项目自己在 V1.1.1 里修过的同一类缺陷（`Market::persist` 重复追加整个日志 → 重启造币）的**上一层版本**。V1.2.3 的对策是给日志加**哈希链 + 锚定 head**，把「守恒」和「审计」建立在可检测篡改的证据上，而不是建立在「假设文件没被动过」上。

### 3.2 【critical】重启会静默关闭证据闸门

```rust
// marketplace/mod.rs:909-933  restore_tasks_from_store
verification_policy: VerificationPolicy::None,   // :926
winner_price: None,                              // :923
```

而结算是这样把关的：

```rust
// marketplace/mod.rs:610
if !matches!(task.verification_policy, VerificationPolicy::None) { /* 证据等级检查 */ }
```

于是**每一个从磁盘恢复的任务都自动豁免证据闸门**，并按 `winner_price.unwrap_or(budget)` 付**满额预算**。**「重启守护进程」本身就是一条绕过路径。**

同一层的另外三条（同样 critical/high）：

* **结果信封从不落盘**，而结算要求它存在（`mod.rs:611-613`）→ 关机时处于「已验收未结算」的任务**重启后永远无法结算**。
* **信誉与质押从不落盘**（`mod.rs:825-903` 只恢复卡片与技能索引）→ 重启后 `submit_bid` 对**每个** agent 都失败（`reputation.rs:210-224` 要求 `Locked` 质押记录），`arbitrate(guilty=true)` 失败并报「无质押记录」（`reputation.rs:172-176`）——**而质押资金仍在账上**。罚没路径在重启后是死的。
* 上游自己的持久化测试（`v274_test.rs:20-107`）只断言「行又出现了」，因此**三条全部漏过**。

### 3.3 【critical】新的 Agent Sandbox 子系统：三个 critical + 五个 high

上游在 v2.7.6–v2.8.0 引入了 sandbox（`gsn-core/src/sandbox/`，1,847 行），其安全边界**全部只存在于文档与单元测试中**：

| 严重度 | 发现 | 证据 |
|---|---|---|
| **critical** | **没有隔离原语**。整个「沙箱」就是 `Command::new("bash")` + `env_clear()` + `current_dir`。全仓 `grep unshare\|setrlimit\|seccomp\|chroot\|landlock\|setuid\|cgroup` **零命中**；子进程以**守护进程同一 OS 用户**运行 | `sandbox/runtime/process.rs:153-166` |
| **critical** | **沙箱代码可读写整个宿主文件系统**。`safe_join` 只被 `read_file`/`write_file` 两个 **Rust 侧 helper** 调用，**从不约束子进程**；`FilesystemPolicy` 四个字段**零执行点** | `process.rs:376-389`、`config.rs:88-97` |
| **critical** | **未认证的远程代码执行**。`POST /api/v1/sandboxes/{id}/exec` 接受任意 Python/JS，而 REST 路径**完全没有认证**（Bearer 闸门只覆盖 `/api/v1/mcp`）；监听 `0.0.0.0:4002`；**无所有权模型**，任何调用者可 exec/pause/destroy 任何 `sb-N` | `node.rs:1069-1105`、`sandbox/api.rs:144-182` |
| **high** | `NetworkGuard::check_egress`、`PermissionChecker::check`、`AuditLog::append`、`ExecutionToken::authorize` **生产调用点为零**（只有 `tests/v279_test.rs`）。所以「默认拒绝出站」是假的，沙箱可无限制出站——包括 POST 回守护进程自己的 API（SSRF） | `sandbox/security.rs:55-78,188` |
| **high** | **六项资源限制只有两项真实生效**（`timeout_ms` 轮询、Unix 上的 `ulimit -u/-n`）。`cpu_millis`/`mem_mb`/`disk_mb` 只被「校验 > 0」然后**从不使用**；**Windows 分支一项都没有**；stdout/stderr 用无上限 `read_to_end` → 父进程内存 DoS | `process.rs:261-276` |
| **high** | **`try_wait` 出错路径不 kill 也不回收**（`:303` 直接 return），子进程永久存活；`shutdown`/`evict_idle` 无生产调用点 → 守护进程重启后**孤儿沙箱不回收** | `process.rs:303`、`manager.rs:226-234` |
| **high** | **id 是 `sb-N` 计数器**（`manager.rs:67-70`），目录在持久化 data dir 下，`acquire` 不检查目录是否已存在 → **重启后 `sb-1` 被重新发放并继承上一个 `sb-1` 的文件**（跨请求泄露 + id 可猜） | `manager.rs:67-70`、`process.rs:218-219` |
| **high** | **请求体被解析后直接丢弃**（`api.rs:85-89` 解析、`:94` 调 `acquire(None)`）→ 调用方与运维**无法设置任何策略**，全部跑在硬编码默认值上；`SandboxConfig.template` 无任何消费者 | `sandbox/api.rs:85-94` |

**声明与代码的漂移还有 12 处**，其中最刺眼的是：`README.md:293` 仍宣称「Sandbox trait（Docker/Firecracker）」、`docs/architecture-v2.5.5.md:147` 仍宣称「microVM（Firecracker）嵌套虚拟化，不共享宿主内核」——而 `docker.rs` 是 82 行的 PATH 探测、`firecracker.rs` 是 78 行的 `/dev/kvm` 存在性检查，**两者都没有实现 `Sandbox` trait**，全仓没有任何 `docker run` 或 Firecracker API 调用。

### 3.4 【critical/high】新的 mesh / swarm / scheduler / collaboration / crowdsource / security 模块

这七个模块（合计约 2,600 行）**六个在生产代码中零调用点**，且**全部 fail-open**：

| 模块 | 关键缺陷 | 证据 |
|---|---|---|
| `swarm/consensus.rs` | **`vote(proposal, voter, approve, weight)` 接受投票者自报权重**，无成员校验、不查质押、不验签、不去重 → 任何人传 `weight = u64::MAX` 可通过任意提案；`set_total_stake` 同样可被任意设置；法定人数用 f64 计算后截断 | `consensus.rs:65-100,106` |
| `crowdsource/mod.rs` | **`complete_task` 无状态前置条件**：对已完成任务可**反复领取奖励**，可把 `Cancelled` 复活为 `Completed`，任何调用者可完成任何任务；`task_queue` 只增不减且**从不被读**；`Solver.available` 字段全库零引用 | `crowdsource/mod.rs:87-117` |
| `scheduler/router.rs` | `task.budget / candidates.len()` → **空候选列表 panic**（任何技能筛选无人的任务均可触达） | `router.rs:68` |
| `scheduler/load_balancer.rs` | `average_utilization` 除以 `capacity` 无零检查；`LeastResponseTime` 的 `partial_cmp().unwrap()` 在 `capacity == 0` 时 **panic**；`RoundRobin` 实际返回 `HashMap` 里的第一个元素，**从不轮转** | `load_balancer.rs:72-100` |
| `security/mod.rs` | 文件头声称「身份验证 / 数据签名 / 防 Eclipse」，文件里**没有任何身份、密钥、签名或验证调用**，只用随机数在**攻击者可填充的 `Vec`** 上抽样；`report_behavior` **相信任何调用者的指控**，6 次即可封禁任意节点（测试把这个当作预期行为写死），**无解封、无持久化、无衰减、无限流**；`ban_node` 连测试都没有 | `security/mod.rs:1-4,58-87` |
| `mesh/` | `discover_peer` 盲目接受并记住全部对等方提供的 `listen_addrs`/`hostname`/`protocol_version`，无长度上限、无 multiaddr 校验、无签名；`record_pong` 相信对方自报的 RTT；`DiscoveryTable.peers` 与 `HeartbeatTracker.peers` **只增不删**（永不清除 `Offline`） | `mesh/discovery.rs:8-38,77-84` |
| `collaboration/` | `send_message` 推入**从不排空、从无读取、无上限**的 `Vec`，而 `ttl` 字段**从不被查询**；`join_group` 允许任意 agent 自加入任意组，无策略无容量无认证 | `collaboration/mod.rs:52,71,99-110` |
| `crdt/mod.rs` | `merge` 是**盲目的逐节点取 max，无签名无认证**：任何对等方把 `node -> u64::MAX` 塞进来即可永久支配你的因果历史，**无法回滚**；`increment` 未检查溢出 | `crdt/mod.rs:24-38` |

### 3.5 【high】LLM / DeepSeek / MCP 层：旧缺陷只修了一半，新风险在别处

* **「没有 HTTP 客户端」这条在 v2.8.2 仍然成立。** 11 个模型家族**全是 mock**，且适配器字段是**具体 mock 类型**（`llm/adapter.rs:44-47` `client: MockOpenAiClient`），因此**真实客户端根本无法注入**。`deepseek/`（767 行）自称「本模块不做真实 HTTP 调用……默认提供 MockClient」（`deepseek/adapter.rs:8-9,44`）。**认证头机制仍只存在于注释里**（`anthropic.rs:8`）。
* **修出来的新失效模式**：panic 改成返回 `LlmResult`，但**错误变成了字符串 `format!("ERROR: llm request: {e}")`**（`adapter.rs:70-76`），而 deliberation 把它当**提案**参与加权投票（`hetero_llm.rs:61-69`）——**一个失败的请求可以赢得投票**。
* **真实 provider 响应根本解析不了**：`AnContentBlock.text` 必填（`tool_use` 块没有 text）、`GePart.text` 必填（`functionCall` 部分没有）、`OaChatResponse` 要求 `id`/`usage`/`choices` 都在（tool-call-only 的 `content: null` 与某些网关缺 `usage` 都会整体反序列化失败），**全部没有 `#[serde(default)]`**。而 mock 永远发出友好形状，所以测试证明的是一个**没有任何真实 provider 能满足的解码器**。
* **`partial_cmp().unwrap()` 仍在**：`hetero_llm.rs:68,100`，权重与置信度都是**调用方提供的未校验 `f64`** → `NaN` 即 panic。这是 v2.5.6 §7.3 的缺陷原样存活。
* **MCP 的参数校验写了、测了，但不在任何生产路径上**：`validate_arguments`（`tool.rs:165-201`）**只被 `server.rs:202` 调用**，而 `McpServer` **零生产调用点**；两个真实传输 `sse.rs:130-147`（HTTP）与 `stdio.rs:85-93` 直接调 bridge。后果是 v2.5.6 §8.1 **原样复现**：`market_deposit {"amount":"lots"}` 经 `get_money` 的 `unwrap_or(Money::ZERO)` **存入 0 并返回 `{"status":"deposited"}`**；`market_arbitrate {guilty: 1}` → `unwrap_or(false)`。
* **REST 侧仍然完全无认证**（H3）：Bearer 闸门只管 `/api/v1/mcp`，而 `POST /api/v1/accounts/{acct}/deposit`（**免费、无上限、无背书的信用**，唯一检查是「非负」）、`/disputes/{id}/arbitrate`、`/tasks/{id}/settle`、`/tasks/{id}/verify` 全部公开在 4002 端口。
* **`Access-Control-Allow-Origin: *`** 加无 `Origin`/`Host` 校验（`node.rs:741-746`）→ **运维访问的任何网页都能驱动本地守护进程**。
* **无请求体上限、无读超时**（`node.rs:984-1007`）：慢速灌入（slow-loris）可永久占住一个任务。
* **`mgr.lock().unwrap()`**（`node.rs:1075`、`sandbox_tools.rs:91`）→ 任何 panic 毒化互斥锁后，**后续每一次沙箱 REST/MCP 调用都 panic**。

### 3.6 【critical/high】账本持久化的四个新缺陷（与 §3.2 同源）

| 缺陷 | 说明 | 证据 |
|---|---|---|
| **水位用物理行数索引过滤后的逻辑列表** | `ledger_water = ledger_count()`（`SELECT COUNT(*)`，**把解析失败的行也计入**）而 `load_ledger_records` **静默跳过**解析失败的行。一行跳过就让水位永久超前 → 之后的写入落在错误的切片或干脆不写 → **账本出现静默、永久性的空洞，而 API 一直返回 200** | `market_actor.rs:248-260`、`persist.rs:405-426` |
| **写入失败被吞掉且水位照涨** | `let _ = store.append_ledger_record(r);` 紧接 `ledger_water = records.len();` → 磁盘/lock 错误**永久丢失该笔资金变动**，无重试无告警。agent/task 快照同一写法 | `market_actor.rs:257,263,266` |
| **恢复失败会永久关闭持久化** | 只 `eprintln!("⚠️ 账本恢复失败")`，引擎留空，而水位已按物理计数读入 → 此后 `records.len() > ledger_water` **永远为假，该进程再也不会写入任何记录** | `market_actor.rs:218-227` |
| **重复的 agent 写入竞态** | `node.rs:1120-1141` 重新解析 HTTP body 造 `StoredAgent`（`skills` 用 `join(",")` 有损、`reputation: 0.0` 硬编码、`created_at` 用 RFC3339），而 `upsert_agent` 会覆盖 reputation；同时 `spawn_with_store` 用真实 reputation 写同一行 → **两个写者、同一行、内容不同**，且 RFC3339 时间戳在恢复时 `parse().unwrap_or(0)` 变成 0 | `node.rs:1120-1141`、`persist.rs:122-126`、`mod.rs:892-893` |

### 3.7 【critical】状态转换被绕过，罚没金额由调用方决定

```rust
// marketplace/mod.rs:689-695  open_dispute
if let Some(task) = self.tasks.get_mut(task_id) { task.state = TaskState::Disputed; }
```

**直接赋值，绕过项目自己在别处新建的状态转换表**（`Open → Disputed` 甚至不在 `can_validate_to` 的合法边里，`task.rs:98-141`），**并且可以从终态 `Settled` 这样改**。`mod.rs:745-752` 同样直接赋 `Accepted`/`Slashed`。
`arbitrate`（`mod.rs:715-759`）**无仲裁者身份**，罚没金额 `slash_amount` **来自请求体**（`rest.rs:283-286`），唯一约束是质押余额。上游的测试把它当成正确行为写死（`v234_test.rs:677`）。
再叠加上 §3.5 的 REST 无认证，**任何调用者都能翻转任何任务的状态并自行决定罚款**。

### 3.8 其他可确证的次级缺陷（选摘）

* `chain/pocv.rs:39-43 verify_proof` **只重新哈希别人交给它的字节**，`prover_did` 是自由字符串且从不被读，无签名——而 `RELEASES.md:193` 称其为「真实的 ProofOfComputation 验证」。
* `verifier/client.rs:28-35` 的 `verify` **无条件返回 `valid: true, score: 0.95`**，参数全部未使用，端点从未被调用。
* `MarketAgentCard`（`agent_card.rs:61-101`）**根本没有签名字段**，`register_agent` 只检查 id/name 非空与质押区间——而 `RELEASES.md:249` 写明「质押准入，能力声明 **+ 签名**」。`DisputeCase.complainant` 与 `TaskSpec.requester` 都是自由字符串。
* 委员会 API `QaCommittee::new(n,f)` + `add_member` + `cast_vote` 仍是**公开且无认证**的，`tally` 统计的是 `self.members` 而非 `n`，因此 `new(3,0)` 加一个成员 = **一票决定**；它正是「历史回归套件」在测的路径。
* `verify_result_authenticated` 在**校验状态转换之前**就把 `evidence_grade` 提升为 `Verified`（`mod.rs:462-468`），随后 `:470-479` 的 `transition(target)?` 可能失败 → **一次返回错误的验证调用已经永久把信封标记为可信**，无授权、无回滚。
* 罚没在两条路径上口径不一（`mod.rs:592-596` 只扣账本、`mod.rs:733-735` 先扣信誉再扣账本且**不回滚**）→ **资金与资格会与账本不一致**。
* `MarketReputation` 无任何时间输入，而文档仍称「半衰期 90 天」；`StakeStatus::{Withdrawing, Withdrawn}` 全库零引用 → **没有退出/解押路径**。
* ACA 运行时（`AcaProcessor`/`process_message`/`execute_task`/`submit_review`/`register_peer`）在 `tests/` 中**零匹配**——v2.5.6 §4.7 的「零测试」这一半完全未动；`handle_incoming_receipt`（`aca/runtime.rs:388-436`）仍不看 `msg.message_id`/`msg.timestamp`，**每次重放仍发放 +60 Quality / +40 Availability**。

---

## 4. 上游测试覆盖的核查：声明与测试的对应关系

上游把 `gsn-core/tests/` 描述为「历史 Bug 回归套件」，但该标签的定义其实**窄得多**（`CHANGELOG.md:281-286` 指的是 `test/regression.js` 14 条 + `gsn-core/tests/regression_net.rs`），并不覆盖 `tests/*_test.rs`。核查结果：

**确实覆盖良好**：拓扑确定性 + 真实 LCA + N→2N 规模对照（`layer.rs:216-270`）；真 SHA-256 链与首个断链索引（`layered.rs:142-151`、`handoff.rs:119-128`）；真 LRU 且测试在 LFU 下会失败（`enhanced.rs:119-140`）；签名投票的伪造/过期/错任务/非成员/双签/重放（`qa_committee.rs:376-478`）；状态转换表与恢复边（`v234_test.rs:1130-1243`）；证据闸门拒绝（`:1245-1305`）。

**声明无测试**（且部分根本无法作为声明的证据）：

* 委员会**授权**：没有任何测试断言「调用方指定的委员会是非法的」；相反，测试构造出这种委员会并断言成功（`v235_test.rs:186-214`、`v273_test.rs:210-246`）——**没有首次失败回归**。
* 账本水位 `spawn_with_store`：**没有任何测试引用它**（只有文档注释）。§3.6 的三条全部无测试。
* 日志防篡改：审计测试改的是内存余额（`settlement.rs:539-565`），**从不改持久化日志**。
* 签名载荷的浮点排除：唯一跨语言向量的载荷里**没有浮点**，所以 §2.4 的第二条**在构造上就测不到**。
* ACA 运行时：`tests/` 中 **零匹配**（同 v2.5.6 §4.7）。
* 重启后的策略/信封/信誉/质押存活：`v274_test.rs` 只检查「行又出现了」，**三条全漏**（§3.2）。
* `reject_task` 可达性：唯一测试直接调库方法（`v234_test.rs:864`）。
* `is_weak_pubkey`、`VerifierClient`、`VersionVector` 的生产使用：没有测试，因为没有调用点。

**上游自己承认未验证**：`releases/v2.8.2.md` 的验证章节把 macOS 的绿色标为「由 CI 确认」，并把 Windows 复测列为「待办」。

---

## 5. V1.2.3 的响应（本项目做了什么、以及刻意没做什么）

针对上述发现，V1.2.3 的方向是**把边界从「文档承诺」变成「代码执行」，并让无法执行的边界变成拒绝而不是忽略**。逐条对应：

| 上游缺陷 | V1.2.3 的响应 |
|---|---|
| §3.1 日志无完整性 → 守恒与审计失效 | `nau-ledger` 对持久化记录加**哈希链**（每条含前一条哈希与本条规范字节的哈希），恢复与审计时校验并报**首个断链序号**；head 锚定在 store 元数据中，并被明确记录「能重写整份文件者仍可如何」，只声称 **tamper-evident** 而非 tamper-proof |
| §3.2 重启关闭证据闸门 | 持久化并恢复 `verification_policy`、结果信封及其 `evidence_grade`、`winner_price`、信誉与质押记录；用**关闭再打开**的测试断言「重启后闸门不放宽、仍可出价、仍能找到质押」 |
| §3.6 水位错位 / 吞错 / 恢复失败 | 水位从**与恢复相同的过滤后列表**派生（或持久化逻辑序号）；解析失败的行**必须显式报告**而非静默跳过；追加失败**返回错误且不推进水位**；恢复失败**拒绝服务或在 API 上显式标注降级** |
| §3.7 绕过状态转换 + 调用方定罚款 | 所有状态变更只经转换函数；`dispute`/`arbitrate` 要求显式**操作者**参数；罚则由**服务端规则**决定而非请求体；终态无入边（有测试）；证据提升只发生在转换成功之后 |
| §3.5 REST 无认证 / 通配 CORS / 请求体无上限 | 变更类 REST 路由在**配置了凭据时要求认证、未配置时默认拒绝**；不使用通配 `Access-Control-Allow-Origin`；请求体有上限、读有超时；每个变更端点都有「未认证被拒」的测试 |
| §3.5 MCP 校验不在生产路径 | 让**所有传输**经过同一个校验入口，并把「新增一条绕过校验的传输」变成结构上做不到（单一 dispatch 点），而不是靠自觉；`amount` 之类的金额参数**非法即拒绝，绝不默认为 0** |
| §3.3 sandbox 三个 critical | 默认后端是 **`NullExecutor`：什么也不执行**；唯一真正执行的后端必须**声明它实际能强制执行哪些边界**，**请求了它无法执行的策略就拒绝**（说出是哪条边界），绝不静默地不受限地跑；Windows 上用 **Job Object** 强制内存/进程数上限与**整棵进程树 kill**；输出有上限；id 为**密码学随机**且必须是通过单一校验函数的单个路径组件；启动时**清扫孤儿目录**；**认证与所有权**在每个路由上 |
| §3.4 自报权重 / 重复领奖 / 除零 panic | 共识投票的权重**由记录的质押派生**而非入参，且按 (提案, 投票者, nonce) 去重；奖励发放要求真正的状态转换且只发一次；所有除零点改为显式错误；`NaN`/非有限 `f64` 在任何比较或转换处**返回类型化错误** |
| §2.4 委员会仍由调用方指定 | 委员集合必须来自**服务端状态**（已注册、已质押、信誉达标、且与请求者/所有者不同），并绑定 DID↔投票密钥 |
| §2.4 签名载荷含浮点 | 规范签名载荷**拒绝任何非整数**（不是「应该」而是**不可能**）；金额入口拒绝 JSON 浮点，**不再有 `as f64 as i64`** |
| §2.2 NAT / §2.4 纠删码「声明 vs 测试」 | NAT：**不宣称任何真实 NAT 类型**，不可达时返回 `Unknown`，且**没有公开的类型会携带它的输出**。纠删码：保留**穷举 504 个子集**的测试（含仅剩校验片），并明确**不做纠错**；断言的是**恢复行为**本身，不是「分片都在时能解码」 |
| §3.5 LLM mock / 错误即答案 | `nau-http` 是**真实 HTTP/1.1**；provider 层每个失败路径返回 `Err`，**结构上不可能把错误当成答案**（有测试断言）；解码器接受真实 provider 载荷（可空 `content`、`tool_use`/`functionCall` 无 text、缺 `usage`/`id`、tool-call-only） |

**刻意不做的事**（如实标注，而不是含糊过去）：不实现 Intel/AMD 证书链（因此 `HardwareAttested` 由构造不可达）；不实现任何证明系统（Merkle 包含证明**不是**零知识、**不证明**计算正确性）；libp2p 为守 MSRV 裁掉 `dns/quic/tls/websocket`（**无 QUIC、无 DNS 解析**）；Tauri 桌面外壳**尚不能编译**（`E0255` 宏重复展开），其打包任务因此改为仅手动触发；TEE/迁移只读取 JSON（**没有数据库读取器**）。

---

## 6. 引用

本文件所有 `文件:行号` 均指上游 `TwinsEarth/agent-universe` **v2.8.2**（`main` 在审计时的状态，`gsn-core` 版本 `0.2.82`）。由于上游持续演进，行号可能随后续提交变化；引用时的源码片段已在本文逐条摘录，可据此定位。

上游采用本审计章节号作为修复路线图这一事实（§1），已记录在 [`../ATTRIBUTION.md`](../ATTRIBUTION.md)，以便将「审计 → 修复」的因果关系与时间顺序如实留档。
