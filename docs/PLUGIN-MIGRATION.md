# 一切插件化：全量重审与迁移方案（v3.2.1）

> 本文是 SOP「阶段一」的重审交付物：**逐个 crate、逐个模块**对照方案文档要求的插件清单，
> 标出**已经是插件**、**还只是 crate**、以及**文档要求但当前不存在**的三类。
>
> 规则与全项目一致：**只把有测试断言的东西写进「已完成」**；做不到的写「未实现」并让请求失败。

---

## 1. 重审方法

1. **清点**：`crates/` 下 17 个 crate 的公开类型与职责（`Cargo.toml` description + `lib.rs` 公开项）。
2. **映射**：文档 §2.1.1（系统插件 10 项）、§8.3（SYS-1..SYS-5）、§8.4（OFF-1..OFF-9）
   与 §10（迁移路径表）逐条对照现有代码。
3. **判定**，只有三种，不含糊：
   * **已接线**——有 `SystemPlugin` 实现（或官方清单）**且有测试**证明它可装载、可应答、越权会被拒；
   * **只是 crate**——功能存在、经过测试，但**没有插件外壳**，因此不在注册中心、不经总线、不受能力令牌约束；
   * **不存在**——文档要求而代码里没有。
4. **命名**：一律用 §5.2 的反向域名规则（`com.twinsearth.sys.*` / `.official.*` / `.certified.*`），
   而不是 §2.1.1/§8.3 里那套简写（`sys.identity.did`）。理由：**分级由名字前缀推导**，
   两套写法会推出两个分级。文档两处自相矛盾，以实现为准。

---

## 2. 系统插件（T0，进程内，不可热插拔）

| 文档插件 ID | 承担的功能 | 现有代码 | 状态 |
|---|---|---|---|
| `com.twinsearth.sys.identity` | DID 派生、Ed25519 验签、DID↔公钥绑定 | `nau-core::identity` | **已接线**（`plugins/identity.rs`） |
| `com.twinsearth.sys.storage` | 自有目录的追加存储与元数据 | `nau-store` | **已接线**（`plugins/storage.rs`） |
| `com.twinsearth.sys.policy` | 能力矩阵查询与判定 | `nau-plugin::capability` | **已接线**（`plugins/policy.rs`） |
| `com.twinsearth.sys.orchestrator` | 依赖图与装载顺序 | `nau-plugin::registry` | **已接线**（`plugins/orchestrator.rs`） |
| `com.twinsearth.sys.blacklist` | 黑名单查询、条目回读、申诉图 | `nau-plugin::blacklist` | **已接线** |
| `com.twinsearth.sys.lifecycle` | 状态机事实、后继状态、拒绝解释 | `nau-plugin::lifecycle` | **已接线** |
| `com.twinsearth.sys.arbiter` | 装载阶段契约、拒绝码词表 | `nau-plugin::arbiter` | **已接线** |
| `com.twinsearth.sys.sandbox` | 后端**真实**边界表、沙箱规格预检 | `nau-sandbox` | **已接线**（报告进程后端；`with_executor` 可换） |
| `com.twinsearth.sys.net.transport` | 传输常量报告、地址预检（不连接） | `nau-net` | **已接线** |
| `com.twinsearth.sys.net.dht` | DHT/拓扑常量报告、peer 标识预检（不连接） | `nau-net` | **已接线** |
| `com.twinsearth.sys.net.gossip` | 广播载荷上限报告、topic 预检 | `nau-net`（**无订阅面**，见下） | **已接线** |
| `com.twinsearth.sys.chain` | 链上读配置契约与输入预检（**不执行读**，见下） | `contracts/` | **已接线** |
| `com.twinsearth.sys.ledger` | 余额、托管、守恒、审计（**只读**） | `nau-ledger` | **已接线**（`new()` 装空账本，见下） |
| `com.twinsearth.sys.erasure` | Reed-Solomon 编解码 | `nau-erasure` | **已接线** |
| `com.twinsearth.sys.attest` | 存证信封验证、已固定根报告 | `nau-attest` | **已接线**（`new()` 不固定任何根，见下） |
| `com.twinsearth.sys.http` | 一次 GET + 免拨号预检 | `nau-http` | **已接线** |
| `com.twinsearth.sys.migrate` | 上游 AgentCard 校验与投影 | `nau-migrate` | **已接线**（不构造 `AgentCard`，见下） |

**结论：17 项全部已接线**——全部由 `standard_plugins()` 构造、`standard_declarations()` 声明、
并在 `system_plugins.rs` 里逐个跑到 `Running`，各自的越权请求被令牌拒绝并点名能力。

### 2.0 两处「名字比能力大」的地方（如实标注）

* **`sys.net.gossip` 没有可委托的订阅面。** 本工作区里 **`nau-net` 完全没有 pub/sub**：没有 topic 类型、
  没有订阅注册表、没有扇出上限（该 crate 的 `lib.rs` 自己写明上游的 `net/gossip.rs::GossipSub` 是个
  HashMap 假的，本 crate 有意不做）。工作区里唯一的真实 topic 规则在 `nau_libp2p::naming`，而
  **`nau-plugins` 不依赖 `nau-libp2p`**——为了一个 topic 长度常量把整个 libp2p 栈拖进 T0 宿主 crate 不成比例。
  因此该插件对订阅相关的上限一律返回 `null`，并在应答里**明说本工作区不存在订阅面**。
* **`sys.chain` 不执行任何链上读。** Rust 侧没有链客户端，所以该插件报告**链上读所需的配置契约**
  （RPC 端点形状、链 ID、调用编码校验）并做输入预检，**不假装读过链**。

`plugin-invariants` 关卡新增一条检查：**每个 `SystemPlugin` 实现都必须出现在
`standard_plugins()` 与 `standard_declarations()` 里**。它首次运行就抓到 5 个刚写好、尚未接线的插件——
这正是「写了但没接线」在源码层的样子。

### 2.1 三个「接了但接在退化默认上」的说明（不粉饰）

`standard_plugins()` 用无参构造器装配，其中三个因此**对什么都给不出有用答案**。这是新建节点与测试的正确默认
（插件不得凭空捏造它没被赋予的状态），但**部署必须接真的**：

| 插件 | 装配到的退化对象 | 真实接线入口 |
|---|---|---|
| `sys.ledger` | 空账本 → 每次 `balance` 答 `0 / known:false` | `LedgerPlugin::sharing(arc)` |
| `sys.attest` | 不固定任何根 → 每个信封都被拒 `signer_not_trusted`（fail-closed） | `AttestPlugin::with_roots(...)` |
| `sys.sandbox` | 描述**进程后端能强制什么**，而节点默认执行器是 `NullExecutor` | `SandboxPlugin::with_executor(...)` |
| `sys.blacklist` | 空名单 → 每个 `check` 答 `condemned:false` 且 `wired:false` | `BlacklistPlugin::with_list(...)`（需自带签名校验的 `TrustStore`） |

---

## 3. 官方插件（T1，独立进程）

| 文档插件 ID | 功能 | 可运行实现 | 状态 / 若未实现，**理由** |
|---|---|---|---|
| `com.twinsearth.official.market` | 注册、匹配、任务生命周期、托管结算 | `nau-plugin-market.rs`（`rank` → `nau_market::matching::rank_bids`） | **可运行** |
| `com.twinsearth.official.mcp` | MCP 工具面 | `nau-plugin-mcp.rs`（`initialize` → `nau_mcp::protocol`，`rpc` → `nau_mcp::rpc::parse_request`） | **可运行** |
| `com.twinsearth.official.scheduler` | 任务路由与负载均衡 | `nau-plugin-scheduler.rs`（`validate`/`transition` → `nau_core` 的 `Task`/`TaskState` 校验与转移） | **可运行** |
| `com.twinsearth.official.agent` | 分层记忆（个体/群体/跨代） | `nau-plugin-agent.rs`（`validate`/`project` → `nau_core::domain::agent` 的**当前** `AgentCard`） | **可运行** |
| `com.twinsearth.official.skill` | 谁做得了一个活：由调用方给出的名册决定（上游 `v3.5.0` 的 `official.agent-skill`） | `nau-plugin-skill.rs`（`match` → `nau_core::domain::agent::Skill` 解析 + `Market::discover` 所用的**小写 id** 规则） | **可运行** |
| `com.twinsearth.official.chain-anchor` | 只写一次的 AgentCard 锚点，离线：`AgentCardAnchor.sol` 的规则（上游 `v3.5.0` 的 `official.chain-anchor`） | `nau-plugin-chain-anchor.rs`（`anchor`/`verify`/`anchorable`/`page`） | **可运行（离线部分）** |
| `com.twinsearth.official.agent-council` | 在**已存在的**沙盒之上召集一个智能体委员会，对各自状态做快照与恢复（v3.6.0 新增） | `nau-plugin-agent-council.rs`（`convene`/`snapshot`/`restore`/`roster`） | **可运行** |
| `com.twinsearth.official.economy` | 多维信誉、质押、结算策略 | — | **未实现**：`nau-ledger` 已是 T0 的 `sys.ledger`；多维信誉的独立面已被 T3 的 `com.example.reputation` 用掉 |
| `com.twinsearth.official.swarm` | 群体智能、BFT-lite 委员会 | `nau-plugin-emergence.rs`（`detect`） | **可运行，但 `detect` 不作判断**——见下方「我们收窄了什么」 |
| `com.twinsearth.official.shard` | 分片存储 | — | **未实现**：`nau-erasure` 已是 T0 的 `sys.erasure`；没有独立于它的分片面 |
| `com.twinsearth.official.bridge` | 跨链信誉桥接 | `nau-plugin-bridge.rs`（`commit`/`verify`） | **可运行（离线部分）**——**此前写成硬限制是误述，见下方更正** |
| `com.twinsearth.official.mesh` | 全对等网络 | — | **未实现**：`nau-net` **没有 pub/sub**（无 topic 类型、无订阅注册表、无扇出上限）。这是硬限制，见 §2.0 |
| `com.twinsearth.official.crdt` | CRDT 状态同步 | — | **未实现**：**本仓库没有任何 CRDT crate**。`nau-core` 的词法规范化不是 CRDT，把它包装成一个是**换名字而不是迁移** |
| `com.twinsearth.official.test-runner` | 用智能体执行测试用例 | — | **未实现**：v3.x 新增，**没有可委托的 crate**；它需要的是一套「以智能体为执行者」的运行器，不是对既有 crate 的包装 |

**结论：11 项都有清单，其中 4 项可运行、7 项未实现——而 7 项里每一项都有具体理由，不是待办**。

### 3.2 一处更正：`bridge` 的「硬限制」是误述

本文此前把 `com.twinsearth.official.bridge` 写成**硬限制**，理由是「Rust 侧没有链客户端」。
对着上游 `agent-universe` **v3.5.0** 接地核实后：**那句话前半是真的，结论是错的**。

上游的 `chain-bridge` 是 `contracts/src/ReputationRegistry.sol` 的**离线移植**——
纯状态函数，注册表状态随载荷传递，哈希是**内联在模块里的纯 Python keccak256**，
**没有 RPC、没有 provider、没有链客户端**。它的姊妹项 `chain-anchor` 也把同一件事写在字面上：
*「offline port of `contracts/src/AgentCardAnchor.sol`（no RPC；does NOT claim real on-chain）」*。

> **写链需要链客户端；桥的语义从来不需要。**

**这是一类本仓库一贯拒绝的断言**：一个关于**代码库**的事实（没有链客户端）
被当成了关于**设计**的事实（所以桥不可能存在），而中间那一步没有去查上游到底怎么做。
准确的句子是「桥需要的是一份注册表聚合规则的离线移植，不是链客户端」——
真正缺的是**离线的承诺与校验设计**，而 `nau-attest::commit` 已经是一个。

**仍未实现的那一半如实标注**：`commit`/`verify` 只提供承诺与离线包含证明；
上游的**验证者集合、逐 epoch 中位数、`floor(n/2)+1` 法定人数、keccak 身份键、
已定稿 epoch 不可推翻**这些聚合语义**没有移植**。要写链仍然需要链客户端，那部分依然为真。

### 3.3 我们收窄了什么：`official.swarm` 的 `detect` **不作判断**

上游 `swarm-emergence` 的判据是**调用方给定阈值的窗口均值相对变化**——阈值由调用方传入。
**本仓库没有任何涌现检测器**：`nau-consensus` 决定选票、`nau-market` 给投标排序、
`nau-agent` 持有分层记忆，`crates/` 里没有任何窗口统计量。

移植它意味着 (a) 搬来一套算法，(b) 把**调用方给定的阈值**当作决定性参数引入——
这正是本工作区已经从共享记忆里移除的同一个缺陷（发布者给的权重决定自己的排名）。

所以 `detect` **只校验上游的输入形状、回显参数、并记录它没有套用的那条上游判据**，答案里是
`available: false`、`judgement: "not_made"`、`detected: null`，并且**完全省略 `signals` 键**——
因为上游的 `signals: []` 意思是「判过了，没发现」，而这里的空列表会被读成一个
**它并没有挣得的否定结论**。有一条测试喂进一份**会触发**上游 `collaboration` 信号的历史，
断言仍然没有结论出现；将来若有人偷偷塞进一个阈值，那条测试会失败。

前四项由 `crates/nau-node/src/plugin_process.rs`（宿主侧执行）在**真实沙箱**里驱动，
端到端测试见 `crates/nau-node/tests/plugin_process.rs`（Windows 门控，平台矩阵见 `docs/VERIFICATION.md` §5.2）。
四个二进制都在同一个测试表里，因为对它们的主张是同一条。

### 3.1 本构建交付的**全部**可运行插件二进制

上表只管 T1。下表是本构建**实际能运行的每一个进程插件**，跨全部层级——它存在是因为一个
只有散文里才有的数量会过期：同一会话里上表被更新为四项，而本节末尾的句子仍写着「1 项可运行」，
**没有任何东西比对过它**。现在 `scripts/check-plugin-invariants.mjs` 会比对：
`src/bin/` 下每一个非夹具的 `nau-plugin-*.rs` 都必须被一行标「可运行」的表格命名，而每一行命名的文件都必须存在。

| 插件 ID | 层级 | 二进制 | 状态 |
|---|---|---|---|
| `com.twinsearth.official.market` | T1 | `nau-plugin-market.rs` | **可运行** |
| `com.twinsearth.official.mcp` | T1 | `nau-plugin-mcp.rs` | **可运行** |
| `com.twinsearth.official.scheduler` | T1 | `nau-plugin-scheduler.rs` | **可运行** |
| `com.twinsearth.official.agent` | T1 | `nau-plugin-agent.rs` | **可运行** |
| `com.twinsearth.official.skill` | T1 | `nau-plugin-skill.rs` | **可运行** |
| `com.twinsearth.official.chain-anchor` | T1 | `nau-plugin-chain-anchor.rs` | **可运行** |
| `com.twinsearth.official.agent-council` | T1 | `nau-plugin-agent-council.rs` | **可运行** |
| `com.twinsearth.official.swarm` | T1 | `nau-plugin-emergence.rs` | **可运行** |
| `com.twinsearth.official.bridge` | T1 | `nau-plugin-bridge.rs` | **可运行** |
| `com.twinsearth.certified.swarm` | T2 | `nau-plugin-swarm.rs` | **可运行** |
| `com.example.reputation` | T3 | `nau-plugin-reputation.rs` | **可运行** |

`nau-plugin-echo.rs` **不在表内，因为它是测试夹具而不是交付的插件**；这条豁免写在这里，
是为了让它是一个公开的决定，而不是命名习惯的副产品。

**7 项未实现里，5 项的理由是「功能已由别的插件承担或用不到独立面」**（economy / swarm / shard / crdt / test-runner），
**1 项是硬限制**（mesh 没有 pub/sub）。把这些写成「待办」会让它们看起来像是额度问题；
它们是**关于这份代码库的事实**，而 §4 与 §2.0 分别记录了那两条硬限制。

**四项可运行，而且现在有操作者能用的入口**：`nau plugin run <dir> --trust <key> --op <name> [--payload <json>]`
先把插件送上**与 `verify` 完全相同**的装载流水线，通过后**真的启动并调用**它。
在此之前 `ProcessPluginHost`（唯一能启动进程插件的东西）**只被它自己的测试构造**——
T1/T2/T3 能被装载、审核、认证，而**没有任何交付的工具运行过它们**。`verify` 自己如实写着「The plugin was NOT executed.」，
那句话在整个构建里都是准确的；`run` 是补上的那一半。

**四个可运行插件各自声明的能力，没有一个被自己的 op 行使**——它们在 `capabilities` 里如实报告
`declared_capabilities_backed_by_ops: false`。这是**架构事实而非缺口**：清单里的能力集是目录决定的，
而本 ABI **收一帧就退出**、调用之间不保留状态，所以注册、结算、订阅这类需要跨帧状态的 op 不可能诚实实现。
宿主不该把声明读成已实现的功能。

「有清单」与「能运行」是两件事，本文件不在两者之间含糊：清单证明**分级、能力声明与依赖**是对的，
不证明任何代码能跑。V3.2.1 没有 WASM 运行时，也没有把这 11 项实现成进程插件。

---

## 4. 为什么官方插件不能照抄「WASM」这一步

文档 §1.5/§9.1 把 Wasmtime 定为插件标准格式。**本构建没有 WASM 运行时**，理由是硬件可验证的：
`wasmtime` 及其 cranelift 依赖树不在 `Cargo.lock`、不在本机 registry 缓存，
而「引入了却无法验证」正是本项目拒绝的事。所以 T1 只能走**进程隔离**（`ProcessRuntime`
+ `nau-sandbox` 的强制边界），且它与文档的四层隔离相比：

| 文档要求的层 | 本构建的实际能力 |
|---|---|
| Layer 1 WASM 沙箱 | **不存在**——类型化拒绝 |
| Layer 2 进程沙箱 | 有：Job Object（整树 kill、内存与进程数上限）、独立工作目录、环境白名单、输出上限、超时 |
| Layer 3 内存隔离 | 部分：独立进程即独立地址空间；**但同机内存总量无隔离** |
| Layer 4 网络隔离 | **不存在**：任何平台都没有针对子进程的 egress 原语。「T3 无网络」是关于**总线**的陈述，不是关于子进程能否开 socket 的陈述 |

配额矩阵同理：**CPU 时间、磁盘配额、句柄上限在任何平台都没有原语**，因此请求它们的插件
**被具名拒绝**，或在签名覆盖的 `waivers` 段逐条豁免并说明理由。

---

## 5. 迁移计划（本版执行顺序）

1. **系统插件补全**（本文第 2 节 13 项 → 0 项）：每一项写成一个 `SystemPlugin`，
   **委托给既有 crate**，不重写功能；每个插件必须有「可装载、可应答、越权被令牌拒绝」三条测试。
   **已完成**：17/17。
2. **官方插件**：先给全部 11 项**可验证的清单**（分级、能力集、依赖、ABI），
   再实现其中**能在进程隔离下真实运行**的若干项；**未实现的保持「仅清单」并不对外声称可运行**。
   **现状**：11 份清单齐备，**4 项可运行**（§3.1 是全部层级可运行二进制的完整清单，并由关卡比对）。
3. **T2/T3 的运营面此前只有模型**：`nau-plugin` 有完整的审核状态机与黑名单模型，
   但**没有任何命令驱动它们**——所以「第三方注册审核流程」与「黑名单管理」都是数据结构、不是流程。
   本版补上两个驱动器（详见 §5.1）。
4. **测试与验证**：沿用既有 24 道关卡，新增「插件清单与实际能力一致」检查。
5. **三平台部署验证**：`scripts/deploy-local.mjs` 一直是本地关卡，**CI 从不运行它**，
   所以「三平台部署」只是断言。本版把它加进 `ci.yml` 的三平台 rust job。
6. **发布**：按 v2.8.0 起的 SOP（版本管理、配置、查漏补缺、GitHub 发布）。

### 5.1 两个运营驱动器（本版新增）

| 命令 | 驱动什么 | 关键性质 |
|---|---|---|
| `nau plugin review open\|scan\|advance\|show\|certify` | `nau-plugin::certify` 的六阶段状态机（submitted → auto_scanned → manual_review → grey_run → certified，任一步可 rejected）与限定范围的 `Certification` | **「通过审核」必须意味着「能装载」**：`scan` 跑的是**真正决定装载的那套检查**，不是为审核另造的一套更宽松的检查。一个批准了、仲裁器却拒绝的审核，比没有审核更糟——因为人会信它 |
| `nau plugin blacklist add\|list\|check\|appeal\|unblock` | `nau-plugin::blacklist` 的**已签名条目**与申诉状态机（appealed → under_review → grey_list → lifted / denied） | 完整性来自**每条条目的签名**，不是文件权限：读取时**重新验签**，手改过的条目必须是具名拒绝。`unblock` 只在申诉到达终局**且条目本身允许**时才移除，否则拒绝并**点名还缺哪一步** |

**持久化设计**：两者都用**可重放的事件日志**而非序列化快照。`Review` 与 `Blacklist`
都不加 serde 派生——日志每次被**重放**进内核的状态机，所以被篡改的历史会被**内核**拒绝
（`Review::advance` 判边），而不是被驱动层悄悄接受。这是「内核是权威」在持久化上的体现。

---

## 6. 本文件的自我约束

* 本文每一条「已接线」都指得到测试；每一条「只是 crate」都指得到现有代码；
  每一条「不存在」都是我在 `crates/` 下找不到。
* 第 4 节的限制不是免责声明，而是**让请求失败**的依据：请求 WASM 运行时、请求网络拒绝、
  请求磁盘配额，都会得到**具名拒绝**，不会静默降级。
* 文档与实现冲突时（如 §2.1.1 的简写命名 vs §5.2 的反向域名），**以实现为准**并在本文写明。
