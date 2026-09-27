# 更新记录 / Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
版本号有唯一机器可读来源：仓库根 [`VERSION`](VERSION)。

---

## [1.1.1] — 进行中

V1.0.1 把七项能力**明确标注为未实现**而不是留空。V1.1.1 开始逐项兑现，
并且对每一项都标注**验证程度**，因为「实现了」和「验证过」不是同一件事。

### 已实现并有本地验证证据

* **纠删码**（`crates/nau-erasure`）：GF(256) 系统化 Reed-Solomon，任意 k 片可重建。
  82 单元测试 + 9 文档测试通过，穷举 **504 个擦除子集**。明确**不**做纠错。
* **NAT 类型检测**（`crates/nau-net::{stun,nat}`）：RFC 5389 编解码 + RFC 4787 映射/过滤分类。
  97 个 `nau-net` 测试通过；其自身测试在开发中发现并修复了 4 个协议缺陷。
  **不宣称任何真实 NAT 类型**——那需要可达的公网 STUN 服务器，不可达时返回 `Unknown`。
* **真实 LLM HTTP**（`crates/nau-http` + `nau-agent::provider`）：真实 HTTP/1.1（分块解码、
  截断检测、超时、体积上限）+ OpenAI/Anthropic/Gemini 形状。63 个测试通过；空补全是
  类型化错误而非 panic。**TLS 路径可编译但无任何测试执行**，未启用时 `https://` 在建立
  socket 之前就返回类型化错误，绝不静默降级为明文。
* **GUI 客户端**（`client/`）：浏览器客户端**端到端 81 项断言**通过，真实调用守护进程、
  真实 Ed25519 签名、完整市场生命周期。**Tauri 外壳未编译未运行**（仅源码 + CI）。
* **合约**：首次真正被编译**并运行**。修掉 6 个编译缺陷与 9 个测试缺陷，
  现为 `forge test` **71/71**（钉定 solc 0.8.24），`forge-lint` **31 → 0 警告**。

### 基础设施

* **CI**：修正工具链钉版（1.83 → **1.85**，因为 `zeroize 1.9.0` 是 edition-2024，
  cargo 1.83 连其 manifest 都无法解析）；修正一个不存在的 action SHA；
  替换被当前 Foundry 拒绝的 `forge install --no-commit`；收窄过宽的版本检查；
  新增 `concurrency` 组；并把 `forge test` 限定到本项目（此前它在跑 forge-std 自己的 17 个套件）。
* **`scripts/verify-all.mjs`**：一条命令跑完全部关卡，**缺少工具是「未验证」而不是「通过」**。
* **`scripts/bump-version.mjs`**：任何目标无法更新就大声失败，修掉上游 `sed -i` 静默无效的缺陷。
* **发布脚本**：不再上传构建产物与取回的依赖（一次真实事故：57 个 Foundry 缓存文件被发布，
  导致 CI 在以 `.sol` 结尾的**目录**上崩溃）。

### 后三项（本轮完成）

* **libp2p 网络栈**（`crates/nau-libp2p`）：TCP + Noise + Yamux + Kademlia + GossipSub +
  Circuit Relay v2 + AutoNAT + DCUtR + identify/ping 组合进真实 swarm，并通过
  `Transport` 端口接入。**88 个测试通过**，含真实多节点 dial/identify、GossipSub 投递
  （断言发送者归属）、跨节点 Kademlia 记录与 relay reservation。
  **未验证：DCUtR 打洞与 AutoNAT 可达性**——环回场景下「打洞成功」只是拨通本地地址，
  这种测试不测任何东西也通过。**代价：为守住 MSRV 1.85 裁掉 `dns/quic/tls/websocket`，
  即没有 QUIC、没有 DNS 解析**，bootstrap 必须是 IP 形式 multiaddr。
  另有一条值得传播的 MSRV 发现：**直接 `cargo generate-lockfile` 得到的依赖树在 1.85 上无法编译**
  （`yoke-derive 0.8.3` 用了 1.87+ 的 `str::from_utf8` 路径、`multibase 0.9.3` 拉进使用
  不稳定 `slice_as_chunks` 的 `base45`、`idna_adapter 1.2.2`/`icu_* 2.3.x` 声明 1.86/1.88）；
  可行的 pin 列表与复现命令记录在 `crates/nau-libp2p/Cargo.toml` 与 crate 文档中。
* **TEE / zkML 验证**（`crates/nau-attest`）：63 + 1 测试。验证信封结构、固定根签名、
  nonce 绑定、新鲜度与 payload 绑定；**四种格式全部返回 `ChainNotImplemented`**，
  `HardwareAttested` 由构造保证不可达（没有实现 Intel/AMD 证书链）。
  Merkle 承诺与包含证明是真实的，但**不是零知识、不简洁，也不证明计算正确**——
  包含证明对垃圾输出同样成立，这一点有专门测试锁定。
* **上游历史数据迁移**（`crates/nau-migrate`）：65 测试。金额按十进制文本精确转换，
  无法精确表示则类型化拒绝；上游签名逐条验证；幂等（同一计划二次应用被拒绝，
  因为账本是仅追加的）。限制：只读 JSON/JSONL，没有数据库读取器；夹具为建模而非真实抓取。

### 本轮同时修掉的自身缺陷（由实机部署发现）

* **重启会让余额凭空增加**：`Market::persist` 每次把整个账本重复追加，重启时重放重复条目，
  部署实测余额从 12.8 变成 38。已改为只追加未落盘条目（`journaled` 计数），并加了回归测试。
* 发布脚本曾把 Foundry 构建产物上传，导致 CI 在他建的、**以 `.sol` 结尾的目录**上崩溃。
* 工具链钉错版本（1.83 vs `zeroize 1.9.0` 的 edition-2024）。

## [1.0.1] — 2026-09-27

**首个发布。** 基于对上游 [`TwinsEarth/agent-universe`](https://github.com/TwinsEarth/agent-universe)
**v2.5.6** 全量源码（648 个文件）的逐行审计，进行全新架构重写。

### 审计

* 覆盖上游 **648 个文件**：Rust 15,735 行、Python 934 行、JavaScript 1,373 行、
  Solidity 216 行、文档 23,039 行、论文 PDF 114 份、CI/部署 705 行。
* 记录 **76 条缺陷**，每条附 `文件:行号` 证据与原始代码引用，
  分为严重 12 / 高 17 / 中 26 / 低 21。全文见 [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)。
* 本地执行上游 JS 测试（12/12 通过）与回归套件（14/14 通过）作为行为基线。
* **上游的 Rust 代码未能编译**：其依赖树（libp2p + rusqlite bundled + TLS）
  在 8 核 / 16 GB 机器上以 cargo 默认 8 路并行触发
  `rustc-LLVM ERROR: out of memory` 与 `STATUS_STACK_BUFFER_OVERRUN`。
  因此对上游 Rust 运行时行为的判断基于源码阅读，已在文档中逐处标注。

### 新增

* **工作区架构**：9 个单向依赖的 crate（`nau-core` / `ledger` / `consensus` /
  `store` / `market` / `net` / `agent` / `mcp` / `node`），替代上游单一 15.7 kLOC crate。
* **`nau-core`**：DID（`did:nau:`，兼容解析 `did:aip:`）、手写规范 JSON 序列化器、
  `Money(i64)` 整数货币、七种带签名领域结构 + `Verifiable` 契约、`NonceGuard`、`Clock` 端口。
* **`nau-ledger`**：精确整数双入式账本，托管/释放/退回/罚没，
  O(1) 守恒 + **可失败的 O(N) 审计**。
* **`nau-consensus`**：**签名投票**、固定成员集、`checked` 算术、
  `safety_violation` 检测、equivocation 归责、带恢复的轮次重置。
* **`nau-store`**：`Store` 端口 + 追加 JSONL `FileStore`（容错截断末行、原子 `compact`）
  + `MemoryStore`；**账本日志可重放**。
* **`nau-market`**：注册、**确定性整数匹配**、任务生命周期状态机、
  结算、争议与仲裁；`persist`/`restore` 往返。
* **`nau-net`**：`Transport` 端口 + **真实 TCP 分帧传输** + **确定性 Lv1–Lv7 拓扑**
  + 强制容量的中继池。
* **`nau-agent`**：分层记忆 + **真实 SHA-256 溯源链**（含载荷，可校验每一环）
  + 真实 LRU + 强制防污染 + `LlmProvider` 端口与整数 token 预算。
* **`nau-mcp`**：单一事实来源的工具定义（派生 schema + 类型校验 + `-32602`）、
  `RequestId::Null`、`-32002` 未初始化、工具级 `isError`。
* **`conformance/`**：跨语言唯一事实来源 `vectors.json`（10 条向量 + 5 条拒绝用例），
  由 **Node/OpenSSL Ed25519** 生成，与 Rust 实现不共享代码。
* **Python SDK**（`sdks/python`）：**零第三方依赖**，含纯 Python RFC 8032 Ed25519；
  上游因 `cryptography` 可选而使 11/17 个测试在 CI 中被静默跳过。
* **JavaScript SDK**（`sdks/js`）：零依赖，单一线程一致的身份方案，
  显式码点比较器，拒绝 `NaN`/`Infinity`/`undefined`/`BigInt`/`Date`/超安全范围整数。
* **合约**（`contracts/`）：Foundry 工程，四个合约重写 + 逐缺陷测试 + 部署脚本。
* **CI**：真实门禁（`clippy -D warnings`、`fmt --check`、三端测试、向量可复现、
  `forge test`），发布流程**依赖测试**；上游的三条发布 workflow 在任意 `v*` 上独立触发。

### 修复的严重缺陷（摘要）

| 上游缺陷 | 证据 | 本项目 |
|---|---|---|
| 验收委员会由调用方合成，可自我批准 | `api/market_actor.rs:360-386` | 签名投票 + 固定成员集 |
| 结算在余额不足时铸币 | `marketplace/mod.rs:352-355` | 发布即托管，拒绝无资金 |
| 货币为 `f64`，守恒用容差 `.abs() < 0.001` | `settlement.rs:28,37-40,173` | `Money(i64)`，精确相等 |
| 负数额度被接受且守恒仍报 true | `settlement.rs:76-80,148-160` | 拒绝非正数 |
| 跨语言 `Receipt` 因浮点格式无法互验 | `aca/receipt.rs:29-32` | 规范载荷拒绝一切浮点 |
| 序列化失败时签名 `null` | `aca/crypto.rs:20,24` | 返回 `Result` |
| 存储只写不读，账本从不落盘 | `persist.rs:132,178`；`node.rs:1050` | 往返测试 + 日志重放 |
| 所有变更接口无授权、无状态前置条件 | `marketplace/mod.rs:302-472` | 六步纪律 + 状态机 |
| 三个 Solidity 合约不可部署（无鉴权、可重入、可自我接单） | `PoCVSettlement.sol:29-88` | 重写 + 逐缺陷测试 |
| CI 静默跳过 11/17 Python 测试；clippy 被 `\|\| echo` 中和 | `ci.yml:45,64` | 零依赖测试 + 真实门禁 |
| 版本已漂移 6 处（登记表本身遗漏） | `aip/__init__.py:31` 等 | 唯一来源 `VERSION` + 断言 |

### 明确未实现（不宣称）

Kademlia DHT、GossipSub、Circuit Relay v2、AutoNAT、DCUtR、NAT 类型检测、
纠删码、TEE/zkML 验证、GUI 客户端、真实 LLM HTTP 调用、上游历史数据迁移。
理由见 [README](README.md#明确未实现的范围) 与 GAP-ANALYSIS §10。

### 来源

上游 [TwinsEarth/agent-universe](https://github.com/TwinsEarth/agent-universe) v2.5.6，
MIT，`Copyright (c) 2026 Agent Universe Contributors`。
保留项、替换项与放弃项的完整清单见 [ATTRIBUTION.md](ATTRIBUTION.md)。

---

## 版本号约定

* `VERSION` 文件是唯一事实来源。
* `[workspace.package] version` 必须与之相同（`cargo test -p nau-core` 会断言）。
* 任何 crate 都不得声明**字面**版本，只能用 `version.workspace = true`
  （`version_consistency.rs` 会断言）。
* Python 与 JS SDK 在运行时**读取** `VERSION`，不重述数字。
