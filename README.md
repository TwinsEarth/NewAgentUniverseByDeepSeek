# NewAgentUniverseByDeepSeek · V3.9.7

> **基于对 `TwinsEarth/agent-universe` 全量源码审计的全新架构重写；V2.2.2 起为「一切插件化」架构，V3.2.1 起可在线演进。**
> A clean-room rewrite of the agent-universe design, produced from a line-by-line audit
> of upstream; everything-is-a-plugin from V2.2.2, and hot-updatable from V3.2.1.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B%20edition%202021-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3.10%2B%20stdlib--only-blue.svg)](sdks/python)
[![Node](https://img.shields.io/badge/node-18%2B%20zero--deps-green.svg)](sdks/js)

[![CI](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/ci.yml/badge.svg)](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/ci.yml)
[![Client](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/client.yml/badge.svg)](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/client.yml)
[![CodeQL](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/codeql.yml/badge.svg)](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/codeql.yml)
[![Release](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/release.yml/badge.svg)](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/actions/workflows/release.yml)
[![npm](https://img.shields.io/npm/v/@twinsearth/nau-dsh-plugin?label=npm&color=cb3837)](https://www.npmjs.com/package/@twinsearth/nau-dsh-plugin)
[![GitHub Release](https://img.shields.io/github/v/release/TwinsEarth/NewAgentUniverseByDeepSeek?label=release)](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases)

---

## V3.2.1：热更新、热插拔、热兼容与安全信道

### V2.2.2：一切插件化

内核只做四件事——**注册、路由、仲裁、生命周期**——其余全部是插件。
开发方案（架构、原理图、流程图、技术方案、以及**对草案逐条的偏离说明**）见
**[docs/PLUGIN-ARCHITECTURE.md](docs/PLUGIN-ARCHITECTURE.md)**。

| | |
|---|---|
| **插件内核** | `nau-plugin` — 分级、能力令牌、签名清单、生命周期、注册中心、总线（PMB）、隔离端口、黑名单、认证范围、**ABI 适配器**、**热切换**、**安全信道** |
| **插件实现** | `nau-plugins` — T0 系统插件框架 + 四个真实插件（identity / storage / policy / orchestrator） |
| **五级体系** | T0 系统 / T1 官方 / T2 认证 / T3 第三方 / 黑名单（判决，不是等级） |
| **外部接口** | `nau plugin tiers \| runtimes \| verify <dir> \| system \| blacklist` |
| **隔离** | 进程后端复用 `nau-sandbox` 的强制边界；**无法强制的边界必须由插件显式豁免并给理由，否则拒绝启动** |
| **热兼容** | 宿主 ABI `3.2`；`2.x` 插件**通过具名适配器**运行，或**被具名拒绝**——默认适配器注册表为空（fail-closed） |
| **热更新** | 双缓冲：先健康检查、再单次原子切换、最后排空旧实例；**排空失败不复辟** |
| **安全信道** | X25519 + HKDF-SHA256 + ChaCha20-Poly1305，需能力 `crypto:channel`（T3 一律拒绝） |
| **写进去的规则** | 声明→证据的完整映射见 **[docs/VERIFICATION.md](docs/VERIFICATION.md) §5 与 §6**，含硬限制与未实现项 |

**三条本版守住的线**：文档里写的能力，代码里必须可达（`Grant::RequiresApproval` 曾不可达，已修）；
被写下的规则，必须有东西执行它（「三次违规→隔离」曾在总线上没有接线，已接）；
**在一个平台上验证过的强制，不能在未验证的平台上被声明**。
WASM 运行时**在本构建中不存在**，实现为类型化拒绝而非静默降级。

---

## 来源 / Provenance — 请先读这一段

| | |
|---|---|
| **上游项目** | [TwinsEarth/agent-universe](https://github.com/TwinsEarth/agent-universe) — **Agent Universe（智能体宇宙）** |
| **上游版本** | **v2.5.6**（Rust crate `gsn-core` `0.2.56`），后续增量审计至 **v2.8.2** |
| **审计规模** | 全部 **648 个文件**：Rust 15,735 行 / Python 934 行 / JS 1,373 行 / Solidity 216 行 / 文档 23,039 行 / 论文 PDF 114 份 |
| **本项目** | **NewAgentUniverseByDeepSeek V3.2.1** — 依据审计结论进行的**重写**，非复刻、非重命名 |
| **来源说明** | **[ATTRIBUTION.md](ATTRIBUTION.md)** — 逐项列出保留了什么、替换了什么、放弃了什么 |
| **审计全文** | **[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)**（v2.5.6，76 条缺陷）与 **[docs/GAP-ANALYSIS-v2.8.2.md](docs/GAP-ANALYSIS-v2.8.2.md)**（v2.8.2 增量 + 对上游修复声明的核实） |

**上游提出的核心命题**——「群体智能 = 网络结构的 Scaling Law」、群众化 AGI 路线、
去中心化智能体共享网络、Lv1–Lv7 分层拓扑、结算守恒、BFT-lite 验证、三层记忆、
跨语言规范签名——是本项目的**设计起点**。上游采用 MIT 许可，本项目依 MIT 保留其版权声明
（见 [LICENSE](LICENSE)），并在此明确标注出处。

**本项目不声称与上游作者有隶属关系，也未获其背书。**

---

## 为什么重写：审计发现的三个严重问题

完整清单见 [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)（严重 12 / 高 17 / 中 26 / 低 21）。
其中三条使系统在安全意义上不成立：

### 1. 验收闸门完全由调用方控制（上游 `api/market_actor.rs:360-386`）

```rust
MarketCommand::VerifyResult { task_id, approvals, committee_size, reply } => {
    let n = if committee_size > 0 { committee_size } else { 4 };
    let f = (n - 1) / 3;
    let mut committee = QaCommittee::new(n, f)?;
    for i in 0..n {
        let did = format!("qa-{}", i);              // 现场合成委员
        committee.add_member(did.clone());
        let vote = if i < approvals { QaVote::Stop } else { QaVote::Continue };
        let _ = committee.cast_vote(&did, vote);    // 现场合成票
    }
```

`approvals` 与 `committee_size` 直接来自 HTTP 查询串（`api/rest.rs:214-221`，默认 3 与 4）。
**任何客户端都能自我批准任何任务**，且该工具原样暴露给 LLM 调用者。

**本项目的做法**：`Vote` 是**带签名的 `Verifiable` 结构**，
`Committee::assign` 在构造时固定成员并强制 `members.len() == n`，
`cast()` 校验签名与成员资格。**不存在**任何接受「赞成票数」的 API。

### 2. 结算凭空铸币，且货币是 `f64`（上游 `marketplace/mod.rs:352-355`、`settlement.rs`）

```rust
// 确保付款方有余额
if self.settlement.balance(&payer) < amount {
    self.settlement.deposit(&payer, amount);      // ← 直接造钱
}
```

配合 `conservation_check` 的容差判定（`(balance_sum - expected_sum).abs() < 0.001`，`settlement.rs:173`），
守恒**仍报告 true**——该不变量在结构上无法察觉此事。

**本项目的做法**：`Money(i64)` 整数最小单位，全仓无浮点货币、无 epsilon；
发布即托管，余额不足返回 `InsufficientBalance`；守恒为**精确相等**，
并提供**能够失败**的 O(N) 独立审计（上游有该函数但零调用点）。

### 3. 跨语言签名在真实载荷上不成立

上游规范载荷对同一份回执的默认计量字段产出**三方互不相同的字节**：

| 值 | Python | JavaScript | Rust `serde_json` |
|---|---|---|---|
| `1.0` | `1.0` | `1` | `1.0` |
| `1e21` | `1e+21` | `1e+21` | `1e21` |
| `NaN` | `NaN`（非法 JSON） | `null` | `null` |

因此 **JS/Python 签发的 `Receipt` 无法被 Rust 验证，反之亦然**——
而这是每次任务完成的主路径。上游唯一的跨语言向量
（`tests/cross_lang_signature.rs:13`）**不含任何浮点数**，所以 CI 看不见。

**本项目的做法**：规范载荷**拒绝一切浮点数**（`CanonicalError::NonIntegerNumber`），
货币与计量以整数最小单位承载；`conformance/vectors.json` 把 `100.0`/`1.5`/`1e2`
钉为必须拒绝，并用 10 条向量 + 5 条拒绝用例覆盖三端。

---

## 已验证的上游兼容性

`conformance/vectors.json` 的第一条向量取自**上游自己的测试**
（`gsn-core/tests/cross_lang_signature.rs:11-14`）：

```
seed      = 0x01 × 32
公钥       = 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
上游 DID   = did:aip:34750f98bd59fcfc
规范载荷   = {"capabilities":["text-generation","mcp"],"did":"did:aip:34750f98bd59fcfc","name":"CrossLang","stake":100}
上游签名   = e14d3f9e8204ea185ea4ba32a8117f262095ab9dac1352e1a7964ce36d3355c288dd6804ffa7daeb5f6eba9f30428f52702a75fd3efbb6a62555a7f24665da0e
```

本项目产出的签名**逐字节相同**，且 `Did::parse` 接受上游的 `did:aip:` 前缀。
因此 **agent-universe v2.5.6 铸造的身份与签名在本项目中仍然可验证**。
新身份使用 `did:nau:` 前缀以示区分。

该向量的签名由 `conformance/generate.mjs` 用 **Node/OpenSSL 的 Ed25519** 生成——
与 Rust 实现**不共享任何代码**——所以这是真正的跨实现校验，
而不是上游那种「自己验自己」的自洽检查。

---

## 架构

```
NewAgentUniverseByDeepSeek/
├── crates/
│   ├── nau-core        领域契约：DID/Ed25519、规范 JSON、Money、领域类型。无 I/O、无 async
│   ├── nau-ledger      精确整数账本：账户、托管、罚没；O(1) 守恒 + 可失败的 O(N) 审计
│   ├── nau-consensus   认证式 BFT-lite 委员会：签名投票、法定人数、equivocation 归责
│   ├── nau-store       持久化端口：追加日志 + 原子快照，可容错被截断的末行
│   ├── nau-market      市场服务：注册、确定性匹配、任务生命周期、结算
│   ├── nau-net         传输端口：真实 TCP 分帧 + 确定性 Lv1–Lv7 拓扑 + 中继池
│   ├── nau-agent       分层记忆（真实 SHA-256 溯源链）+ LlmProvider 端口
│   ├── nau-mcp         MCP 服务：单一事实来源的工具定义 + 真实参数校验
│   └── nau-node       组合根：HTTP API、守护进程、CLI
├── conformance/        跨语言唯一事实来源：vectors.json + 生成器
├── sdks/python         零依赖 SDK（纯 Python Ed25519，无需 cryptography）
├── sdks/js             零依赖 SDK（node:crypto）
├── contracts           Foundry 工程：四个合约 + 逐缺陷测试
└── docs                GAP-ANALYSIS / ARCHITECTURE / CONFORMANCE
```

**依赖方向是单向的**（`nau-core` 不依赖任何东西；`nau-node` 依赖一切），
`nau-core` 有 `#![forbid(unsafe_code)]` 且无 I/O。

**依赖策略**：全仓**纯 Rust，无 C 工具链依赖**，不引入 `libp2p` / `rusqlite` /
TLS 栈。原因有二：
(a) 上游的 libp2p 传输层虽真实，但**应用层数据面缺失**——GossipSub 事件从不处理、
DHT 从不 bootstrap、Kademlia 结果全丢弃、DCUtR 从不驱动（GAP-ANALYSIS §5.1）；
(b) 上游的依赖树在本机（8 核 / 16 GB）以 8 路并行 rustc 触发
`rustc-LLVM ERROR: out of memory`，**无法编译**。
本项目通过裁剪依赖 + [`.cargo/config.toml`](.cargo/config.toml) 的 `jobs = 2`、`debug = 0`
使其可构建、可测试。详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

---

## 快速开始

```bash
# 构建并运行全部 Rust 测试
# 内存受限的机器请保留 jobs 限制（8 路并行会 OOM）
CARGO_BUILD_JOBS=2 cargo test --workspace

# 跨语言一致性：生成器可复现检出内容，Rust/Python/JS 都要通过同一组向量
node conformance/generate.mjs
git diff --exit-code conformance/vectors.json

# Python SDK（零依赖，无需 pip install）
python sdks/python/run_tests.py

# JS SDK（零依赖，无需 npm install）
node sdks/js/test/run.js

# 启动守护进程
cargo run -p nau-node --bin nau-daemon -- --api-port 4002
curl http://127.0.0.1:4002/health
```

---

## 与上游的能力对照

| 能力 | 上游 v2.8.2 | 本项目 V1.2.3 |
|---|---|---|
| DID / Ed25519 / 规范签名 | ✅（但浮点使跨语言失效） | ✅ 整数化，三端向量验证 |
| 上游身份向后兼容 | — | ✅ 逐字节命中上游签名 |
| 精确整数账本 + 守恒 | ❌ `f64` + 容差 | ✅ `Money(i64)` + 精确相等 |
| 可失败的独立审计 | ⚠️ 有函数，零调用点 | ✅ 一等 API，有测试证明能失败 |
| 托管 / 防铸币 | ❌ 余额不足时铸币 | ✅ 发布即托管，拒绝无资金 |
| 认证式 BFT-lite | ❌ 调用方合成委员会 | ✅ 签名投票 + 固定成员集 |
| 重放保护 | ❌ 无 nonce | ✅ nonce + 时间戳 + 过期 |
| 状态机恢复边 | ❌ `NoQuorum` 吸收态 | ✅ `no_quorum→open`、`rework→running` |
| 证据分级作为结算闸门 | ⚠️ 有谓词，零调用点 | ✅ 强制门禁 |
| 持久化可读回 | ❌ 只写不读，账本不落盘 | ✅ 往返测试 + 日志重放 |
| MCP 参数校验 | ❌ `unwrap_or(0.0)` 静默降级 | ✅ 派生 schema + `-32602` |
| 合约可部署性 | ❌ 4 个中 3 个不可部署 | ✅ 重写 + 逐缺陷测试 |
| CI 覆盖率真实性 | ❌ 11/17 Python 测试被静默跳过 | ✅ 零依赖，无跳过 |
| 版本一致性 | ⚠️ 手工登记表，已漂移 | ✅ 唯一来源 `VERSION` + 断言 |
| 应用层 P2P 数据面 | ❌ 订阅但从不处理 | ⚠️ **明确不实现**，见下 |
| NAT 穿透 / 纠删码 / TEE | ⚠️ 硬编码或无法恢复 | NAT ✅ 真实 STUN 测量；纠删码 ✅ 任意 k 片可恢复；TEE/zkML 见下方状态更新 |

上游的优势同样如实记录：其 libp2p **传输层是真的**（真实 Noise/Yamux/QUIC/WebSocket、
真实 Relay Client 多通道预订），其 `relay_pool` 是本仓库结构最干净的模块，
其跨语言向量是整份代码库最有价值的产物。这些在 [ATTRIBUTION.md](ATTRIBUTION.md) 中有完整列举。

---

## 明确未实现的范围

为避免重演上游「文档承诺 > 代码事实」的问题（GAP-ANALYSIS §9.6 记录了 12 处以上），
以下能力**本版本没有实现，也没有对外宣称**：

- **不实现 libp2p 网络栈**：提供 `Transport` 端口、真实 TCP 分帧传输与内存替身；
  Kademlia DHT、GossipSub、Circuit Relay v2、AutoNAT、DCUtR 均未实现。
- ~~**不实现 NAT 类型检测**~~（上游返回硬编码常量）→ **V1.1.1 已实现**：真实 RFC 5389 STUN 测量 + RFC 4787 映射/过滤分类，97 个 `nau-net` 测试通过。**仍不宣称任何真实 NAT 类型**（需要可达的公网 STUN 服务器）。
- ~~**不实现纠删码**~~（上游的实现无法恢复丢失的数据分片）→ **V1.1.1 已实现**：GF(256) 系统化 Reed-Solomon，**任意 k 片可恢复**；82 个单元测试 + 9 个文档测试通过，穷举 504 个擦除子集。
- **不实现 TEE / zkML 验证**（上游的 `tee_quote`/`zk_proof` 是不经校验的字符串）—— V1.1.1 有部分进展，且**不会**把它说成硬件证明，见下方状态更新。
- **不提供 GUI 客户端**：上游的 `client/` 与 `desktop/` 合计仅 36 行 Rust、暴露 2 个命令，
  前端**从不调用** Rust 侧；`desktop/` 的图标缺失使 `tauri build` 必然失败，
  且无任何 workflow 构建它。与其发布一个必然失败的 UI，不如不发布。
- **不实现真实 LLM HTTP 调用**：`LlmProvider` 是端口，提供方以数据描述。
- ~~**不迁移上游历史数据**~~（身份层兼容，但存储与账本语义不同，原先无迁移脚本）→ **V1.1.1 已实现** `crates/nau-migrate`：逐字节按十进制文本转换金额（不经过 `f64`），逐条验证上游签名，无法精确表示则类型化拒绝。**只读 JSON/JSONL，没有数据库读取器**。

---

## CI 与发布 / CI and Releases

### CI 状态

徽章见页面顶部。最近 10 次运行**全部 success**。

| Workflow | 触发 | 作业 | 说明 |
|---|---|---|---|
| [CI](.github/workflows/ci.yml) | push / PR / 可复用 | `rust` `python` `js` `conformance` `contracts` `version` `shellcheck` `libp2p` | 主验证。Rust 工具链**固定为项目最低支持版本 `1.85.0`**，三平台矩阵 |
| [Client](.github/workflows/client.yml) | push / 手动 | `verify` `gate` `tauri`（矩阵） | 前端与 Tauri 构建 |
| [CodeQL](.github/workflows/codeql.yml) | push / PR / 定时 / 手动 | `analyze`（矩阵） | 静态安全分析 |
| [Release](.github/workflows/release.yml) | push / 手动 | `verify` · `tag agrees with VERSION` · `build release binaries` · `publish GitHub release` | 发布二进制。**tag 必须与 `VERSION` 一致**，不一致即失败 |
| [Packages](.github/workflows/packages.yml) | tag `v*` / 手动 | `DSH bundle to GitHub Packages` | 把 DSH 插件发布到 GitHub Packages；**已发布则跳过并读回校验**，重跑不会失败 |

### npm 包

| | |
|---|---|
| 包名 | [`@twinsearth/nau-dsh-plugin`](https://www.npmjs.com/package/@twinsearth/nau-dsh-plugin) |
| 版本 | `3.4.5` |
| 协议 | MIT |
| 内容 | **DeepSeek Harness 插件**（bundle）：5 个只读工具 —— `nau_version`、`nau_inspect`、`nau_conformance`、`nau_amount`、`nau_node_status` |
| 源码 | [integrations/dsh](integrations/dsh) |

安装（harness 自带命令）：

```sh
dsh plugin --profile <profile> add @twinsearth/nau-dsh-plugin
```

tarball 直链：`https://registry.npmjs.org/@twinsearth/nau-dsh-plugin/-/nau-dsh-plugin-3.4.5.tgz`

该包**同时发布到两个 registry**：npmjs（公开、免凭据）与
[GitHub Packages](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/packages)
（GitHub Packages 即使公开包也要求凭据）。

### 发布产物

[`v3.4.5` Release](https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases/tag/v3.4.5) 提供：

- `nau`、`nau-daemon` —— 节点二进制
- `SHA256SUMS` —— 校验和
- `twinsearth-nau-dsh-plugin-3.4.5.tgz` —— DSH 插件包（与 npm 上的**逐字节相同**）

### 本地复现全部验证

```sh
node scripts/verify-all.mjs
```

**23 道关卡** + **58 项部署检查**。缺少外部工具时该关卡标为 **SKIP 并列入 NOT VERIFIED**——
不静默通过，也不假装通过；需要全部通过时加 `--allow-missing-tools` 会反过来失败。

---

## 文档

| 文档 | 内容 |
|---|---|
| [ATTRIBUTION.md](ATTRIBUTION.md) | **来源**：保留了哪些设计、替换了什么、为什么 |
| [NOTICE](NOTICE) | 上游版权声明与其 MIT 许可要求的完整转载 |
| [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) | **76 条缺陷**逐条证据（`文件:行号` + 原始代码）与修复映射 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 技术架构、系统框架、依赖策略、端口/适配器分层 |
| [docs/CONFORMANCE.md](docs/CONFORMANCE.md) | 规范载荷规则、跨语言契约、可移植性边界 |
| [CHANGELOG.md](CHANGELOG.md) | 版本记录 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献流程与「先加失败测试」纪律 |
| [SECURITY.md](SECURITY.md) | 安全模型、威胁边界、报告方式 |

---

## 验证记录 / Verification

本机实测（Windows，8 核 / 16 GB，Rust 1.98.1，Node 24，Python 3.12）：

| 检查 | 命令 | 结果 |
|---|---|---|
| Rust 全工作区测试 | `cargo test --workspace` | **320 通过 / 0 失败** |
| Rust 编译 | `cargo build --workspace` | 通过，0 error |
| 格式 | `cargo fmt --all --check` | 通过 |
| Lint 门禁 | `cargo clippy --workspace --all-targets -- -D warnings` | **通过，0 warning** |
| Python SDK | `python sdks/python/run_tests.py` | **171 测试 / 0 失败 / 0 跳过** |
| JS SDK | `node sdks/js/test/run.js` | **223 测试 / 0 失败** |
| 跨语言向量可复现 | `node conformance/generate.mjs` 后比对 | 检出内容**逐字节不变** |
| 上游身份兼容 | `cargo test -p nau-core --test conformance` | 上游签名 `e14d3f9e…da0e` **逐字节命中** |
| UTF-8 完整性 | `node scripts/repair-encoding.mjs --dry-run` | 159 个文本文件全部合法 |

合计 **714 个测试**（Rust 320 + Python 171 + JS 223），**0 跳过**。
作为对照：上游「17 个 Python 测试」中有 11 个在 CI 里被**静默跳过**（GAP-ANALYSIS §9.2）。

**守护进程端到端实测**（真实 TCP + HTTP，`nau-daemon --ephemeral`）：

```
GET  /health                     → {"version":"1.1.1","protocol":"nau/1",
                                    "upstream":"TwinsEarth/agent-universe v2.5.6", …}
POST /accounts/alice/deposit 0.1 → balance_minor 100000
POST /accounts/alice/deposit 0.2 → balance "0.3", balance_minor 300000   ← f64 做不到
GET  /conservation               → conserved true, discrepancy 0
GET  /audit                      → 与 O(1) 结果一致
GET  /tasks/x/settle             → 405（读方法不得触发结算）
GET  /nope                       → 404
POST /accounts/bob/deposit 12.5  → 422（拒绝浮点金额）
```

CLI 实测：`nau version` / `nau identity` / `nau amount 12.5`（→ `minor 12500000`）/
`nau conformance`（复现夹具身份并完成一次签名-验签）/ `nau verify`（规范化 stdin 载荷）。

**未在本机验证的部分（诚实记录，避免重演上游「文档承诺 > 代码事实」）：**

* **Solidity 合约未编译**：本机无 `forge`/`solc`。合约含 5 个测试文件（含余额不变量与 fuzz 测试）
  与部署脚本，由 CI 执行 `forge fmt --check`、`forge build --sizes`、`forge test -vvv`。
* **GUI 客户端未构建**：该应用已从本项目移除（理由见上）。
* **上游 `gsn-core` 在本机无法编译**（其依赖树在 8 路并行 rustc 下触发 LLVM OOM），
  因此 76 条缺陷中涉及**运行时**行为的判断基于源码阅读而非执行，
  已在 [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) §0 与各条中逐处标注。

---

## V1.2.3：对上游 v2.8.2 的增量审计，以及由此产生的加固

V1.1.1 审计的是上游 **v2.5.6**（[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)，76 条缺陷）。
上游随后从 v2.5.6 迭代到 **v2.8.2**（Rust 从 15 文件 / 15,735 行增长到 **153 文件 / 21,530 行**），
于是 V1.2.3 做了一件不同性质的事：**核实上游的修复声明是否成立**，并审计它新增的代码。

**一个必须如实记录的事实：上游把本项目的审计当成了修复路线图。**
`grep 'GAP §'` 在上游 `gsn-core/src` 中命中 **52 处**，其 `CHANGELOG.md`/`RELEASES.md` 逐条引用本审计的章节号
（v2.5.8 引用 §2.1–2.3 修 f64 账本，v2.6.2 引用 §9.3/§9.4/§5 修合约与纠删码，v2.7.2 引用 §5.6 修 NAT，等等）。
审计 → 修复的因果关系与时间顺序已留在 [ATTRIBUTION.md](ATTRIBUTION.md)。

### 核实结果：三类，第三类最有信息量

**一、真的修了（必须保住，不许回退）**
整数 `Money(i64)` + 精确相等守恒（无 epsilon、无 f64）；只重放日志、按账户比对的**可失败独立审计**；
`route_hops` 真实求 LCA 而非常量 7；边数 10k vs 20k 规模对照；房间分配 `BTreeSet` 顺序无关；
**真 SHA-256 哈希链**且报出首个断链索引；**真 LRU**（测试在 LFU 下会失败）；`blind_attempt` 死循环逃逸；
**纠删码真的用 `reconstruct` 从校验片重建**；网络替身诚实化（旧名零命中，新名逐文件声明「这不是真实 DHT」）。

**二、仍是老样子**
NAT 模块仍然 `#[allow(dead_code)]` **无任何调用点**；`LocalSniffer` 仍是空操作；`MeshNode`/`ModeController`
零调用点；中继**健康统计在重新添加时被覆盖**（已死中继可复活）；**硬编码第三方 bootstrap 仍在**；
`PeerEvent::Gossipsub` 仍无消费者；信誉「半衰期 90 天」仍是空话（无时间输入）；**仍无退出/解押路径**。

**三、声明不被代码支持（本次审计的主要产出）**

| 上游声明 | 代码现实 |
|---|---|
| v2.7.2「NAT 占位检测不再猜测类型」 | 只把骗人的常量换成诚实的常量；仍不测量、仍无调用点；守护进程的守卫测试是 `assert!(!nat_type.is_empty())`——**任何新的编造值都能通过** |
| v2.6.2「数据片丢失可靠校验片真实重建」 | 实现为真，**但被指名证明它的测试把 6 个分片全部交回**（`tests/v232_test.rs:382-396`），正是 v2.5.6 被批评的手法；真正做恢复的测试在别处且未被引用 |
| v2.6.4「消除八处时钟 panic」 | **至少十条仍在**，三条就在被点名的文件里 |
| v2.6.4「弱公钥拒绝」 | `is_weak_pubkey` **零非测试调用点** |
| v2.6.4「贡献验证绑定身份」 | 签名覆盖了 DID 字符串，但**从不校验 DID↔公钥**，一把密钥可伪造多个 DID 绕过去重 |
| v2.6.3「终局拒绝可达」 | `reject_task` 零生产调用点，唯一调用者是测试 |
| v2.6.1「tools/call 执行前用 schema 校验」 | 校验器只被 `McpServer` 调用，而 **`McpServer` 零生产调用点**；两个真实传输都绕过它 → `market_deposit {"amount":"lots"}` **存入 0 并返回成功** |

### v2.8.2 新增代码里的严重缺陷（详见 [docs/GAP-ANALYSIS-v2.8.2.md](docs/GAP-ANALYSIS-v2.8.2.md)）

* **账本日志没有任何完整性保护**：`independent_audit` 声明只信任只追加日志，而该表只有 `(seq, payload)`，
  无哈希链、无签名、无校验和 → 任何能写库文件的人插一行 `Deposited`，**守恒与审计都会报告 `conserved: true`**。
* **重启会静默关闭证据闸门**：恢复任务时把 `verification_policy` 置为 `None`、`winner_price` 置为 `None`，
  于是每个从磁盘恢复的任务都豁免证据检查并按**满额预算**付款——**「重启」本身就是一条绕过路径**。
  同一层还有：结果信封不落盘（重启后永久无法结算）、信誉与质押不落盘（重启后所有 agent 无法出价、
  罚没路径报「无质押记录」**而资金仍在账上**）。
* **新的 Agent Sandbox（1,847 行）三个 critical**：所谓隔离就是 `Command::new("bash")`（全仓无
  `unshare/setrlimit/seccomp/chroot/cgroup`）；`safe_join` 只约束 Rust 侧 helper、**从不约束子进程**；
  `POST /api/v1/sandboxes/{id}/exec` **完全无认证**且无所有权模型，id 是可猜的 `sb-N` 计数器
  （重启后复用目录 → 跨请求文件泄露）。`NetworkGuard`/`PermissionChecker`/`AuditLog`/`ExecutionToken`
  **生产调用点全为零**；六项资源限制只有两项真实生效，**Windows 分支一项都没有**；stdout/stderr 无上限读取。
* **六个新模块（mesh/swarm/scheduler/collaboration/crowdsource/security，约 2,600 行）全部 fail-open**：
  `LightweightConsensus::vote` **接受投票者自报权重**（`weight: u64::MAX` 可通过任意提案）；
  `complete_task` 无状态前置条件（**可反复领取奖励**）；`assign_task` 除以空候选列表 **panic**；
  `security/` 头部声称「身份验证/数据签名」而文件里**没有任何密码学调用**。
* **状态转换被直接赋值绕过**，`open_dispute`/`arbitrate` **无操作者身份**且罚没金额**由请求体决定**；
  REST 侧**完全没有认证**（免费无上限的 deposit、任意罚没），并配 `Access-Control-Allow-Origin: *`
  且无 Origin/Host 校验；请求体无上限、无读超时。

### V1.2.3 的响应

对应上述每一条，V1.2.3 的原则只有一句：
**边界要么由代码强制执行，要么让请求失败——绝不接受一个策略然后忽略它。**

* 账本日志加**哈希链 + 锚定 head**，恢复与审计时报**首个断链序号**；只声称 **tamper-evident**，
  并明确写出「能重写整份文件者仍可如何」。
* 持久化并恢复 `verification_policy`、结果信封与 `evidence_grade`、`winner_price`、信誉与质押；
  用**关闭再打开**的测试断言「重启不放宽任何闸门」。
* 水位从**与恢复相同的过滤后列表**派生；解析失败**显式报告**；追加失败**返回错误且不推进水位**；
  恢复失败**拒绝服务或在 API 上显式标注降级**。
* 状态变更只经转换函数；终态无入边；证据提升只发生在转换成功之后。
* sandbox 默认后端是 **`NullExecutor`：什么也不执行**；唯一执行的后端必须**声明它强制执行的边界**，
  策略无法强制就**拒绝并说出是哪条**；Windows 用 **Job Object** 强制内存/进程数上限与整棵进程树 kill；
  输出有上限；id 密码学随机并经单一校验函数；启动清扫孤儿；认证与所有权覆盖每个路由。
* 共识权重**由记录的质押派生**而非入参；奖励发放要求真实状态转换且只发一次；
  所有除零点与非有限浮点改为类型化错误。
* 委员集合必须来自**服务端状态**并绑定 DID↔密钥；规范签名载荷**拒绝任何非整数**；
  金额入口拒绝 JSON 浮点，**不再有 `as f64 as i64`**。

## 把同一套标准用在自己身上：自审

对上游的主要批评不是「代码坏」，而是**文档承诺 > 代码事实**、**声明没有测试支撑**、
**策略写了但没有执行点**。只对上游用这套标准、不对自己用，它就只是一种修辞。
因此 [`docs/SELF-AUDIT.md`](docs/SELF-AUDIT.md) 用同一格式（声明 → 证据 → 裁定）检查本项目自己，
并如实记录了它发现的东西：6 处生产代码的 `expect()` 与本项目自己写的「`#[cfg(test)]` 之外无 panic 路径」冲突；
一个名为 `expect` 但返回 `Result` 的方法会污染 grep 审计；
以及**本项目的版本升级脚本自己复现了它本来要修的那类缺陷**——
模式 `nau-[a-z]+` 匹配不到含数字的 `nau-libp2p`，于是 13 个目标里漏掉 1 个而脚本仍报成功（已修，并加了交叉校验）。
该文件同时写明**审计方法本身的局限**：朴素 `grep unwrap` 会把文档注释里引用的上游代码算进去，
第一次扫描报 312 处而真实生产命中只有 6 处——所以「按 grep 计数」当缺陷证据不可靠，对上游与本项目都一样。

## 声明 → 关卡：每条能力声明由哪道关卡验证

[`docs/VERIFICATION.md`](docs/VERIFICATION.md) 把 README 里的每一条能力声明映射到**验证它的那道关卡**，
并集中列出**没有实现或没有验证的东西及其理由**。
它存在的理由是本项目对上游的主要批评：**「实现了」与「验证过」不是同一件事**——
一份把两者混在一起的 README 就是在把信任洗白。所以那张表里每一行都指明关卡名，
而关卡名对应 `verify-all` 输出里的一行，**你可以自己跑一遍看它是不是绿的**。
状态刻意不写进那个文件（写死的状态会腐坏），当前结果由关卡打印，并逐次粘贴进对应的 Release 说明。

## 一条命令复现全部验证

本项目的立场是「文档承诺 ≤ 代码事实」，所以验证过程本身也必须可复现、可审计：

```bash
node scripts/verify-all.mjs
```

它按顺序跑每一道关卡——Rust 格式、`Cargo.lock` 与 manifest 是否一致、
`cargo test --workspace`、`cargo clippy -D warnings`、conformance 向量是否逐字节可复现、
Python SDK、JavaScript SDK、浏览器客户端端到端、合约静态检查、`forge build`、
`forge test`——并输出一张表。

**关键设计：缺少工具是「未验证」而不是「通过」。** 上游的检查会在依赖缺失时
静默跳过自己（审计发现其 Python CI 跳过了 17 个测试中的 11 个然后报绿）。
这里的区别是显式的：

* 缺少 `forge`/`python` 等工具时，该行输出 `SKIP` **并打印启用它的确切命令**；
* 只要出现任何 `SKIP`，退出码就是非 0，除非显式加 `--allow-missing-tools`；
* 结尾单独列出 `NOT VERIFIED` 清单——因为「没看」和「看过了没问题」必须能区分。

其中的 `deploy` 关卡会**真的把 release 二进制装到前缀目录、用持久化数据目录启动守护进程、
走真实 HTTP、再用 CLI 读同一份磁盘状态，最后重启并断言状态仍在**——
它是唯一覆盖「重启后状态是否存活」的关卡，也正是它发现了「重启会让余额凭空增加」的
账本重复缺陷（详见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)）。

可用 `--only=<id列表>` 只跑其中几项，用 `--quick` 跳过慢的编译与测试关卡。
Rust 版本默认钉在 CI 验证的 MSRV（`1.85.0`），可用 `NAU_RUST` 覆盖；
`FORGE_BIN`、`SOLC_BIN`、`NAU_PYTHON` 用于指定本机工具路径。

## V1.1.1 状态更新（覆盖上文的「未实现」清单）

V1.0.1 曾明确列出七项「未实现」，并把它们写进文档而不是留空。
V1.1.1 实现了其中四项，并如实标注**验证程度**（这是本项目对上游「文档承诺 > 代码事实」的纠正）：

| 能力 | 状态 | 验证程度（实测） |
|---|---|---|
| NAT 类型检测 | **已实现**：RFC 5389 STUN 编解码 + RFC 4787 映射/过滤行为分类 | 对本地 UDP STUN 服务器实测；`nau-net` 97 个测试通过，其自身测试发现并修复了 4 个协议缺陷（IPv6 掩码越界、XOR 偏移错误、CHANGE-REQUEST 位序反了、legacy MAPPED-ADDRESS 解错）。**不宣称任何真实 NAT 类型**：分类真实 NAT 需要可达的公网 STUN 服务器，本机不具备，因此不可达时返回 `Unknown` 而不是猜测 |
| 纠删码 | **已实现**：GF(256) + 系统化 Reed-Solomon（**生成多项式/余式构造**），n = k+m ≤ 255 | `cargo test -p nau-erasure`：**82 单元测试 + 9 文档测试全部通过，exit 0，零警告**。穷举 **504 个擦除子集**（(2,1)/(3,2)/(4,2)/(5,3) × 6 种载荷长度，覆盖全部 C(n,k)），包含「全部数据片丢失、仅剩校验片」这一上游永远无法处理的场景。校验字节确为 m(x)·x^m mod g(x)，`C(a^r)=0 (r<m)` 恒等式有断言。**明确不实现纠错**（无 Berlekamp-Massey/Forney/syndrome）：损坏但未声明丢失的分片会产生**错误结果**，这一点由测试断言，需要上层校验和/MAC 检测 |
| 真实 LLM HTTP 调用 | **已实现**：`nau-http` 真实 HTTP/1.1（分块解码、截断检测、超时、体积上限）+ OpenAI/Anthropic/Gemini/DeepSeek 形状的提供方层 | 29（`nau-http`）+ 34（`nau-agent` provider）测试通过；空 `choices`/`content` 是类型化错误而非 panic。**TLS 路径已编译（rustls+ring 可编译）但未经测试执行**：本机出站 TLS 不可用，因此未启用 feature 时 `https://` 在建立 socket 之前就返回类型化错误，绝不静默降级为明文 |
| GUI 客户端 | **已实现**：浏览器客户端（真实调用守护进程）+ Tauri 2 外壳 | 浏览器客户端 **端到端 81 项断言通过**：真实 HTTP、真实 Ed25519 签名（`crypto.subtle`）、完整市场生命周期、`conservation`/`audit` 一致、浮点金额 422、读方法 405。**Tauri 外壳未编译、未运行**（仅源码 + CI 工作流），因为本机对同等依赖树曾触发 `rustc-LLVM out of memory` |

### 七项全部落地，但「落地」不等于「同等可信」——逐项标注验证程度

| 能力 | 状态 | 实测到什么程度 / 硬限制是什么 |
|---|---|---|
| **libp2p 网络栈** | ✅ 真实可用 | `crates/nau-libp2p`：TCP + Noise + Yamux + Kademlia + GossipSub + Circuit Relay v2 + AutoNAT + DCUtR + identify/ping 组合进一个真实 swarm，并适配到 `nau_net::Transport` 端口。**88 个测试通过**，其中真实多节点测试覆盖：dial + identify、GossipSub 投递（且断言发送者归属）、跨节点 Kademlia 记录、relay reservation。<br>**未验证**：DCUtR 打洞与 AutoNAT 可达性。理由是诚实的——环回测试里「打洞成功」只是拨通了本地地址，那种测试**不测任何东西也会通过**，比承认缺口更糟。AutoNAT 只断言「返回 `Unknown` 而不是编造 NAT 类型」。<br>**代价**：为守住 MSRV 1.85 裁掉了 `dns/quic/tls/websocket`，因此**没有 QUIC、没有 DNS 解析**，bootstrap 必须是 IP 形式的 multiaddr。 |
| **NAT 类型检测** | ✅ | 真实 RFC 5389 STUN + RFC 4787 分类，97 个测试。**不宣称任何真实 NAT 类型**。 |
| **纠删码** | ✅ | GF(256) 系统化 Reed-Solomon，82 + 9 测试，穷举 **504 个擦除子集**。**不做纠错**。 |
| **TEE / zkML 验证** | ⚠️ **部分，且刻意如此** | `crates/nau-attest`：63 + 1 测试。验证的是「信封结构 + 固定根签名 + nonce 绑定 + 新鲜度 + payload 绑定」，**四种格式全部返回 `ChainNotImplemented`**，`HardwareAttested` 由构造保证不可达——因为没有实现 Intel/AMD 证书链。Merkle 承诺/包含证明是真的，但它**不是零知识、不简洁，也不证明计算被执行正确**（包含证明对垃圾输出同样成立，这一点有专门测试）。**这才是对上游 `tee_quote` 是不经校验字符串的正确回应**：换成一个范围明确的可验证性质，而不是换一个更好听的名字。 |
| **GUI 客户端** | ✅ 浏览器客户端 | 端到端 **81 项断言**通过（真实 HTTP、真实 Ed25519 签名、完整市场生命周期）。**Tauri 外壳未编译未运行**（仅源码 + CI）。 |
| **真实 LLM HTTP** | ✅ | `nau-http` 真实 HTTP/1.1 + 四个提供方形状，63 测试。**TLS 可编译但无任何测试执行**（本机无出站 TLS），未启用时不静默降级。 |
| **上游历史数据迁移** | ✅ | `crates/nau-migrate`，65 测试。金额**逐字节按十进制文本**转换（绝不经过 `f64`），无法精确表示则**类型化拒绝**；上游签名用本项目规范化规则逐条验证。限制：只读 JSON/JSONL，**没有数据库读取器**（上游确实有 SQLite，但只写不读、且没有任何账本表）；测试夹具是**按审计结果建模**而非真实抓取。 |

**仍然未做、且不会伪装成已做**：真实硬件证明链（Intel/AMD PKI）、任何证明系统（zkML）、DCUtR/AutoNAT 的真实网络验证、QUIC、DNS 解析、上游 SQLite 文件级迁移。

## 开源协议

[MIT](LICENSE) — 同时载明本项目与上游 `Agent Universe Contributors` 的版权声明。

---

**NewAgentUniverseByDeepSeek · V1.2.3**

*Upstream: **Agent Universe · 智能体宇宙** — 让科技造福全人类！*
