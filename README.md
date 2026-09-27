# NewAgentUniverseByDeepSeek · V1.0.1

> **基于对 `TwinsEarth/agent-universe` v2.5.6 全量源码审计的全新架构重写。**
> A clean-room rewrite of the agent-universe design, produced from a line-by-line audit
> of upstream v2.5.6.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B%20edition%202021-orange.svg)](https://www.rust-lang.org/)
[![Python](https://img.shields.io/badge/python-3.10%2B%20stdlib--only-blue.svg)](sdks/python)
[![Node](https://img.shields.io/badge/node-18%2B%20zero--deps-green.svg)](sdks/js)

---

## 来源 / Provenance — 请先读这一段

| | |
|---|---|
| **上游项目** | [TwinsEarth/agent-universe](https://github.com/TwinsEarth/agent-universe) — **Agent Universe（智能体宇宙）** |
| **上游版本** | **v2.5.6**（Rust crate `gsn-core` `0.2.56`），MIT 许可，`Copyright (c) 2026 Agent Universe Contributors` |
| **审计规模** | 全部 **648 个文件**：Rust 15,735 行 / Python 934 行 / JS 1,373 行 / Solidity 216 行 / 文档 23,039 行 / 论文 PDF 114 份 |
| **本项目** | **NewAgentUniverseByDeepSeek V1.0.1** — 依据审计结论进行的**重写**，非复刻、非重命名 |
| **来源说明** | **[ATTRIBUTION.md](ATTRIBUTION.md)** — 逐项列出保留了什么、替换了什么、放弃了什么 |
| **审计全文** | **[docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md)** — **76 条缺陷**，每条附 `文件:行号` 证据与原始代码 |

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

| 能力 | 上游 v2.5.6 | 本项目 V1.0.1 |
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
| NAT 穿透 / 纠删码 / TEE | ⚠️ 硬编码或无法恢复 | ⚠️ **明确不实现**，见下 |

上游的优势同样如实记录：其 libp2p **传输层是真的**（真实 Noise/Yamux/QUIC/WebSocket、
真实 Relay Client 多通道预订），其 `relay_pool` 是本仓库结构最干净的模块，
其跨语言向量是整份代码库最有价值的产物。这些在 [ATTRIBUTION.md](ATTRIBUTION.md) 中有完整列举。

---

## 明确未实现的范围

为避免重演上游「文档承诺 > 代码事实」的问题（GAP-ANALYSIS §9.6 记录了 12 处以上），
以下能力**本版本没有实现，也没有对外宣称**：

- **不实现 libp2p 网络栈**：提供 `Transport` 端口、真实 TCP 分帧传输与内存替身；
  Kademlia DHT、GossipSub、Circuit Relay v2、AutoNAT、DCUtR 均未实现。
- **不实现 NAT 类型检测**（上游返回硬编码常量）。
- **不实现纠删码**（上游的实现无法恢复丢失的数据分片）。
- **不实现 TEE / zkML 验证**（上游的 `tee_quote`/`zk_proof` 是不经校验的字符串）。
- **不提供 GUI 客户端**：上游的 `client/` 与 `desktop/` 合计仅 36 行 Rust、暴露 2 个命令，
  前端**从不调用** Rust 侧；`desktop/` 的图标缺失使 `tauri build` 必然失败，
  且无任何 workflow 构建它。与其发布一个必然失败的 UI，不如不发布。
- **不实现真实 LLM HTTP 调用**：`LlmProvider` 是端口，提供方以数据描述。
- **不迁移上游历史数据**：身份层兼容（上面已证明），但存储与账本语义不同，无迁移脚本。

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
GET  /health                     → {"version":"1.0.1","protocol":"nau/1",
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

## 开源协议

[MIT](LICENSE) — 同时载明本项目与上游 `Agent Universe Contributors` 的版权声明。

---

**NewAgentUniverseByDeepSeek · V1.0.1**

*Upstream: **Agent Universe · 智能体宇宙** — 让科技造福全人类！*
