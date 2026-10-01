# 来源说明 / Attribution and Provenance

**NewAgentUniverseByDeepSeek V1.2.3**

本文件明确说明本项目的来源、与上游项目的关系、保留了哪些设计、以及哪些部分是全新的。
**This file states, precisely and verifiably, what this project derives from, what it
preserves, and what is new.**

---

## 1. 上游项目 / Upstream project

| 项目 | 值 |
|---|---|
| 名称 | **Agent Universe（智能体宇宙）** |
| 仓库 | <https://github.com/TwinsEarth/agent-universe> |
| 审计版本 | **v2.5.6**（`gsn-core` `0.2.56`）与 **v2.8.2**（`gsn-core` `0.2.82`）两次审计 |

### 1.1 上游采用了本项目的审计作为修复路线图（如实记录）

这一因果关系应当在时间顺序上留档，因为它同时说明了本项目的价值与它的边界。

本项目的首次审计（对上游 v2.5.6，即 [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) 的 76 条缺陷）
发布之后，上游在 v2.5.7 → v2.8.2 的迭代中**逐条引用本审计的章节号**推进修复：

```
v2.5.8  修复：精确整数账本（Money），根治 f64 跨语言守恒失效          （GAP §2.1–2.3）
v2.5.9  修复：认证式 BFT、可失败独立审计、重放保护                    （GAP §2.4/§2.5/§3.1/§4.7）
v2.6.1  修复：账本落盘与重放恢复、MCP 参数校验                        （GAP §6.1/§8.1）
v2.6.2  修复：版本唯一来源、合约可部署、纠删码真修与网络替身诚实化    （GAP §9.3/§9.4/§5）
v2.6.4  修复：BFT checked 算术 + 规范签名 Result 化 + 时钟端口 + 弱公钥拒绝（GAP §3.3/§3.6/§4.2–§4.9）
v2.6.7  修复：真 SHA-256 链存载荷 + 真 LRU + 派生质量防污染 + 盲猜死循环（GAP §7.1–§7.4/§7.7）
v2.6.8  修复：MCP 认证闸门与 LLM 去 panic                            （GAP §7.5/§8.3/§8.4/§8.5/§8.8）
v2.7.2  修复：NAT 占位检测不再猜测类型                                （GAP §5.6）
```

`grep 'GAP §'` 在上游 `gsn-core/src` 中命中 **52 处**。可自行核实：

```bash
# 取得上游 v2.8.2 后
curl -sL https://codeload.github.com/TwinsEarth/agent-universe/tar.gz/refs/tags/v2.8.2 | tar xz
cd agent-universe-2.8.2 && grep -rn 'GAP §' gsn-core/src | wc -l   # => 52
grep -n 'GAP §' CHANGELOG.md | head
```

**两点必须同时说清楚，否则这段记录就会变成自我表扬：**

1. 本项目**没有**参与上游的代码；上游的修复是上游自己写的，本项目只提供了缺陷清单。
   因此「已修复」的判定权仍在上游，而本项目的第二次审计（V1.2.3 的 [docs/GAP-ANALYSIS-v2.8.2.md](docs/GAP-ANALYSIS-v2.8.2.md)）
   只是**核实**那些声明，并且发现了相当一部分**声明与代码不符**。
2. 上游对 v2.5.6 的修复**引入了新的、更严重的缺陷**——账本日志无完整性保护（守恒与审计同时失效）、
   重启关闭证据闸门、以及一个无认证、无隔离原语的 sandbox 子系统。
   这说明「按清单修好了」与「系统变安全了」是两件不同的事，本项目对此的立场是不把审计报告当作保证。
| 提交形态 | `main` 分支 tarball，283 MB，648 个文件 |
| 许可证 | **MIT** — `Copyright (c) 2026 Agent Universe Contributors` |
| 作者 | TwinsEarth 及 Agent Universe 贡献者 |

上游项目提出的核心命题——**「群体智能 = 网络结构的 Scaling Law」**、群众化 AGI 路线、
去中心化智能体共享网络、Lv1–Lv7 分层拓扑、结算守恒、BFT-lite 验证、三层记忆体系、
跨语言规范签名——是本项目的**设计起点**。

上游采用 MIT 许可证。MIT 允许使用、修改、再分发与再许可，
**前提是保留原版权声明与许可声明**。这正是本文件存在的原因，
也是 [`LICENSE`](../LICENSE) 同时载明两行版权声明的原因。

---

## 2. 本项目与上游的关系 / The relationship

本项目是**依据对上游 v2.5.6 全量源码的逐行审计而进行的重写（clean-room rewrite）**，
不是上游的复刻、不是重命名、不是版本迭代。

### 2.1 审计范围（已验证的事实基础）

审计覆盖上游仓库的**全部 648 个文件**：

| 类别 | 数量 | 行数 |
|---|---|---|
| Rust 源码（`gsn-core`） | 131 个 `.rs` | 15,735 行 |
| Python SDK（`aip-sdk-py`） | 12 个 `.py` | 934 行 |
| JavaScript SDK（`js`、根 `index.js`） | 14 个 `.js` | 1,373 行 |
| Solidity 合约（`contracts/src`） | 4 个 `.sol` | 216 行 |
| 文档（`.md`） | 79 个 | 23,039 行 |
| 论文 PDF（`docs/papers`） | 114 个 | — |
| CI/部署脚本（`.yml`、`.sh`） | 10 个 | 705 行 |
| Tauri 客户端（`client`、`desktop`） | Kotlin/Gradle/XML/TS 等 | — |

审计结论、缺陷编号与证据（`文件:行号` + 原始代码引用）完整记录在
[`docs/GAP-ANALYSIS.md`](GAP-ANALYSIS.md)。**该文档是本项目最主要的来源凭证**：
它逐条记录了我们从上游读到了什么、以及为什么重写。

审计范围不止默认分支：上游的 **6 个分支、12 个 PR、12 个标签与发布**
均已查询并记录在 [docs/GAP-ANALYSIS.md §12](GAP-ANALYSIS.md)。
要点：唯一的非自动分支 `feat/gsn-daemon-real-network`（PR #8）
**已合并进 main**，其余 5 个为 dependabot 依赖升级分支且**未合并**，
因此对 `main` 的全量审计已覆盖上游的实际代码。
上游 MIT 许可要求的版权声明转载见 [`NOTICE`](NOTICE)。

### 2.2 明确保留自上游的设计 / Deliberately preserved

以下设计**有意保留**，因为审计认定它们是正确的。保留处均在源码中以
`upstream v2.5.6` 注释标注。

| 保留项 | 上游位置 | 保留理由 |
|---|---|---|
| DID 推导算法 | `identity/did.rs:9-15`；`aip/crypto.py:41-44`；`js/lib/aca.js:71-72` | `sha256(原始32字节公钥) 前 8 字节` 的构造是可互操作的，且已被跨语言验证 |
| 规范载荷语义 | `aca/crypto.rs:19-25`；`aip/crypto.py:47-56` | 移除 `signature`、紧凑分隔符、键排序、非 ASCII 不转义——语言中立的签名封装 |
| 跨语言测试向量 | `tests/cross_lang_signature.rs:11-14` | **仓库中最好的产物**：固定种子 `[0x01;32]` 的三端一致向量 |
| 结算守恒不变量 | `marketplace/settlement.rs:162-183` | `balance_sum = total_budget − total_slashed`，O(1) 增量维护 + O(N) 独立对账的分工 |
| 命名空间托管账户 | `js/lib/market.js:56-58` | `__stake__:<id>` 内部账户使守恒可 O(1) 审计 |
| BFT-lite 参数与规则 | `marketplace/qa_committee.rs:52-132` | `n ≥ 3f+1`、`q = 2f+1`、equivocation 整轮作废、`silence > f ⇒ NoQuorum` |
| 六字段任务规范 | `marketplace/task.rs:78` | `goal / context / done / todo / trace / owner` 的交接纪律 |
| 证据分级 | `marketplace/evidence.rs:12-33` | `verified / cpu-proto / unverified`，默认 fail-closed |
| 中继分类优先级 | `relay_pool/mod.rs:66-73` | `Dedicated > SelfHosted > ThirdParty > General`，按 `fail_count` 打破平局 |
| 中继池容量公式 | `relay_pool/mod.rs:99-124` | 纯函数、可复现、有单元测试 |
| actor 独占状态模型 | `api/market_actor.rs:159-197` | 单一所有者 + `mpsc`/`oneshot`，消除 TOCTOU 与锁序问题 |
| 任务 ID 幂等结算 | `settlement.rs:97-107` | 唯一真正生效的经济护栏 |
| 三态存活判定 | `mesh/heartbeat.rs:87-96` | `Online/Suspicious/Offline` 的滞回逻辑 |
| SN→DID 委托与会话计数 | `mesh/session.rs:32-67` | 临时身份绑定永久身份 |
| 分层拓扑 Lv1–Lv7 概念 | `topology/layer.rs` | 分层与有界扇入的**意图**正确（实现有缺陷，见下） |
| 确定性种子实验 | `swarm/memory.rs:29-50` | SplitMix64，跨平台位一致，单变量对照 |
| 沙箱诚实降级契约 | `sandbox/mod.rs:23-29` | `EnvBlocked` 显式失败，不静默降级 |
| 发行版登记表与回归套件编号 | `docs/version-checklist.md`；`test/regression.js` | 概念优秀（机制被替换，见 GAP-ANALYSIS） |

### 2.3 明确放弃或替换的上游实现 / Replaced or dropped

| 上游实现 | 本项目做法 | 原因 |
|---|---|---|
| `libp2p` 0.54（Noise/Kad/GossipSub/QUIC/Relay/DCUtR） | 自定义 `Transport` 端口 + 真实 TCP 分帧传输 | 上游的 libp2p 传输层是真的，但**应用层数据面缺失**：GossipSub 事件从不处理、DHT 从不 bootstrap、Kademlia 结果全丢弃、DCUtR 从不驱动。编译 libp2p 亦会在此类低内存机器上 OOM |
| `rusqlite`（bundled） | 纯 Rust 追加日志 + 原子快照 | 需要 C 工具链；且上游的存储是**只写不读**的（`load_agents`/`load_tasks` 零调用点），账本从未持久化 |
| 手写 HTTP 解析 | 类型化路由 + 强制方法与状态前置条件 | 上游几乎所有路由都忽略 HTTP 方法（`GET /tasks/:id/settle` 可结算），并用中文字符串 `contains("不存在")` 决定 404/422 |
| Tauri 客户端 `client/` 与 `desktop/` | **放弃** | 两个应用合计仅 36 行 Rust、暴露 2 个命令，且前端**从不调用** Rust 侧；`desktop/` 是 `client/` 的真子集且无任何 workflow 构建（图标缺失，`tauri build` 必然失败）。详见 GAP-ANALYSIS |
| 单一 15.7 kLOC crate、31 个顶层模块 | 依赖有序的 10 个 crate 工作区 | 上游 `node.rs` 是 1,228 行的「上帝函数」，且存在 `net/dht.rs`、`net/gossip.rs`、`net/libp2p_node.rs` 三个与真实实现同名的内存 mock，并被 crate 根重新导出，导致集成测试对着 `HashMap` 「证明」了联网能力 |

---

## 3. 兼容性承诺（已用测试证明）/ Proven compatibility

本项目**不是**与上游互操作的替代品，但**身份层保持兼容**，并有测试证明：

`conformance/vectors.json` 的第 1 条向量 `upstream-v2.5.6-compat` 是**上游自己钉住的向量**
（`gsn-core/tests/cross_lang_signature.rs:11-14`）：

```
seed            = 0x01 × 32
public key      = 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
did:aip: (上游) = did:aip:34750f98bd59fcfc
canonical       = {"capabilities":["text-generation","mcp"],"did":"did:aip:34750f98bd59fcfc","name":"CrossLang","stake":100}
signature       = e14d3f9e8204ea185ea4ba32a8117f262095ab9dac1352e1a7964ce36d3355c288dd6804ffa7daeb5f6eba9f30428f52702a75fd3efbb6a62555a7f24665da0e
```

本项目产出的签名与此**逐字节相同**，且 `Did::parse` **接受**上游的 `did:aip:` 前缀
（`crates/nau-core/src/identity/mod.rs`，常量 `DID_PREFIX_LEGACY`）。
因此**上游 v2.5.6 铸造的身份与签名在本项目中仍然可验证**。
本项目的身份铸造使用 `did:nau:` 前缀以示区分。

该向量由 `conformance/generate.mjs` 使用 **Node/OpenSSL 的 Ed25519** 生成——
与 Rust 实现不共享任何代码——因此这是真正的跨实现校验，
而不是上游那种「自己验自己」的自洽检查。

---

## 4. 未使用上游的代码 / No code copied

本项目**没有复制上游的源代码文件**。Rust、Python、JavaScript 实现均为重新编写：

* 结构不同（工作区拆分 vs 单 crate；端口/适配器 vs 直接调用；整数货币 vs `f64`）；
* 类型不同（`Money(i64)` vs `f64`；`NauError` 分类 vs `String`；带签名与非签名的 `Verifiable` 结构 vs 无签名结构）；
* 算法在保留处重新实现（规范载荷、DID、结算、BFT-lite），在缺陷处重新设计。

上游的**领域词汇**（AgentCard、TaskSpec、BftLite、EvidenceGrade、RelayClass、
Dedicated/SelfHosted/ThirdParty/General、Lv1–Lv7 等）作为设计概念沿用，
这是「注明来源」的实质内容。

`conformance/vectors.json` 中 `upstream-v2.5.6-compat` 一条**引用了上游测试文件中的常量值**
（公钥、DID、规范载荷、签名）——这是测试数据，不是代码，且其用途正是证明兼容性。

---

## 5. 如何自行核实 / How to verify these claims yourself

```bash
# 1) 取得上游 v2.5.6 以供比对
git clone --depth 1 https://github.com/TwinsEarth/agent-universe.git _upstream

# 2) 读取本项目的逐条缺陷分析（含 文件:行号 证据）
#    docs/GAP-ANALYSIS.md

# 3) 运行跨语言一致性测试
node conformance/generate.mjs
git diff --exit-code conformance/vectors.json   # 生成器可复现检出内容
cargo test -p nau-core                          # Rust 侧验证 JS/OpenSSL 产出的签名
python sdks/python/run_tests.py                 # Python 侧验证同一组签名
node sdks/js/test/run.js                        # JS 侧验证同一组签名
```

---

## 6. 免责声明 / Disclaimer

本项目由独立重写产生，**与上游作者无隶属关系，未获上游背书**。
上游的商标、项目名「Agent Universe」与「智能体宇宙」归其作者所有；
本项目以 `NewAgentUniverseByDeepSeek` 为名，并在文档中始终标注上游出处。

本项目**不应**被视为对上游安全性的评估结论或对其生产可用性的判断。
GAP-ANALYSIS.md 记录的是针对特定版本（v2.5.6）在特定时间点的代码审计结果；
上游后续版本可能已修复其中任何一条。
