# 验证对照表 / Verification map — NewAgentUniverseByDeepSeek V1.2.3

本文件回答两个问题，而且是**可自行复核**地回答：

1. README 里的每一条能力声明，**是哪一道关卡在验证它**？
2. 哪些东西**没有实现或没有验证**，理由是什么？

它存在的理由是本项目对上游的主要批评：**「实现了」与「验证过」不是同一件事**，
而一份把两者混在一起的 README 就是在把信任洗白。所以下面每一条都指明关卡名，
而关卡名对应 `node scripts/verify-all.mjs` 输出里的一行——**你可以自己跑一遍，看它是不是绿的。**

> 状态不写在本文件里，因为写死的状态会腐坏。当前结果由 `scripts/verify-all.mjs` 打印，
> 并逐次粘贴进对应的 GitHub Release 说明（那是「某一次运行的结果」该待的地方）。

---

## 1. 一条命令

```bash
node scripts/verify-all.mjs              # 全部 16 道关卡
node scripts/verify-all.mjs --quick      # 跳过慢关卡
node scripts/verify-all.mjs --only=no-panics,unsafe-containment
node scripts/verify-all.mjs --allow-missing-tools   # 把 SKIP 当作非失败
```

设计约定（与上游的关键区别）：

* **缺工具是 `SKIP`，并在结尾单列于 `NOT VERIFIED`，且让退出码非 0**——除非显式 `--allow-missing-tools`。
  上游的 Python CI 有 17 个测试跳过其中 11 个仍然报绿。
* 每个 `SKIP` 都打印**启用它的确切命令或环境变量**（例如 `NAU_PYTHON`、`FORGE_BIN`）。
* 结尾分别列出 `NOT VERIFIED`（未验证）与 `FAILED`（失败）——**两者不是一回事**。

---

## 2. 声明 → 关卡

| # | 声明（README / docs） | 关卡 | 关卡实际做什么 |
|---|---|---|---|
| 1 | Rust 工作区 15 个 crate 编译并通过测试 | `rust-test` | `cargo +1.85.0 test --workspace --locked` |
| 2 | 依赖解析可复现 | `rust-lock` | `cargo metadata --locked`（锁与清单一致） |
| 3 | 零 lint 警告 | `rust-clippy` | `cargo +1.85.0 clippy --workspace --all-targets -- -D warnings` |
| 4 | 格式统一 | `rust-fmt` | `cargo +1.85.0 fmt --all --check` |
| 5 | **`#[cfg(test)]` 之外无 `unwrap`/`expect`/`panic!`** | `no-panics` | `scripts/check-no-panics.mjs`：**先剥离注释与字符串**再匹配；豁免必须写进 ALLOW 表并附理由 |
| 6 | **`unsafe` 收容在显式 opt-in 的模块内，每块配 `// SAFETY:`** | `unsafe-containment` | `scripts/check-unsafe-containment.mjs`：crate 根必须 `forbid`/`deny`；含 `unsafe` 的文件必须位于声明 `#![allow(unsafe_code)]` 的模块树内 |
| 7 | **VERSION 是版本号的唯一书写处** | `version-consistency` | `scripts/check-version-consistency.mjs`：镜像 CI 的 `version` job（6 项检查，含「npm/Python 清单不得重述版本」） |
| 8 | 与上游身份的**逐字节兼容** | `conformance` | 重新生成 `conformance/vectors.json` 并比对**逐字节一致**（含上游真实签名向量） |
| 9 | NAT：RFC 5389 STUN + RFC 4787 分类；不可达时返回 `Unknown` 而非猜测 | `rust-test` | `nau-net` 的 97 个测试（含测试自身发现并修复的 4 个协议缺陷） |
| 10 | 纠删码：GF(256) 系统化 Reed-Solomon，**任意 k 片可恢复** | `rust-test` | `nau-erasure` 的 82 单元 + 9 文档测试，**穷举 504 个擦除子集**（含仅剩校验片） |
| 11 | 真实 LLM HTTP；空 `choices`/`content` 是类型化错误而非 panic | `rust-test` + `no-panics` | `nau-http` 29 + `nau-agent` provider 34 测试 |
| 12 | GUI 客户端真实调用守护进程（真实 HTTP + 真实 Ed25519 签名） | `client` | 浏览器客户端 81 项断言，对本机**真实运行**的守护进程 |
| 13 | libp2p 真实 swarm（TCP+Noise+Yamux+Kademlia+GossipSub+Relay v2+AutoNAT+DCUtR） | `libp2p` | 需 `--features libp2p`，88 测试，单线程运行 |
| 14 | TEE/zkML **刻意只做范围明确的性质** | `rust-test` | `nau-attest` 63 + 1 测试；四种格式全部 `ChainNotImplemented`，`HardwareAttested` 由构造不可达 |
| 15 | 上游历史数据迁移（金额按十进制文本转换，绝不经过 `f64`） | `rust-test` | `nau-migrate` 65 测试 + 静态检查 |
| 16 | 合约可编译、可测试、调用点与声明成员一致 | `contracts-static` / `contracts-build` / `contracts-test` | 静态检查（无需工具链）+ `forge build --sizes` + `forge test --no-match-path '*lib/forge-std*'` |
| 17 | Python SDK | `python` | `sdks/python/run_tests.py`（需 `NAU_PYTHON`） |
| 18 | JavaScript SDK + 历史回归套件 | `javascript` | 223 项 JS 测试 |
| 19 | 本机部署：安装、运行、重启、状态存活 | `deploy` | `scripts/deploy-local.mjs` 的 19 项检查 |
| 20 | V1.2.3 sandbox：边界**由代码强制执行**，无法强制则拒绝 | `rust-test`（`nau-sandbox`）+ `unsafe-containment` | 见 `crates/nau-sandbox` 与 `docs/GAP-ANALYSIS-v2.8.2.md` §5 |
| 21 | V1.2.3 账本：持久化记录带哈希链，篡改可检出并报首个断链序号 | `rust-test`（`nau-ledger`/`nau-store`） | 见 `docs/GAP-ANALYSIS-v2.8.2.md` §3.1 |

---

## 3. 硬限制（**没有**实现或**没有**验证的东西）

这一节是本文最有用的部分。每一条都给出理由，因为**没有理由的缺口和没有缺口的声明一样不可信**。

### 3.1 平台与环境的硬限制

| 限制 | 理由 | 能否自行复现 |
|---|---|---|
| **TLS 路径无任何测试执行** | 本机出站 TLS 不可用。`https://` 在未启用 feature 时于建立 socket 之前返回类型化错误，**绝不静默降级为明文** | `cargo test -p nau-http`（TLS feature 关闭） |
| **Windows 上 Unix 沙箱后端未验证** | 本机是 Windows。`nau-sandbox` 的 `platform/unix.rs`（`setrlimit` + `setsid`）被标记为未在本机验证；能验证的是 `platform/windows.rs` 的 Job Object | `cargo test -p nau-sandbox`（报告 SKIP-with-reason 的项） |
| **macOS 从未运行** | 本机是 Windows。CI 在 `macos-latest` 上跑，但那是 CI 的结论，不是本机的 | CI |
| **没有 QUIC、没有 DNS 解析** | 为守住 MSRV 1.85，libp2p 裁掉了 `dns/quic/tls/websocket`。bootstrap 必须是 IP 形式的 multiaddr | `cargo tree -p nau-libp2p` |
| **DCUtR 打洞与 AutoNAT 可达性未验证** | 环回测试里「打洞成功」只是拨通了本地地址——**那种测试不测任何东西也会通过**，比承认缺口更糟。AutoNAT 只断言「返回 `Unknown` 而不是编造 NAT 类型」 | `cargo test -p nau-libp2p --features libp2p` |
| **真实 NAT 类型不宣称** | 分类真实 NAT 需要可达的公网 STUN 服务器，本机不具备 | 同上 |
| **Tauri 桌面外壳未编译、未运行** | 本机对同等依赖树触发过 `rustc-LLVM out of memory`。**浏览器客户端是真正被验证的那个** | `--only=client`（浏览器）；Tauri 仅源码 + CI 工作流 |

### 3.2 能力上的硬限制

| 限制 | 理由 |
|---|---|
| **纠删码不做纠错** | 没有 Berlekamp-Massey/Forney/syndrome。损坏但**未声明丢失**的分片会产生**错误结果**——这一点由测试断言，需要上层校验和/MAC 检测 |
| **Merkle 包含证明不是零知识、不简洁、不证明计算正确** | 包含证明对**垃圾输出同样成立**，有专门测试断言这一点。它是对上游「`tee_quote` 是不经校验的字符串」的正确回应：换成一个范围明确的可验证性质，而不是换一个更好听的名字 |
| **不实现 Intel/AMD 证书链** | 因此 `HardwareAttested` **由构造不可达**，四种证明格式全部返回 `ChainNotImplemented` |
| **迁移工具只读 JSON/JSONL** | **没有数据库读取器**（上游确实有 SQLite，但只写不读、且没有任何账本表）。测试夹具是**按审计结果建模**而非真实抓取 |
| **应用层 P2P 数据面无消费者** | ⚠️ **明确不实现**。不假装有 gossip 应用层 |
| **TEE/zkML 之外不声称任何硬件信任** | — |

### 3.3 验证方法本身的限制

| 限制 | 说明 |
|---|---|
| **`--quick` 会跳过慢关卡** | 跳过的会进入 `NOT VERIFIED` 列表，不会被算作通过 |
| **`no-panics` 是文本分析，不是语义分析** | 它剥离注释与字符串字面量后按行匹配。宏展开产生的 panic 路径、或跨行的 `unsafe` 结构，它看不见 |
| **`unsafe-containment` 只检查属性与注释的存在性** | 它**不能**证明某个 `SAFETY` 注释的论证是**正确**的。那需要人读 |
| **`cross-target` 关卡只做类型检查，不链接** | 它用 `cargo check --target` 覆盖 Linux/macOS，因此能抓到「只在某个平台编译的代码路径里的类型错误」，**抓不到链接错误**——需要该平台的链接器，本机没有。这不是理论问题：`platform/rt.rs` 里的 `#[link(name = "kernel32")]` 曾被无条件编译，Linux 上链接器报 `cannot find -lkernel32`，而**所有本地关卡都是绿的**（`cargo check` 不链接）。CI 抓到了它，两次。结论：**跨平台链接正确性只能由 CI 证实**，本文件的任何本地结果都不覆盖它。 |
| **本文件第 20、21 行的 sandbox/账本断言** | 由 `cargo test` 覆盖，但**具体的边界清单**以 `docs/GAP-ANALYSIS-v2.8.2.md` §5 的逐条对应为准——那里写明了哪些边界是**拒绝**而不是静默放行 |
| **`cross-target` 在本机跑不起来（2026-10-01 修正）** | 该关卡跑 `cargo check --workspace --all-targets --target <triple> --locked`。但 `ring`（经 `nau-libp2p` 引入）会构建 C 代码，从 Windows 主机交叉检查需要 `x86_64-linux-gnu-gcc` / `cc`，**本机没有**。于是它在某个 build script 里就死了，这个结果**对 Rust 代码本身不构成任何陈述**（报错原文：`ToolNotFound: failed to find tool "x86_64-linux-gnu-gcc"`）。此前它把这个报成 FAIL，与「代码编译不过」无法区分；现已改为 **SKIP 并点名缺失的工具**，而 SKIP 按本脚本头部的规则会让退出码非零——它仍然是在说「这些平台的代码在这里**没有**被验证过」，不是通过。 |
| **一处对 V1.2.3 时期结论的更正（如实记录）** | V1.2.3 的验证报告把 `cross-target` 记为 **PASS**，并称「Linux 与 macOS 检查无错且无警告」。**这个结论今天无法复现**：两个 target 都已安装（所以关卡不会 SKIP），而检查因上面那条工具链原因失败。由于本仓库没有 `.git`、也没有留存当时的运行输出，我**无法判定**是关卡当时更弱、还是那次运行并不如报告所述。因此：**把 V1.2.3 时期的 cross-target 声明视为未验证**，本工作区跨平台正确性的唯一证据是 CI（在 Linux/macOS runner 上 target 等于本机，不涉及交叉编译）。 |
| **2026-10-01 对 `nau-p2p-daemon.rs` 的修改在本机没有被类型检查** | 改动位于 `#[cfg(unix)]` 内（把 `.expect("install SIGTERM handler")` 换成优雅降级），Windows 上**根本不会被编译**。由于上一条，Linux/macOS 的类型检查在本机也不可用。这次改动**只能由 CI 证实**。 |

### 3.4 V1.2.3 新能力自身的缺口（由实现者报告，未被粉饰）

这一节专门记录**新做的东西没做到哪里**。写在声明旁边，而不是藏在提交信息里。

| 缺口 | 说明 |
|---|---|
| **sandbox 路由没有套接字级测试** | `crates/nau-node/src/api/sandbox_routes.rs` 的 20 个测试全部走**纯路由函数**（`route(...)`，无需绑定端口）。守护进程的字节帧循环**未针对 sandbox 路由单独测试**。纯函数是刻意选择（可测且不依赖端口），但它是纯函数测试，不是端到端测试 |
| **`NAU_SANDBOX_BACKEND` 的环境变量读取本身未测试** | 只有纯选择函数 `executor_for` 被测试。默认值是 `none` → `NullExecutor`，**什么也不执行**；选 `process` 时调用方必须放弃平台无法强制的每一条边界，否则创建请求会被**具名拒绝** |
| **Unix 上进程后端被拒绝（不是「未验证」）** | 沙箱的进程后端只在 **Windows** 上被证明能兑现自己的能力声明。CI 给出了反证：Ubuntu 上**超时未被强制执行**，macOS 上四个「经路由执行」的测试失败（同一后端在 Ubuntu 上却通过）。因此**守护进程在非 Windows 平台上拒绝 `NAU_SANDBOX_BACKEND=process`**，并给出具名理由——与其半执行，不如拒绝。默认后端 `none`（`NullExecutor`）**什么都不执行**，在所有平台上都如此，且这条默认值有测试断言。实际含义：**在 Linux/macOS 上沙箱目前不能运行任何东西**。这是能力缺口，不是安全漏洞；把它写成「未验证」会低估它。 |
| **Unix sandbox 后端未在本机验证** | 本机是 Windows。`platform/unix.rs`（`setrlimit` + `setsid`）与 `platform/windows.rs`（Job Object）走同一段测试代码，但**只在 Windows 上运行过** |
| **exec 输出是有损 UTF-8** | 没有 base64 通道；截断通过 `stdout_truncated`/`stderr_truncated` 报告；无法排空的流是 500（`SandboxError::Internal`），不是静默成功 |
| **sandbox 注册表是「每进程 + 每数据目录」** | 若数据目录在进程运行期间被删除/重建，守护进程会继续服务旧根；`max_sandboxes`(64) 与 `ORPHAN_AGE_SECS`(120) 是 crate 默认值，**未通过守护进程暴露配置** |
| **哈希链只能证明 tamper-evidence** | 能重写日志**且同时**重写 `meta.json` 锚点的攻击者**检测不到**——没有签名、没有见证者。链只能证明「相对于锚点，日志事后未被修改」，**永远不能证明「这是诚实的历史」** |
| **`ConservationReport.journal_intact` 等字段经公开 API 不可达为 false** | `from_journal` 拒绝不通过校验的列表，`append` 维持 `verified == len`，所以在进程内经公开 API 拿到的 `Ledger` 报告永远是 `intact`。有意义的两道闸门是 `from_journal`（采纳）与 `verify_journal_against`（整份重写） |
| **结算仍按托管总额付款，而非中标价** | 中标价被持久化、恢复并作为**下限**使用，但 `Ledger::release` 释放的是整笔托管；要按中标价付款并退还差额，需要市场的「退款 + 重新托管」或新增 `Ledger::release_amount`。**上游 `unwrap_or(budget)` 的静默回退已封死**，金额语义未改 |
| **`api.rs` 有 8 处丢弃持久化错误** | `let _ = node.persist();` 使一次**未落盘**的变更仍能返回 200。`Market::persist` 返回类型化错误；API 应映射为 5xx 或重试 |
| **`NAU_API_TOKENS` 无法表达标准形式的 DID** | 格式是 `id:token[:did][:scope,scope]`、以 `:` 分隔，因此 `did:nau:<id>` 里的冒号会被当成字段分隔符——**照文档推荐「让 token 携带 DID」会写出让守护进程启动失败的配置**。可行写法：无 DID 时用**双冒号** `id:token::read,write`；需要绑定时用**不含冒号的指纹** |
| **浏览器 e2e 走的是 loopback 匿名逃生阀** | 浏览器客户端尚无 token 通道，所以 `client/test/e2e.mjs` 以 `NAU_API_ALLOW_ANONYMOUS_WRITES=1` 启动守护进程（守护进程拒绝在非 loopback 绑定上承认该开关）。该关卡因此**不证明**浏览器端到端的认证路径；那条路径由 `cargo test -p nau-node` 与 `scripts/deploy-local.mjs` 双向覆盖 |
| **`nau-node` 不提供 `/mcp` 路由** | 「变更类 MCP 工具需要认证」在**单一 dispatch 点**强制，而非在某条真实守护进程路由上 |
| **所有权检查在 7 条路由上实现，端到端只测了 2 条** | 其余需要构造大型签名对象 |

---

## 4. 自行复核上游与本项目的差异

```bash
# 1) 取上游 v2.8.2（675 文件 / 314 MB，Rust 153 文件 / 21,530 行）
curl -sL https://codeload.github.com/TwinsEarth/agent-universe/tar.gz/refs/tags/v2.8.2 | tar xz

# 2) 本项目对上游两次审计的结论（第二次含对上游各条修复声明的核实）
less docs/GAP-ANALYSIS.md            # 对象：v2.5.6，76 条缺陷
less docs/GAP-ANALYSIS-v2.8.2.md     # 对象：v2.8.2，含「声明不被代码支持」的裁定

# 3) 上游把本项目的审计当作修复路线图的证据
grep -rn 'GAP §' agent-universe-2.8.2/gsn-core/src | wc -l    # => 52

# 4) 本项目对自己用同一套标准的结果
less docs/SELF-AUDIT.md

# 5) 全部关卡
node scripts/verify-all.mjs
```

---

## 5. V2.2.2 插件化架构：声明 → 证据

本节的规则与 §2 相同：**每一条声称都要指到能证伪它的地方**。指不到的，写「未验证」。

| 声称 | 由什么证实 | 证伪它会看到什么 |
|---|---|---|
| 分级只从签名的名字推导，第三方不能占用厂商命名空间 | `nau-plugin/src/tier.rs` 的 `Tier::from_name`，含 `a_third_party_cannot_squat_on_the_vendor_namespace` | 那条测试失败 |
| T3 永远拿不到敏感能力 | `capability.rs` 的 `a_third_party_plugin_can_never_hold_a_sensitive_capability`，在 `能力 × 分级` **全笛卡尔积**上遍历 | 新增敏感能力后该测试自动覆盖它 |
| 内核权限没有审批通道 | `no_approval_and_no_authority_grants_a_refused_capability`：4 种权威 × 全部内核能力 × 每个非系统等级 | 任一组合成功即可证伪 |
| 审批分支是**可达的**（不是文档里的空话） | `the_approval_branch_of_the_matrix_is_reachable` + `Certification` 的范围检查 | 该测试失败 |
| 清单摘要不覆盖 `signature` 段，但覆盖每个可编辑字段 | `manifest.rs` 的 `the_digest_does_not_cover_the_signature_section` 与 `editing_any_signed_field_invalidates_the_digest` | 后者枚举 4 类篡改 |
| 模块字节与清单绑定 | `replacing_the_module_without_resigning_is_refused` | — |
| 生命周期只有一个赋值点 | 关卡 `plugin-invariants`（`scripts/check-plugin-invariants.mjs`）读源码计数 | 出现第二个 `self.state =` 即失败 |
| 插件启动只有一个入口 | 同一关卡：`runtime.start(` 只允许出现在 `arbiter.rs` | 别处出现即失败 |
| 名字**永远不能**推出黑名单判决 | 同一关卡：`from_name` 里不得出现 `Ok(Tier::Blacklisted)` | — |
| 内核不依赖宿主 crate | 同一关卡读 `nau-plugin/Cargo.toml` | 加入 `nau-node` 等即失败 |
| 文档词汇与代码一致 | 同一关卡比对 `PLUGIN-ARCHITECTURE.md` 与 `tier.rs`/`capability.rs` 的前缀与能力名 | 文档少列一个能力即失败（**首次运行就抓到少列 2 个**） |
| 被拒绝的装载不留任何痕迹 | `arbiter.rs` 的 `a_refused_load_leaves_no_trace_in_the_registry_or_the_bus`，在两个不同拒绝点各验一次 | — |
| 三次越权 → 隔离（**且已接线**） | `arbiter.rs` 的 `three_authority_violations_at_the_bus_quarantine_the_sender`；`Bus::refusal_is_misconduct` 明确哪三类拒绝算越权 | 限流/超长/竞态被算作越权即失败 |
| 伪造来源被拒绝 | `bus.rs` 的 `a_message_that_claims_another_plugins_identity_is_refused` | — |
| 黑名单必须由受信厂商密钥签名 | `blacklist.rs` 的 `an_entry_signed_by_an_untrusted_key_is_refused` | — |
| 锁定摘要的条目不会否定修好的新构建 | `a_pinned_entry_does_not_condemn_a_different_build` | — |
| 申诉可 Lifted，但没有任何操作能删除条目 | `AppealOutcome` 无删除路径；`an_appeal_can_be_lifted_but_never_erases_the_entry` | — |
| CLI 的矩阵与代码强制的一致 | `nau plugin tiers` 逐格调用 `Capability::decision`，命令内**不重述**策略 | 代码改而输出不变即失败 |
| CLI 端到端可用（真签名 / 真拒绝 / 退出码） | `crates/nau-node/tests/plugin_cli.rs` 13 个测试，**启动真实二进制** | — |
| T0 系统插件真的能跑（不是只注册） | `plugin_host.rs` 与 `plugin_cli.rs` 的 `the_system_plugins_boot_to_running_and_are_actually_called`：断言恰好 4 个 `running`、`policy.matrix` 有应答、越权被令牌拒绝 | 插件停在 `loaded` 即失败（这**确实发生过**） |

### 5.1 插件化的硬限制（**没有**验证或**没有**实现）

| 限制 | 说明 |
|---|---|
| **没有任何 T1/T2/T3 插件被实现** | 官方/认证/分析那几份是**已验证的清单**，不是能跑的插件。清单能通过四重校验 ≠ 代码能运行 |
| **`ProcessRuntime::call` 从未端到端执行过** | 它按设计返回「exec 由宿主完成」。`nau-plugins` 的进程插件测试是**直接在 `nau-sandbox` 里跑二进制**再把应答帧读回来——那是更弱的声明，不是同一条链路 |
| **WASM 运行时不存在** | 实现为类型化拒绝。任何 `wasm` 请求都被拒并说明本构建不含该运行时 |
| **无法强制的边界必须由插件豁免** | 出站网络拒绝、文件系统隔离、磁盘配额、CPU 时间、句柄上限在任何平台上都没有原语。因此「T3 没有网络」是**关于总线的陈述**，不是关于子进程能否直接开 socket 的陈述 |
| **T0 出站消息不触发隔离升级** | `SystemPluginHost::flush_outbox` 拿到的是与宿主共享的 `Arc<Registry>`，没有 `&mut` 可记录违规。升级在内核已接线并有测试，但**不适用于经此路径的 T0 流量** |
| **第三方审核流程与申诉只有状态机** | 有 `Review`/`Certification` 的状态机与范围控制，没有运营后端、没有工单系统、没有人工流程 |
| **`Grant::RequiresApproval` 可达但无生产调用方** | 门开了，但没有任何生产代码签发过带审批的令牌；目前只有测试走过这条路 |
| **`nau-plugins` 的 T0 插件比其名字窄** | `sys.policy` 无可变上限（`write` 是类型化拒绝）、`sys.orchestrator` 只出计划不启停、`sys.identity` 验证的是 UTF-8 字符串上的分离签名（非规范化载荷）、`sys.storage` 只暴露元数据/账本 |

### 5.2 「沙箱里跑插件」的三平台真实情况（2026-10-01 由 CI 教出来）

本项一开始是**被我写错**的，如实记录：

* 我最初写了一条 `#[cfg(not(windows))]` 测试，断言「无法强制边界的平台上进程插件会被拒绝」。
* **CI 证明这个断言是错的**：ubuntu-latest 上插件**真的启动了**（测试跑进 `Ok` 分支并 panic），
  只有 macOS 在 `exec` 处以 `EINVAL` 拒绝。所以「Unix 后端跑不了进程」不是事实——
  它是**关于 macOS 的事实、关于 Linux 的假话**。
* 该断言已替换为一条**平台无关且为真**的检查：进程后端**不得声明它无法强制的东西**
  （`unenforced()` 非空，且没有任何边界同时出现在 enforced 与 unenforced 两侧）。

真实矩阵（**只有第一行是端到端验证过的**）：

| 平台 | 沙箱内运行插件 | 限制是否被强制 | 证据 |
|---|---|---|---|
| **Windows** | **是** | **是**（Job Object：整树 kill、内存与进程数上限） | 本地 + CI，`the_echo_plugin_runs_inside_a_real_sandbox_and_answers_a_frame`（Windows-only） |
| **Linux** | 观察到**能启动** | **未验证** | CI ubuntu-latest 上测试进入 `Ok` 分支。且 `nau-node` 的 `executor_for` 在非 Windows 上**拒绝选用**该后端——这是策略性拒绝，不是后端不能用 |
| **macOS** | **否**，`exec` 处 `EINVAL` | 不适用 | CI macos-latest |

**这意味着**：`sandboxed process plugin` 这条能力目前**只在 Windows 上有端到端证据**；
其余两个平台的结论是「观察到的事实」，不是「验证过的能力」。V1.2.3 关于 Unix 的拒绝立场
因此需要修正表述：不是「Unix 后端兑现不了声明」，而是「**在一个平台上验证过的强制，不能在
未验证的平台上被声明**」。
