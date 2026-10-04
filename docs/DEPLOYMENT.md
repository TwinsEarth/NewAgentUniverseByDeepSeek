# 实机部署与验证 / Local Deployment

本文记录在**一台真实 Windows 机器上**部署、运行并验证本项目的完整过程，
以及在这个过程中**发现并修复的所有问题**。

做法上有一条刻意的区别：测试套件回答的是「代码是否工作」，
本文回答的是只有真正装上去、跑起来之后才会出现的问题——
进程重启后状态还在不在、CLI 与守护进程是否读同一份磁盘格式、
以及一个**只写不读**的持久化层会不会在第二次 `persist` 时把账本写两遍。

---

## 1. 前置条件

| 需要 | 版本 | 说明 |
|---|---|---|
| Rust | **1.85.0** | 项目声明的 MSRV，也是 CI 钉定的版本。`rustup toolchain install 1.85.0` |
| Node.js | ≥ 18 | 仅用于 `scripts/deploy-local.mjs` 与 JS SDK |
| Python | ≥ 3.10 | 仅用于合约静态检查 |
| Foundry（可选） | forge 1.8.3 | 只在需要 `forge build`/`forge test` 时；`solc` 由 `foundry.toml` 钉在 **0.8.24** |

**内存是这台机器上的硬约束。** 8 核 / 16 GB 上，多路并行 `rustc` 会以
`rustc-LLVM ERROR: out of memory` 或**静默退出**收场（`release` 构建在本轮
连续失败两次，原因就是同时有 3 个子构建在跑）。因此：

```bash
export CARGO_BUILD_JOBS=2     # PowerShell: $env:CARGO_BUILD_JOBS="2"
```

`.cargo/config.toml` 已经把这个上限写进仓库，但**同一台机器上并行跑多个
cargo 构建时，每个进程各自遵守 jobs=2 仍然会超**——见 §5 环境类问题。

## 2. 构建与安装

```powershell
Set-Location E:\DS\NewAgentUniverseByDeepSeek
$env:CARGO_BUILD_JOBS="2"
cargo +1.85.0 build --release -p nau-node --locked
```

只构建 `nau-node` 得到两个部署产物（`cargo build --workspace` 会连带构建
实验性 crate，部署不需要它们）：

| 产物 | 大小（release） | 作用 |
|---|---|---|
| `target/release/nau.exe` | ~0.8 MB | 离线 CLI：`version` / `identity` / `keygen` / `inspect` / `verify` / `amount` / `conformance` / `daemon` |
| `target/release/nau-daemon.exe` | ~1.9 MB | HTTP 守护进程 |

安装到一个前缀目录：

```
<prefix>/
  bin/     nau.exe, nau-daemon.exe
  data/    ledger.jsonl, meta.json, agents/…    ← 持久化状态
  logs/    daemon-boot1.log, deploy-local.log
```

`scripts/deploy-local.mjs` 会自动完成安装并执行 §3、§4 的全部验证：

```powershell
node scripts/deploy-local.mjs --prefix E:\DS\nau-deploy --port 4713
```

## 3. 运行

```powershell
<E:\DS\nau-deploy\bin\nau-daemon.exe> --data-dir <prefix>\data --api-port 4713
```

可用参数（`nau-daemon --help`）：

| 参数 | 说明 |
|---|---|
| `--api-port <PORT>` | `--api-addr 127.0.0.1:<PORT>` 的简写 |
| `--api-addr <ADDR>` | 完整绑定地址，默认 `127.0.0.1:4002` |
| `--data-dir <DIR>` | 持久化目录，默认 `nau-data`，支持 `~` |
| `--ephemeral` | **全部放内存、不落盘**——测试用，不要用于部署 |
| `--min-stake <N>` / `--min-reputation-bps <N>` | 市场准入阈值 |

**CLI 的参数顺序是有约定的：子命令在前，选项在后。**

```powershell
nau inspect --data-dir <prefix>\data      # 正确
nau --data-dir <prefix>\data inspect      # argv[1] 成了选项 → 报 unknown command
```

第二种写法原本只打印一大段 usage 并退出 2，不说明原因；本轮已让它明确指出
子命令与选项的先后顺序（见 §4 问题 3）。

## 4. HTTP 接口（守护进程实际接受的路由）

这份表是**实测**得到的，而不是从代码注释抄的——第一版部署脚本按 `/deposit`
和 `/balance/:id` 去调，拿到 4 个 404。账户是**路径段**，只有金额在请求体里：

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health`、`/version` | 版本、协议 `nau/1`、上游来源 |
| GET | `/stats` | agents / tasks / escrowed 统计 |
| GET | `/agents` | 列出/搜索（`?skill=&q=`）；**POST 同一路径**注册 AgentCard |
| GET | `/agents/:did` | 单个 agent |
| GET | `/tasks` | 列出；**POST 同一路径**发布任务 |
| GET | `/tasks/:id` | 单个任务 |
| POST | `/tasks/:id/bids` | 提交出价 |
| POST | `/tasks/:id/match` · `/start` · `/submit` · `/verify` · `/settle` | 状态机动作 |
| GET | `/accounts/:account/balance` | 余额（同时给出 `balance_minor` 与十进制字符串） |
| POST | `/accounts/:account/deposit` | 入金，请求体 `{"amount":"12.5"}` |
| GET | `/conservation` | O(1) 守恒检查 |
| GET | `/audit` | O(N) 全量审计 |
| GET | `/leaderboard` | 排行榜 |
| GET/POST | `/disputes`、`/disputes/:id`、`/disputes/:id/arbitrate` | 争议与仲裁 |

已实测的行为约定：

* **金额必须是十进制字符串**。`{"amount": 12.5}`（JSON 浮点）→ **422**；
  `"1.0000001"`（低于最小单位精度）→ **422**；`"not-a-number"` → **422**。
* **方法错误是 405 而不是 404**：`GET /accounts/x/deposit` → 405。
* 未知路径 → 404。
* `12.5 + 0.2 + 0.1` = **恰好 12.8**（整数最小单位账本，无 epsilon）。

## 5. 部署中发现并修复的问题

按「先记录、再修、再验证」的顺序列出。每一条都给出**触发方式**与
**修复后的实测证据**，而不是「已修复」三个字。

### 问题 1（严重）：重启会让余额凭空增加——`persist` 重复追加整个账本

* **触发**：部署脚本向守护进程入金 `12.5 + 0.2 + 0.1 = 12.8`，读取余额得到
  `12.8`；随后**重启守护进程**，同一账户余额变成 **38**。
* **根因**：`crates/nau-market/src/service.rs` 的 `persist()` 遍历
  `ledger.entries()` 并对**每一条**调用 `Store::append_ledger`。该 store 方法是
  **追加**语义，于是每次 `persist` 都把整个账本再写一遍；重启时
  `restore()` 按文件顺序重放，重复条目被重复计入余额。
  实测 `ledger.jsonl` 在「3 次入金 + 1 次重启」后从应有的 3 行变成 **12 行**，
  且 `seq` 被重新编号成 `0,1,2 / 0,1,2 / 0..5`。
* **更糟的一点**：`restore()` 上方原有注释写着「只有尚未应用的条目会在下次
  `persist` 时追加，因此先 restore 再 persist 不会重复账本」——
  **注释描述了代码并未实现的意图**。这正是本项目批判上游的那类缺陷
  （文档承诺 > 代码事实），而它出现在我自己的代码里。
* **修复**：
  1. `Market` 新增 `journaled: usize`，记录已落盘的条目数；
  2. `persist(&mut self, store)` 只追加 `entries[journaled..]`，然后更新该计数；
  3. `restore()` 重放完 journal 后设置 `market.journaled = journal.len()`，
     使上面那句注释成真；
  4. `Node::persist` 相应改为 `&mut self`（`serve` 持有 `Arc<Mutex<Node>>`，
     所有调用点都拿得到 `&mut`）。
* **验证**：
  * 新增回归测试 `persisting_twice_does_not_duplicate_the_journal`
    （`crates/nau-market/tests/lifecycle.rs`）：空转 `persist` 不得增长 journal；
    一次入金只允许 +1 条；`restore` 后再 `persist` 也不得增长。
  * 重新部署：账本 **3 行**、`seq = 0,1,2`（稠密递增），重启后余额仍为
    **12.8**，`conservation` 与 `audit` 的 `discrepancy` 均为 0。
* **为什么既有测试全都看不见它**：仓库里其他测试都是「构建 → persist **一次**
  → restore」。重复需要**第二次** `persist`，而那正是长期运行的守护进程做的事
  （定时器 + 每次写请求后）。**只有把真实二进制跑起来才会暴露。**

### 问题 2：把 Foundry 构建产物发布到了仓库，导致 CI 崩溃

* **触发**：本地跑过 `forge build` 后执行发布，CI 的 contracts job 报
  `IsADirectoryError: .../cache/solidity-files-cache.json.abi/<hash>/…/X.sol`。
* **根因**：Foundry 会创建一个**名字以 `.sol` 结尾的目录**，而
  `contracts/verify_api.py` 用 `rglob("*.sol")` 把它当文件读；
  同时发布脚本的跳过列表里没有构建产物，把 57 个缓存文件上传了。
* **修复**：发布脚本新增显式 `SKIP_PATHS`（`contracts/{lib,cache,out,broadcast}`、
  `client/src-tauri/target`）——**刻意不用笼统的 `lib`**，因为
  `sdks/js/lib/` 是真实源码；`verify_api.py` 新增 `source_files()` 跳过
  非文件与依赖/构建目录。
* **验证**：本地重建该崩溃条件（把 `cache/.../X.sol` 建成**目录**），
  `verify_api.py` 现在 exit 0；发布文件数 437 → 230，且 `sdks/js/lib/*` 仍在。

### 问题 3：CLI 的参数顺序没有任何提示

* **触发**：`nau --data-dir <DIR> inspect` → 打印 usage、退出 2。
* **根因**：子命令取 `argv[1]`，选项可在其后任意位置，但报错只说
  `unknown command \`--data-dir\``，不提顺序。
* **修复**：当「命令」以 `-` 开头时，额外提示
  `note: the subcommand comes first and options follow it, e.g. \`nau inspect --data-dir <DIR>\``。
* **验证**：部署脚本新增断言——非零退出**且**包含 `unknown command`。

### 问题 4：部署脚本按臆测的 URL 调用，得到 4 个 404

* **触发**：`POST /deposit`、`GET /balance/deploy-check` → 404
  `no route for \`/deposit\``。
* **根因**：真实路由是 `/accounts/:account/{balance,deposit}`，账户在**路径**里。
  这不是代码缺陷，而是**文档缺口**：路由只在 `api.rs` 的实现里，运维人员没有
  可查的表。
* **修复**：本文 §4 给出实测路由表；部署脚本改为正确路径，并新增
  「畸形金额 → 422」的断言。
* **验证**：53 项部署检查全绿（数目由 `scripts/verify-all.mjs` 的 `doc-counts` 关卡比对）。

### 问题 5（环境类）：并行 cargo 构建把内存耗尽，且会**静默**失败

* **现象**：`cargo build --release` 在 `Compiling tracing-*` 阶段以 **exit -1**
  结束，**没有任何错误输出**。同时机器上有 3 个子构建在跑。
* **诊断**：15.9 GB 总内存、已提交 11.3 GB；`rustc/cargo` 进程 4 个。
  内存耗尽时 Windows 上的 rustc 会直接被杀，于是既没有 `error:` 也没有
  `Finished`——**看起来像「什么都没发生」**。
* **处理**：等子构建结束后串行重跑，2 分 56 秒构建成功。
* **结论**：`.cargo/config.toml` 里的 `jobs = 2` 只约束**单个** cargo 进程；
  同一台机器上跑 N 个 cargo 时总并行度是 N×2。要把这条写进文档，
  否则下一个人会以为是「构建不稳定」。

### 问题 6（环境类）：cargo 增量缓存返回了**过期的编译期常量**

* **现象**（由 `nau-attest` 子任务报告）：一个运行期表达式
  `SGX_QUOTE_HEADER_LEN + SGX_REPORT_DATA_OFFSET_IN_BODY` 求值成 **368**，
  而把两个操作数分别打印出来是 **48** 和 **320**；同一表达式在 const-eval
  阶段则直接失败。
* **处理**：`Remove-Item -Recurse target` 后一切正常。
* **结论**：本工作区出现过「不可能的常量求值 / 算术失败」时，**先删 `target/`
  再调试代码**。这条已写入 `nau-attest` 的文档与本节。
  另外注意：并发协作时某个 agent 删除 `target/` 会让另一个 agent 的构建产物
  **凭空消失**（本轮确实发生了 `target/debug` 消失）。

### 问题 7：文档里的版本与声明陈旧

* 文档通篇写 **V1.0.1**，而 `VERSION`/`Cargo.toml`/两个 SDK 已是 **1.1.1**；
  README 的 `/health` 示例还是旧构建的输出。
* 纠删码与 NAT 检测在 5 处文档里仍写作「不实现」，而它们已实现并通过测试。
* **修复**：9 处版本引用更正；5 处「未实现」声明改为事实，并保留
  `~~删除线~~` 形式以留住审计轨迹；`CHANGELOG.md` 的 `[1.0.1]` 条目**不改写**
  （那是历史记录），改为新增 `[1.1.1]` 条目。

## 6. 复现全部验证

```powershell
# 一次性跑完全部关卡（缺少工具会显式报告为 SKIP 并让退出码非 0）
node scripts/verify-all.mjs

# 只跑部署验证
node scripts/deploy-local.mjs --prefix E:\DS\nau-deploy --port 4713

# 需要 forge 时指定本机路径
$env:FORGE_BIN="E:\DS\_private\foundry\forge.exe"
$env:SOLC_BIN="E:\DS\_private\solc-0.8.24.exe"
```

`verify-all.mjs` 的立场：**缺少工具是「未验证」，不是「通过」**。
出现任何 `SKIP` 时退出码非 0（除非显式 `--allow-missing-tools`），
并在结尾单独列出 `NOT VERIFIED` 清单。
