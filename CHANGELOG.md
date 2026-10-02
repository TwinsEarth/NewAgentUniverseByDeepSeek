# 更新记录 / Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。
版本号有唯一机器可读来源：仓库根 [`VERSION`](VERSION)。

### B3：`sys.chain` 的离线锚点日志

上游 B3 给 4 个 T0 系统插件接真实句柄。逐项核实后**我们只缺一处**：`sys.identity` 与 `sys.storage` 早已有真实句柄（后者有真的 `FileStore`），而 **`ChainPlugin` 结构体里只有 `id` 与 `grant`——连 store 都没有**，op 只有 `config`/`precheck`。

现在它有了 `open(dir)` 与两个新 op：

| op | 能力 | 行为 |
|---|---|---|
| `record_anchor` | **`chain:evm:write`** | 追加一条本地锚点，答 `seq`/`count`/`on_chain:false` |
| `list_anchors` | `chain:evm:read` | 返回日志，**最新在前** |

**动手前先解决的那个问题**：`record_anchor` 是**写**，而该插件只声明 `chain:evm:read`——**在读能力下写**正是本项目一贯拒绝的错配。所以它新增 `chain:evm:write`，且**那个 op 单独要求它**。

这暴露了原代码里一个**当时还正确、加了写 op 就变错**的东西：能力检查原本是 `match` **之上**的一条笼统 `chain:evm:read`。留着它，`record_anchor` 会同时要求读和写，而「这个门要求 `chain:evm:read`」就成了对日志的**假陈述**。检查下移到各分支——**一个覆盖超过该操作所需的检查，就是在宣称这个门比它实际更窄**。

**每一条答案都带 `on_chain: false`**：一个叫「anchor」的门最大的风险，就是调用方把它读成一次链上写入。

**三处测试抓到的东西**（都不是我审查出来的）：

1. **一个并行才出现的失败**：我的 `scratch()` 用进程 id 做唯一性，而**同一进程内所有测试共享它**。这在插件没有状态时无害，**它一有状态就变成共享日志**。改用计数器。
2. **一条本会空洞为真的断言**：`system_plugins.rs` 的能力表是「每插件一个额外能力」；`sys.chain` 现在有两个。表自己的注释说「多出一个能力就会失败」——**设计是对的，形状是旧假设**。把值从单个改成集合，而不是把插件压回一个错的答案。
3. **`payload::protocol` 与逐 arm 能力检查**：编译器与既有测试各自指出了我第一版的错误。

### `official.skill`：上游四个业务化官方插件的第三个

上游 v3.5.0 的 `com.twinsearth.official.agent-skill` 落地为本仓库的 **`com.twinsearth.official.skill`**（短名，与我们目录的其余条目一致；映射记在 `docs/PLUGIN-MIGRATION.md`）。

op 是 `match`：**谁做得了一个活，由调用方给出的名册决定**。名册之所以由调用方给，是因为**进程插件读不到市场**——真实的技能索引在市场里，一个假装能读的门就是在汇报一个它看不见的邻域。

技能经 `nau_core::domain::agent::Skill` **解析**（第二个解析器就是技能的第二种拼写），匹配用 **`Market::discover` 所用的同一条规则**：按小写 id 大小写不敏感。**版本只上报、不推断**——`min_version` 只在调用方给出时生效，且达不到的 agent 进 `below_floor` 而**不是被悄悄丢掉**（丢掉会让「没人能做」和「最强的差一个版本」变成同一个答案）。每条答案都带 `ranks_nobody: true` 与 `consults_reputation: false`。

**13 条测试**，并已进宿主 e2e 表——真的在 `ProcessPluginHost` 沙箱里跑过。

### 一条写死数字、却声称比对文档的断言

`official.rs` 里有一句：

```rust
assert_eq!(OFFICIALS.len(), 11, "the document lists eleven");
```

**它从没打开过那份文档。** 加第 12 个条目时它报出「文档列了十一个」——而文档里其实已经有我的新行。改成**真的比对名字集合**。

**改成数行数是我第二次做错**：文档有**两张表**（完整目录 + 「可运行」清单），数行数读到 18 行对应 12 个插件。**集合比对不会被合法重复骗到，而它仍然会在真正要命的地方失败：一个名字只出现在一边。** 而集合比对本身也立刻抓到了我自己的解析 bug（剥掉前缀后取到的是后缀），**它大声失败了**——这正是它该有的样子。

### 一处让 CI 单平台变红的流竞态（不是产品缺陷）

发布后 `Client | verify / rust / ubuntu-latest` 失败，而**同一套验证**在 `CI` 与 `Release` 的 ubuntu 上都通过，在 Client 的 macos/windows 上也通过。日志给出的根因是：

```
Error [ERR_STREAM_WRITE_AFTER_END]: write after end
Emitted 'error' event on WriteStream instance at: ...
```

`deploy-local.mjs` 把守护进程的 **stdout 与 stderr 接到同一个文件流**：

```js
p.stdout.pipe(logStream);
p.stderr.pipe(logStream);
```

**Node 的 `pipe` 在自己的源结束时调用 `dest.end()`**——所以先 EOF 的那个流结束了共享文件，另一个流的下一次写入就是 write-after-end。**哪个流先 EOF 取决于缓冲与时序**，所以它表现成「一个平台红、另两个绿」的偶发失败。而 WriteStream 上的 `error` 事件**没有人处理**，于是它直接结束了整个部署运行。

修法：两个 `pipe` 都加 `{ end: false }`，进程退出时**显式结束一次**，并给流装上 `error` 处理——**一个未处理的流错误不该以「关于流」的消息让部署检查失败，而那只手边的磁盘或句柄才是真正的原因**。

### 发布到 GitHub Packages（第一个包）

`https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/packages` 上现在有第一个包：`@twinsearth/nau-dsh-plugin@3.4.5`。

**为什么走 workflow 而不是又一个 token。** GitHub Packages 是**另一个 registry**，发布需要 `write:packages`——而仓库现有自动化 token 的 scope 是 `gist, read:org, repo, workflow`，**没有**它；本机也没有任何别的凭据（我查了环境变量与 `gh` CLI 的 `hosts.yml`——那里只有用户名、没有 token）。

所以新增 [`.github/workflows/packages.yml`](NewAgentUniverseByDeepSeek/.github/workflows/packages.yml)：由 CI 用它自带的 `GITHUB_TOKEN`（**仅这一个 job** 授予 `packages: write`）发布。**不需要任何新凭据，也不需要谁再把一个能覆写包的 token 贴进对话或落进磁盘。**

**刻意没做的事**：没有给包加 `publishConfig.registry`。那个字段是 manifest 里的**永久声明**，一个写着「我属于 GitHub Packages」的 manifest 会让**之后的 npmjs 发布悄悄走错地方**。registry 在这里按次选择，manifest 继续以 npmjs 为默认。

**同一个包名、两个 registry**：`@twinsearth/nau-dsh-plugin@3.4.5` 同时在 npmjs.com（公开可读、无需凭据）与 GitHub Packages（需凭据读取，GitHub 对自家包也如此）。

**一个我自己写出来的 bug，被日志一眼看穿。** 第一版在发布前加了一道守卫，检查「npm scope 必须等于仓库所有者」，结果它把一个**完全正确**的名字拒绝了：

```
package: @twinsearth/nau-dsh-plugin@3.4.5  scope: @twinsearth  owner: TwinsEarth
##[error]GitHub Packages requires the npm scope to be the repository owner
```

`@twinsearth` 与 `TwinsEarth` 小写后当然相等——**我忘了剥掉前导的 `@`**。修好后 `scope: twinsearth  owner: TwinsEarth`。

**那两行特意并排打印了出来，所以错误的守卫展示的是它比较了什么，而不只是它拒绝了。** 我本地先复现（原样比较 false、剥掉后 true）再重跑。

**发布之后仍然去读回来**——job 的最后一步拉取 registry 并核对版本，输出 `readable: @twinsearth/nau-dsh-plugin versions 3.4.5`。**「发布报告成功」和「读得到」是两件事，这个仓库不把前者当作后者的证据。**

### 同时发布到 npm

```
@twinsearth/nau-dsh-plugin@3.4.5  →  https://www.npmjs.com/package/@twinsearth/nau-dsh-plugin
```

安装即：`dsh plugin --profile <profile> add @twinsearth/nau-dsh-plugin`

**发布前先补的一件关键事**：scoped 包在 npm 上**默认是 restricted**，所以 `publishConfig.access = "public"` 不是装饰，而是「别人能不能看见」的开关。

**过程中最值得记的一次误判。** 发布报告成功，而 registry 随后对**所有人**（包括所有者本人）返回 404。两个结论不可能同时为真，于是我做了第二次发布——registry 的回答是：

```
403 Forbidden - PUT ... - You cannot publish over the previously published versions: 3.4.5.
```

**写路径拒绝覆写，就是包确实存在的证明。** 而 tarball URL 立刻可取（200），packument 约 75 秒后传播。所以那是**新 scoped 包的读路径滞后**，不是失败——**「发布成功」与「读不到」可以同时为真，而分辨它们的方法是问第二次，不是重试同一次。**

**验证方式**：全程用**未认证**请求读取（一个只对所有者可见的包照样能被我装上，而「我能拿到」恰好会掩盖这一点），然后按**名字**从公开 registry 解析、装进全新 profile，再导入那份安装副本——5 个工具注册并运行。

**一个使用者会遇到的细节**：harness 有**最小发布时长**策略（供应链保护）。刚发布的包会被它拦下，安装器会自动往 `pnpm-workspace.yaml` 加一条 `minimumReleaseAgeExclude`。这是设计行为，不是故障。

两条安装路径都保留：市场的一键安装**优先用「经仓库验证的 npm 包」**，而 release tarball **完全不依赖 registry**。

### 提交到 DSH 插件市场（`awesome-dsh-plugin`）

先说清楚一件事：**这个构建里没有「官方应用商店」**。核实过程与结论：

| 查了什么 | 结果 |
|---|---|
| archive 里名为 `marketplace` 的文件 | **0 个** |
| `listBundles()` | 只列**当前 profile** 里的 bundle，不是远程目录 |
| `plugin-package-inventory-deepseek` | **不是商店**——它是把当前插件清单**报给官方 LLM 请求**的遥测插件 |
| `registryPlan()` | 处理的是 **npm registry**（含公私之分，私有的永不回退到公有） |

**实际存在的市场是社区的**：`dshmarket`（dshmarket.com）每次打开实时读 [`awesome-dsh-plugin.com/plugins.json`](https://awesome-dsh-plugin.com/plugins.json)——**4,412 条**、4.8 MB、CI 每日刷新。它的收录规则写在站点上：

> 「**`data/plugins/` 下的一个 YAML 文件就是全部提交**；README 与站点自动重新生成。**给你的仓库加上 `dsh-plugin` topic**」

**我们做的三件事：**

1. **加 topic**：仓库 topic 变为 `["deepseek-harness","dsh-bundle","dsh-plugin"]`
2. **写条目** [`integrations/dsh/market-entry.yml`](NewAgentUniverseByDeepSeek/integrations/dsh/market-entry.yml)——**留在仓库里**，可审阅、可 diff、可复现，而不是只存在于一个 PR 里
3. **开 PR**：https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/pull/6352

**用 `tarball` 而不是 `npm`**：目录两者都收，**224 条**用的是 GitHub release 附件而无 npm 包——正是我们的形状，而且那条安装路径是**端到端验证过的**（从 release URL 下载 → 装进全新 profile → 导入 → 5 个工具注册并运行）。

**状态如实说明**：PR 已开（`open`，1 个文件，`+23 −0`），条目在其 CI 合并并重新生成目录后才会出现在市场里。**提交 ≠ 已上架。**

---

## DeepSeek Harness 插件（`integrations/dsh/`）

本项目现在也是一个 **DSH bundle**：一个 npm 包，装进 profile 后给 Harness 提供五个**只读**工具，覆盖 `nau` 命令行。

| 工具 | 回答什么 |
|---|---|
| `nau_version` | 项目版本、线协议，以及本构建命名的**两个**上游版本 |
| `nau_inspect` | 某个数据目录会恢复成什么，外加账本审计——**不需要启动守护进程** |
| `nau_conformance` | 本构建是否仍与共享一致性向量相符 |
| `nau_amount` | 精确十进制 → 本项目存储的整数最小单位 |
| `nau_node_status` | 某 host:port 上是否有东西在监听，以及会用哪个二进制 |

**刻意不暴露「驱动节点」**：启动/停止守护进程、存款、发总线消息在本项目里都是有各自拒绝语义的**特权且受审计**的操作。一个绕过它们去 `execFile` 的工具，等于让审计轨迹变成可选。诚实的做法是现在只给只读面，特权面等它能带上本项目自己的审批规则时再加。

### 三步才做对，每一步都是被工具（而不是我）纠正的

1. **patch 的 `insert` 语法**：`dsh` 自己的诊断是 `patch: entry "nau-dsh-probe" not found`——**patch 是按 id 定位已有条目的叠加层**。它的 schema 里写着：*「An insert appends entries, optionally inside the group identified by `id`」*。之前我把 patch 写成了普通条目列表。
2. **包必须自带依赖闭包**：profile 的 `pnpm-workspace.yaml` 里 **`autoInstallPeers: false`** 是 harness 的刻意策略。只声明 peer 的包装得上、组合得出正确的配置树——然后**在真实会话里加载失败**：`dsh-tools` 在顶层 import `@deepseek-ai/cordis`，而 profile 里没有它。**安装成功、配置正确、模块会抛异常**，这三件事可以同时为真。
3. **`defineTool` 不是纯类型助手**：它校验参数、重绑方法、编译 schema。所以不能为了躲开依赖而不用它。

**并且做成了关卡**（第 21 道 `dsh-bundle`）：导入模块、调用 `apply`、要求每个工具通过 harness 自己的 `defineTool` 校验，并真的运行不依赖节点的工具。依赖闭包未安装时如实报 **SKIP 并给出安装命令**——在这里失败会让每台没网的机器变红，而不跑就通过会让关卡变成装饰。

### 产物

* **安装包**：`twinsearth-nau-dsh-plugin-3.4.5.tgz`，作为 release 附件发布
* **本地安装已验证**：装进全新 profile，依赖闭包物化（19 个 `@deepseek-ai/*`），并**从 profile 里那份安装副本导入、注册 5 个工具、真的运行**

**未验证**：Harness 在**真实会话中挂载**它——那需要启动应用。CLI 没有能报告挂载状态的子命令（`dsh plugin` 只是转发给 pnpm）。

---

## [3.4.5] — 上游 v3.5.0 的 A 类接地、B1 主数据面接管与 B2 进程插件主动通信

基于 `TwinsEarth/agent-universe` **v3.5.0**（其 `v3.2.1→v3.5.0` 的 7 个提交）。本版按本仓库既有架构落地——**我们的进程插件是原生二进制帧 ABI，不是上游的 Python 沙箱**——并逐项做接地核实：上游宣称的每一项都用 grep/读码/运行核实，区分「上游已修」「我们已有」「我们必须新做」。

### 上游审计点名的缺陷，在我们树里是**活的**，恰好 8 处

| 上游 v3.4.2 点名 | 在我们树里 |
|---|---|
| 约 8 处 `let _ = node.persist()` 丢弃持久化错误 | **真实存在，恰好 8 处** |
| 结算按托管总额付款而非中标价 | **我们已有**（`nau-market::settle` 拒绝用托管预算顶替中标价）|

上游 v3.4.5 称第一条在它自己树里已不适用（`gsn-core` 无 `persist`）——**在我们树里它是活的**。8 处统一改为 `persist_or_report`：失败返回 **500** 并说明「变更已应用但未落盘，重启不保留」——**既不是「成功」也不是「什么都没发生」，而是第三种结果**。**关卡 `no-dropped-persist`** 防止回归，并已证明它会失败。

### B1：插件的回答决定市场能不能动钱

前置条件是先修好一处**接地发现**：`sys.ledger` 曾建在**自己的空账本**上（`LedgerPlugin::new()`，而 `sharing` 全仓库只有一个测试调用过），所以它对任何账户都答 `0 / known:false`。修法是把 `Market` 的账本改为 `Arc<Mutex<Ledger>>`，由 `Node` **只建一次句柄、交给市场与插件两边**。**部署检查第 29 条**比较两个答案。

然后 B1 才成立：结算路由在 `market.settle` **之前**先问 `sys.ledger` 是否为该任务托管，**答否就 409 并点名该插件**。**部署检查第 30 条**证明门在守护进程里是活的；**快乐路径由浏览器 e2e 覆盖**——而正是它抓到了我引入的**半接线**（只修了 `Node::open`、没修 `Node::ephemeral`，后者仍自造第二本账）。

### B2：进程插件的 outbox 主动通信

帧 `Response` 增加可选的 `outbox`（空时**帧字节与之前完全一致**，兼容承诺保留），宿主 `deliver_declared` 逐条投递；`nau plugin run` 打印每条投递结果或**拒绝原因**。

### 采纳的官方插件与如实标注的硬限制

新增 `official.swarm`（**不作涌现判断**——本工作区没有检测器，且上游的判据要调用方给阈值）与 `official.bridge`（离线 Merkle 承诺，`on_chain:false`）。两者现在都在 **`ProcessPluginHost` 的真实沙箱下**运行过。

### CLI 停止下一个含糊的单一断言

`nau --version` 曾只打一行 `based on … v2.5.6`，而 `nau-plugin::UPSTREAM_AUDITED` 指向另一个上游版本，**没有任何东西比对它们**。两者都是真的、回答的是不同问题，所以横幅现在**分别说明**：`ported from … v2.5.6` 与 `answers agent-universe v3.5.0`。

---

## [3.2.1] — 热更新、热插拔、热兼容与安全信道

本版把 V2.2.2 的静态插件体系变成**可在线演进**的：宿主 ABI 从 `2.2` 升到 **`3.2`**，
`HOT_SWAP_SUPPORTED` 由 `false` 变为 **`true`**。

### 一切插件化：全量重审与系统插件补全

对 17 个 crate 逐项重审后（见 [`docs/PLUGIN-MIGRATION.md`](docs/PLUGIN-MIGRATION.md)），
**系统插件（T0）从 4 个补到 17 个 —— 方案文档 §2.1.1 列出的系统插件现已全部接线**，
每一项都委托给既有 crate 而不重写功能：

`sys.blacklist` · `sys.lifecycle` · `sys.arbiter` · `sys.sandbox` · `sys.erasure` ·
`sys.ledger` · `sys.attest` · `sys.http` · `sys.migrate` · `sys.net.transport` ·
`sys.net.dht` · `sys.net.gossip` · `sys.chain`
（连同既有的 `sys.identity` / `sys.storage` / `sys.policy` / `sys.orchestrator`）

**两处「名字比能力大」的地方如实标注**：`sys.net.gossip` 没有可委托的订阅面——本工作区
`nau-net` 完全没有 pub/sub，唯一的真实 topic 规则在 `nau_libp2p::naming`，而为它把整个 libp2p 栈
拖进 T0 宿主 crate 不成比例，所以该插件对订阅上限返回 `null` 并在应答里明说不存在订阅面；
`sys.chain` 不执行任何链上读，它报告配置契约并做输入预检，**不假装读过链**。

**官方插件（T1）从 1 份清单补到 11 份**（`nau_plugins::official::OFFICIALS`）：分级由名字前缀推导、
能力集在本分级可持有、所需审批权威由矩阵导出、`draft()` 产物通过 `validate()`。

### 守护进程终于会**停止**它的插件——`HotPlug::stop_plan` 的第一个调用者

守护进程自获得信号处理器起就有**关闭路径**，而那条路径对插件**什么也没做**：十七个插件在跑，进程退出，有没有状态需要冲刷**没有任何人负责**。

核实：`SystemPluginHost::shutdown` **只在测试里被调用**，而 `HotPlug::stop_plan`——那个算出「必须先暂停哪些依赖者」的函数——**在整个仓库里没有调用者**。

现在 `SystemBoot::shutdown(now)`：

* **按依赖安全序**停止每一个插件（先调 `stop_plan` 拿到该名字的安全计划，再跳过已 `Stopped` 的——因为逆序会先访问依赖者，而依赖者自己的计划又会再次命名它）；
* 顺序**从启动时用的同一张图算出**，不是选出来的：**图里有边的那天，停止顺序自动是对的**，没有人需要改这个函数；
* 接进守护进程的 SIGTERM/Ctrl-C 路径，**失败被打印而不是吞掉**——一个停不下来的插件是操作者需要知道的事实，而进程无论如何都要结束。

**测试断言的是状态而不是「函数返回了」**：17 个全部变为 `Stopped`，停过的插件**不再应答**，再停一次**被拒**（`Stopped` 是终态）——「它停下来了吗」因此可以从外部回答。

**部署检查平台感知**：Node 的 `child.kill()` 在 Windows 上调用 `TerminateProcess`，**没有任何处理器会运行**，所以那条日志在那里**不该出现**，而检查断言了它不出现；Linux/macOS 上断言 `stopped 17 plugin(s); 0 could not be stopped`。**跳过会让该平台看起来像是从未尝试过**。

### PMB 的外部接口：`GET /bus`——总线从外部不可见，变成可观察

目标点名「PMB 内部协议**与外部接口**」。内部协议上一轮接上了载体，但**外部接口不存在**：`Bus::audit()` 与 `Bus::limits()` 在 `nau-node` 里**没有任何调用者**，所以操作者看不到插件发了什么、发给了谁、有没有送到。

现在 `GET /bus`（read 作用域）报出：

* 总线的三条上限（最大消息字节、每分钟条数、审计记录上限）；
* 审计的记录数、**已送达**数、**被拒**数，以及最近 50 条（新的在前，并**有界**——把 4096 条全返回等于给了一条按需让守护进程吐大响应的路）。

**部署检查第一次运行时它报了 `1 audit record(s), 1 carried`**——**总线真的运送了一条消息**：`sys.orchestrator` 的 `announce` 经第 18 轮接上的 outbox 排空进入总线，被审计记下，再由这条路由报出。**整条链现在从外部可观测。**

### 没有 `POST /bus/send`，而载荷自己说出了原因

一次 PMB 发送必须出示**调用者的能力令牌**，而经 HTTP 来的操作者**没有**——令牌是装载时发给插件的。为了让一条路由能发送而现场铸一个，就是**创造一个宿主并不拥有的权限**，正是本构建一直拒绝的那种悄悄放宽。

所以载荷里带着 `send_via_http: false` 与一句 `why_not`，并由部署检查断言二者存在且非空。**「做不到」与「忘了做」从外面看是一样的**，所以这个区别必须被写出来。

### 第 23 轮的 `doc-counts` 关卡，在同一会话里就抓到了自己造成的漂移

本轮新增一条部署检查，部署检查数从 26 变成 27——**关卡立刻报出**：

```
docs/DEPLOYMENT.md:188 says 26 deployment checks, 27 are defined
docs/SELF-AUDIT.md:158 says 26 deployment checks, 27 are defined
```

**十分钟前做的机制，抓住了十分钟后产生的真实漂移，而我不需要记得去更新那两处。** 这正是它存在的理由。

### 两个新官方插件的宿主 e2e，以及 B3 的接地

**还清一笔欠账**：`official.swarm`（涌现检测）与 `official.bridge`（离线跨链）此前**只在作者手里对着真实可执行文件跑过**，从未在 `ProcessPluginHost` 下运行。两者现在都进了宿主测试表——**与之前每一个插件同样的处理**，而不是再写第四份近乎相同的测试体。

对 `official.swarm` 特别说明：`detect` 的 op 是**刻意不作判断**的，所以「跑起来」本身就是断言的内容；一条去找结论的测试等于要求插件凭空发明一个。

### B3 接地：我们缺的正是上游 B3 补的那一处

上游 B3 给 4 个 T0 系统插件接上真实句柄（`SystemHandles { store, peer_cmd_tx }`）。逐项核实我们的对应物：

| 插件 | 我们的现状 | 结论 |
|---|---|---|
| `sys.identity` | mint/parse/fingerprint | **已有** |
| `sys.storage` | `set`/`get`/`append`/`ledger`/`flush`/`dir`，**真的 `FileStore`** | **已有**（视角是「插件自己的房间」，不是缺口） |
| `sys.chain` | 只有 `config`/`precheck`，**结构体里连 store 都没有** | **真缺口** |

上游 B3 后 `SYS_CHAIN` 有 **`record_anchor` / `list_anchors`**（本地 `kv_meta: chain_anchors`，`rpc:"offline"` 如实标注）。我们的 `nau_store::Store` 正有 `get_meta`/`set_meta`，形态对得上；而它还与刚加的 `official.bridge` **配套**——桥提交离线承诺，**锚点日志是记录它的地方**。

**设计已定，但有一处必须先想清楚再动手**：`record_anchor` 是**写**，而该插件只声明 `chain:evm:read`——**在读能力下写**正是本项目一贯拒绝的错配。所以它需要 `chain:evm:write`（System 层为 `Always`，分级允许）。**实现留给下一轮，连同这个能力问题一起。**

### B1 落地：插件的回答决定市场能不能动钱——以及一次被 e2e 抓住的「半接线」

前置条件（上一轮）闭合后，**B1 建起来了**：结算路由在 `market.settle` 之前先问 `sys.ledger`「你是否为这个任务托管」，**答否就不放款**。

这与上游「编排器接管主数据面」同形。我们的门问账本，是因为**市场与账本是同一笔钱的两种记录，而在放款之前从来没有任何东西让它们一致过**。**这一点在上一轮之前无法诚实实现**：插件建在自己的空账本上，门会拒绝每一次结算，同时看起来像一个控制。

**部署检查第 30 条**证明门在守护进程里是活的：一个从未被 publish 过的任务不能结算，且拒绝语点名 `com.twinsearth.sys.ledger`。

### 我引入的半接线，被浏览器 e2e 抓住

我只修了 `Node::open`，**没有修 `Node::ephemeral`**——后者仍用 `Market::new(...)`，**自己造第二本账**。于是：

| | |
|---|---|
| 部署检查（用 `open`） | **全绿**——它看到的是共享了账本的那个构造器 |
| 浏览器 e2e（用 `--ephemeral`） | **在第一次真实结算上失败**：`HTTP 409 ... holds no escrow for it` |

**这正是本仓库一再发现的「接线只接了一半」形态**，而这次抓住它的是**一条覆盖真实生命周期（publish → bid → match → start → submit → verify → settle）的 e2e**。

### 我写下的一句话是错的，已更正

我在部署检查的注释里写了「正常路径**没有**测试覆盖，只能靠构造论证」。**那是错的**：浏览器 e2e 走的正是这条路由，**而且正是它抓到了上面那个缺陷**。注释已改为陈述事实——**一条假的自述比没有自述更糟**。

### B1 的前置条件已闭合：`sys.ledger` 现在读的是**节点自己的账**

上一轮接地发现 `sys.ledger` 报的是另一本账（`LedgerPlugin::new()`，一本空账本），并量准了修复面。这一轮**整块做完**：

* `Market` 的账本由 `Ledger` 改为 **`Arc<Mutex<Ledger>>`**，新增 `Market::sharing` / `restore_sharing` / `ledger_handle`，全部 23 处读取改走一个 `books()` 守卫（**中毒恢复而不是传播**：一次留下半笔移动的 panic，不会因为此后的每次读取都拒绝而变得更好）；
* `standard_plugins` **接收一个 `books` 句柄**——签名本身让「给插件一本空账」不再可能顺手做出来；
* `Node` **只建一次句柄、交给市场与插件两边**；
* `Market::ledger()` 经核实**没有任何调用者**，所以它的消失没有影响任何东西。

**部署检查第 29 条比较两个答案**：

```
the ledger plugin reports the same balance the market does
  PASS  plugin=1000000 = market=1000000, known=true
```

修复前插件会对同一个账户答 `0 / known:false`。**这条检查就是本该抓到原缺陷的那一条。**

**一处差点变成空洞为真的测试**：`crates/nau-market/tests/authority.rs` 用源码字面量断言 `!SERVICE.contains("ledger.stake(")`——账本移进 `Mutex` 后路径变成 `books().stake`，这两个**否定断言会永远为真：测试继续通过而什么也没测**。

> **否定断言是唯一一类主语被改名后会静默失效的断言。**

所以它们改为匹配市场**不该发出的调用**（`.stake(` / `.unstake(`），而不是通往它的路径；同文件里两个肯定断言也一并改为匹配调用本身。

`doc-counts` 又一次抓到本轮造成的 28→29 漂移。

### B1 的接地：`sys.ledger` 在运行中的节点里报的是**另一本账**

上游 v3.4.5 的核心是 **B1「主数据面编排接管」**——让插件的判断决定市场能不能动手，而不是事后汇报。上游的门是 `settle_task_gated`：先取账本快照 → 审计 → 通过才结算。

对我们的架构，对应的门是：**结算前先问 `sys.ledger`「这本账是否为该任务托管过钱」，答否就不许放款**。

**动手前先接地，结果这道门在今天会永远拒绝**：

* `standard_plugins` 在 `crates/nau-plugins/src/host.rs:1135` 用 **`LedgerPlugin::new()`** 构造 `sys.ledger`——**一本空账本**；
* `LedgerPlugin::sharing`（把宿主已有的账本交进去）**在整个仓库里只被一个测试调用过**；
* 所以运行中的节点里，`balance` 对任何账户都答 `0 / known:false`，`escrow` 对所有任务都答 `open:false`——**无论节点实际拿着多少钱**。

**我们自己的注释早就预言了这件事**（`host.rs:1099`）：

> *「A host with real books **must** use `LedgerPlugin::sharing` at the wiring site, because this function has no way to know which ledger the node runs.」*

**在动手之前抓住它，正是接地的意义**：建在空账本上的结算门会永远拒绝——**一个看起来像控制、实则是装饰的门**，比没有门更糟，因为它会被读成「结算受账本保护」。

**实测的修复面**（供下一轮直接执行）：`Market` 内联持有 `Ledger`（`service.rs:140`），共享需改为 `Arc<Mutex<Ledger>>`，牵动 **26 处 `self.ledger`（`service.rs` 23、`persistence.rs` 3）、8 个方法**，以及 `pub fn ledger(&self) -> &Ledger`。**这一轮没有半做**：一个改到一半的可变性模型比现状更危险。

### A 类接地：上游审计点名的那处缺陷，在我们树里是**活的**，恰好 8 处

按上游 v3.4.5 的方法，先做 **A 类接地核实**——把上游 v3.4.2 审计点名的缺陷**在我们自己的代码里**逐个查，而不是相信上游「已不适用」的结论。

| 上游 v3.4.2 点名的缺陷 | 在我们树里的核实结果 |
|---|---|
| `node.rs/api.rs` 约 8 处 `let _ = node.persist()` 丢弃持久化错误 | **真实存在，且恰好 8 处**（`crates/nau-node/src/api.rs`）|
| 结算按托管总额付款而非中标价 | **我们已有**：`nau-market` 的 `settle` 按中标价付款，并**拒绝用托管预算顶替**——注释里点名了上游的 `winner_price.unwrap_or(budget)` |

**上游 v3.4.5 说这条在它自己树里已不适用**（`gsn-core` 里 `persist` 零命中）。**在我们树里它是活的**：调用方 POST 一个变更、拿到 200/201，而写盘失败的**错误被丢弃**——崩溃即静默丢失。

**修法必须诚实**：变更**已在内存中生效但未落盘**，既不是「成功」也不是「什么都没发生」。所以 8 处统一改为 `persist_or_report`，失败时返回 **500 并明说**「变更已应用但未能写盘，重启不会保留」。

**并且做成关卡**：这是**文本层面**的性质（对端难以在三平台可靠制造磁盘故障来观察 500），所以新增第 20 道关卡 `no-dropped-persist`，扫全部生产 `.rs` 文件里的 `let _ = ….persist();`。**并证明了它会失败**：改回一处后它报出 8 处，恢复后回到 PASS。`doc-counts` 随即抓到本轮造成的 19→20 漂移。

### 文档里的关卡数目：五处断言写了三个不同的数字，而没有东西比对过

沿上一轮的线索继续查可检验的散文断言，这次查**关卡与检查的数目**：

| 位置 | 写着 |
|---|---|
| `docs/VERIFICATION.md:20` | 全部 **16** 道关卡 |
| `docs/PLUGIN-ARCHITECTURE.md:339` | **17** 道关卡必须继续全绿 |
| `docs/PLUGIN-MIGRATION.md:169` | 沿用 **17** 道关卡 |
| `docs/DEPLOYMENT.md:188` | **18** 项部署检查 |
| `docs/SELF-AUDIT.md:158` | **19** 项部署检查 |

**同一个数字，文档之间写出了三个值**；而真实数字是别的（当时 **18 道关卡 / 26 项部署检查**）。

**「17 道关卡保持全绿」不是装饰**——读者正是用它判断「被描述的验证」是不是「跑过的验证」。一个过期的数目会让整张表看起来**从未被重读**。

### 新增第 19 道关卡：`doc-counts`

两个数字现在**从定义它们的脚本里导出**——本文件的 `gate(` 调用数与 `deploy-local.mjs` 的 `await check(` 调用数——所以**改数字改不出合规**，只能改事实。关卡跑出 `4 stated count(s) agree (19 gates, 26 deployment checks)`。

**并且验证了它真的会失败**：故意把一处改回 `18 项部署检查`，关卡报出

```
docs/DEPLOYMENT.md:188 says 18 deployment checks, 26 are defined
```

——精确到文件、行号与两个数字；恢复后回到 PASS。**一个不会失败的关卡是装饰**，所以「它能不能红」本身也验了一遍。

文档仍可以不带数字地谈论过去的版本；它**不能**把当前总数写成一个已经不是的数。

### 文档里的数字也是断言——两条已经过期，现在由关卡比对

上一轮发现「测量胜过记忆」。这一轮沿同一条线索查**文档里的数字**，当场找到两条过期断言：

| 位置 | 写着 | 实际 |
|---|---|---|
| `docs/PLUGIN-MIGRATION.md` §5 | 11 份清单齐备，**1 项可运行** | **4** 项（T1），加上 T2/T3 共 **6** 个二进制 |
| `docs/VERIFICATION.md` | 交叉目标**仍只覆盖 7 个 crate**，`ring` 来自 `nau-libp2p` | **16/17**，`ring` 来自 **`nau-node`** |

**第一条正是在把它变假的那个会话里过期的**：同一节的表格被更新为四项，而节末的句子仍写着一项——**没有任何东西比对过它**。

### 于是把关卡加上第 8 条不变量

新不变量：**`docs/PLUGIN-MIGRATION.md` 必须命名 `src/bin/` 下每一个非夹具的 `nau-plugin-*.rs`，且它命名的每一个文件都必须存在**。

它第一次运行就抓到了真问题：**`nau-plugin-swarm.rs`（T2）与 `nau-plugin-reputation.rs`（T3）在运行，却没有任何一行声明它们可运行**——因为 §3 的表格只覆盖 T1。正确的修法不是放宽检查，而是**让文档在一处完整声明本构建交付的全部可运行二进制**（新增 §3.1，跨全层级），这样检查才是精确的。

`nau-plugin-echo.rs` 的豁免**写在关卡里、也写在文档里**——让它是一个公开的决定，而不是命名习惯的副产品。

**「一个描述系统的文档，在这里是系统正确性的一部分」**——这正是本仓库「写了不等于接线了」纪律的前提。散文里的断言不被比对，就会在无人察觉时变假。

### `cross-target` 关卡：从一张记错的常量表改成一次实测

关卡在缺 C 交叉工具链时回退到一个**硬编码的 7 个 crate 列表**。实测：

| | 结果 |
|---|---|
| 工作区 crate | **17** |
| 无 C 工具链即可为 **Linux** 完成类型检查 | **16** |
| 无 C 工具链即可为 **macOS** 完成类型检查 | **16** |
| 唯一失败的 | **`nau-node`**（`ring@0.17.14` 需要 `x86_64-linux-gnu-gcc` / `cc`） |

**那张表错了 9 处，而且它无法知道——没有任何东西重算过它。** 一个回答「什么被验证了」的常量，在依赖变化的瞬间就过期，而**过期是不可见的**：关卡继续报一个曾经为真的数字。

现在还发现关卡注释把 `ring` 归因于 `nau-libp2p`——**实测把它定位到 `nau-node`**。这正是测量能做对、而记忆做不对的事。

关卡现在**逐个 crate 实测**，报出 `N of 17 crates type-check; nau-node needs <tool>`。判定仍是 SKIP（工作区整体确实未在此验证，而 CI 在三平台上原生运行它——那比本地类型检查更强），**但细节从一句记忆变成了一个测量**。

### T0 的依赖图为空——核实过的结论，而不是假设；以及依赖机制第一次真的排了序

上一轮我把「没有发布的插件声明依赖」标为待考。这一轮**去核实为什么**，逐项审计了 17 个系统插件的 `init`：

> **全部只有 `self.grant.adopt(ctx)` 加一行日志。** 没有任何插件在初始化时向另一个插件索取东西；而 T0 插件唯一的跨插件通道是**总线**，且**没有任何一个发送**。

所以空图是**正确的**，`HotPlug` 无法重排 T0 插件也是**正确的行为**——不是未接线的特性。`dependencies` 字段真正服务的是 **T2/T3 的进程插件**。**凭空发明一张 T0 依赖图会让「启动顺序」看起来有依据而实际上没有。**

**同时补上第 19 轮缺的那个证明**：两条端到端测试，走**完整流水线**（parse → blacklist → verify → certification → compat → limits → runtime → registry）：

* **`a_declared_dependency_is_ordered_before_its_dependent`** —— 两个真实插件装载后，注册表把被依赖者排在前面。没有它，机制可以完整却**从未排过任何东西**。
* **`a_dependency_that_is_not_registered_is_refused`** —— 指向不存在插件的依赖**被拒绝**，并点名缺的是哪一个。**边被强制，而不只是被记录**。

夹具构造器也要重签：**边必须在签名之前就在清单里**（摘要覆盖载荷），这正是 schema 测试从另一侧钉住的同一性质。

### 清单终于可以声明依赖——而「摘要不变」是这条特性的承重墙

上一轮发现 `Manifest` **没有依赖字段**，所以 `HotPlug::start_order`/`stop_plan`、`Registry::load_order` 与 `sys.orchestrator` 这一整套机器**对任何存在的插件都做不了事**——一个只在夹具里能做的声明不是声明。

现在 `Manifest` 有 **`dependencies: Vec<Dependency>`**，且 `LoadRequest::new` 把清单里的边**真的送进流水线**（它此前永远 `Vec::new()`，而 `depending_on` 的唯一调用者在测试里）。

**承重的是那个 serde 属性**：

```rust
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub dependencies: Vec<Dependency>,
```

序列化后的清单正是**发布者签名覆盖的载荷**。如果这个字段对每个插件都输出一个空数组，**每一个摘要都会改变，每一个已经在场的签名都会失效**——而本版本承诺 2.x 插件仍可装载。`skip_serializing_if` 守住那个承诺，而测试守住 `skip_serializing_if`：

- 一份**不声明依赖**的清单**不出现 `dependencies` 键**，且仍能回读；
- 一份**声明了依赖**的清单，边**在**签名覆盖的载荷里（可回读）；
- `LoadRequest::new` 的提取被**直接测试**，包括「形状不是数组时产出**零条**边而不是猜」——而流水线自己的 `parse` 阶段用 `deny_unknown_fields` 反序列化整份清单，所以这个宽松的提取**不会放进流水线本会拒绝的东西**。

**一处 clippy 抓到的静默风险**：我插入的测试与原有 `#[test]` 属性重叠，clippy 报 `duplicated attribute`。真正的属性在两个测试之间悬空——**这类错误可以让一个测试悄悄不再运行**，所以它值得被编译器抓住而不是被人眼放过。

**如实标注**：**没有任何随版本发布的插件声明依赖**，所以 T0 的启动序**仍然是插入序**。机制已经完整且有测试；**T0 的依赖图是一个需要证据的设计决定，不是可以凭空发明的**——`docs/PLUGIN-MIGRATION.md` 与 `VERIFICATION.md` 都如实写着这一点。

### `sys.orchestrator` 一直在回答「没有插件」——而测试把它钉成了正确行为

`boot_system_plugins` 用注释写下：

> *the plugin cannot reach the registry, only this answer* —— 一个「**empty at boot and filled as plugins register**」的注册表。

**没有任何东西填它，也不可能填**：`Arc<Registry>` 共享且不可变，而 `host.register` 写的是**宿主自己的表**。于是：

> **`sys.orchestrator`——那个唯一职责就是回答「插件该按什么顺序启动」的 T0 插件——永远回答一个空列表。**

`/plugins` 显示 17 个插件在运行，而它自己的 orchestrator 说一个都没有。全仓库 `LoadRequest::depending_on` 的**唯一调用者在测试里**。

**更糟的是测试**：`the_orchestrator_cannot_see_the_registry_only_the_order` 断言 `order == 0`，理由是「它拿到的注册表是空的」——**那不是属性，那是把 bug 写成了要求**。测试让空答案看起来是刻意的，所以启动存在多久它就藏了多久。

**修法**：把顺序反过来——**先验证全部 17 份清单、填好注册表、用 `HotPlug::start_order` 算出启动序，再创建插件对象**，并按该顺序注册。`HotPlug` 从此有了生产调用方（它此前**一个都没有**）。

**测试重写**：保留真正的属性——**端口**。orchestrator 现在必须**点名每一个**插件（与 `/plugins` 一致），并且答案里**只有名字与数量**，不含能力、令牌或摘要；`capability`/`token`/`grant`/`digest` 出现即失败。

**如实标注**：`Manifest` **没有依赖字段**，所以插件无法声明依赖，`HotPlug` 仍然**无法重排任何东西**——一个没有边的图上的拓扑序就是插入序。生产检查现在是 **26 项**（新增一条：orchestrator 必须点名 17 个，第一个是 `com.twinsearth.sys.arbiter`）。

### `nau plugin run`——T1/T2/T3 终于有一个操作者能用的入口

核实发现：**`ProcessPluginHost` 只在它自己的测试里被构造**。守护进程与 CLI 都不构造它，CLI 虽然把 `ProcessRuntime` 注册给了仲裁器（能过运行时的门），却**从不调用 `start`**。于是：

> **T1/T2/T3 可以被装载、被审核、被认证，而没有任何交付的工具运行过它们。**

`verify` 自己也如实写着 *"The plugin was NOT executed."*——那句话在整个构建里都是准确的。**一整套分级能通过每一道门却从不运行**，是本仓库里**规模最大的一处「写了没接线」**。

现在 `nau plugin run <dir> --trust <key> --op <name> [--payload <json>]`：

* **复用 `verify` 的整条流水线**（同一个函数体、同一个 trust/仲裁器构造）——两套「今天一致、下一次编辑后不一致」的构造，在这里的分歧会是**操作者验证的东西与他们运行的东西之间的分歧**；
* 通过后**真的启动**（`ProcessPluginHost` + 真实沙箱，一份一次性的临时根目录）并调用一个 op；
* 打印插件的**原始应答**（`ok` / `code` / `message` / `payload`），并如实说明它只驱动**进程运行时**；
* `--payload` 不是 JSON 时按 JSON 字符串传递——**插件的载荷形状归插件所有**，这条命令不做第二个解析器；
* 清单里的 `limits` 取自**清单本身**（流水线刚校验过那个对象），而不是测试夹具。

测试用的是**真的 echo 二进制**而不是其他夹具用的 shell 桩——这个差别就是重点：**桩能过流水线但答不出帧，所以它能证明「装载」而不能证明「执行」**。测试还断言未知 op 退出码为 1 并回报插件自己的 `abi_unknown_operation`。

### 违规升级接上了 T0 流量——「三次越权即隔离」不再只是一句话

内核自 `send_checked` 起就会把**被拒绝为 misconduct** 的消息记为违规，三次即隔离。而那条路需要 `&mut Registry`，`SystemPluginHost` 没有（它的插件不在装载注册表里）。所以对系统插件而言，规则**止步于拒绝**：它可以无限越权并继续运行——「三次违规即隔离」对进程插件为真、对内建插件**只是一句话**。

生命周期就在宿主里，所以违规现在记在这里。

**哪些拒绝算 misconduct 由总线回答**——`Bus::refusal_is_misconduct` 本来就 `pub`，宿主直接问它，**不在这份文件里另立一份清单**：一份策略，一个地方。

测试驱动同一个越权插件三次，断言第三次后状态为 `Quarantined`，并断言**被隔离的插件连排队都不行**。最后一条是我写错、被实现纠正的：我原本断言「排队仍然有效，因为插件对象还在」，而宿主给了更好的答案——***"a plugin that is not serving does not answer"***。升级把插件从**交换的两半**里都拿了出去。

### PMB 内部协议接上了运行时载体

上一轮定位的缺口：**一个把消息放进 outbox 的 T0 插件，在运行中的节点里没有任何东西会把那条消息送出去**。这一轮把它闭合，而**根因比一开始以为的小得多**：

`Bus::send` 用注册表**只做一件事**——`require_running` 问「这个插件在运行吗」。把这个问题抽象成 **`BusMembership`** trait 之后，`SystemPluginHost` **自己就能回答**（生命周期就在它的 `entries` 里），于是 `flush_outbox` **不再需要一个宿主没有的 `Registry`**。

* `Node` 现在持有总线，`POST /plugins/<id>/call` 在应答后**排空 outbox**，并把结果作为 `bus` 数组回报给调用方（**部署检查断言该字段存在**）。
* `Node::drain_plugin_outbox` 借的是**两个不相交字段**：`node.plugins_mut()` 与 `node.bus_mut()` 是两次对 `node` 的可变借用，**借检会在看到总线之前就拒绝**——直接借字段才写得出来。这个方法因此属于 `Node`，因为只有它同时拥有两者。

**仍如实标注**：`SystemPluginHost` 的**违规升级**（三次越权即隔离）**不适用于经此路径的 T0 流量**，因为记录违规需要 `&mut Registry`，而这条路径没有。这是内核里剩下的缺口，与上一轮同源。

### PMB 内部协议没有运行时载体——以及让「没人取走的消息」可见

沿上一轮的脉络核实「总线是否真的在跑」，结果是**没有**：

- 生产中 `Bus::new` 只出现在 `plugin_cli.rs` 与 `plugin_review.rs` 的**一次性装载流水线**里（其余全是测试）；
- **`Node` 既不持有 `Bus` 也不持有 `Registry`**；
- **`SystemPluginHost::flush_outbox` 没有生产调用方**。

于是：**一个把消息放进 outbox 的 T0 插件，在运行中的节点里没有任何东西会把那条消息送出去**。目标里点名的「PMB 内部协议」是**内核组件**（能力校验的 `send`、优先级规则、审计记录、违规升级都有测试），但它**在运行时没有载体**。

而它**按现状无法接线**：`flush_outbox` 调 `bus.send(registry, ...)` 需要注册表解析接收方，而 `SystemPluginHost` 只持有 `entries`、**不持有 `Registry`**。这是内核层面的设计缺口，不是一处小接线——所以我**没有半接线**，而是**把它变成可见的**：

* `SystemPluginHost::outbox_len(name)` + `/plugins` 每个插件的 `outbox_pending`；
* 部署检查新增断言：**17 个插件在启动时的待发队列必须都为 0**（现在 25 项检查）。

**「队列没人读」与「队列永远是空」在没有这个数字时无法区分**——这是载体缺失期间诚实的下限。

### 第二处：`HotPlug::start_order` 在系统插件上**结构上无法接入**

`SystemPlugin` 只有 `id`/`capabilities`/`init`/`handle`——**没有依赖方法**，所以内核基于 `Registry` 的顺序计算**没有输入可算**。把它接在系统插件上，产出会是一个**单元素计划**，也就是装饰。它属于**进程插件**那条路径（那里的 `Registry` 真的带依赖）。这一条**没有接线，理由写明**——因为唯一能接的方式是装饰。

### 热插拔：从「无人使用的机制」到真实路径

上一轮核实发现：`nau-plugin/src/lib.rs:116` 把 `HOT_SWAP_SUPPORTED = true` 的机制指为 `hot::HotSwapper`，
而它在 `crates/` 下的**唯一引用就是它自己的模块与测试**——**本版的门面特性建立在一个没有生产调用方的机制上**。

现在 `ProcessPluginHost` 持有它，并走完真实的三步：

1. **准备**：替换件在自己的沙箱里启动，**与运行中的版本并存**，尚未切换。
2. **健康检查**：用探针调用替换件。**未通过者永不进入路由表**——所以坏发布是一次失败的替换，而不是一次故障。
3. **切换与排空**：单次指针替换（写锁下），随后销毁旧沙箱。排空失败会被**记录**，但**不会把旧版放回去**——新版已在服务，因为旧版停不干净就复活它，是伪装成回滚的降级。

**两处由内核自己的拒绝句教出来的设计**：

- **`prepare` 必须与 `start` 分开。** 第一版 `swap` 建在 `start` 上，`RoutingTable::insert` 拒绝为已路由的名字再插一次，而它的拒绝句自己说出了原因：*"use `swap` so the running instance is drained"*。建在 `start` 上的 `swap` 根本不可能工作——所以拆分不是装饰。
- **健康检查必须要求 `ok: true`。** `call` 对**拒绝帧也返回载荷**（第 4 轮修的原则：帧是协议、退出码是提示），所以只查传输错误会放过一个「对什么都答不」的替换件。健康检查必须意味着「它答出了被问的那个问题」。

测试断言**两半**，因为只说「替换成功」会在「换成什么都算成功」的实现上也通过：健康替换件接管（新 generation、版本被记录、历史一条），而**拒绝探针的替换件永不接管流量**（版本不变、历史不变、旧版仍应答）。

**如实标注**：`HotPlug`（启停顺序）**仍无生产调用方**。

### 官方插件 3/11 → 4/11，并把「未实现」逐项说明成有理由的事实

* **`com.twinsearth.official.agent`** → `nau-plugin-agent.rs`，`validate` 委托 `nau_core` 的**当前** `AgentCard::validate`/`Verifiable::verify`/`check_freshness`，`project` 只读字段。
  它与 `sys.migrate` 的区别被写进模块文档：后者读的是**上游 v2.5.6 的遗留** card（逐字文本 + 需要外部 DID→key 注册表），本插件拿的是**本仓库当前的类型**并让内核判它。

**`AgentCard::validate` 只返回第一个失败**——这是 API 的真实性质，也是宿主会依赖的性质，所以它被报告成三个字段而不是一个布尔：`verdict_is_first_failure_only: true`、`later_invariants_not_examined`、以及列出 11 条检查**顺序**的 `invariant_order`，让宿主看得见判定停在了哪里（该字段是**转述**而非调用结果，由 13 个单问题夹具 + 4 个双问题夹具守护）。

**签名与结构从不合并**：三个独立调用、三个独立字段；未问时 `signature_valid` 是 `null` 而非 `false`。两个只有分开才看得见的情形被测试钉住：**结构非法但确实由 owner 签名**（`valid: false` 而 `signature_valid: true`），以及**结构合法但签名已不覆盖它**（`valid: true` 而 `signature_valid: false`）。

**`docs/PLUGIN-MIGRATION.md` §3 的表格重写了**：11 项里 4 项可运行、7 项未实现，而**7 项里每一项都有具体理由**——5 项是「功能已由别的插件承担或用不到独立面」（economy→`sys.ledger`、swarm→T2 swarm、shard→`sys.erasure`、crdt→**本仓库没有任何 CRDT crate**、test-runner→没有可委托的 crate），2 项是**硬限制**（bridge 没有 Rust 链客户端、mesh 没有 pub/sub）。**把这些写成「待办」会让它们看起来像是额度问题；它们是关于这份代码库的事实。**

### 官方插件 1/11 → 3/11：official.mcp 与 official.scheduler

* **`com.twinsearth.official.mcp`** → `nau-plugin-mcp.rs`，`initialize` 委托 `nau_mcp::protocol::{negotiate, is_supported}` 与 `capability::InitializeResult`，`rpc` 委托 `nau_mcp::rpc::parse_request`。
* **`com.twinsearth.official.scheduler`** → `nau-plugin-scheduler.rs`，`validate`/`transition` 委托 `nau_core` 的 `Task::validate`、`Task::validate_and_verify`、`Task::is_expired`、`TaskSpec::gaps`、`TaskId::parse`、`TaskState::{can_transition_to, transition, is_terminal}`。

**依赖边要在两处存在**——这是一个真实的坑，由 teammate 以「**在我创建任何文件之前**的紧急检查」形式拦下：`nau-mcp` 既不在 `nau-plugins` 的依赖里、**也不在根 `[workspace.dependencies]` 里**。我第一次只补了一半，cargo 把错误报在**毫不相干的 `crates/nau-node`** 上（`failed to load manifest for workspace member`）。两次教训都写进了清单注释。teammate 的排序是对的：**边不到位就不创建文件**，先写不需要新依赖的 scheduler，MCP 在临时工作区里先跑绿——所以上一轮的 `autobins` 断裂没有重演。

**审计信息如实而非凑数**：两个插件都只声明 `plugin:message:send`（基础集），所以 `required_approvals: []` 是**准确值**。为了让层级规则仍然可见，它们另外用代码走 `Capability::ALL` 导出 `non_basic_capability_authorities: ["vendor-team"]`——**而不是为了让它非空去声明一个目录项并未给出的能力**。

**调度器的真实 API 比假设更丰富**（无需收窄），但 `Task::validate` **比它的名字窄**，所以结论被刻意拆开：`valid` 只覆盖 spec 字段与上限，**不看 `id`**（`serde` 能从任意字符串构造 `TaskId`，所以 op 用内核自己的 `TaskId::parse` 重新校验，并有测试钉住 `valid: true` 而 `id_valid: false`）；**不覆盖签名**（`signature_valid` 在未校验时是 `null` 而非 `false`）；`validate_and_verify` 调的是 `verify` 而**不是** `verify_fresh`，所以 `expired` 单独由 `Task::is_expired(now)` 回答；生命周期合法性属于 `transition` 的表。`TaskState::can_transition_to` **没有自环**而 `transition` 对 `from == to` 返回 `Ok`，两者都被调用并分别报告（`legal_edge` 与 `applied`），让宿主自己选语义。

**MCP 的真实 API 也如实标注**：`negotiate` **不会失败**——不支持的请求会被答以默认版本，所以答案里 `requested_version_supported` 与 `negotiated_version` 并列；只看后者的宿主会看到一个合理版本，**永远不会知道它没被兑现**（该 crate 自己的模块文档描述的正是这个上游缺陷）。`parse_request` **不检查 `jsonrpc` 字面量**，所以 `has_valid_version()` 单独调用并报告。

**宿主层**（`plugin_process.rs`，Windows）：两个都在真实沙箱里经 `ProcessRuntime` 启动并应答——**又是二进制作者明确说无法证明的那一半**，这已经是连续第三轮，所以它现在是例行项而不是人情。

### 第一个 T3 第三方插件对象，以及它让两条路径首次相遇

**`com.example.reputation`** → `crates/nau-plugins/src/bin/nau-plugin-reputation.rs`，
`advise` 委托 `nau_market::reputation::Reputation::{record_settled, record_fault, record_clean,
overall_bps, overall, is_eligible}`。**第一个发布在第三方名字下的插件**——而第三方层级正是
「注册审核流程」为之而建的层级，也是**黑名单条目要拦下的层级**；在此之前没有对象，所以这两条路径从未相遇。

**弧线（`crates/nau-node/tests/plugin_cli.rs`）**：同一个目录、同一份清单、同一个 trust 存储——
**两半之间只有隔离名单不同**：先是 `verify` 装载成功（trace 显示 `tier 3rd`），加上一份已签名的黑名单条目后**被拒**，
且拒绝来自**黑名单阶段自己的句子**。所以第二半的拒绝不可能是别的原因。

**设计收窄是刻意的**：T3 **只持有基础集**，而声誉模型没有任何 T0 插件包装。插件作者把 op 收窄成一个**纯函数**
（对调用方给的内存结构施加模型自己的 mutator 并返回），因此它**真的**只需要 `Capability::BASIC`——
`declares_only_the_basic_set: true`、`required_approvals: []`。作者请我复核这个判断：如果「施加声誉更新」
被认为需要 `economy:settle`，那么**任何** T3 插件都做不了这件事（T3 直接拒绝它）。我同意收窄，因为它是对的。

**宿主层**（`crates/nau-node/tests/plugin_process.rs`，Windows）：经 `ProcessRuntime` 在真实沙箱里启动。
**这一层又是二进制作者明确说自己无法证明的那一半**——这次它提前提醒我 `tier` 的精确字符串是 `"3rd"` 而非
`"third_party"`，所以这条测试一次通过。

**无需改 `Cargo.toml` 依赖**：`nau-market` 在前一轮已是 `nau-plugins` 的依赖，所以尽管 `autobins`
让新文件立刻成为 target，`--locked` 首次检查即通过。

**三处与任务假设不符、由作者如实报出的 API 事实**：三个 mutator **返回 `()`**（所以「报告返回值」字面上就是
「报告被改动的结构体」）；`overall` 的**权重不可获取**（是 `overall_bps()` 内部的私有常量），所以插件报告四个
**维度**分数而**不重述权重**——重述就是在重算模型拥有的东西；`record_settled(latency_ratio_bps, evidence_trustworthy)`
的延迟参数是**相对自身宣称 p95 的基点**（10000 = 正好达标），不是毫秒。

### 第一个 T2 认证插件对象，以及它走完的整条弧线

**`com.twinsearth.certified.swarm`** → `crates/nau-plugins/src/bin/nau-plugin-swarm.rs`，
进程插件，`tally` 直接委托 `nau_consensus::Committee::{assign, cast, tally}`。
这是**第一个发布在 `com.twinsearth.certified.*` 名字下的插件**——该层级此前只有机器、没有对象。

端到端证据分三层，缺一层都不能说「一个认证插件在运行」：

1. **流程层**（`crates/nau-node/tests/plugin_cli.rs`，真实二进制）：提交申请 `swarm:consensus`
   （T2 下需委员会审批、T3 下直接被拒）→ 扫描零阻塞 → 四阶段推进 → 认证范围含该能力 →
   **`verify --certification` 装载成功**；把范围缩小后**被拒并点名该能力**。
2. **二进制层**（其作者在真实 exe 上验证）：帧 ABI、未知 op 是类型化退出码、
   截断帧不 panic、以及用**另一进程签名的选票**驱动 `tally`（接受/拒绝/模棱两可作废/伪造选票被拒）。
3. **宿主层**（`crates/nau-node/tests/plugin_process.rs`，Windows）：经 `ProcessRuntime` 在**真实沙箱**里启动，
   回答 `capabilities` 与未知 op 的拒绝。**这一层是二进制作者明确说自己无法证明的那一半**，
   他如实标注而不是含糊过去——所以补了这条测试。

**审计信息如实区分**：`declared_capabilities_backed_by_ops: false` 而
`every_approval_gated_capability_backed_by_ops: true`，并附 `notes` 说明 `tally` 是
`swarm:consensus` 的**计票那一半**——它不替自己投票、不开网络轮次、不 gossips。三个基础能力被声明但没有 op 行使它们，
所以聚合值为 false。

**一处真实的构建陷阱，由 teammate 以「紧急」而非脚注报出**：cargo 的 `autobins` 默认开启，
`src/bin/*.rs` **立刻**成为被发现的 target，所以「新文件 + 缺依赖」会让 `-p nau-plugins` **对所有人**编译失败，
而 `[[bin]]` 段只是文档、不是开关。已在 `Cargo.toml` 里写明这一点。
（新增工作区内部依赖会重写 `Cargo.lock`，所以**第一次构建不能带 `--locked`**——之后 `--locked` 通过。）

### T2 认证插件现在真的能被审核与认证（此前三处各拒绝一件它本该许可的事）

「认证插件 T2」一直是纸面层级。要让它可用，需要打通三处**各自都在拒绝自己本该许可之物**的检查：

1. **能力判定硬编码 T3**（上一版已修为按名字推导）。
2. **`Grant::RequiresApproval` 被记成 Blocker**——流程拒绝「以审批为条件的能力」，而它**正是唯一能授予该审批的地方**。T2 层级的全部意义就是「委员会批准后可以持有敏感能力」。
3. **装载信任里只有发布者密钥**——而 `com.twinsearth.certified.*` **要求 vendor 反向签名**，于是扫描把该层级**自身的存在条件**报成了阻塞。

同时把「认证即审批」接上：`Arbiter::with_certification` 现在**从认证范围推导审批**（用同一份 `Capability::decision`）。要求操作者分别提供审批与范围，会让后者冗余、前者容易漏——而**同一次决定被拆到两个可能互相矛盾的地方**，正是缺陷的温床。

**扫描的问题被重新表述清楚**：认证是扫描**之后**才产出的，所以扫描只能问「**若按本次评审将要授予的范围认证，能否装载？**」。因此它对照的是**审核将创建的宿主状态**（一份**明确标注为预期、不落盘、署名留空**的 `Certification`），而不是一个「没有任何审核」的宿主。此前它问的是后者，于是**每个 T2 提交都在 `certification` 阶段被拒**。

新增端到端测试走完整条弧线：`com.twinsearth.certified.*` 提交申请 `net:dht:read`（T2 下需委员会审批、T3 下直接被拒）→ **扫描零阻塞** → 走完阶段 → **认证范围包含该能力** → 产出 `certification.json`。

### 认证层级按插件名推导（修掉我上一版引入的可操作性回归）

`nau plugin review` 的 `certify` **硬编码 `Tier::ThirdParty`**（在扫描规则、逐能力判定与
`Certification::issue` 共四处）。而第 4 轮让**仲裁器要求每个 `com.twinsearth.certified.*` 名字都持有认证**——
于是出现了我造成的一个回归：**能产出认证的唯一工具把它签发在 T3 上限上，而 T3 直接拒绝 T2 存在的意义**
（T3 只能持有基础集；`net:dht:read` 等在网络/链/经济/共识类上被 T3 **直接拒绝**）。
**一个层级要求认证，而发布的工具链无法为它产出认证。**

现在层级**从插件名推导**（`named_tier`），与内核在别处判定插件层级的规则同一条：扫描的层级规则、
逐能力判定、重放中的 `issue`、`certify` 命令都使用它。本流程登记 **T3 与 T2** 两类名字
（系统层是进程内的、官方层由发布方发布，两者都不走提交流程）。

新增断言的**两个方向**（只有成对才说明「是层级在决定」）：同一份评审、同一个能力
`net:dht:read`，**T2 范围接受**、**T3 范围拒绝**并点名该层级。

### 守护进程现在**使用**它的插件（此前只启动、从不调用）

上一版让守护进程启动了 17 个系统插件并报告状态。但**启动并报告不等于让它们做事**——守护进程启动了自己的功能，然后从不调用。这正是同一缺陷再深一层，也是 `plugins_mut` 一直躺在 `Node` 里当死代码的原因。

新增 **`POST /plugins/<id>/call`**（**Admin** 权限，不是 Write：这条路由通向节点自身的机械装置——`sys.policy` 写策略表、`sys.blacklist` 读隔离名单、`sys.orchestrator` 代表装载顺序；让 write 级调用者够到它们，就是让调用者通过一个插件 id 够到节点内部）：

* 调用者**自己声明**它要求插件以哪个能力行事，**由插件自己的 `require_declared` 判定是否可接受**。路由**不保留**「哪个插件接受哪个能力」的第二份清单——那会变成能力模型的第二事实源，而第二份事实源就是会过时的那份。
* 除 `capability` 外的字段**原样透传**给插件：在这里重塑它等于把每个插件协议的第二份、且不一致的视图放进路由。
* 宿主与插件的拒绝都是**值**（未知目标、插件未运行、能力未被声明），以 400 返回而不是异常。

部署关卡新增两条（现在 **25** 项，CI 三平台执行）：
`the daemon can call a system plugin and read its answer`（`policy.matrix` 答出 4 条，与 `nau plugin system` 这个独立调用者可比对）、
`a plugin call under a capability the plugin does not declare is refused`（**由插件**拒绝，不是由路由）。

### 守护进程现在真的承载它的插件（此前 17 个插件只在有人敲命令时才跑）

`boot_system_plugins` 此前只被**它自己的单元测试**和 `nau plugin system` 命令调用——
**守护进程从不调用它**。于是 17 个系统插件被注册、被测试、被文档化，**却没有一个在运行中的节点里跑过**。
这正是「写了但没接线」规模最大的一处，而且**单元测试结构性地看不见它**：每个单元测试自己启动宿主，
所以全绿的测试套件无法发现「没有人启动宿主」。

现在：

* `Node::open` 与 `Node::ephemeral` 都**启动插件**（放在 `<data_dir>/plugin-state`，与账本 `FileStore`
  分开——`sys.storage` 也会开一个 store，两个 store 挤一个目录正是它们互相写进对方文件的方式）。
  `--ephemeral` **也启动**：那是部署检查与多数测试用的模式，不启动会让「守护进程承载插件」这句话
  **恰好在没人看的地方**为真。
* **启动失败是节点启动失败**，不是一条日志。整个构建的要点就是系统自身功能即插件；一个起来了却没带
  插件的节点不是它自称的那个东西，而说明这一点的日志行在第一请求之前没人读。
* 新增 `GET /plugins`（读权限）报告 `count` / `host_key` / 每个插件的 `id` 与 `state`。
  **一个没人能观察的插件宿主，与一个没在运行的插件宿主无法区分**——此前唯一的办法是读日志。
* **部署关卡新增一条**：`the daemon hosts its compiled-in system plugins`，断言 17 个全部 `running`
  且 `host_key` 是 32 字节十六进制。部署检查现在 **23 项**，并在 CI 的 ubuntu/macos/windows 上执行。

实机验证：`GET /plugins` → `count 17`，`{"running":17}`。

### 认证范围现在是装载时的强制检查（此前是「没人读的记录」）

`Certification::require_within_scope` 早就写好、也单元测试过，但它**只被自己的测试调用**——
没有任何装载路径读取认证。更糟的是：审核命令的**面向用户输出里写着**「the loader enforces this
scope」——所以那不是「缺一个检查」，而是**用户可见输出里的一句假话**。

现在 `Arbiter` 持有按插件名绑定的认证，并在 `verify` 与 `compat` **之间**新增 `certification` 阶段：

* 认证存在 → `require_within_scope` **真的被调用**。清单即便**反向签名有效、能力也在本层级可持有**，
  只要能力在认证范围之外就被拒——拒绝句点名那个能力并打印整个范围。
* **T2（certified）插件没有认证 → 拒绝**，码为新增的 **`certification_missing`**，
  **不是** `counter_signature_missing`：反向签名此时**是存在的**，把操作者指向错误的文档会浪费一小时。
  这是层级的定义性要求，此前在装载路径上**从未被行使过**（仓库里没有任何测试通过 `Arbiter::load`
  装载过 T2 插件——所以这条改动对既有测试零波及，也说明这个层级的本质性质没被验证过）。

**从 CLI 可达**：`nau plugin review certify` 现在额外写出 `certification.json`，
`nau plugin verify --certification <file>` 把它交回仲裁器；两侧共用**同一个投影函数**，
所以文件形状只有一个定义。

三件事一起被钉住（否则「范围错时拒绝」在「拒绝一切」的实现上也会通过）：无认证被拒、
范围不覆盖被拒且点名能力、**范围覆盖则装载**。

新增拒绝码 `certification_missing` 触发了 `sys.arbiter` 系统插件的**两道 tripwire**：
词表漂移检查要求它被覆盖，阶段表检查要求新增 `certification` 阶段。两道都按设计报警并按事实更新。

### T2/T3 的运营面：从「模型」到「流程」

此前 `nau-plugin` 里有完整的**审核状态机**（六阶段 + 扫描报告 + 限定范围的认证）和**黑名单模型**
（已签名条目 + 申诉状态机），但 **CLI 没有任何命令驱动它们**——所以「第三方插件注册审核流程」
与「黑名单管理（管理&权限&维护&更新&解封）」都是**数据结构，不是流程**。本版补上两个驱动器：

* **`nau plugin review open|scan|advance|show|certify`** —— 走真实的六阶段状态机。
  最重要的性质是**「通过审核」必须意味着「能装载」**：`scan` 跑的是**真正决定装载的那套检查**
  （同一个 `Arbiter`，同一套 `LoadRefusal`），不是为审核另造的更宽松的一套。
  一个批准了、仲裁器却拒绝的审核，比没有审核更糟——因为人会信它。
* **`nau plugin blacklist add|list|check|appeal|unblock`** —— 维护仲裁器在黑名单阶段真正读取的清单。
  完整性来自**每条条目的签名**而非文件权限：读取时**重新验签**，手改过的条目是具名拒绝。
  `unblock` 只在申诉到达终局**且条目本身允许**时才移除，否则拒绝并**点名还缺哪一步**。

**两者的持久化都是可重放的事件日志**，而不是序列化快照：`Review` 与 `Blacklist` 都**没有**加
serde 派生——日志每次被**重放**进内核状态机，所以被篡改的历史会被**内核**拒绝（`Review::advance`
判边、`Blacklist::add` 验签），而不是被驱动层悄悄接受。

**两处如实标注**（都在 `docs/PLUGIN-MIGRATION.md`）：
1. **只有被信任为 vendor 的密钥能签发黑名单条目。** `Blacklist::add` 只查
   `TrustStore::is_trusted_vendor_key`；`trust_third_party_key` 填的是另一个集合，`add` 从不查它。
   `BlacklistReason::CommunityReport` 存在，但它只是**原因字段**——条目仍需 vendor 签名。
   所以**第三方无法自行谴责插件**，社区举报只有在 vendor 签名后才成为条目。这是本构建的真实限制。
2. **能「解封」的只有 `key_revoked` 条目**，且必须把申诉逐边走到 `lifted`。
   `requires_review_on_republish()` 对 `KeyRevoked` 之外的每一种原因都为真，所以其余原因会拒绝并
   **引用该谓词的真实取值**：它们谴责的是**代码**而不是发布者，出路是**通过审核的新构建**，不是状态变更。

### 三平台部署验证：从断言变成 CI 检查

`scripts/deploy-local.mjs`（安装 → 运行 → 重启 → 状态存活）一直是本地关卡，**CI 从不运行它**——
三平台 rust job 只跑 `cargo build/test/fmt/clippy`。所以「三平台**构建与测试**」由 CI 验证，
而「三平台**部署**」只在当时操作者所用平台（这里是 Windows）上跑过，两者被混成一句。
现已加进 `ci.yml` 的三平台 rust job，在 **ubuntu / macos / windows** 上都真正执行。

**同时修掉一处我自己造成的源码损坏**：`crates/nau-node/tests/plugin_cli.rs` 的首行与一处文档注释
含 GBK 乱码（v2.2.2 干净、v3.2.1 出现），是 PowerShell 读写 UTF-8 时把内容当 GBK 解码再写回所致，
且同一段文档被重复了两遍。已修复（498 → 494 行，乱码归零，无 BOM）。
`crates/nau-libp2p/src/swarm.rs` 的两行同类乱码经比对**在 v1.2.3 就已存在**，非本次引入，未动。

### 第一个真正可运行的官方插件，以及进程插件链路的闭合

**`com.twinsearth.official.market` 现在是一个可运行的进程插件**
（`crates/nau-plugins/src/bin/nau-plugin-market.rs`），`rank` 直接委托
`nau_market::matching::rank_bids`。此前 11 项官方插件**全部只是清单、0 项能跑**。

**补上了 `ProcessRuntime` 缺失的那一半宿主。** `ProcessRuntime::call` 一直**刻意拒绝**，说
「exec 由宿主 `nau-node` 拿 handle 去执行」——而 `nau-node` 对沙箱、frame、该运行时**零引用**。
进程插件能被 `start` 和 `stop`，**永远不能被 `call`**。这是本项目里规模最大的一处「声明了但没接线」。
`crates/nau-node/src/plugin_process.rs` 现在是那个宿主：按插件的 `StartSpec` 构造 `SandboxSpec`、
经 `SandboxManager` 起进程、走 frame ABI 收发。**经沙箱而不是 `std::process::Command`**，
否则该运行时关于边界的每一句声明都会从外部看不出差别地变成假的。

**闭合过程中，端到端测试立刻抓到宿主自己的一个缺陷**：它**先查退出码、后读帧**，
于是把「以类型化拒绝应答、因而退出码为 1」的插件当成失败，**把一个合法应答丢掉了**——
正是本系统处处遵守的「拒绝是值，不是错误」。已改为**帧是协议、退出码是提示**。

**如实标注**：这一项运行了，但它声明的三个能力**一个都没实现**——`capabilities` 自己报告
`declared_capabilities_backed_by_ops: false`。这是**架构事实**：`rank` 是匹配而矩阵里没有匹配令牌，
注册需要已注资账本、结算需要完整生命周期，而本 ABI **收一帧就退出**、调用之间无状态。
端到端证据也**分两半**：e2e 证明过程边界（含一次拒绝往返），委派正确性由插件自身测试证明
（对同一夹具直接调 `rank_bids` 比对每个字段）——e2e 里那次 `rank` 用的是 `{}`，
**没有跑通一次成功的排序**。

**新增关卡检查**：`plugin-invariants` 现在断言**每个 `SystemPlugin` 实现都必须被
`standard_plugins()` 构造、被 `standard_declarations()` 声明**。它首次运行就抓到 5 个刚写好、
尚未接线的插件——「写了但没接线」在源码层的形态。

**新增审批通道**：`Manifest::verify_with_approvals` + `Arbiter::with_approval`（**按插件名绑定**，
给 A 的评审不授权 B）。此前 T1 的能力审批在矩阵里可表达、却**没有任何装载路径能到达**——
模型能写、走不通，是同一个缺陷低一层的形式。

**两个不可达的拒绝码已接上**：`capability_not_approved`（此前所有能力拒绝都折叠成
`capability_not_permitted`）与 `name_invalid`（此前名字不合法被折叠成 `manifest_invalid`）。
它们对操作者意味着不同的下一步——「去找具名权威申请」对「去找个死路」，以及「改名字」对「改文档」——
折叠两者会让码表里出现**没有任何阶段能产生**的条目。这是读该词表的系统插件报告出来的。

**三个「接了但接在退化默认上」的装配已写明**：`standard_plugins()` 用无参构造器装配，
因此 `sys.ledger` 装空账本、`sys.attest` 不固定任何根、`sys.sandbox` 描述进程后端而节点默认执行器是
`NullExecutor`。这是新建节点的正确 fail-closed 默认，**部署必须接真的**——真实入口在
`standard_plugins` 的文档里逐个点名，而不是让读者从空结果里推断。

### 热兼容（先决条件）

**真实性**与**兼容性**被拆成两个问题。`Manifest::verify` 只回答前者：这份清单是不是其发布者
签的、格式对不对。**这台宿主能不能服务**这个 ABI 由仲裁器通过
[`hot::AdapterRegistry`](crates/nau-plugin/src/hot.rs) 回答，成为装载流水线中 `verify`
之后的一个独立阶段 `compat`。

因此 `2.x` 插件**能通过校验**（它是真的），然后被**具名适配**或**具名拒绝**：

* `Abi2To3` 适配器随本版发布；它把 2.x 的 `Event`+corr_id 识别为 3.x 的 `Request`，
  并**拒绝**无 topic 的广播——因为给它编一个 topic 会**改变谁能收到这条消息**；
* **默认适配器注册表是空的**（fail-closed）：没决定要服务哪些旧 ABI 的宿主就拒绝它们；
* **来自未来的 ABI 一律拒绝**且**在 `parse` 阶段就拒绝**——没有任何适配器能向下翻译，
  因为宿主不知道新版本加了什么。

### 热更新（双缓冲 + 单次原子切换）

`hot::HotSwapper` 的顺序就是要点：

1. **先健康检查**——坏构建根本进不了路由表，所以常见失败**不需要回滚**；
2. **再切换**——`RwLock<Arc<RoutingTable>>` 下一次指针替换。请求要么看到旧表要么看到新表，
   **永不看到半成品混装**；已经取到快照的请求不会被中途改道；
3. **最后排空旧实例**。排空失败**只记录，不复辟**——因为新版本已经在服务，
   把旧版本放回去是**伪装成回滚的降级**。

### 热插拔（依赖图）

`HotPlug::start_order` 复用注册表的拓扑序（一份实现，两处不会分歧）；
`stop_plan` 算出**必须先暂停的反向依赖**，最远者最先——停一个还被别人调用的插件，
只会把故障挪到别处。系统插件（T0）**仍不可热插拔**：它们编译在内核里，只能热配置。

### 安全通信（零新依赖）

`secure::Party` / `secure::Channel`：**X25519** 临时密钥协商 → **HKDF-SHA256**（两个公钥
进 `info`）→ **ChaCha20-Poly1305** 认证加密。需要能力 `crypto:channel`：
T0 自动持有，T1/T2 需审批，**T3 一律拒绝**——宿主审计不到的信道，插件不得自行开。

三条结构性约束：

* **nonce 绝不重复**：单调计数器，`seal` 在会重复时**返回错误而不是回绕**。ChaCha20-Poly1305
  一旦重用 nonce，机密性**静默失效**（密文照样解密），所以这条不能靠调用方记得；
* **低阶公钥拒绝**：全零共享密钥会让每次会话同钥；
* **密钥类型不 derive `Debug`**：手写脱敏实现，印公钥与计数器，永不印密钥。

### WASM 运行时：仍然是类型化拒绝

`wasmtime` 不在依赖锁内、不在本机缓存中，而「引入了却无法验证」正是本项目拒绝的事。
`WasmRuntime` 声明它**什么也不强制**并拒绝一切请求。本版不改变这一点。

### 测试在构建期抓到的缺陷（都是真的）

* **安全信道根本不通**：HKDF 的 `info` 里两个公钥顺序取决于「我是哪一方」，
  于是 Alice 由 `alice||bob` 派生、Bob 由 `bob||alice` 派生——**两把不同的密钥**。
  改为按字典序，顺序成为**密钥对的性质**而非调用方的性质。若没有往返测试，
  这会以「一个永远打不开任何消息的安全信道」发布出去。
* **`parse` 阶段吞掉了具体拒绝码**：所有解析错误都被硬编码成 `manifest_invalid`，
  把 `abi_incompatible` 这个操作者唯一需要的事实扔掉了。
* **帧层的 ABI 规则会悄悄废掉热兼容**：`frame::Request::abi_is_compatible` 仍要求主版本
  相等，会在清单被读之前就拒掉每一个 2.x 插件——**在实现它的那一层的下面**把功能关掉。
* **`plugin-invariants` 关卡误报**：它检查整个文件里是否出现 `Ok(Tier::Blacklisted)`，
  而我新增的 `Tier::from_label`（**按标签解析**，合法地可以返回该判决）触发了它。
  检查已限定到 `from_name` 函数体，并**内联了自我测试**——被缩小作用域的检查可能变成
  空检查，而空检查会报「ok」，那比没有检查更糟。

### 未实现（不是「将实现」）

WASM 运行时不存在；没有任何 T1/T2/T3 插件被实现（那几份是**已验证的清单**）；
`ProcessRuntime::call` 仍从未端到端执行过；沙箱内运行插件**只在 Windows 上有端到端证据**
（macOS `EINVAL`，Linux 能启动但强制未验证）。逐条见
[`docs/VERIFICATION.md`](docs/VERIFICATION.md) §5。

---

## [2.2.2] — 一切插件化

本版把项目从**单体架构**重构为**插件化架构**：新增插件内核 `nau-plugin` 与插件实现
`nau-plugins` 两个 crate，16 个既有 crate 通过内核的端口被重新组织为「插件 + 宿主」。

开发方案见 [`docs/PLUGIN-ARCHITECTURE.md`](docs/PLUGIN-ARCHITECTURE.md)。
它同时是一份**偏离说明**：草案里若干技术选型在本项目的构建与验证条件下无法成立，
文档逐条写明为什么偏离、替代方案是什么、代价是什么。

### 内核 `nau-plugin`（12 模块）

* **五级体系**：分级**只从签名的名字前缀推导**（`com.twinsearth.sys.*` / `.official.*` /
  `.certified.*` / 第三方反域名 / 黑名单）。第三方**不能占用厂商命名空间**——否则
  `com.twinsearth.某名字` 会落进「可加载的第三方」。
* **能力令牌**：`(能力 × 分级)` 矩阵具三态（含审批）；**T3 永远拿不到敏感能力**（在
  **全笛卡尔积**上断言，新增敏感能力自动被覆盖）；**内核权限没有审批通道**——不是
  「未获批准」，而是「不存在能批准的权威」。
* **四重清单校验**：名字/分级、规范化摘要、发布者签名、厂商副签（T1/T2）或操作者信任
  的公钥（T3，默认信任库为空即**未配置不加载任何插件**）；外加**模块字节摘要绑定**。
  规范化器**不覆盖** `signature` 段（否则签名无法构造），但覆盖其余每一个可编辑字段。
* **生命周期**：**只有一个赋值点**（有源码级关卡）、终态无出边、**无自环**（V1.2.3 市场中
  「终态可被重入并二次罚没」的缺陷没有重演）；3 次违规 → 隔离。
* **总线（PMB）**：唯一通道，五道投递检查，**被拒绝的消息也记审计**。规范化为 JSON 而非
  bincode，因为跨语言逐字节一致的规范化器已经存在且被 10 条向量固定。
* **黑名单**：条目必须由**受信厂商密钥签名**（否则第一个人就能拉黑竞争对手）；锁定摘要的
  条目**不会连带否定修好的新构建**；申诉可走到 Lifted，但**没有任何操作能删除条目**。
* **认证范围**：清单可以拥有一切有效签名，但只要它要的能力**超出该次评审批准的范围**就拒绝——
  否则副签只证明「厂商见过*某份*清单」，无法把批准与**实际被评审的能力集**绑定。

### 隔离与如实标注的边界

运行时端口 `PluginRuntime` 声明各自**能强制什么**；请求它强制不了的东西是**具名拒绝**，不是降级。

* 进程后端（复用 `nau-sandbox` 的 Job Object 强制）强制：超时、内存、进程数、输出上限、
  环境白名单、独立工作目录。
* **无法强制**（因此必须由插件在**签名覆盖的** `waivers` 段逐条写明理由，否则拒绝启动）：
  出站网络拒绝、文件系统隔离、磁盘配额、CPU 时间、句柄上限。
* **WASM 运行时在本构建中不存在**，实现为**类型化拒绝**。草案以 Wasmtime 为标准格式，
  但它不在依赖锁内、不在本机缓存中，而「引入了却无法验证」正是本项目拒绝的事。
  T1–T3 的隔离改由进程后端承担——在「独立进程 / 独占内存」这一条上它**强于**同进程内的
  WASM 线性内存隔离。

### 外部接口

`nau plugin tiers | runtimes | verify <dir> | system | blacklist`。
`tiers` 的矩阵**逐格由 `Capability::decision` 生成**，因此命令行不可能描述出一套与代码强制的
不一样的策略；`runtimes` 打印每个后端**不能**强制什么及原因；`verify` 走完整装载流水线并
逐阶段打印 trace 或具名拒绝。**13 个集成测试用真实二进制端到端验证**，包括真 Ed25519 签名的
接受路径、篡改清单在摘要检查处被拒、未配置时拒绝第三方而后显式信任即接受，以及退出码纪律
（2 = 工具错误 / 1 = 插件被拒 / 0 = 通过）。

### 测试在构建期抓到的缺陷（都是真的）

* **限流窗口会丢掉一秒前的发送**：`cutoff = now - 60_000` 配 `t > cutoff`，在 `now = 1000`
  时把 `t = 0` 整条丢弃。
* **`Grant::RequiresApproval` 曾不可达**：`CapabilityToken::issue` 收不到审批，于是
  Official/Certified **只能持有基础集**——架构文档描述了一个代码表达不了的模型。
  由插件夹具报告发现（写实的市场清单只能做成拒绝夹具），已补 `resolve_with_approvals`
  与 `issue_with_approvals`。
* **`Bus::send` 曾信任 `message.source`**：总线按消息里自带的字段查令牌，**插件可以自选身份**
  并冒用他人能力。现改为必须**出示调用者的令牌**，不一致即以 `bus_source_forged` 拒绝。
* **「3 次违规 → 隔离」曾在总线上没有接线**：生命周期有升级规则、总线有拒绝，但两者无人相连。
  现由 `Registry::record_violation` + `Bus::send_checked` 接上，且明确**哪些拒绝算越权**
  （伪造来源 / 越权能力 / 占用保留优先级）——把限流也算进去会让「忙」变成「被封」。
* **`nau plugin` 的每条命令都只打印用法并以 0 退出**：`&args[1..]` 把 `"plugin"` 当成了
  子命令名。「写了但没接线」的典型，被「启动真实二进制」的集成测试抓到。
* **系统插件只注册没启动**：四个 T0 插件停在 `loaded`，每次派发都被拒「not running」。

### 验证与硬限制

见 [`docs/VERIFICATION.md`](docs/VERIFICATION.md)。本版新增关卡 `plugin-invariants`
（生命周期单一赋值点、插件启动单一入口、令牌单一签发点、内核不依赖宿主、名字不能推出黑名单
判决、文档词汇与代码一致）。

**如实标注的硬限制**：本机**无法**跑 `cross-target`（`ring` 需要 C 交叉编译器，本机没有），
关卡因此报 SKIP 并点名缺失的工具；SKIP 按脚本规则让退出码非零，即**这些平台的代码在这里
没有被验证过**。同一节还记录了一处对 V1.2.3 时期结论的更正：当时记为 PASS 的 cross-target
如今无法复现，在缺少 `.git` 与运行输出留存的情况下**无法判定**原因，故视为未验证。

### 未实现（不是「将实现」）

没有任何 **T1/T2/T3 插件被实现**——官方/认证/分析那几份是**已验证的清单**，不是能跑的插件；
`ProcessRuntime::call` **从未端到端执行过**（exec 归宿主）；第三方审核流程与申诉在代码中只有
状态机与规则，没有运营后端；`Grant::RequiresApproval` 现在可达，但**没有任何生产调用方签发
过带审批的令牌**。

---

## [1.2.3] — 进行中

本版的对象是上游 **v2.8.2**（`gsn-core` `0.2.82`）。V1.1.1 审计的是 v2.5.6，
而 v2.8.2 已把 Rust 从 15 文件 / 15,735 行扩展到 **153 文件 / 21,530 行**，
并新增了 sandbox、llm/deepseek、mesh、swarm、scheduler、collaboration、crowdsource、security、crdt 等模块。
因此本版做的是**增量审计 + 由审计结论驱动的加固**，而不是重写。

### 审计（[docs/GAP-ANALYSIS-v2.8.2.md](docs/GAP-ANALYSIS-v2.8.2.md)）

* 核实上游对 V1.1.1 所报 v2.5.6 各条缺陷的**修复声明**：区分「真的修了」「仍老样子」
  和「**声明不被代码支持**」三类，逐条附 `文件:行号` 证据。
* 审计 v2.8.2 新增代码，发现三类严重缺陷：
  **账本日志无完整性保护**（使守恒与独立审计同时失效）、**重启静默关闭证据闸门**
  （每个从磁盘恢复的任务都豁免证据检查并按满额预算付款）、
  以及**新的 Agent Sandbox 三个 critical**（无隔离原语、可读写整个宿主文件系统、未认证的远程代码执行）。
* 记录了一个应当在时间顺序上留档的事实：上游把本项目对 v2.5.6 的审计**当作修复路线图**，
  在 `CHANGELOG.md`/`RELEASES.md` 中逐条引用本审计章节号（`grep 'GAP §'` 命中 52 处）。
  本项目**没有**参与上游代码，并且第二次审计发现「按清单修好了」与「系统变安全了」是两件事。

### 加固（由上述审计结论驱动）

原则只有一句：**边界要么由代码强制执行，要么让请求失败——绝不接受一个策略然后忽略它。**

* **账本**：持久化记录加**哈希链 + 锚定 head**，恢复与审计时报**首个断链序号**；
  只声称 tamper-**evident**，并写明「能重写整份文件者仍可如何」。
* **重启安全**：持久化并恢复 `verification_policy`、结果信封与 `evidence_grade`、`winner_price`、
  信誉与质押；用关闭再打开的测试断言「重启不放宽任何闸门」。
* **持久化正确性**：水位从与恢复相同的过滤后列表派生；解析失败显式报告；
  追加失败返回错误且**不推进水位**；恢复失败拒绝服务或显式标注降级。
* **状态机**：所有状态变更只经转换函数，终态无入边，证据提升只发生在转换成功之后。
* **Sandbox**：默认后端为 `NullExecutor`（什么也不执行）；唯一执行的后端必须**声明它强制执行的边界**，
  无法强制的策略**拒绝并指出是哪条**；Windows 用 Job Object 强制内存/进程数上限与整树 kill；
  输出有上限；id 密码学随机；启动清扫孤儿；认证与所有权覆盖每个路由。
* **授权**：变更类 REST 路由配置了凭据则要求认证、未配置则**默认拒绝**；不使用通配 CORS；
  请求体有上限、读有超时。
* **数值纪律**：共识权重由记录的质押派生而非入参；任何非有限浮点在比较或转换处返回类型化错误；
  金额入口拒绝 JSON 浮点；规范签名载荷**拒绝任何非整数**。

### 验证（本机实跑，可复现）

```
node scripts/verify-all.mjs        # 16 passed, 0 failed, 0 skipped
```

| 关卡 | 结果 |
|---|---|
| Rust formatting / `Cargo.lock --locked` | PASS |
| Rust 工作区测试 | **938 passed, 0 failed**（67 个套件） |
| clippy `-D warnings` | **0 warnings** |
| libp2p 真实 swarm（`--features libp2p`） | **88 passed** |
| 与上游身份的规范向量 | **逐字节一致** |
| 生产代码无 panic 路径 | PASS |
| VERSION 单一来源 | PASS |
| `unsafe` 收容 | PASS（12 块 / 12 条 SAFETY，全在 `nau-sandbox/src/platform/`） |
| Python SDK / JavaScript SDK | PASS / **223 passed** |
| 浏览器客户端 ↔ 真实守护进程 | PASS（上游签名向量逐字节一致） |
| 本机部署（安装/运行/重启/状态存活） | **22 项检查通过**（含 3 项认证检查） |
| 合约静态检查 / 编译 / 测试 | PASS / PASS（0 lint 警告）/ **71 passed** |

**关于「缺工具」**：缺任何工具都会打印 `SKIP`、进入结尾的 `NOT VERIFIED` 列表，并让退出码非 0——
上游的 Python CI 有 17 个测试跳过其中 11 个仍然报绿。

### 本轮修复的、由本项目自身发现的缺陷

如实记录，因为它们比「我们实现了什么」更能说明验证是怎么做的：

* **`nau-store` 自死锁（严重）**：`append_journal` 与 `compact` 在持有写锁时调用 `self.anchor()`（读锁）
  与 `self.set_meta`（写锁）——`std::sync::RwLock` 不可重入，**同一线程永久等待自己持有的锁**。
  后果是链式日志 API 完全不可用；唯一暴露它的是一个会**永久挂起**的测试，而 `cargo test --workspace`
  因此永远跑不完。单测没抓到，因为它们测的是纯编码函数而不是存储路径。已拆出不加锁的内部方法。
* **`nau-libp2p` 陈旧版本断言**：`assert_eq!(VERSION, "1.1.1")` 是**第二份版本号副本**，
  升级到 1.2.3 后仍写着旧值。而 `scripts/bump-version.mjs` 的目标枚举不完整（正则 `nau-[a-z]+` 匹配不到含数字的 `nau-libp2p`），
  版本一致性关卡当时也只查清单与 SDK——**两次都漏了同一类缺陷**。现已让关卡扫描 Rust 源码，
  并用负向测试证明它会拦住。
* **`nau-node` 的 `api.rs` 有 8 处 `let _ = node.persist();`** 丢弃持久化错误（见 `docs/VERIFICATION.md` §3.4），
  仍是已知缺口。

### 版本

VERSION、`[workspace.package] version`、`contracts/VERSION`、两个 SDK 一并升到 **1.2.3**，
由 [`scripts/bump-version.mjs`](scripts/bump-version.mjs) 完成（任何目标无法更新即大声失败）。

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
