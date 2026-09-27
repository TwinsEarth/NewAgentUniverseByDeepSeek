# 贡献指南 / Contributing

## 项目定位

本项目是 [TwinsEarth/agent-universe](https://github.com/TwinsEarth/agent-universe)
v2.5.6 的**重写**。提交前请阅读：

* [ATTRIBUTION.md](ATTRIBUTION.md) — 来源、保留项与放弃项
* [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) — 上游 76 条缺陷的逐条证据
* [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 分层与依赖原则

---

## 铁律

### 1. 先加会失败的测试，再修

任何缺陷修复都必须**先**添加一个在修复前会失败、修复后通过的测试。
上游有同样的规则（`test/README.md:70-74`），但其回归套件实际断言的是 **JS** 实现，
而缺陷在 **Rust** 实现里——绿色套件对守护进程零保证（GAP-ANALYSIS §9.7）。
因此：**测试必须覆盖出问题的那一端。**

### 2. 签名载荷里不得出现浮点数

规范形式只接受整数（见 [docs/CONFORMANCE.md](docs/CONFORMANCE.md)）。
货币用 `Money`（整数最小单位），比率用整数 bps，需要小数语义时用十进制字符串。
**不要**为了「方便」引入 `f64`——那正是上游跨语言签名失效的根因。

### 3. 变更 `nau-core` 中任何带签名的结构 = 协议变更

新增字段会改变规范载荷。若该结构可被签名，则必须：

1. 评估对 `conformance/vectors.json` 的影响；
2. 如影响字节兼容性，递增 `PROTOCOL_VERSION` 并在 [docs/CONFORMANCE.md](docs/CONFORMANCE.md) 记录；
3. 同步更新 Python 与 JS SDK 并让三端测试通过。

### 4. 版本只有一个来源

不要在任何文件中写死版本号。用 `version.workspace = true`（Rust）
或读取 `VERSION`（Python/JS）。

### 5. 不要引入 C 工具链依赖或重型网络栈

默认构建必须是**纯 Rust**。理由见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §0：
上游的依赖树在 16 GB 机器上编译会 OOM。如需 libp2p 互操作，
请作为独立的**可选**适配器 crate，不要动默认依赖。

### 6. 不要在 `nau-net` 里给测试替身起网络服务的名字

上游把三个内存 mock 命名为 `KademliaClient` / `GossipSub` / `GsnNode`
并从 crate 根再导出，导致集成测试对着 `HashMap`「证明」了联网能力。
测试替身必须以 `Memory*` 命名。

---

## 开发环境

```bash
# 内存受限的机器：保留 jobs 限制（8 路并行 rustc 会 OOM）
export CARGO_BUILD_JOBS=2      # Windows PowerShell: $env:CARGO_BUILD_JOBS="2"

cargo build --workspace
cargo test  --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

Python 与 JS SDK **零依赖**，无需 `pip install` / `npm install`：

```bash
python sdks/python/run_tests.py
node   sdks/js/test/run.js
```

跨语言一致性：

```bash
node conformance/generate.mjs
git diff --exit-code conformance/vectors.json   # 生成器必须可复现检出内容
```

合约（需要 Foundry，本机可能没有）：

```bash
cd contracts && forge fmt --check && forge build --sizes && forge test -vvv
```

---

## 提交规范

* 一个提交聚焦一件事。
* 提交信息说明**为什么**，不只是做了什么。若修复的是上游缺陷，
  引用 [docs/GAP-ANALYSIS.md](docs/GAP-ANALYSIS.md) 中的章节号。
* 代码中标注上游修复时使用统一注释：`// upstream v2.5.6 fix: ...`
* 新增 crate 必须用 `version.workspace = true` 并在 `Cargo.toml` 的
  `[workspace.dependencies]` 中登记。

## 代码风格

* `#![forbid(unsafe_code)]`，`#![warn(missing_docs)]`，公开项必须有文档注释。
* 除 `#[cfg(test)]` 外禁止 `unwrap()` / `expect()` / `panic!()` / `todo!()`。
* 用户可见的序列一律使用 `BTreeMap` 或显式排序（确定性）。
* 任何可增长的集合都要有显式上限。
* 文档中不得声称代码没有实现的能力——这是上游最严重的问题之一
  （GAP-ANALYSIS §9.6 记录了 12 处以上）。**若未实现，就写「未实现」。**

---

## 报告问题

请附上：

* 复现步骤与期望/实际行为；
* 若涉及经济或签名语义，附上最小化的载荷（**脱敏**，不要提交真实私钥）；
* 若是与上游行为的差异，请注明这是**有意修复**还是**回归**。
