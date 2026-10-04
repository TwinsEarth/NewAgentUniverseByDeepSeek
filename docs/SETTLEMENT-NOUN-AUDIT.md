# 结算名词核对 / Settlement noun audit

**E-02 的交付物**：设想里每一个链上名词在本仓库的命中表，**含方法**。

---

## 为什么要带方法

**一个不带方法的命中数不是一个结论。**

这份文档的第一次草稿里，我打算给十项名词各写「3 处」——**因为我在插件里就是这么硬编码的** ✗。
一次实际扫描显示**它们并非都一样**，而**真正决定数字的是**：

* 搜哪些目录（`crates/`？还是也含 `contracts/`、`packages/`、`docs/`？）
* 用什么匹配规则（字面量？正则？大小写？）
* 同一文件内出现多次算几次（行数？文件数？）

**所以在 `crates/` 里硬编码十个数字，会是「发明数字」这个缺陷第五次出现，
而且是在唯一一个职责就是核对数字的版本里。** 计数因此**留在本文档里，与产生它的方法一起**。

---

## 方法（可复跑）

在仓库根目录运行：

```powershell
$files = Get-ChildItem "crates" -Recurse -File -Filter *.rs
foreach ($n in @("ERC-8004","x402","L402","Lightning","Taproot","RGB","HTLC","USDC","ERC-4337","Paymaster")) {
  $hits = ($files | Select-String -Pattern $n -SimpleMatch -List | Measure-Object).Count
  "  {0,-12} 出现在 {1,3} 个文件里" -f $n, $hits
}
```

**规则**：`crates/` 下全部 `.rs`；**字面量**匹配（`-SimpleMatch`，大小写不敏感）；
**同一文件内多次出现只计一次**（`-List`），**为的是不受注释长度影响**。

---

## 结果（本次测量）

扫描 **266 个 `.rs` 文件**：

| 名词 | 出现在几个文件里 | 计划记录的 |
|---|---|---|
| `ERC-8004` | **2** | 0 |
| `x402` | **2** | 0 |
| `L402` | **2** | 0 |
| `Lightning` | **2** | 0 |
| `Taproot` | **2** | 0 |
| `RGB` | **2** | 0 |
| `HTLC` | **2** | 0 |
| `USDC` | **2** | 0 |
| `ERC-4337` | **2** | 0 |
| `Paymaster` | **2** | 0 |

### **「0 命中」已经不再为真，而改变它的是我自己**

计划（`docs/DEVELOPMENT-PLAN-v3.8-v3.9-Economy.md` 第 44–53 行）记录这十项**各 0 处命中**。
**写下时那是真的。** 而 **v3.8.0 的 D-02 把十项全部写进了
`crates/nau-plugins/src/plugins/resource.rs` 的 `REFUSED` 表** ✓——
**那是「正确的那类命中」，但它不是零。**

**这个区别支撑不同的句子：**

* 「本仓库不提及 X」——**在零命中时可以说**
* 「本仓库只在拒绝里提到 X」——**在现在才可以说的那一句**

**一份把计划里的数字当作事实引用的自查，会把这个错误复制下去。**

### 而这两个文件是哪两个

按同一个方法看，命中的是**资源插件的拒绝表**与**市场 crate 里的那份同名常量**。
**而 `crates/nau-plugins/src/plugins/settlement.rs`（本版新增）也应当被计入**——
它带着同一张表 ✓。**上面那个 2 与这个事实之间的差别，本身就是「计数依赖方法」的例子**，
所以我把它写在这里而不是消掉它。

---

## 已有的四个合约（E-02 第二条）

这份仓库**真实拥有的**链上界面是四个合约，都确认存在：

| 路径 | 状态 |
|---|---|
| `contracts/src/GovernanceToken.sol` | ✓ 存在 |
| `contracts/src/Settlement.sol` | ✓ 存在 |
| `contracts/src/ReputationRegistry.sol` | ✓ 存在 |
| `contracts/src/AgentCardAnchor.sol` | ✓ 存在 |

它们的测试在 `contracts/test/` 下：`GovernanceToken.t.sol`、`Settlement.t.sol`、
`ReputationRegistry.t.sol`、`AgentCardAnchor.t.sol`，
以及 **`SettlementInvariant.t.sol`**（不变量测试）。

**注意路径而不是名字**：计划用的是名字，而**一个读者能打开的是路径** ✓

---

## 这十项名词各自对应哪条轨道

`crates/nau-plugins/src/plugins/settlement.rs` 的 `SETTLEMENT_NOUNS` 给出这张对应表，
**而它不带计数** ✓。每一项都映射到一条**不可用**的 `SettlementRail`，
所以**这张表和那些轨道不可能互相矛盾**（有一条测试断言这一点）✓

---

## 与 E-01 的关系

**E-01 先把「轨道」变成可查询的东西，E-02 再核对名词。**
两者合起来的意思是：**「这个节点能不能这样结算？」是一条有答案的问题**，
而**「不能」带着理由**——

> **在写任何集成之前，先把「做不到」变成一条有理由的拒绝，而不是一次静默降级。**
