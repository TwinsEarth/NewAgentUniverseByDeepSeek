# 跨语言一致性规范 / Conformance — protocol `nau/1`

本项目的一致性**不是靠三份各自测试的代码**来保证的，而是靠**一份共享向量文件**
`conformance/vectors.json`：Rust、Python、JavaScript 三端都必须对它成立，
CI 还会重新运行生成器并断言检出内容可复现（`git diff --exit-code`）。

上游 v2.5.6 的对比：它有一条向量，但由**一个 Rust 测试 + 一个 JS 测试**断言，
**Python 套件从不引用该向量**（只自验自洽），
而且那 11 个 Python 加密测试在 CI 中因缺 `cryptography` 而被**静默跳过**
（`test_crypto_aca.py:21-23` 的模块级 `skipif`）。
因此上游「三端逐字节一致、可互验」的承诺在 CI 中**从未被执行**。

---

## 1. 规范形式（Canonical form）

规范形式是**唯一的字节序列**，签名覆盖它。

| # | 规则 | 上游 v2.5.6 | 三端分歧风险 |
|---|---|---|---|
| 1 | 根必须是 JSON **对象** | 未检查（数组/字符串也签） | — |
| 2 | 任意深度删除名为 `signature` 的键 | **仅顶层**删除 | 嵌套签名被外层覆盖 |
| 3 | 对象键按 **Unicode 码点**升序 | Rust/Python 正确 | **JS 默认 `sort()` 按 UTF-16 码元**，星平面键顺序相反 |
| 4 | 无空白；分隔符恰为 `,` 与 `:` | 一致 | — |
| 5 | 字符串原始 UTF-8；仅转义 `"` `\` 与 7 个短控制转义；其他控制字符用**小写** `\u00xx` | 一致 | — |
| 6 | **数字必须是整数**，且落在 `i64`/`u64` 内 | **接受浮点** | 见 §3，这是致命项 |
| 7 | 嵌套深度 ≤ 64 | 无限制 | 恶意文档可爆栈 |
| 8 | 序列化失败**报错** | `unwrap_or(Value::Null)` ⇒ **签名 `null`** | 静默签下错误载荷 |

### 1.1 为什么规则 6 是致命的

同一个值在三种实现下的输出：

| 值 | Python `json.dumps` | JS `JSON.stringify` | Rust `serde_json` 1.0.151 + zmij |
|---|---|---|---|
| `1.0` | `1.0` | `1` | `1.0` |
| `-0.0` | `-0.0` | `0` | `0.0` |
| `1e21` | `1e+21` | `1e+21` | `1e21` |
| `1e-7` | `1e-07` | `1e-7` | `1e-7` |
| `1e16` | `1e+16` | `10000000000000000` | `10000000000000000` |
| `NaN` | `NaN`（非法 JSON） | `null` | `null` |

**三者在至少一行上互不相同。** 上游的 `ResourceMetering`
（`aca/receipt.rs:29-32`）有两个 `f64` 字段且默认零值，因此
**JS/Python 签发的 `Receipt` 无法被 Rust 验证，反之亦然**——而这是任务完成的主路径。
上游唯一的向量里没有任何浮点数，所以 CI 看不见。

**本项目的规则**：签名载荷中的数字**必须是整数**。
货币用整数最小单位（`Money(i64)`，10⁻⁶）；
需要小数语义的量（如比率）用整数 bps 或十进制**字符串**承载。
浮点、指数记法与越界整数一律返回 `NonIntegerNumber` / `NumberOutOfRange`。

### 1.2 为什么规则 3 需要显式比较器

`"a"`(U+0061) < `"\uE000"`(私有区) < `"😀"`(U+1F600) —— 按**码点**。
JavaScript 的默认 `Array.prototype.sort()` 比较 **UTF-16 码元**：
`😀` 是代理对 `D83D DE00`，其首码元 `0xD83D` **小于** `0xE000`，
于是 JS 会把 `😀` 排在 `\uE000` **之前**——与 Rust/Python 相反。

向量 `astral-plane-key-ordering` 专门钉住此行为。

---

## 2. 身份

```
did:nau:<SHA-256(原始 32 字节 Ed25519 公钥) 的前 8 字节，小写十六进制>
```

* 公钥是**原始 32 字节**，不是 SPKI/DER。
  JS 通过固定 PKCS#8 前缀 `302e020100300506032b657004220420` 把种子变成私钥，
  取 SPKI DER 的**末 32 字节**作为原始公钥。
* 上游 JS 还存在第二套方案 `did:au:<sha256(SPKI DER)[:32]>`
  （`js/lib/keychain.js:26`），与 Python/Rust **不兼容**：
  同一密钥对产生两个 DID。本项目**只有一套**方案。
* `did:aip:` 前缀（上游）在**解析**时被接受，因此上游身份可迁移。

---

## 3. 共享向量文件

`conformance/vectors.json` 由 [`generate.mjs`](../conformance/generate.mjs) 生成。
生成器使用 **Node/OpenSSL 的 Ed25519**，与 Rust 实现**不共享任何代码**——
所以「Rust 验证该文件中的签名」是真正的跨实现校验，而非自洽检查。

结构：

```jsonc
{
  "protocol": "nau/1",
  "canonicalization_rules": [ ... ],
  "seed_hex": "0101...01",
  "identity": { "public_key_hex": "...", "did_nau": "...", "did_legacy": "..." },
  "payloads": [
    { "id": "...", "note": "...", "input_json": "<文本>", "canonical": "<文本>",
      "signature_hex": "<128 hex>", "canonical_hex": "<canonical 的 UTF-8 hex>",
      "languages": { "javascript": "unsupported-by-json-parse" }   // 可选
    }
  ],
  "rejections": [ { "id": "...", "input_json": "...", "error": "non_integer_number" } ]
}
```

`input_json` 是**文本**而不是对象，正是为了让 64 位整数原样存活。

### 3.1 每条向量的三方断言

对 `payloads` 的每一项，三端测试都必须：

1. 从 `seed_hex` 派生公钥，断言等于 `identity.public_key_hex`；
2. 解析 `input_json` → 规范化 → 断言**逐字节等于** `canonical`；
3. 用 `signature_hex` **验证**（签名由 OpenSSL 产生）；
4. **重新签名** `canonical` 并断言**逐字节等于** `signature_hex`
   （Ed25519 是确定性的，这是对实现最强的检验）。

对 `rejections` 的每一项，规范化必须抛出**对应类型**的错误。

### 3.2 向量清单

| id | 钉住的性质 |
|---|---|
| `upstream-v2.5.6-compat` | **与上游逐字节兼容**（含上游钉住的签名 `e14d3f9e…da0e`） |
| `basic-card` | 键顺序被刻意打乱后仍规范化正确 |
| `nested-signature-stripped-at-depth` | 任意深度删除 `signature` |
| `non-ascii-left-raw` | 非 ASCII 原样输出，不 `\u` 转义 |
| `control-characters-escaped-minimally` | 仅 7 个短转义；其余用**小写** `\u00xx` |
| `astral-plane-key-ordering` | 码点排序（JS 必须用显式比较器） |
| `integers-typed-and-null-and-empty` | `null`/空数组/空对象/负数；`"z"` 排在 `"zero"` 前 |
| `js-safe-integer-boundary` | `2⁵³ − 1`：三端都能精确表示的上界 |
| `int64-max` | `2⁶³ − 1`：JS 标记为 `unsupported-by-json-parse` |
| `uint64-max` | `2⁶⁴ − 1`：同上 |
| `reject: float-value` / `fractional-value` / `exponent-notation` | 浮点必须被拒绝 |
| `reject: root-is-array` / `root-is-string` | 根必须是对象 |

---

## 4. 可移植性边界（诚实记录）

JavaScript 的 `JSON.parse` 把数字读成 `f64`，因此**无法精确表示 `|n| > 2⁵³ − 1`**。
这不是本项目的缺陷，而是语言事实。处理方式：

* 向量中 `int64-max` 与 `uint64-max` 显式标注
  `"languages": { "javascript": "unsupported-by-json-parse" }`；
* JS SDK 的规范化对超出安全范围的整数抛出 **`UnsafeInteger`**，
  并提示调用方改用字符串；
* Rust 与 Python 接受完整 `i64`/`u64` 范围。

**因此：需要在三端同时签名的数值，应当保持在 ±(2⁵³ − 1) 内。
货币用整数最小单位，通常远低于该上界。**

---

## 5. 自行验证

```bash
# 1) 生成器可复现检出内容（CI 门禁）
node conformance/generate.mjs
git diff --exit-code conformance/vectors.json

# 2) 三端分别对同一组向量断言
cargo test -p nau-core --test conformance      # Rust（含验证 OpenSSL 产出的签名）
python sdks/python/run_tests.py                # Python（纯 Python Ed25519，零依赖）
node sdks/js/test/run.js                       # JavaScript（node:crypto，零依赖）
```

三端都必须退出 0。若任一端与向量不符，**该端的实现是错的**——
不要修改向量，除非同时更新生成器与全部三端。
