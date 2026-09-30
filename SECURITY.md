# 安全 / Security

## 安全模型与信任边界

本项目的设计目标是**不信任输入**。以下边界是明确的：

| 边界 | 处理 |
|---|---|
| 网络传入的 JSON | 规范形式拒绝浮点、非对象根、>64 层嵌套；所有长度有上限 |
| 传入的签名结构 | `verify()` 校验签名**且**校验「DID 是该公钥的指纹」；`verify_fresh()` 追加过期与 ±300 s 时钟偏移检查 |
| 重放 | 每个签名结构带 `nonce`；`NonceGuard` 按 DID 拒绝重用与回退；`TaskState` 有完备转移表 |
| 委员会投票 | 票是签名的；成员集在 `Committee::assign` 时固定并强制 `members.len() == n`；非成员/篡改/重放票被拒绝 |
| 资金 | 整数最小单位；非正数额度在任何变更方法上被拒绝；余额不足返回错误，**绝不创建资金**；发布即托管 |
| 公钥 | 拒绝小阶（weak）点，包括全零的恒等点编码 |
| 时间 | 通过 `Clock` 端口注入；`SystemClock` 饱和而非 panic |
| 合约 | 状态先于外部调用；`nonReentrant`；pull 支付；owner-only 管理函数；bps 上限校验 |

## 已知的安全相关限制（诚实记录）

1. **DID 指纹为 64 位**（与上游一致，为兼容性保留）。
   生日碰撞约 2³² 量级。更宽的指纹需要一次协议版本升级
   （见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §10）。
2. **未实现传输层加密与身份握手。**
   本版本的 `TcpTransport` 做长度前缀分帧，**不做** Noise/TLS，
   也**不**在传输层验证对端身份。应用层的消息签名是当前的信任基础。
   若部署在不可信网络，请在 `Transport` 之下自行加隧道，
   或等待后续的加密适配器。
3. **未实现 DHT / GossipSub / NAT 穿透。** 因此没有跨网段发现与打洞能力。
4. **未实现 TEE / zkML 验证。** `EvidenceGrade` 是**声明**，
   不是密码学证明（上游同样如此，且其 `tee_quote`/`zk_proof` 甚至不经校验）。
   在需要强保证的场景，`Verified` 必须由实际的独立重执行产生。
5. **合约未经审计、未在主网部署。** 本项目重写了四个合约并配有 Foundry 测试，
   但**没有**第三方审计，构建时本机亦无 Solidity 编译器可执行验证。
   在真实资金场景使用前请自行审计。
6. **Python SDK 的 Ed25519 是纯 Python 实现。**
   它通过共享向量验证（含上游钉住的签名），
   但**纯 Python 实现不具备常量时间保证**，因此不适合处理高价值长期密钥。
   对这类用途，请把签名交给 Rust 侧或使用经过审计的库。

## 密钥处理

* `Keypair` 的 `Debug` 实现**不打印私钥**（有测试断言）。
* 仓库不包含任何私钥、助记词或 API 令牌；`.gitignore` 排除 `*.pem`、`*.key`、`.env*`、`secrets/`。
* 发布脚本 [`scripts/publish-github.mjs`](scripts/publish-github.mjs)
  在扫描待上传文件时会**主动跳过**形如凭证的文件，并只从环境变量读取令牌。

## 报告漏洞

请**不要**通过公开 issue 报告安全漏洞。

* 使用 GitHub 的 [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)；
* 或在仓库的 Security 标签页提交 draft advisory。

请包含：受影响的组件与版本、复现步骤或最小化载荷、影响评估，以及（如有可能）修复建议。
**不要**在报告中附带真实私钥或生产凭证。

我们会在确认后于 [CHANGELOG.md](CHANGELOG.md) 中记录修复，
并在需要时发布安全公告。

## 依赖策略与供应链

* 默认构建为**纯 Rust**，依赖树刻意保持精简（见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §0）。
* Python 与 JS SDK **零第三方依赖**——不存在依赖投毒面。
* CI 中的 GitHub Actions 应固定到具体版本；发布流程必须依赖测试通过
  （上游的三条发布 workflow 在任意 `v*` 上独立触发，无测试依赖）。
