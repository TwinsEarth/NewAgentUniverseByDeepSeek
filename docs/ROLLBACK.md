# 回滚方案 / Rollback

**v3.9.9 新增**。此前 `docs/DEPLOYMENT.md` 有部署与验证，**没有回滚** ——
出事时只能靠人回忆。本文档补上这一段。

**本文档的每一条都是可执行的**，不是流程描述。命令按「回滚不需要读代码」的标准写。

---

## 一、先决定：这次要回滚什么

回滚的粒度决定代价。**先回答这个问题，再动手。**

| 症状 | 回滚目标 | 代价 | 数据 |
|---|---|---|---|
| 某个版本引入缺陷 | **回滚二进制** | 分钟级 | 不动 |
| 数据被写坏 | **回滚数据目录** | 分钟级 | 回到快照点 |
| 配置写错（策略/token）| **回滚配置** | 秒级 | 不动 |
| 插件行为异常 | **停用该插件** | 秒级 | 不动 |

> **不要为了一个配置错误去回滚二进制** —— 那会让「出了什么事」和「做了什么」更难对上。

---

## 二、回滚二进制

### 2.1 先把当前状态存证（**别跳过这一步**）

```bash
# 当前版本
curl -s http://127.0.0.1:4002/version

# 当前账本守恒状态 —— 这是回滚后要对比的基准
curl -s http://127.0.0.1:4002/conservation > /tmp/conservation-before.json

# 审计尾部的指纹
curl -s http://127.0.0.1:4002/audit > /tmp/audit-before.json

# 容器形态下还要记下镜像 ID
docker inspect --format '{{.Image}}' nau-node
```

```powershell
# Windows 本机
curl.exe -s http://127.0.0.1:4002/version
curl.exe -s http://127.0.0.1:4002/conservation > $env:TEMP\conservation-before.json
(Get-Item .\target\release\nau-daemon.exe).VersionInfo.FileVersion
```

### 2.2 回滚到上一个已发布的 Release

每个版本都有 GitHub Release，带三个资产与 `SHA256SUMS`：

```bash
# 下载上一个版本的二进制与校验和（把 3.9.8 换成要回滚到的版本）
V=3.9.8
curl -sLO "https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases/download/v${V}/nau"
curl -sLO "https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases/download/v${V}/nau-daemon"
curl -sLO "https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases/download/v${V}/SHA256SUMS"

# * * * 先验校验和，再安装 * * *
sha256sum --check --ignore-missing SHA256SUMS
```

```powershell
$V = "3.9.8"
Invoke-WebRequest "https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases/download/v$V/nau-daemon.exe" -OutFile nau-daemon.exe
Invoke-WebRequest "https://github.com/TwinsEarth/NewAgentUniverseByDeepSeek/releases/download/v$V/SHA256SUMS" -OutFile SHA256SUMS
# 人工比对（Windows 的 certutil 不直接吃 SHA256SUMS 格式）
(Get-FileHash .\nau-daemon.exe -Algorithm SHA256).Hash.ToLower()
Get-Content .\SHA256SUMS
```

### 2.3 停 → 换 → 起（容器形态）

```bash
docker compose down                    # 不加 -v：数据卷保留
docker tag nau:3.9.8 nau:rollback      # 确保旧镜像还在本地
# 改 docker-compose.yml 的 image: 为 nau:rollback，然后：
docker compose up -d
docker compose ps                      # 等 (healthy)
```

### 2.4 停 → 换 → 起（本机形态）

```bash
pkill -TERM -f nau-daemon              # SIGTERM，不是 SIGKILL
# 等它退出：守护进程要按顺序停 26 个插件，给它时间
sleep 5
install -m 0755 nau-daemon /usr/local/bin/nau-daemon
/usr/local/bin/nau-daemon --api-addr 127.0.0.1:4002 --data-dir /var/lib/nau &
```

> **用 `SIGTERM` 而不是 `SIGKILL`**：**SIGKILL 打断关闭流程就是存储留下半截写入的方式。**

---

## 三、回滚数据

### 3.1 数据的形状（**这决定了能不能热回滚**）

```
/var/lib/nau/                 ← --data-dir
├── nau-data.sqlite           ← 账本（精确整数最小单位）
├── *.jsonl                   ← 审计尾部
├── *.snapshot                ← 快照
└── sandboxes/                ← 沙箱工作目录（可丢弃）
```

**关键性质**：**账本是单一文件**，所以「停 → 换文件 → 起」就是一次完整回滚 ✓

### 3.2 快照

```bash
# 停服务，保证文件不再被写
docker compose stop nau

# 备份当前（即使是坏的那份也留着：事后分析要用）
cp -a /var/lib/nau /var/lib/nau.broken.$(date +%s)

# 恢复
rm -rf /var/lib/nau
cp -a /var/lib/nau.backup.20261005 /var/lib/nau
chown -R 10001:10001 /var/lib/nau     # 容器用户的 uid

docker compose start nau
```

```powershell
Stop-Process -Name nau-daemon
Copy-Item -Recurse -Force .\nau-data .\nau-data.broken.$(Get-Date -Format yyyyMMddHHmmss)
Copy-Item -Recurse -Force .\nau-data.backup .\nau-data
```

### 3.3 回滚后必须验的三件事

```bash
curl -s http://127.0.0.1:4002/conservation    # 守恒
curl -s http://127.0.0.1:4002/audit           # 审计尾部完整
curl -s http://127.0.0.1:4002/accounts/alice/balance
```

**判定**：

| 检查 | 通过标准 |
|---|---|
| `/conservation` | **`discrepancy` 为 0** —— 非 0 即失败，**不要「先上线再说」** |
| `/audit` | 尾部没有断口 |
| 余额 | 与快照点一致 |

---

## 四、回滚配置

不用停服务：

```bash
# 改 .env（或 compose 的 environment）
NAU_API_TOKENS="..."      # 作废一个泄露的 token
NAU_SANDBOX_BACKEND=none  # 立刻停止执行 agent 代码
NAU_API_HOSTS="..."       # 收窄可达的名字

docker compose up -d nau  # 只重建这一个服务
```

**三个「立刻生效」的紧急开关**（各自的语义见 `.env.example`）：

| 想做的事 | 设什么 |
|---|---|
| **停止一切 agent 代码执行** | `NAU_SANDBOX_BACKEND=none` |
| **停止一切写入** | 清空 `NAU_API_TOKENS`（节点变只读）|
| **停止所有跨源访问** | 清空 `NAU_API_ORIGINS` |

> **这三个都是「收紧」而不是「放开」，所以它们可以立刻做，不需要先想清楚。**

---

## 五、停用单个插件

不用重启节点：`tribunal` 提供隔离，`police` 提供黑名单 ✓（v3.7.1 的分权设计）。

```bash
# 隔离一个插件（需要 admin scope，且 tribunal 持有 kernel:policy:write）
curl -s -X POST http://127.0.0.1:4002/plugins/com.twinsearth.sys.security.tribunal/call \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"capability":"kernel:policy:write","op":"rule","plugin":"<id>"}'
```

> **注意**：`Quarantined` 在本仓库里是**终态**——被隔离的插件不会自动恢复 ✓
> **所以隔离前要确认它不会被别的东西需要。**

---

## 六、回滚**不可以**做什么

| 不可以 | 为什么 |
|---|---|
| **移动一个已有 Release 的 tag** | 只有**尚未创建 Release** 的 tag 才可安全移动。已发布的 tag 移动会让「v3.9.8 是哪个提交」有第二个答案 |
| **删掉坏数据就当作回滚** | 那会让事后分析失去证据。**先 `cp -a`，再覆盖** |
| **用 `SIGKILL` 停进程** | 会留下半截写入 |
| **跳过校验和** | 回滚到一半的二进制比不回滚更糟 |
| **在守恒不为 0 时上线** | 账本的守恒是硬基线，`nau-ledger` 自己就会拒绝 |

---

## 七、回滚演练（**建议每季度做一次**）

```bash
# 1. 记基准
curl -s http://127.0.0.1:4002/conservation > /tmp/before.json

# 2. 停机、备份、换回上一个版本、起机
#    （照第二节做一遍）

# 3. 验
curl -s http://127.0.0.1:4002/conservation > /tmp/after.json
diff /tmp/before.json /tmp/after.json && echo "✓ 守恒状态一致"

# 4. 跑完整验证
node scripts/verify-all.mjs --allow-missing-tools
node scripts/deploy-local.mjs --prefix /tmp/rollback-check
```

> **没演练过的回滚方案不是方案，是愿望。**
> 演练会发现的东西——比如旧镜像已被清理、比如数据目录属主不对——
> **正是真出事那天最不想发现的东西。**
