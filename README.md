# RealityChecker

RealityChecker 是一个用于自动发现、深度检测与智能筛选 Xray Reality SNI 目标的网站检测与资产管理引擎。它整合了 ASN 网段智能发现、内置原生并发 TLS 扫描器、密码学协议检验、两阶段极速过滤体系以及 SQLite 资产数据库，帮助你从入口 VPS 的 IP 出发，一键找到符合最佳实践的高质量 Reality 真实目标。

> 本项目仅用于网络技术研究与学习。请遵守当地法律法规，合理使用网络资源。

---

## 🌟 Reality 目标选型最佳实践

- **与入口 VPS 同 ASN / 同机房**：流量特征自然，阻断率最低；
- **不使用公共 CDN**：防止 VPS 变成公网免费反代，避免 CDN 封锁；
- **非热门大厂网站**：避开 Google、Apple 等流量异常显眼的超大站点；
- **TLS 握手延迟尽量低**：确保科学出海连接体验极速流畅；
- **真实运营的业务网站**：排除 Nginx/OpenResty/Apache/Caddy 默认欢迎页、Tunnel 占位页或短回显服务。

---

## ✨ 核心特性

- **两阶段过滤架构 (Two-Stage Filtering)**：
  - **阶段一（网络扫描与硬性技术底线）**：只执行一次真实的 TLS 握手与技术底线检验（TLS 1.3、X25519 密钥交换、HTTP/2、SNI 匹配、证书未过期、非国内保留地址、排除默认页与 Dummy 占位等），生成候选资产池；
  - **阶段二（纯内存进阶偏好过滤）**：纯内存 0 耗时即时计算，支持白名单后缀 (`include_suffixes`)、黑名单后缀 (`exclude_suffixes`)、延迟阈值 (`max_handshake_ms`)、状态码排除 (`exclude_status`)、星级门槛等。
- **本地 SQLite 资产库与 Cache-First 秒级直出**：
  - 自动持久化存储于 `data/reality_targets.db`（SQLite WAL 模式，带 ASN/国家复合索引）；
  - **默认 0 网络请求极速直出**：同机房/同 ASN + 国家 IP 二次查询时直接复用本地历史参数秒出结果；
  - **按需在线复核 (`--recheck`)**：如需对缓存资产进行在线连通性与握手延迟重新复核，传入 `--recheck` 或 `--verify-cache` 即可触发安全并发检测。
- **全量摸底扫描 (`--check-all`) 与资产导出 (`--export`)**：
  - 支持全量网段摸排模式（不提前终止），摸清并沉淀该 ASN 下所有合规资产入库，并可导出为标准化 JSON 文件。
- **Tunnel 占位与微型回显服务识别 (Anti-Dummy / Anti-Tunnel)**：
  - 智能识别并剔除 `tuwunel`、`boringproxy`、`default backend`、`<150字节` 极短无 HTML 结构回显以及 Nginx / OpenResty / Apache / Caddy / Microsoft IIS 等默认欢迎页与错误页。
- **网络环境策略化配置**：
  - `require_no_cn`：默认 `true`（排除国内站点），海外回国翻墙用户可设为 `false`；
  - `check_gfw`：默认 `false`（本地家宽直连模式依靠真实网络握手连通性自然淘汰，避免静态规则误杀）。
- **灵活规则引擎**：支持白名单后缀 (`include_suffixes`) 与外部规则文件 (`data/exclude_rules.txt`)。
- **优雅信号中断 (Ctrl+C Graceful Exit)**：
  - 单击 `Ctrl+C` 立即停止网络扫描并格式化输出当前已发现的可用目标表格；双击即刻强制终止。
- **标准输入流式检测**：支持 `cat domains.txt | reality-checker pipe` 管道极速并发检测。

---

## 🚀 推荐工作流程

### 工作流一：根据 VPS IP 自动全流程筛选（最推荐）

输入一个 VPS IP 后，程序会：
1. 查询该 IP 所属 ASN 及已宣布网段；
2. 依据入口 IP 的国家（或 `--country` 指定国家）智能过滤网段；
3. 优先检查本地 SQLite 资产库（**Cache-First**），命中则秒级直出；
4. 未命中时自动启动原生并发扫描，执行两阶段过滤并按推荐星级输出结果。

```bash
./reality-checker auto 85.155.184.100 --limit 5
```

单个 IP 会按就近原则扩展为 IPv4 `/24` 或 IPv6 `/64` 网段用于扫描；如果输入的是 CIDR，则直接扫描该网段：

```bash
./reality-checker auto 5.45.102.0/24 --limit 10
```

指定国家过滤（ISO 两位代码，如 `US`、`DE`、`JP`、`HK`）：

```bash
./reality-checker auto 85.155.184.100 --country US --limit 10
```

### 工作流二：全量摸底扫描并导出 JSON 数据集

使用 `--check-all` 开启全量摸底模式（不提前刹车），摸清该 ASN 下所有合规资产并存档到本地 SQLite 库：

```bash
./reality-checker auto 85.155.184.100 --check-all --export targets.json
```

### 工作流三：查询 ASN 网段，再自定义扫描

只想获取某个 ASN 在指定国家的 CIDR 时：

```bash
./reality-checker asn AS15169 US > as15169-us.txt
```

然后扫描文件中的网段（每行一个 CIDR 或 IP）：

```bash
./reality-checker auto --in ./as15169-us.txt --limit 10
```

### 工作流四：从标准输入流式检测 (Pipe 模式)

`pipe` 可以接收纯域名列表，也可以接收 RealiTLScanner 或其他工具输出的 CSV，适合流水线整合：

```bash
cat domains.txt | ./reality-checker pipe
```

Windows PowerShell 示例：
```powershell
Get-Content domains.txt | .\reality-checker.exe pipe
```

---

## 🔍 检测内容与指标

只有通过硬性技术底线的结果才会被纳入资产池并参与星级评定：

- **密码学与协议**：TLS 1.3、X25519 密钥交换和 HTTP/2 支持；
- **握手延迟**：真实 TLS 密码学握手往返延迟 (RTT)；
- **证书有效性**：证书剩余有效天数（默认 >= 10天）和 SNI 匹配度；
- **页面状态与默认页**：HTTP 状态码（支持自定义 `exclude_status` 排除 301/302/404 等）、Nginx/Apache/Caddy 默认欢迎页及 Tunnel/回显服务识别；
- **CDN 与热门站点**：智能识别 CDN 厂商及 Alexa/Tranco 热门大站；
- **地理位置**：目标 IP 的 GeoIP 归属地判定。

典型结果输出如下：

```text
适合的域名:
+------------------------------------+----------+----------+----------+-----+------+------+----------+
| 最终域名                           | 基础条件 | 握手时间 | 证书时间 | CDN | 热门 | 推荐 | 页面状态 |
+------------------------------------+----------+----------+----------+-----+------+------+----------+
| https://mirror-csail.debian.org    |     ✓    |   282ms  |   87天   |  无 |   -  | **** |    200   |
| https://specimens.avrenela.com     |     ✓    |   285ms  |   79天   |  无 |   -  | **** |    200   |
| https://xn--chq864an8ppa.cc        |     ✓    |   283ms  |   80天   |  无 |   -  | **** |    200   |
+------------------------------------+----------+----------+----------+-----+------+------+----------+
```

---

## 📋 命令速查

```text
reality-checker auto <ip/cidr> [选项]        从 IP/CIDR 自动发现并筛选目标 (支持 Cache-First)
reality-checker auto --in <文件> [选项]     扫描文件中的 IP/CIDR 列表
reality-checker asn <ASN> <国家>             查询并按国家过滤 ASN CIDR
reality-checker pipe                         从 stdin 管道流式读取检测域名或 CSV
reality-checker check <domain>               检测单个域名
reality-checker batch <d1> <d2> ...          并发检测多个域名
reality-checker version                      显示版本、提交和构建信息
```

### `auto` 常用选项：

```text
--limit N / -m          指定获取合适目标的数量上限 (默认 5)
--check-all / -a        开启全量摸底扫描模式 (不提前终止，全量入库)
--no-cache              跳过本地资产库缓存，强制重新发起网络扫描
--recheck               对本地命中的资产发起在线网络健康复核 (默认直接复用历史参数)
--export FILE           将扫描发现的所有合格资产导出为 JSON 文件
--country CODE          指定国家过滤 (两位 ISO 代码，如 US, DE)
--max-handshake MS      设置最大握手延迟 (毫秒, 默认 400)
--min-cert-days DAYS    证书最低剩余天数 (默认 10)
--min-stars STARS       最低推荐星级 1-5 (默认 3)
--no-cdn / --allow-cdn  强制排除 / 允许 CDN 节点
--no-hot / --allow-hot  强制排除 / 允许热门大站
--debug                 输出逐 IP 调试日志
```

---

## ⚙️ 配置文件 (`config.yaml`)

程序启动时会自动读取同目录下的 `config.yaml`（支持挂载 `data/exclude_rules.txt`）：

```yaml
# 日志配置
log:
  level: info
  file: ""

# REALITY 目标选型过滤策略
reality_filter:
  # ==================== 网络与运行环境策略 ====================
  # 1. 排除国内网站 (true: 默认排除国内站点；若为海外回国翻墙/访问国内流媒体，可设为 false)
  require_no_cn: true

  # 2. GFW 静态黑名单检测 (false: 本地家宽直连时建议关闭，纯靠真实网络握手连通性自然淘汰，避免静态名单误杀)
  check_gfw: false

  # 3. 资产数据库与缓存快速通道 (true: 优先复用本地 SQLite 数据库中已验证的同 ASN/国家 优质资产并秒级复核)
  use_cache: true
  cache_max_days: 7

  # ==================== 阶段二：进阶偏好过滤策略 ====================
  # 4. 强制非 CDN 过滤 (true: 剔除 Cloudflare/Akamai/Fastly 等 CDN 节点，防止 VPS 变成公网免费反代)
  require_no_cdn: true

  # 5. 握手时间延迟上限 (毫秒): 高于此延迟的节点抛弃 (默认 400ms)
  max_handshake_ms: 400

  # 6. 热门大站过滤 (true: 依据 data/hot_websites.txt 匹配剔除 Google/Apple 等超级大站)
  require_no_hot: true

  # 7. 证书剩余有效天数下限: 默认 10 天
  min_cert_days: 10

  # 8. 最低推荐星级门槛: (1~5 星)
  min_stars: 3

  # 9. 默认返回页与占位服务过滤 (true: 识别并剔除 Nginx/Apache/Caddy 等默认欢迎页及 Tunnel/极短回显占位)
  require_no_default_page: true

  # 10. 外部排除规则文件路径 (默认载入 data/exclude_rules.txt)
  exclude_rules_file: "data/exclude_rules.txt"

  # 11. 白名单域名后缀（可选，若配置则只保留指定后缀，如只要 .com/.de）
  # include_suffixes:
  #   - ".com"
  #   - ".de"
  #   - ".org"

  # 12. 排除的 HTTP 页面状态码（被排除的状态码将被标记为不适合）
  exclude_status:
    - 400
    - 401
    - 403
    - 404
    - 407
    - 408
    - 429
    - 500
    - 501
    - 502
    - 503
    - 504

# 网络检测配置
network:
  timeout: 3s
  retries: 1

# 并发性能
concurrency:
  max_concurrent: 10
  check_timeout: 3s
```

---

## 🛠️ 快速开始

### 1. 直接下载

从 [Releases](https://github.com/V2RaySSR/RealityChecker/releases) 下载对应平台的免安装压缩包。

### 2. 本地构建

需要 Go 1.25 或更高版本。构建产物自动输出到 `dist/`，包含 Linux `amd64`/`arm64` 和 Windows `amd64`（采用纯 Go 驱动，完全免 CGO 静态编译）：

```bash
# Linux / macOS
./build.sh
```

```powershell
# Windows PowerShell
.\build.ps1
```

### 3. 数据文件

程序首次运行会自动初始化 `data/` 目录并准备检测所需数据。若离线部署，请确保 `data/` 包含：
- `Country.mmdb`（MaxMind GeoIP 国家数据库）
- `gfwlist.conf`（GFWList 规则）
- `cdn_keywords.txt`（CDN 识别特征库）
- `hot_websites.txt`（热门大站特征库）
- `exclude_rules.txt`（排除规则库）
- `reality_targets.db`（SQLite 资产持久化数据库，自动生成）

---

## 🤝 致谢

- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) - GeoIP 数据库
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - GFW 规则
- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) - Xray 官方 TLS 扫描器
