# 项目介绍

> 本项目仅用于网络技术研究与学习。请遵守当地法律法规，合理使用网络资源。

叫什么名字没想好，one-reality or reasni？
是一个用于针对特定ip扫描和匹配reality目标的引擎。
因为reality 目标域名的最佳实践是

- **与入口 VPS 同 ASN / 同机房**：流量特征自然，延迟一致；
- **不使用公共 CDN**：防止 VPS 变成公网免费反代，避免 CDN 封锁；
- **非热门大厂网站**：避开 Google、Apple 等流量异常显眼的超大站点；
- **TLS 握手延迟尽量低**：确保科学出海连接体验极速流畅；
- **真实运营的业务网站**：真实运营的网站跑路风险低，demo网站跑路了还要再换

---

## ✨ 核心特性

- **24 小时全网 ASN 自适应扫描守护引擎 (Daemon Mode)**：
  - **全球 ASN 状态机调度**：支持全网/指定国家/单个 ASN 循环轮转，内置热门高优池倾斜调度（默认 70% 倾斜）；
  - **网段级断点续传 (Checkpoints)**：毫秒级记录 CIDR 网段扫描游标，支持进程异常重启或平滑中断后无缝恢复；
  - **网络画像与自适应探测**：智能识别目标机房 (Datacenter) 与住宅宽带 (Residential) 属性，自动避免对家宽网段进行无意义扫描。

- **硬核深度探测与反假冒识别 (Anti-Dummy / Anti-Tunnel)**：
  - **硬性技术底线**：一次握手完成 TLS 1.3、X25519 椭圆曲线、HTTP/2、严格 SNI 匹配、证书有效性及真实延迟检验；
  - **微型隧道与回显过滤**：深度特征识别并自动剔除 `tuwunel`、`boringproxy`、`default backend`、`<150 字节` 极简无结构回显以及 Nginx / OpenResty / Apache / Caddy / IIS 等默认欢迎页与错误页。

- **三阶梯候选召回与智能多维打分引擎 (Smart Recommendation)**：
  - **索引下推三阶召回**：Tier 1 (同 ASN 极速直连) $\rightarrow$ Tier 2 (同国家骨干) $\rightarrow$ Tier 3 (全球高星底池)，物理截断候选规模，十万级大表请求响应 $<10\text{ms}$；
  - **多维动态加权评分**：融合 ASN 亲和度、物理延迟、证书寿命、状态码及标签权重，经 $O(N \log N)$ 快速排序输出最优伪装资产；
  - **ACME 30 天自动续期感知与按需懒探测 (Lazy Recheck)**：结合绝对到期时间戳 `cert_expire_at`，自动识别证书进入 30 天续期窗口未换新的高危僵尸站点并降权，API 命中时触发防抖按需外呼更新。

- **双模企业级存储架构 (Dual-Store Architecture)**：
  - **双引擎统一抽象**：轻量单机开箱即用 **SQLite (WAL 模式)**，大规模分布式生产无缝切换 **PostgreSQL (`pgxpool`)**，单库稳定承载 10万+ 活跃伪装资产池；
  - **存量健康巡检与自愈 (Patrol & Auto-Purge)**：后台自动化资产巡检体系，周期性淘汰失效域名，支持全量合规资产导出与导入。

- **多形态接入服务体系**：
  - **RESTful API & SSE 流式长连接**：提供 `/api/targets/smart`、`/api/targets/stream`、`/api/targets/check` 标准接口，并支持通过 `POST/DELETE /api/targets/{domain}/star` 收藏或取消收藏目标；收藏结果会优先展示；
  - **嵌入式可视化控制台 (Web UI)**：基于 React + TypeScript 构建，支持单二进制内嵌分发（`go:embed`），可视化管理资产、ASN 队列与即时测算；
  - **高并发 CLI & 管道流式处理**：原生支持 `reality-checker pipe` 管道批量验证与 `Ctrl+C` 平滑中断输出。
---

## ⚡ 一键安装与 Systemd 守护进程部署 (NanoPi / VPS)

支持所有主流 Linux 发行版以及 **NanoPi / 树莓派 / Armbian 嵌入式盒子** 与云服务器：

```bash
# 在线一键极速安装 (自动识别 CPU 架构，嵌入式设备自适应并发限流)
curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash

# 自定义 Token 与并发参数安装 (例如软路由/单板盒子建议 -t 150)
curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash -s -- --token my-secret-token -t 150
```

> 💡 **单板电脑 / NanoPi 优化提示**：安装脚本会自动读取设备特征（NanoPi / Armbian / 内存 < 2GB），默认将并发协程数优化为 `-t 150`，避免并发 TCP 探测占满家用路由器的 NAT 连接表（Conntrack）。详细调优策略请参阅 [Systemd 守护进程部署运维文档](doc/deploy/systemd-daemon.md)。

安装后可通过内置管理工具轻松运维：
```bash
reasni-service status   # 查看守护进程运行状态
reasni-service log      # 查看实时追踪扫描日志
reasni-service restart  # 重启服务
reasni-service config   # 快捷修改启动参数与 Token (/etc/default/reasni)
reasni-service update   # 一键热升级至最新版本
```

---

## 🚀 使用方式

### 网络环境

如果使用透明代理，请配置本程序走直连规则。
推荐使用单独socks入站-> direct。
由于初次启动会自动连接 GitHub 下载必要的规则库与 GeoIP 数据库，您可直接在 `config.yaml` 中配置分流：

```yaml
proxy:
  url: "http://127.0.0.1:7890"  # 支持 http://, https://, socks5://,此处填直连出口对应的入站
  download: false               # 下载不走改入站（就是不走直连，流向透明代理）
  scanner: true                 # 走直连出站
```

### 工作流一：根据 VPS IP 扫描和筛选（推荐）

输入 VPS IP 后，程序会：
1. 查询该 IP 所属 ASN 及已宣布网段；
2. 依据入口 IP 的国家（或 `--country` 指定国家）智能过滤网段；
3. 优先检查本地 数据库（**Cache-First**），命中直接返回；
4. 未命中时自动启动并发扫描，根据过滤条件筛选结果
比如

```bash
./reasni auto 85.155.184.100 --limit 5
```

命中5个符合筛选的结果后退出

### 工作流二：全量摸底扫描并导出 JSON 数据集

使用 `--check-all` 开启全量摸底模式（不提前刹车），摸清该 ASN 下所有合规资产并存档到本地 SQLite 库：

```bash
./reality-checker auto 85.155.184.100 --check-all --export targets.json
```

---

## 🔍 检测内容与指标

只有通过硬性技术底线的结果才会被纳入资产池并参与星级评定：

- **密码学与协议**：TLS 1.3、X25519 密钥交换和 HTTP/2 支持；
- **证书有效性**：证书剩余有效天数（默认 >= 10天）和 SNI 匹配度；
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
reality-checker auto --in <文件> [选项]       扫描文件中的 IP/CIDR 列表
reality-checker asn <ASN> <国家>             查询并按国家过滤 ASN CIDR
reality-checker pipe                         从 stdin 管道流式读取检测域名或 CSV
reality-checker check <domain>               检测单个域名
reality-checker batch <d1> <d2> ...          并发检测多个域名
reality-checker version                      显示版本、提交和构建信息
```

### `auto` 常用选项：

```text
--limit N / -m          指定获取合适目标的数量上限 (默认 5)
--check-all / -a        开启全量摸底扫描模式 (不提前终止，全量入库，自动支持断点续传)
--reset-scan            重置断点记录，从第 1 个网段重新开始全量扫描
--threads N / -t        设置网络扫描并发协程数 (默认 200，高性能 VPS 建议 500~1000)
--timeout SEC           单 IP 握手超时秒数 (默认 3 秒，死 IP 快速熔断建议 1~2 秒)
--no-cache              跳过本地资产库缓存，强制重新发起网络扫描
--recheck               对本地命中的资产发起在线网络健康复核 (默认直接复用历史参数)
--ipv4-only / -4        仅拉取与扫描 IPv4 网段
--ipv6-only / -6        仅拉取与扫描 IPv6 网段
--export FILE           将扫描发现的所有合格资产导出为 JSON 文件
--country CODE          指定国家过滤 (两位 ISO 代码，如 US, DE)
--max-handshake MS      设置最大握手延迟 (毫秒, 默认 800)
--min-cert-days DAYS    证书最低剩余天数 (默认 7)
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

# 资产选型与查询过滤策略 (filter)
filter:
  # ==================== 网络与运行环境策略 ====================
  # 1. 排除国内网站 (true: 默认排除国内站点；若为海外回国翻墙/访问国内流媒体，可设为 false)
  require_no_cn: true

  # 2. GFW 静态黑名单检测 (false: 本地家宽直连时建议关闭，纯靠真实网络握手连通性自然淘汰，避免静态名单误杀)
  check_gfw: false

  # 3. IP 协议族过滤 (拉取与解析 CIDR 时直接过滤)
  ipv4_only: false             # 是否仅拉取与扫描 IPv4 网段 (默认 false)
  ipv6_only: false             # 是否仅拉取与扫描 IPv6 网段 (默认 false)

  # 4. 资产数据库与缓存快速通道
  use_cache: true              # 是否优先使用本地 SQLite 资产库 (默认 true)
  verify_cache: false          # 是否对本地缓存发起在线网络复核 (默认 false: 直接使用历史参数 0 延迟秒出; true: 在线并发复核)
  cache_max_days: 7            # 缓存有效天数 (默认 7)

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

### 3. 数据文件与内置资产

为保证开箱即用与跨网络环境的稳定性，程序内置了完整的静态规则与 GeoIP 离线库：
- **静态规则库**（`cdn_keywords.txt`、`hot_websites.txt`、`exclude_rules.txt`）：已全部通过 `go:embed` 内嵌在可执行文件中，无需额外下载。如需自定义，可在 `data/` 目录下放置同名文件实现优先覆盖。
- **GeoIP 国家数据库**（`Country.mmdb`）：编译构建时会自动联网拉取最新数据库并内置嵌入（`go:embed`）。运行时程序会定期检测更新（15 天周期）；若在弱网或离线环境下下载失败，将**自动无缝回退至内置版本**，无需人工干预即可完整运行。
- `reality_targets.db`：SQLite 资产与扫描持久化数据库（程序运行自动创建与维护）。

---

## 🤝 致谢

- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) - GeoIP 数据库
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - GFW 规则
- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) - Xray 官方 TLS 扫描器
