# Reality Target 寻找和分析工具

一键找到符合最佳实践的SNI

基于原项目，整合Xray官方RealiTLScanner的功能，简化了操作步骤，实现 `输入ip段，返回符合条件的域名`,大大减少了心智负担和操作难度

Reality SNI目标域名的最佳实践

- 不使用CDN
- 非热门大厂
- 和入口机ip同ASN
- TLS握手延迟尽量低

## ✨ 功能特性

* **被墙检测** - 基于GFWList检测网站是否被墙
* **地理位置检测** - 检测IP地理位置，国内网站直接终止
* **TLS协议检测** - 检测TLS 1.3和X25519支持
* **证书检测** - 检测证书有效性和SNI匹配
* **CDN检测** - 智能检测CDN使用情况
* **热门网站检测** - 检测是否为热门网站
* **Nginx/Web 默认页识别** - 精准识别并剔除 Nginx/OpenResty 默认欢迎页与测试页
* **灵活过滤规则** - 支持外部规则文件与后缀/通配符注入（排除 .local, .internal, .arpa 等私有后缀）
* **重定向检测** - 检测域名重定向
* **批量与流式检测** - 支持标准输入 (Stdin) 管道流式极速并发检测
* **智能报告** - 生成详细的检测分析报告

### 推荐工作流程

1. 用 VPS IP 启动自动流程。程序会通过 RIPEstat 查询 IP 所属 ASN 的宣布网段，并使用 `data/Country.mmdb` 过滤为与入口 IP 同国家的网段。

2. 自动查询该ASN下的已公告IP段，并按国家过滤：

   ```bash
   ./reality-checker asn AS7203 US > as7203-us.txt
   ```

   国家参数支持 ISO 两位代码（如 `US`、`DE`、`CN`）或 GeoIP 数据库中的名称。

3. 直接一键全自动内嵌扫描检测目标：

```bash
./reality-checker auto <vps-ip> --limit 10
```

也可以继续把自定义网段填入文件（每行一条），再用以下命令开始检测 (本地电脑运行，请先关闭代理（确保请求为直连))：
   `--limit 10` 是取前 10 条（大部分情况已经足够筛选中好用的目标）

```bash
./reality-checker auto --in ./cidrs.txt --limit 10
```

4. 或通过标准输入管道流式处理已有域名/CSV：

```bash
cat domains.txt | ./reality-checker pipe
```

### 过滤条件

二进制同目录下 `config.yaml`（支持挂载 `data/exclude_rules.txt`）：

```yaml
reality_filter:
    # 是否要求无cdn，默认true (推荐)
    require_no_cdn: true
    # TLS握手延迟上限，默认400ms
    max_handshake_ms: 400
    # 最少证书有效期（天）
    min_cert_days: 10
    # 默认返回页过滤 (true: 自动剔除 Nginx/OpenResty 默认欢迎页与测试页)
    require_no_default_page: true
    # 外部排除规则文件
    exclude_rules_file: "data/exclude_rules.txt"

# 并发性能
concurrency:
    max_concurrent: 10
    check_timeout: 3s
```

**实际运行效果：**

![RealityChecker检测结果示例](RealityChecker.png)

**只有满足Reality目标域名硬性条件的（TLS1.3、X25519、H2、SNI匹配、证书有效），才会在列表中显示**


### 热门网站说明

热门网站（如 apple.com、tesla.com、microsoft.com 等）由于使用人群多，容易被识别和封禁，因此不太推荐作为 Reality 协议的目标域名。

**结果分析：**
- 所有域名都支持TLS 1.3、X25519、HTTP/2和SNI匹配
- 证书有效期充足
- 部分使用了CDN且为热门网站
- 部分虽然技术指标优秀，但由于CDN和热门网站特性，推荐度有所降低


## 🚀 快速开始

### 系统要求

* **Linux VPS** - 主要针对VPS环境使用
* **Windows、macOS** - 等自行编译
* **Go 1.25+** - 用于本地编译

### 安装步骤

**方法1：直接下载（推荐）**

从 [Releases](https://github.com/qualvey/RealityChecker/releases) 页面下载对应架构的zip文件：

### 本地构建

Linux/macOS 使用 Bash：

```bash
./build.sh
```

Windows PowerShell：

```powershell
.\build.ps1
```

构建产物统一输出到 `dist/`，包括 Linux `amd64`/`arm64` 和 Windows `amd64`
可执行文件及对应 zip 压缩包。构建时可通过 `VERSION`、`COMMIT`、`BUILD_TIME`
环境变量覆盖版本信息。


## 🔍 使用示例

### 单域名检测

```bash
# 基础检测
./reality-checker check apple.com
```

### 批量检测

```bash
# 批量检测多个域名（空格分隔）
./reality-checker batch apple.com tesla.com microsoft.com
```

### 管道流式检测 (Pipe)

```bash
# 从文件或输出流管道读取检测（支持域名或 CSV 格式）
cat domains.txt | ./reality-checker pipe
```


### 查看帮助

```bash
# 显示使用说明
./reality-checker

# 查看版本信息
./reality-checker version
```

## 🔧常见问题

**1. 数据文件下载失败**

如果自动下载失败，请手动下载以下文件到 `data/` 目录：

- [Country.mmdb](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb)
- [gfwlist.conf](https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt)
- [cdn_keywords.txt](https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/cdn_keywords.txt)
- [hot_websites.txt](https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/hot_websites.txt)


## 🏆 致谢

感谢以下开源项目：

* [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip) - GeoIP数据库
* [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) - GFW规则

---

**注意**: 本工具仅用于技术研究和学习目的，请遵守当地法律法规，合理使用网络资源。
