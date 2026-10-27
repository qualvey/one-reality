# Reasni

Reasni 是一个用于检测和筛选 REALITY 目标的命令行工具。仓库名为 `one-reality`，支持从域名、IP 或 CIDR 网段进行检测，并将合格结果保存到本地资产库。

项目同时提供 HTTP API、Web 控制台和持续运行的 ASN 扫描守护进程。

> 仅对自己拥有或获得明确授权的网络和域名进行检测。请遵守当地法律法规以及目标网络的使用政策。

## 功能

- 检测 TLS 版本、X25519、HTTP/2、SNI、证书有效期和握手延迟。
- 检查 HTTP 状态、重定向、CDN、热门站点、默认页面和网络可达性。
- 根据入口 IP 查询 ASN 和 CIDR，并执行自动化网段扫描。
- 使用 SQLite 保存检测结果和扫描进度，也支持 PostgreSQL。
- 支持本地缓存、断点续传、批量检测和标准输入管道处理。
- 提供 `serve` HTTP API/Web 控制台和 `daemon` 长期扫描模式。

## 安装

### 下载发行版

从 [Releases](../../releases) 下载对应平台的二进制文件。当前构建脚本生成：

- Linux amd64
- Linux arm64
- Windows amd64

Linux 守护进程也可以使用安装脚本。建议先下载并检查脚本，再以 root 权限执行：

```bash
curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh \
  -o /tmp/realitychecker-install.sh
less /tmp/realitychecker-install.sh
sudo bash /tmp/realitychecker-install.sh
```

安装脚本会安装 `reasni` 命令，并注册 `reasni-daemon.service`。`reality-checker` 是当前发行构建使用的兼容二进制名称。
完整的 Systemd 配置、目录和运维说明见
[Systemd 守护进程部署文档](doc/deploy/systemd-daemon.md)。

### 从源码构建

需要 Go 1.26 或更高版本。构建过程会准备用于 GeoIP 查询的 `Country.mmdb`，因此首次构建通常需要访问网络。

```bash
./build.sh
```

构建产物位于 `dist/`。Windows 环境可使用：

```powershell
.\build.ps1
```

直接运行源码：

```bash
go run . version
```

## 快速开始

### 根据入口 IP 获取目标

`get` 会先查询本地资产库；没有足够结果时，再根据入口 IP 所属 ASN 扫描相关网段。

```bash
reasni get 85.155.184.100 --limit 5 --stars 3
```

常用选项：

```text
--limit, -n N       返回目标数量，默认 5
--stars, -s N       最低评分，默认 3
--fresh             忽略本地缓存并重新检测
--json              以 JSON 输出结果
--country CODE      指定国家，例如 US、DE
--4 / --6           仅使用 IPv4 / IPv6
```

### 检测域名

```bash
reasni check example.com
reasni batch example.com example.org
cat domains.txt | reasni pipe
```

### 扫描 IP 或 CIDR

```bash
reasni auto 203.0.113.0/24 --limit 5
reasni auto 203.0.113.0/24 --check-all --export targets.json
```

`--check-all` 会扫描完整输入范围并将符合条件的结果写入资产库；扫描任务启用时会保存进度，便于中断后继续。

### 启动 API 和 Web 控制台

```bash
reasni serve --host 127.0.0.1 --port 8881 --token change-me
```

服务默认监听 `8881` 端口。常用接口包括：

```text
GET /api/health
GET /api/stats
GET /api/targets/smart?ip=<IP>&limit=10
GET /api/targets/stream?ip=<IP>&limit=5
```

如果服务需要被其他主机访问，请设置鉴权 Token，并在防火墙中限制访问来源。

## 长期运行模式

直接启动守护进程：

```bash
reasni daemon --threads 500 --interval 10 --token change-me
```

非中国大陆出口或无法完成出口检测时，需要显式使用 `--force`：

```bash
reasni --force daemon --threads 200
```

生产环境建议使用安装脚本提供的 Systemd 服务，而不是直接在终端运行。安装完成后可使用：

```bash
reasni-service status
reasni-service log
reasni-service restart
reasni-service config
```

## 配置

程序按以下顺序查找配置文件：显式指定的 `-c/--config`、`REALITY_CONFIG` 环境变量、当前目录、可执行文件所在目录。文件名可以是 `config.yaml` 或 `config.yml`。

最小配置示例：

```yaml
log:
  level: info

database:
  driver: sqlite
  sqlite:
    path: data/reality_targets.db

filter:
  require_no_cn: true
  require_no_cdn: true
  require_no_hot: true
  require_no_default_page: true
  min_cert_days: 7
  min_stars: 3

network:
  timeout: 3s
  retries: 1
```

需要代理下载数据时，可以配置：

```yaml
proxy:
  url: http://127.0.0.1:7890
  download: true
  scanner: false
```

默认使用 SQLite。使用 PostgreSQL 时，将 `database.driver` 改为 `postgres`，并填写 `database.postgres` 连接参数。

## 命令概览

```text
get <ip>                  根据入口 IP 获取目标
check <domain>            检测单个域名
batch <domain> ...        批量检测域名
pipe                      从标准输入流式检测
auto <ip/cidr>            扫描 IP 或 CIDR
asn <ASN> <country>       查询并过滤 ASN 网段
serve                     启动 HTTP API/Web 控制台
daemon                    启动持续扫描守护进程
patrol                    巡检本地资产
migrate                   执行数据库迁移
version                   显示版本信息
```

全局选项（放在子命令之前）：

```text
-c, --config FILE         指定配置文件
-f, --force               跳过出口网络限制，强制继续运行
```

帮助信息以实际版本输出为准：

```bash
reasni --help
```

## 数据目录

默认相对路径如下：

```text
data/reality_targets.db  SQLite 资产数据库
data/Country.mmdb        GeoIP 国家数据库
data/exclude_rules.txt   自定义排除规则
```

Systemd 安装会将配置放在 `/etc/reasni/`，运行数据放在 `/var/lib/reasni/`，服务参数放在 `/etc/default/reasni`。

## 相关文档

- [Systemd 守护进程部署与运维](doc/deploy/systemd-daemon.md)
- [ASN 24 小时扫描设计](doc/dev/asn-24h-scanner.md)
- [数据库与资产生命周期](doc/dev/database-and-lifecycle.md)
- [SNI 检测说明](doc/dev/sni.md)

## 参与开发

提交代码前请运行测试：

```bash
go test ./...
```

欢迎提交 Issue 和 Pull Request。提交内容应包含问题描述、复现步骤，以及必要的运行环境信息。

## 致谢

- [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)
- [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)
- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner)
