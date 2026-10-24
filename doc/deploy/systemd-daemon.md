# Systemd 守护进程服务与极速安装分发指南

RealityChecker / Reasni 内置支持 24 小时全网 ASN 自动化扫描与 HTTP API / Web 控制台服务（`daemon` 模式）。为便于在 Linux 服务器及嵌入式设备（如 NanoPi、树莓派、香橙派、Armbian 单板盒子）上快速上线与稳定运行，本项目提供生产级 Systemd 守护进程服务单元与一键安装运维脚本。

---

## ⚡ 极速一键安装

在 Linux 终端执行以下命令即可全自动完成架构侦测、依赖部署、服务注册与开机自启：

::: code-group
```bash [在线安装 (推荐)]
curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash
```

```bash [自定义参数安装]
# 指定鉴权 Token 并限制并发为 150 (适合软路由/嵌入式盒子)
curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash -s -- --token my-secret-token -t 150
```

```bash [非 CN 网络强制拉起]
# 若部署在海外 VPS 或本地出口未识别为 CN 时追加 --force
curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash -s -- --force
```
:::

安装脚本执行过程具备以下智能特性：
1. **CPU 架构自适应**：自动识别 `x86_64` (linux-amd64) 与 `aarch64` (linux-arm64)，下载对应的预编译产物；
2. **嵌入式设备感知**：自动读取硬件模型（NanoPi、Rockchip、Allwinner、Armbian、Raspberry Pi）或物理内存容量；若内存 $< 2\text{GB}$ 或检测到单板电脑，**自动将并发扫描协程数下调为 `-t 150`**；
3. **环境参数解耦**：将运行时参数注入 `/etc/default/reasni`，后续修改参数无需重复编辑 Unit 文件与重载 Systemd；
4. **统一运维快捷工具**：自动部署 `/usr/local/bin/reasni-service`，提供极简运维指令。

---

## 🛠️ 服务快捷运维 (`reasni-service`)

安装成功后，系统已内置 `reasni-service` 管理工具：

| 命令 | 功能说明 | 对应原生指令 |
| :--- | :--- | :--- |
| `reasni-service status` | 查看守护进程当前运行状态 | `systemctl status reasni-daemon` |
| `reasni-service log` | 实时滚动追踪扫描与运行日志 | `journalctl -u reasni-daemon -f -n 50` |
| `reasni-service restart`| 重启守护进程服务 | `systemctl restart reasni-daemon` |
| `reasni-service stop` | 停止守护进程服务 | `systemctl stop reasni-daemon` |
| `reasni-service start` | 启动守护进程服务 | `systemctl start reasni-daemon` |
| `reasni-service config`| 打开并编辑运行参数配置文件 | 编辑 `/etc/default/reasni` |
| `reasni-service update`| 拉取最新版本并热重载服务 | 重新运行安装脚本 |
| `reasni-service uninstall` | 完全卸载服务与二进制程序 | 停止服务、清理 unit 与命令 |

---

## 💡 嵌入式设备 (NanoPi / Armbian) 调优与 NAT 表保护

> [!WARNING] 路由器 NAT 连接表溢出风险
> 家用路由器及轻量级单板电脑（NanoPi R2S/R4S/R5S/R6S 等）通常拥有受限的 Linux Conntrack NAT 连接追踪表（常见上限仅为 32,768 ~ 65,536 条）。
> 若在家庭内网或软路由上将并发设为 500 以上，大量的并发 SYN 探测包会迅速将主路由的 NAT 状态表占满，导致家庭局域网内其他设备网络出现断连或严重丢包。

### 推荐调优参数对照表

| 运行环境 | 推荐并发 (`-t`) | 推荐轮询间隔 (`--interval`) | 适用场景 |
| :--- | :--- | :--- | :--- |
| **嵌入式盒子 / NanoPi** | **`100 ~ 150`** | `10s` | 家庭宽带直连、旁路网关、Armbian 轻量盒子 |
| **家庭软路由 (OpenWrt/PVE)** | **`150 ~ 200`** | `10s` | 软路由多网口直通、局域网共享出口 |
| **轻量 VPS (1核 1G~2G)** | **`200 ~ 300`** | `5s ~ 10s` | 单机独立云服务器 |
| **标准 VPS / 独立服务器 (4核+)** | **`500`** | `5s` | 独享带宽机房服务器 |

### 修改运行参数

只需直接编辑 `/etc/default/reasni`：
```bash
# /etc/default/reasni
DAEMON_OPTS="--host 0.0.0.0 --port 8881 --token your-token -t 150 --interval 10"
```
保存后执行重启即可生效：
```bash
reasni-service restart
```

---

## 📁 目录与文件规范 (FHS)

安装脚本严格遵循 Linux 文件系统层级标准 (FHS)：

```text
/
├── usr/local/bin/
│   ├── reality-checker         # 主二进制程序
│   ├── reasni -> reality-checker # 常用别名软链接
│   └── reasni-service          # 服务快捷管理脚本
├── etc/
│   ├── reasni/
│   │   └── config.yaml         # 全局业务配置文件 (SQLite/PG 路径、代理分流规则等)
│   └── default/
│       └── reasni              # 守护进程启动参数 (DAEMON_OPTS, REALITY_CONFIG)
├── var/lib/reasni/
│   ├── data/
│   │   ├── reality_targets.db  # 核心扫描成果与 SQLite 数据库
│   │   └── Country.mmdb        # 离线 GeoIP 数据库资产
│   └── .checkpoints/           # 网段扫描断点续传游标
└── etc/systemd/system/
    └── reasni-daemon.service   # Systemd 服务单元
```

---

## 📜 Systemd Service 核心单元文件解析

位于 `/etc/systemd/system/reasni-daemon.service`：

```ini
[Unit]
Description=RealityChecker ASN Scanner Daemon
Documentation=https://github.com/qualvey/one-reality
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/reasni
Environment="REALITY_CONFIG=/etc/reasni/config.yaml"
EnvironmentFile=-/etc/default/reasni
EnvironmentFile=-/etc/reasni/daemon.env
# $DAEMON_OPTS 由 EnvironmentFile 注入并自动展开
ExecStart=/usr/local/bin/reasni daemon $DAEMON_OPTS
Restart=on-failure
RestartSec=10s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 关键配置亮点
1. **`WorkingDirectory=/var/lib/reasni`**：确保断点续传游标、SQLite 资产库及扫描产生的临时数据始终持久化在 `/var/lib/reasni`，不会污染系统根目录；
2. **`EnvironmentFile=-/etc/default/reasni`**：前缀 `-` 表示文件不存在时忽略，参数与 Service 单元解耦，避免用户频繁 `daemon-reload`；
3. **`LimitNOFILE=65535`**：自动解除高并发网络套接字句柄数限制，避免报 `too many open files` 异常；
4. **`Restart=on-failure` & `RestartSec=10s`**：守护进程若遇异常崩溃或网络临时中断，10 秒内平滑拉起自愈。

---

## 🔍 故障排查与诊断

### 1. 检查 NAT 连接跟踪数（嵌入式设备排查）
若怀疑扫描影响到了局域网，可在网关或宿主机查看当前网络连接跟踪状态：
```bash
# 查看当前活跃连接数与系统上限
sysctl net.netfilter.nf_conntrack_count
sysctl net.netfilter.nf_conntrack_max
```
若 `nf_conntrack_count` 接近上限，请立即执行 `reasni-service config` 将 `-t` 下调至 100。

### 2. 查看服务实时运行日志
```bash
reasni-service log
# 或指定查看最近 100 行
journalctl -u reasni-daemon -n 100 --no-pager
```

### 3. 出口 IP 非 CN 被拦截
如果在服务日志中看到：
```text
❌ 出口网络限制：当前出口 IP [...] 归属地为 [... / ...]，非中国大陆 (CN) 网络
```
请在 `/etc/default/reasni` 的 `DAEMON_OPTS` 开头加上 `-f` 参数：
```bash
DAEMON_OPTS="-f --host 0.0.0.0 --port 8881 --token your-token -t 150 --interval 10"
```
然后执行 `reasni-service restart`。
