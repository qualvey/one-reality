# Systemd 守护进程服务配置说明

本目录包含 RealityChecker / Reasni 守护进程的 systemd 服务单元与运行环境配置。

## 文件说明

- `reasni-daemon.service`: systemd 服务单元文件，默认部署至 `/etc/systemd/system/reasni-daemon.service`。
- `reasni.env`: 环境变量与运行参数文件，部署至 `/etc/default/reasni` 或 `/etc/reasni/daemon.env`。

## 手动部署步骤

1. 拷贝二进制文件到系统路径：
   ```bash
   cp dist/reality-checker-linux-arm64 /usr/local/bin/reality-checker
   chmod +x /usr/local/bin/reality-checker
   ln -sf /usr/local/bin/reality-checker /usr/local/bin/reasni
   ```

2. 准备运行目录与配置文件：
   ```bash
   mkdir -p /var/lib/reasni /etc/reasni
   cp config.yaml /etc/reasni/config.yaml
   cp deploy/systemd/reasni.env /etc/default/reasni
   ```

3. 安装服务单元：
   ```bash
   cp deploy/systemd/reasni-daemon.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now reasni-daemon
   ```

4. 查看服务状态与日志：
   ```bash
   systemctl status reasni-daemon
   journalctl -u reasni-daemon -f
   ```
