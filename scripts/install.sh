#!/usr/bin/env bash
#
# RealityChecker / Reasni 守护进程一键安装与运维脚本
# 适用平台: Linux (amd64 / arm64), 支持 Armbian / NanoPi / 树莓派 / Ubuntu / Debian / CentOS 等
#

set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="qualvey/one-reality"
BIN_INSTALL_PATH="/usr/local/bin/reality-checker"
BIN_ALIAS_PATH="/usr/local/bin/reasni"
SERVICE_HELPER_PATH="/usr/local/bin/reasni-service"
CONFIG_DIR="/etc/reasni"
DATA_DIR="/var/lib/reasni"
DEFAULT_ENV_FILE="/etc/default/reasni"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/reasni-daemon.service"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_err() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_title() {
    echo -e "\n${CYAN}===================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}===================================================${NC}\n"
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_err "请使用 root 权限或 sudo 运行此安装脚本。"
        exit 1
    fi
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)
            TARGET_ARCH="linux-amd64"
            ;;
        aarch64|arm64)
            TARGET_ARCH="linux-arm64"
            ;;
        *)
            log_err "暂不支持的 CPU 架构: ${arch}，目前支持 linux-amd64 与 linux-arm64。"
            exit 1
            ;;
    esac
}

detect_hardware() {
    IS_EMBEDDED=false
    local model_str=""
    if [ -f /proc/device-tree/model ]; then
        model_str="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || true)"
    fi

    local cpu_info=""
    if [ -f /proc/cpuinfo ]; then
        cpu_info="$(cat /proc/cpuinfo 2>/dev/null || true)"
    fi

    local os_rel=""
    if [ -f /etc/os-release ]; then
        os_rel="$(cat /etc/os-release 2>/dev/null || true)"
    fi
    if [ -f /etc/armbian-release ]; then
        os_rel="${os_rel} $(cat /etc/armbian-release 2>/dev/null || true)"
    fi

    local total_mem_mb
    total_mem_mb="$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 4096)"

    if echo "${model_str} ${cpu_info} ${os_rel}" | grep -qiE "nanopi|armbian|raspberry|rockchip|allwinner|rk3[0-9]|friendlyelec" || [ "$total_mem_mb" -lt 2048 ]; then
        IS_EMBEDDED=true
    fi
}

usage() {
    cat <<EOF
RealityChecker / Reasni 守护进程安装与管理工具

用法:
  bash install.sh [选项]

选项:
  --token <str>        设置 Web/API 鉴权 Token (留空将自动生成随机安全 Token)
  -t, --threads <num>  设置 ASN 扫描并发协程数 (默认: 嵌入式设备 150, VPS/服务器 500)
  --host <str>         设置内置 HTTP API 监听地址 (默认: 0.0.0.0)
  --port <num>         设置内置 HTTP API 监听端口 (默认: 8881)
  --interval <sec>     设置每轮扫描等待间隔秒数 (默认: 10)
  -f, --force          强制运行，跳过非 CN (中国大陆) 公网出口 IP 校验
  --local-bin <path>   使用本地已有二进制安装，不进行网络下载
  --service-only       仅重新安装/更新 systemd 服务与环境配置，不替换二进制
  --repo <user/repo>   指定 GitHub 仓库来源 (默认: ${REPO})
  --uninstall          完全卸载服务与二进制文件
  -h, --help           显示本帮助信息

示例:
  # 快速在线安装 (自动识别 NanoPi/SBC 并优化参数):
  bash install.sh

  # 自定义 Token 与并发参数:
  bash install.sh --token my-secret-token -t 150

  # 在非中国大陆机器上强制启动:
  bash install.sh --force

  # 卸载:
  bash install.sh --uninstall
EOF
}

OPT_TOKEN=""
OPT_THREADS=""
OPT_HOST="0.0.0.0"
OPT_PORT="8881"
OPT_INTERVAL="10"
OPT_FORCE=false
OPT_LOCAL_BIN=""
OPT_SERVICE_ONLY=false
DO_UNINSTALL=false

while [ $# -gt 0 ]; do
    case "$1" in
        --token)
            OPT_TOKEN="$2"
            shift 2
            ;;
        --token=*)
            OPT_TOKEN="${1#*=}"
            shift 1
            ;;
        -t|--threads)
            OPT_THREADS="$2"
            shift 2
            ;;
        --threads=*)
            OPT_THREADS="${1#*=}"
            shift 1
            ;;
        --host)
            OPT_HOST="$2"
            shift 2
            ;;
        --host=*)
            OPT_HOST="${1#*=}"
            shift 1
            ;;
        --port)
            OPT_PORT="$2"
            shift 2
            ;;
        --port=*)
            OPT_PORT="${1#*=}"
            shift 1
            ;;
        --interval)
            OPT_INTERVAL="$2"
            shift 2
            ;;
        --interval=*)
            OPT_INTERVAL="${1#*=}"
            shift 1
            ;;
        -f|--force)
            OPT_FORCE=true
            shift 1
            ;;
        --local-bin)
            OPT_LOCAL_BIN="$2"
            shift 2
            ;;
        --local-bin=*)
            OPT_LOCAL_BIN="${1#*=}"
            shift 1
            ;;
        --service-only)
            OPT_SERVICE_ONLY=true
            shift 1
            ;;
        --repo)
            REPO="$2"
            shift 2
            ;;
        --uninstall)
            DO_UNINSTALL=true
            shift 1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_err "未知参数: $1"
            usage
            exit 1
            ;;
    esac
done

uninstall_reasni() {
    log_title "正在卸载 RealityChecker / Reasni 守护进程服务"
    check_root

    if systemctl is-active --quiet reasni-daemon 2>/dev/null; then
        log_info "停止 reasni-daemon 服务..."
        systemctl stop reasni-daemon || true
    fi

    if systemctl is-enabled --quiet reasni-daemon 2>/dev/null; then
        log_info "禁用 reasni-daemon 自启..."
        systemctl disable reasni-daemon || true
    fi

    log_info "清理服务文件与快捷脚本..."
    rm -f "${SYSTEMD_SERVICE_FILE}"
    rm -f "${SERVICE_HELPER_PATH}"
    rm -f "${BIN_ALIAS_PATH}"
    rm -f "${BIN_INSTALL_PATH}"
    rm -f "${DEFAULT_ENV_FILE}"

    systemctl daemon-reload || true

    echo -e "\n${YELLOW}[提示]${NC} 数据库和配置文件目录仍保留在: ${DATA_DIR} 和 ${CONFIG_DIR}"
    echo -e "若需彻底清除历史数据，可手动执行: ${CYAN}rm -rf ${DATA_DIR} ${CONFIG_DIR}${NC}\n"
    log_info "卸载完成！"
    exit 0
}

install_reasni() {
    check_root
    detect_arch
    detect_hardware

    log_title "开始安装 RealityChecker / Reasni 守护进程服务"
    log_info "系统架构: ${TARGET_ARCH}"

    # 1. 硬件自适应并发设置
    if [ -z "${OPT_THREADS}" ]; then
        if [ "${IS_EMBEDDED}" = true ]; then
            OPT_THREADS=150
            log_warn "检测到嵌入式/单板设备 (NanoPi / Armbian / 低内存)，并发数自动优化为: -t 150 (防占满 NAT 表)"
        else
            OPT_THREADS=500
            log_info "检测到标准服务器/VPS，并发数设置为: -t 500"
        fi
    else
        log_info "使用自定义并发数: -t ${OPT_THREADS}"
    fi

    # 2. Token 生成与配置
    if [ -z "${OPT_TOKEN}" ]; then
        # 检查是否已有配置中的 token
        if [ -f "${DEFAULT_ENV_FILE}" ] && grep -q 'token' "${DEFAULT_ENV_FILE}"; then
            log_info "保留已有配置文件中的鉴权 Token"
        else
            if command -v openssl >/dev/null 2>&1; then
                OPT_TOKEN="$(openssl rand -hex 12)"
            else
                OPT_TOKEN="$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | cut -c 1-24 || echo "reasni-$(date +%s)")"
            fi
            log_info "已自动生成安全 API Token: ${CYAN}${OPT_TOKEN}${NC}"
        fi
    fi

    # 3. 安装或更新二进制文件
    if [ "${OPT_SERVICE_ONLY}" = false ]; then
        local src_bin=""
        if [ -n "${OPT_LOCAL_BIN}" ]; then
            if [ ! -f "${OPT_LOCAL_BIN}" ]; then
                log_err "指定的本地二进制不存在: ${OPT_LOCAL_BIN}"
                exit 1
            fi
            src_bin="${OPT_LOCAL_BIN}"
            log_info "使用本地二进制: ${src_bin}"
        else
            # 优先检查本地当前目录下是否有 dist 编译产物
            local local_candidate="./dist/reality-checker-${TARGET_ARCH}"
            if [ -f "${local_candidate}" ]; then
                src_bin="${local_candidate}"
                log_info "发现本地构建产物: ${src_bin}"
            else
                log_info "正在从 GitHub Release 拉取最新版本 (${REPO})..."
                local tmp_dir
                tmp_dir="$(mktemp -d)"
                local download_url="https://github.com/${REPO}/releases/latest/download/reality-checker-${TARGET_ARCH}"
                log_info "下载地址: ${download_url}"

                if command -v curl >/dev/null 2>&1; then
                    curl -fsSL --connect-timeout 15 --retry 3 "${download_url}" -o "${tmp_dir}/reasni" || {
                        log_err "下载失败，请检查网络或使用 --local-bin 指定本地文件。"
                        rm -rf "${tmp_dir}"
                        exit 1
                    }
                elif command -v wget >/dev/null 2>&1; then
                    wget -q --timeout=15 --tries=3 "${download_url}" -O "${tmp_dir}/reasni" || {
                        log_err "下载失败，请检查网络或使用 --local-bin 指定本地文件。"
                        rm -rf "${tmp_dir}"
                        exit 1
                    }
                else
                    log_err "未找到 curl 或 wget，请先安装下载工具。"
                    rm -rf "${tmp_dir}"
                    exit 1
                fi
                src_bin="${tmp_dir}/reasni"
            fi
        fi

        log_info "安装二进制至 ${BIN_INSTALL_PATH}..."
        install -d -m 755 /usr/local/bin
        install -m 755 "${src_bin}" "${BIN_INSTALL_PATH}"
        ln -sf "${BIN_INSTALL_PATH}" "${BIN_ALIAS_PATH}"
    fi

    # 4. 创建工作与配置目录
    log_info "初始化系统目录..."
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${DATA_DIR}"
    chmod 755 "${CONFIG_DIR}" "${DATA_DIR}"

    # 5. 准备默认 config.yaml
    if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
        if [ -f "./config.yaml" ]; then
            cp "./config.yaml" "${CONFIG_DIR}/config.yaml"
            log_info "已复制当前 config.yaml 至 ${CONFIG_DIR}/config.yaml"
        else
            cat <<'YAMLEOF' > "${CONFIG_DIR}/config.yaml"
# RealityChecker 基础配置文件
log:
  level: "info"
storage:
  type: "sqlite"
  sqlite:
    path: "data/reality_targets.db"
server:
  host: "0.0.0.0"
  port: 8881
YAMLEOF
            log_info "已生成默认 ${CONFIG_DIR}/config.yaml"
        fi
    fi

    # 6. 配置环境参数文件 /etc/default/reasni
    log_info "配置运行参数环境文件 ${DEFAULT_ENV_FILE}..."
    local daemon_opts="--host ${OPT_HOST} --port ${OPT_PORT} -t ${OPT_THREADS} --interval ${OPT_INTERVAL}"
    if [ -n "${OPT_TOKEN}" ]; then
        daemon_opts="${daemon_opts} --token ${OPT_TOKEN}"
    fi
    if [ "${OPT_FORCE}" = true ]; then
        daemon_opts="-f ${daemon_opts}"
    fi

    if [ ! -f "${DEFAULT_ENV_FILE}" ]; then
        cat <<ENVEOF > "${DEFAULT_ENV_FILE}"
# /etc/default/reasni
# RealityChecker / Reasni 守护进程参数配置
DAEMON_OPTS="${daemon_opts}"
REALITY_CONFIG="${CONFIG_DIR}/config.yaml"
ENVEOF
    else
        log_info "${DEFAULT_ENV_FILE} 已存在，更新 DAEMON_OPTS..."
        # 备份并更新
        cp "${DEFAULT_ENV_FILE}" "${DEFAULT_ENV_FILE}.bak"
        if grep -q '^DAEMON_OPTS=' "${DEFAULT_ENV_FILE}"; then
            sed -i "s|^DAEMON_OPTS=.*|DAEMON_OPTS=\"${daemon_opts}\"|" "${DEFAULT_ENV_FILE}"
        else
            echo "DAEMON_OPTS=\"${daemon_opts}\"" >> "${DEFAULT_ENV_FILE}"
        fi
    fi

    # 7. 安装 systemd 服务文件
    log_info "安装 systemd 服务文件至 ${SYSTEMD_SERVICE_FILE}..."
    cat <<SERVICEEOF > "${SYSTEMD_SERVICE_FILE}"
[Unit]
Description=RealityChecker ASN Scanner Daemon
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${DATA_DIR}
Environment="REALITY_CONFIG=${CONFIG_DIR}/config.yaml"
EnvironmentFile=-${DEFAULT_ENV_FILE}
EnvironmentFile=-${CONFIG_DIR}/daemon.env
# 注意：在 Armbian / NanoPi 等嵌入式盒子上，建议通过 -t 适当调低并发（如 100~150），避免占满路由器 NAT 连接表
ExecStart=${BIN_ALIAS_PATH} daemon \$DAEMON_OPTS
Restart=on-failure
RestartSec=10s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICEEOF

    # 8. 创建 reasni-service 运维快捷脚本
    log_info "安装服务运维快捷工具: ${SERVICE_HELPER_PATH}..."
    cat <<'HELPEREOF' > "${SERVICE_HELPER_PATH}"
#!/usr/bin/env bash
# reasni-service: RealityChecker 服务快捷管理工具
set -e

ACTION="${1:-status}"

case "$ACTION" in
    start)
        systemctl start reasni-daemon
        echo "reasni-daemon 服务已启动。"
        ;;
    stop)
        systemctl stop reasni-daemon
        echo "reasni-daemon 服务已停止。"
        ;;
    restart)
        systemctl restart reasni-daemon
        echo "reasni-daemon 服务已重启。"
        ;;
    status)
        systemctl status reasni-daemon
        ;;
    log|logs)
        journalctl -u reasni-daemon -f -n 50
        ;;
    config)
        EDITOR="${EDITOR:-nano}"
        if ! command -v "$EDITOR" >/dev/null 2>&1; then
            EDITOR="vi"
        fi
        "$EDITOR" /etc/default/reasni
        echo "修改后请执行: reasni-service restart 使配置生效。"
        ;;
    update)
        echo "正在更新 RealityChecker 服务..."
        curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash
        ;;
    uninstall)
        curl -fsSL https://raw.githubusercontent.com/qualvey/one-reality/main/scripts/install.sh | bash -s -- --uninstall
        ;;
    *)
        echo "用法: reasni-service {start|stop|restart|status|log|config|update|uninstall}"
        exit 1
        ;;
esac
HELPEREOF
    chmod +x "${SERVICE_HELPER_PATH}"

    # 9. 重新载入 systemd 并启动
    log_info "重载 systemd 配置并启动服务..."
    systemctl daemon-reload
    systemctl enable reasni-daemon
    systemctl restart reasni-daemon

    # 10. 输出就绪信息
    log_title "安装完成并已成功拉起服务！"
    echo -e "Web 控制台与 API 地址: ${CYAN}http://${OPT_HOST}:${OPT_PORT}${NC}"
    if [ -n "${OPT_TOKEN}" ]; then
        echo -e "API 鉴权 Token:        ${YELLOW}${OPT_TOKEN}${NC}"
    fi
    echo -e "扫描并发协程数 (-t):   ${GREEN}${OPT_THREADS}${NC}"
    echo -e "数据工作目录:          ${BLUE}${DATA_DIR}${NC}"
    echo -e "环境配置文件:          ${BLUE}${DEFAULT_ENV_FILE}${NC}"
    echo -e "\n常用运维命令:"
    echo -e "  查看运行状态:        ${CYAN}reasni-service status${NC} (或 systemctl status reasni-daemon)"
    echo -e "  查看实时日志:        ${CYAN}reasni-service log${NC}    (或 journalctl -u reasni-daemon -f)"
    echo -e "  重启服务:            ${CYAN}reasni-service restart${NC}"
    echo -e "  编辑运行参数:        ${CYAN}reasni-service config${NC}"
    echo -e ""
}

if [ "${DO_UNINSTALL}" = true ]; then
    uninstall_reasni
else
    install_reasni
fi
