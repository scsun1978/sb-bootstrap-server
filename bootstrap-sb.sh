#!/usr/bin/env bash
set -euo pipefail

# =========================
# sing-box 一键初始化脚本（Ubuntu）
# - 支持 VLESS Reality
# - 支持 MODE=tun / MODE=socks
# - 自动安装 sing-box（二级兜底：GitHub Release）
# - 自动写配置 / 安装 sb 管理脚本 / systemd 常驻
# =========================

# ---- 可通过环境变量覆盖 ----
MODE="${MODE:-tun}"                 # tun 或 socks

SERVER="${SERVER:-}"                # 必填：Reality 服务器域名/IP
PORT="${PORT:-443}"                 # Reality 端口
UUID="${UUID:-}"                    # 必填：UUID
SNI="${SNI:-apple.com}"             # sni/server_name
PBK="${PBK:-}"                      # 必填：public_key
SID="${SID:-}"                      # 必填：short_id
FP="${FP:-chrome}"                  # fingerprint
FLOW="${FLOW:-xtls-rprx-vision}"    # 可为空：FLOW=""

DIRECT_CIDRS="${DIRECT_CIDRS:-10.19.0.0/16}"  # 额外直连网段（逗号分隔）
SOCKS_PORT="${SOCKS_PORT:-1080}"

TUN_ADDR="${TUN_ADDR:-172.19.0.1/30}"
TUN_IF="${TUN_IF:-singtun0}"

DNS_LOCAL="${DNS_LOCAL:-223.5.5.5}" # 国内DNS（直连）
DNS_REMOTE="${DNS_REMOTE:-1.1.1.1}" # 国外DNS（走代理）

# sing-box 安装兜底版本（可覆盖）
SINGBOX_VER="${SINGBOX_VER:-1.12.15}"

BIN_PATH="/usr/local/bin/sing-box"
CONF_PATH="/etc/sing-box/config.json"
SB_PATH="/usr/local/bin/sb"
SERVICE_NAME="sing-box"

log() { echo "[BOOTSTRAP] $*"; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "请用 root 执行（sudo -i 后再运行）。"
    exit 1
  fi
}

require_params() {
  local missing=0
  for k in SERVER UUID PBK SID; do
    if [[ -z "${!k}" ]]; then
      echo "缺少必填参数：${k}"
      missing=1
    fi
  done
  if [[ "${missing}" -eq 1 ]]; then
    echo
    echo "示例："
    echo "export MODE=tun SERVER=example.com PORT=12162 UUID=... PBK=... SID=... SNI=apple.com FP=chrome FLOW=xtls-rprx-vision DIRECT_CIDRS='10.19.0.0/16'"
    exit 1
  fi
}

install_prereqs() {
  log "安装基础依赖..."
  apt-get update -y
  apt-get install -y curl ca-certificates jq iproute2 tar
}

install_singbox_from_github() {
  local ver="${SINGBOX_VER}"
  local arch="amd64"
  local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${arch}.tar.gz"

  log "从 GitHub Release 安装 sing-box v${ver} ..."
  cd /tmp
  rm -rf "sing-box-${ver}-linux-${arch}" sing-box.tar.gz || true
  curl -fL --retry 3 --retry-delay 2 -o sing-box.tar.gz "${url}"
  tar -xzf sing-box.tar.gz
  install -m 0755 "sing-box-${ver}-linux-${arch}/sing-box" "${BIN_PATH}"
}

install_singbox() {
  log "安装 sing-box..."

  if [[ -x "${BIN_PATH}" ]]; then
    log "检测到已安装：${BIN_PATH}"
    log "sing-box 版本：$(${BIN_PATH} version || true)"
    return 0
  fi

  # 1) 首选官方脚本（在部分国内网络可能被 reset）
  if curl -fsSL https://sing-box.app/install.sh | bash; then
    if [[ -x "${BIN_PATH}" ]]; then
      log "sing-box 版本：$(${BIN_PATH} version || true)"
      return 0
    fi
  fi

  log "官方安装脚本不可达或失败，启用 GitHub Release 兜底..."
  install_singbox_from_github
  log "sing-box 版本：$(${BIN_PATH} version || true)"
}

install_sb_script() {
  log "安装 sb 管理脚本到 ${SB_PATH} ..."
  cat > "${SB_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="sing-box"
BIN="${BIN:-/usr/local/bin/sing-box}"
CONF="${CONF:-/etc/sing-box/config.json}"

usage() {
  cat <<'USAGE'
用法：
  sb install-service      创建/更新 systemd 服务并启用自启动
  sb start                启动 sing-box（systemd）
  sb stop                 停止 sing-box（systemd）
  sb restart              重启 sing-box（systemd）
  sb status               查看状态（systemd）
  sb logs                 跟踪日志（systemd）
  sb logn [N]             查看最近 N 行日志（默认 120 行）
  sb enable               开机自启
  sb disable              取消自启（并停止）
  sb run                  前台运行（直接运行二进制，便于调试）
  sb check                校验配置（尝试启动一次立即退出）
  sb test-socks           测试本地 SOCKS 127.0.0.1:1080 出口（api.ipify.org）
  sb test-direct          测试直连出口（api.ipify.org）
  sb env-proxy            输出当前 shell 可用的代理环境变量（SOCKS）
  sb unset-proxy          取消当前 shell 的代理环境变量
USAGE
}

need_root() { [[ "${EUID}" -eq 0 ]] || { echo "需要 root 权限运行。"; exit 1; }; }
ensure_bin_conf() {
  [[ -x "${BIN}" ]] || { echo "找不到可执行文件：${BIN}"; exit 1; }
  [[ -f "${CONF}" ]] || { echo "找不到配置文件：${CONF}"; exit 1; }
}

install_service() {
  need_root
  ensure_bin_conf

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF2
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} run -c ${CONF}
Restart=always
RestartSec=2
LimitNOFILE=512000

CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF2

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
  echo "已安装/更新 systemd 服务：${SERVICE_NAME}"
}

start_svc()   { need_root; systemctl start "${SERVICE_NAME}"; }
stop_svc()    { need_root; systemctl stop "${SERVICE_NAME}"; }
restart_svc() { need_root; systemctl restart "${SERVICE_NAME}"; }
status_svc()  { systemctl status "${SERVICE_NAME}" --no-pager; }
logs_follow() { need_root; journalctl -u "${SERVICE_NAME}" -f; }
logs_tail()   { need_root; journalctl -u "${SERVICE_NAME}" -n "${1:-120}" --no-pager; }
enable_svc()  { need_root; systemctl enable "${SERVICE_NAME}"; }
disable_svc() { need_root; systemctl disable --now "${SERVICE_NAME}"; }

run_fg() { ensure_bin_conf; exec "${BIN}" run -c "${CONF}"; }

check_conf() {
  ensure_bin_conf
  if command -v timeout >/dev/null 2>&1; then
    timeout 3 "${BIN}" run -c "${CONF}" >/dev/null 2>&1 && true
  else
    "${BIN}" run -c "${CONF}" >/dev/null 2>&1 && true
  fi
  echo "已尝试启动校验（如有错误请用：sb run 或 sb logn 查看日志）"
}

test_socks() { curl --socks5-hostname 127.0.0.1:1080 -sS https://api.ipify.org || true; echo; }
test_direct(){ curl -sS https://api.ipify.org || true; echo; }

env_proxy() {
  cat <<'E'
export ALL_PROXY=socks5h://127.0.0.1:1080
export HTTP_PROXY=$ALL_PROXY
export HTTPS_PROXY=$ALL_PROXY
E
}
unset_proxy(){ unset ALL_PROXY HTTP_PROXY HTTPS_PROXY all_proxy http_proxy https_proxy || true; echo "已取消当前 shell 的代理环境变量。"; }

cmd="${1:-}"; shift || true
case "${cmd}" in
  install-service) install_service ;;
  start) start_svc ;;
  stop) stop_svc ;;
  restart) restart_svc ;;
  status) status_svc ;;
  logs) logs_follow ;;
  logn) logs_tail "${1:-120}" ;;
  enable) enable_svc ;;
  disable) disable_svc ;;
  run) run_fg ;;
  check) check_conf ;;
  test-socks) test_socks ;;
  test-direct) test_direct ;;
  env-proxy) env_proxy ;;
  unset-proxy) unset_proxy ;;
  -h|--help|help|"") usage ;;
  *) echo "未知命令：${cmd}"; echo; usage; exit 1 ;;
esac
EOF
  chmod +x "${SB_PATH}"
}

enable_ip_forward() {
  log "开启 IPv4 转发..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-singbox-ipforward.conf
  sysctl --system >/dev/null
}

ensure_tun() {
  log "检查/加载 TUN 设备..."
  modprobe tun || true
  if [[ ! -c /dev/net/tun ]]; then
    echo "未发现 /dev/net/tun，当前环境可能不支持 TUN。请改用 MODE=socks。"
    exit 1
  fi
}

json_array_from_cidrs() {
  python3 - <<'PY'
import json, os
s=os.environ.get("DIRECT_CIDRS","").strip()
arr=[x.strip().strip('"').strip("'") for x in s.split(",") if x.strip()]
print(json.dumps(arr))
PY
}

write_config_socks() {
  log "写入 SOCKS 模式配置到 ${CONF_PATH} ..."
  mkdir -p /etc/sing-box

  local flow_line=""
  if [[ -n "${FLOW}" ]]; then
    flow_line="\"flow\": \"${FLOW}\","
  fi

  cat > "${CONF_PATH}" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    { "type": "socks", "listen": "127.0.0.1", "listen_port": ${SOCKS_PORT} }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "${SERVER}",
      "server_port": ${PORT},
      "uuid": "${UUID}",
      ${flow_line}
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "utls": { "enabled": true, "fingerprint": "${FP}" },
        "reality": {
          "enabled": true,
          "public_key": "${PBK}",
          "short_id": "${SID}"
        }
      }
    }
  ]
}
EOF
}

write_config_tun() {
  log "写入 TUN 模式配置到 ${CONF_PATH} ..."
  mkdir -p /etc/sing-box

  export DIRECT_CIDRS
  local direct_json
  direct_json="$(json_array_from_cidrs)"

  local flow_line=""
  if [[ -n "${FLOW}" ]]; then
    flow_line="\"flow\": \"${FLOW}\","
  fi

  cat > "${CONF_PATH}" <<EOF
{
  "log": { "level": "info" },

  "dns": {
    "strategy": "ipv4_only",
    "servers": [
      { "tag": "local",  "address": "${DNS_LOCAL}",  "detour": "direct" },
      { "tag": "remote", "address": "${DNS_REMOTE}", "detour": "proxy" }
    ],
    "rules": [
      { "geosite": "cn", "server": "local" }
    ],
    "final": "remote"
  },

  "inbounds": [
    {
      "type": "tun",
      "interface_name": "${TUN_IF}",
      "inet4_address": "${TUN_ADDR}",
      "auto_route": true,
      "strict_route": false,
      "stack": "system",
      "sniff": true
    }
  ],

  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "${SERVER}",
      "server_port": ${PORT},
      "uuid": "${UUID}",
      ${flow_line}
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "utls": { "enabled": true, "fingerprint": "${FP}" },
        "reality": {
          "enabled": true,
          "public_key": "${PBK}",
          "short_id": "${SID}"
        }
      }
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],

  "route": {
    "auto_detect_interface": true,
    "rules": [
      { "protocol": "dns", "outbound": "direct" },
      { "ip_is_private": true, "outbound": "direct" },
      { "ip_cidr": ${direct_json}, "outbound": "direct" },
      { "geoip": "cn", "outbound": "direct" },
      { "geosite": "cn", "outbound": "direct" }
    ],
    "final": "proxy"
  }
}
EOF
}

install_service() {
  log "安装 systemd 服务..."
  "${SB_PATH}" install-service
}

start_service() {
  log "启动 sing-box..."
  systemctl restart "${SERVICE_NAME}" || systemctl start "${SERVICE_NAME}"
  systemctl status "${SERVICE_NAME}" --no-pager || true
}

test_connectivity() {
  log "测试出口 IP（api.ipify.org）..."
  if [[ "${MODE}" == "socks" ]]; then
    curl --socks5-hostname "127.0.0.1:${SOCKS_PORT}" -sS https://api.ipify.org || true
  else
    curl -sS https://api.ipify.org || true
  fi
  echo
}

main() {
  need_root
  require_params
  install_prereqs
  install_singbox
  install_sb_script

  if [[ "${MODE}" == "tun" ]]; then
    ensure_tun
    enable_ip_forward
    write_config_tun
  elif [[ "${MODE}" == "socks" ]]; then
    write_config_socks
  else
    echo "MODE 只能是 tun 或 socks"
    exit 1
  fi

  install_service
  start_service
  test_connectivity

  log "完成 ✅"
  log "常用命令：sb status | sb logs | sb restart | sb stop"
}

main "$@"
