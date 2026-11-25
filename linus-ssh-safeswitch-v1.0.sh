#!/usr/bin/env bash
# =============================================================================
# Linus SSH SafeSwitch v1.0 (正式版)
# 极简安全换端口工具：双端口验证 + 持久化断电回滚 + 防竞态看门狗 + Fail2ban 联防
#
# 用法：
#   新机首次运行：bash /tmp/linus-ssh-safeswitch-v1.0.sh [<新端口号>]
#                 （首次运行会自动安装至 /root/linus-ssh-safeswitch.sh 并启动换端）
#   日常交互模式：bash /root/linus-ssh-safeswitch.sh
#   日常快捷传参：bash /root/linus-ssh-safeswitch.sh <新端口号>
#   强制覆盖更新：bash /tmp/linus-ssh-safeswitch-v1.0.sh --install [<新端口号>]
#   帮助与版本：  bash /root/linus-ssh-safeswitch.sh -h | --help | -v | --version
#
# v1.0 正式版特性摘要：
# - 双端口平滑过渡（兼容 sshd_config.d 与 Systemd ssh.socket 双层架构）及实时端口轮询验收；
# - 独立回滚互斥锁 + 信号安全捕获 + 10 分钟/断电自包含看门狗，确保零失联与零僵尸进程；
# - 全自动适配 UFW / firewalld / nftables / iptables(IPv4+IPv6) 与动态 Fail2ban 联防引导。
# =============================================================================
set -Eeuo pipefail

# ── 常量 ──────────────────────────────────────────────────────────────────────
readonly APP_NAME="Linus SSH SafeSwitch"
readonly APP_VERSION="1.0"
readonly INSTALL_PATH="/root/linus-ssh-safeswitch.sh"
readonly BACKUP_DIR="/root/.linus-ssh-safeswitch"
readonly LOG_FILE="/var/log/linus-ssh-safeswitch.log"
readonly LOCK_FILE="/run/linus-ssh-safeswitch.lock"
readonly ROLLBACK_LOCK_FILE="/run/linus-ssh-safeswitch-rollback.lock"
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly DROPIN_FILE="/etc/ssh/sshd_config.d/99-linus-safeswitch.conf"
readonly SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
readonly SOCKET_DROPIN_FILE="/etc/systemd/system/ssh.socket.d/99-linus-safeswitch.conf"
readonly TIMEOUT_SEC=600

# ── 运行时状态 ────────────────────────────────────────────────────────────────
BACKUP_PATH=""
WATCHDOG_PID=""
ROLLBACK_REASON=""
NEED_ROLLBACK="0"
_IN_ON_EXIT="0"
SOCKET_MODE="0"

# ── 基础工具 ──────────────────────────────────────────────────────────────────
red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
cyan()   { printf '\033[36m%s\033[0m\n' "$*"; }

log() {
  printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE" 2>/dev/null || true
}

have() {
  command -v "$1" >/dev/null 2>&1
}

_trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

print_usage() {
  cat <<EOF
${APP_NAME} v${APP_VERSION}

用法：
  bash $(basename "${BASH_SOURCE[0]:-$0}")                  交互模式切换 SSH 端口
  bash $(basename "${BASH_SOURCE[0]:-$0}") <新端口号>       快捷传参切换至指定端口（1-65535）
  bash $(basename "${BASH_SOURCE[0]:-$0}") --install [端口] 将当前版本安装/更新至 ${INSTALL_PATH} 并运行
  bash $(basename "${BASH_SOURCE[0]:-$0}") -h | --help      显示本帮助信息
  bash $(basename "${BASH_SOURCE[0]:-$0}") -v | --version   显示版本号
EOF
}

_is_public_ipv4() {
  local ip="${1:-}"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local a b c d
  IFS='.' read -r a b c d <<<"$ip"
  (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
  (( a == 10 || a == 127 || a == 0 )) && return 1
  (( a == 172 && b >= 16 && b <= 31 )) && return 1
  (( a == 192 && b == 168 )) && return 1
  (( a == 100 && b >= 64 && b <= 127 )) && return 1
  (( a == 169 && b == 254 )) && return 1
  return 0
}

_detect_display_host() {
  local ip=""
  if [ -n "${SSH_CONNECTION:-}" ]; then
    ip="$(printf '%s\n' "$SSH_CONNECTION" | awk '{print $3}')"
    if _is_public_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  fi
  if have ip; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    if _is_public_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  fi
  printf '%s\n' "<服务器公网IP>"
}

# ── 前置检查 ──────────────────────────────────────────────────────────────────
need_root() {
  [ "${EUID:-$(id -u)}" -eq 0 ] || {
    red "请用 root 运行。"
    exit 1
  }
}

require_runtime_tools() {
  have sshd || {
    red "未检测到 sshd，可执行文件不存在。"
    exit 1
  }
  if ! have ss && ! have netstat && [ ! -r /proc/net/tcp ]; then
    red "系统缺乏端口检测手段，无法安全验证 SSH 监听状态。"
    exit 1
  fi
}

acquire_lock() {
  have flock || {
    red "缺少 flock 命令。"
    exit 1
  }
  # 严格保持同一 inode，绝不 rm -f "$LOCK_FILE"，内核会在持有进程退出后自动释放 flock
  exec 9>>"$LOCK_FILE"
  if flock -n 9; then
    : > "$LOCK_FILE"
    printf '%s\n' "$$" > "$LOCK_FILE"
  else
    local _pid=""
    _pid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
    red "已有其他实例运行中（PID: ${_pid:-未知}）"
    exit 1
  fi
}

detect_operational_config() {
  if ! sshd -t >/dev/null 2>&1; then
    red "❌ 错误：当前系统 OpenSSH 原生语法校验已处于损坏状态，请先修复后再换端！"
    exit 1
  fi
}

_sshd_config_has_dropin_include() {
  local cfg="${1:-$SSHD_CONFIG}"
  awk -v dir="$DROPIN_DIR" '
    BEGIN { IGNORECASE = 1; found = 0 }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^[[:space:]]*Match[[:space:]]/ { exit(found ? 0 : 1) }
    /^[[:space:]]*Include[[:space:]]+/ {
      for (i = 2; i <= NF; i++) {
        p = $i
        gsub(/^["'\'']|["'\'']$/, "", p)
        if (p == dir "/*.conf" || p == dir "/*" || p == "sshd_config.d/*.conf" || p == "sshd_config.d/*") {
          found = 1
          exit 0
        }
      }
    }
    END { exit(found ? 0 : 1) }
  ' "$cfg" 2>/dev/null
}

detect_include_port_conflicts() {
  local found_conflict=0
  local port_count=0 c=0 file=""

  c="$(grep -Eic '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_CONFIG" 2>/dev/null || true)"
  port_count=$((port_count + ${c:-0}))

  if [ -d "$DROPIN_DIR" ]; then
    while IFS= read -r -d '' file; do
      c="$(grep -Eic '^[[:space:]]*Port[[:space:]]+[0-9]+' "$file" 2>/dev/null || true)"
      port_count=$((port_count + ${c:-0}))
      if [ "$file" != "$DROPIN_FILE" ] && [ "${c:-0}" -gt 0 ]; then
        red "❌ 冲突：检测到外部 drop-in 配置文件残留硬编码 Port 定义，将引发监听失控："
        red "   $file"
        found_conflict=1
      fi
    done < <(find "$DROPIN_DIR" -type f -name '*.conf' -print0 2>/dev/null)
  fi

  local effective_ports="" eff_count=0
  effective_ports="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -u || true)"
  if [ -n "$effective_ports" ]; then
    eff_count="$(printf '%s\n' "$effective_ports" | awk 'NF{c++} END{print c+0}')"
    if [ "$eff_count" -gt 1 ]; then
      red "❌ 阻断：sshd -T 检测到当前生效配置存在多个监听端口（$(printf '%s' "$effective_ports" | tr '\n' ' ')），本工具不接管多端口环境。"
      found_conflict=1
    fi
  fi

  if [ "${port_count:-0}" -gt 1 ]; then
    red "❌ 阻断：检测到当前系统配置中存在多个 Port 定义（共 ${port_count} 个），本工具不接管多端口环境，请先统一至单端口后再运行。"
    found_conflict=1
  fi

  if [ "$found_conflict" -eq 1 ]; then
    yellow "💡 提示：请先将系统 SSH 端口统一为单一端口（清理多余的 Port 定义），再运行本工具。"
    exit 1
  fi
}

# ── SSH 服务检测与平滑重载架构 ───────────────────────────────────────────────
_systemd_prop() {
  local prop="$1" unit="$2" out=""
  out="$(systemctl show -p "$prop" "$unit" 2>/dev/null || true)"
  out="${out%%$'\n'*}"
  case "$out" in
    "${prop}="*) printf '%s\n' "${out#*=}" ;;
    *)           return 1 ;;
  esac
}

ssh_service() {
  local cand="" load_state="" canonical_id="" svc_name="" dir=""

  if have systemctl; then
    for cand in ssh.service sshd.service; do
      if systemctl is-active --quiet "$cand" 2>/dev/null; then
        canonical_id="$(_systemd_prop Id "$cand" || true)"
        svc_name="${canonical_id%.service}"
        if [ -n "$svc_name" ]; then
          printf '%s\n' "$svc_name"
          return 0
        fi
        printf '%s\n' "${cand%.service}"
        return 0
      fi
    done

    for cand in ssh.service sshd.service; do
      load_state="$(_systemd_prop LoadState "$cand" || true)"
      if [ "$load_state" = "loaded" ]; then
        canonical_id="$(_systemd_prop Id "$cand" || true)"
        svc_name="${canonical_id%.service}"
        if [ -n "$svc_name" ]; then
          printf '%s\n' "$svc_name"
          return 0
        fi
        printf '%s\n' "${cand%.service}"
        return 0
      fi
    done

    for dir in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
      if [ -f "$dir/ssh.service" ] && [ ! -L "$dir/ssh.service" ]; then
        printf '%s\n' "ssh"
        return 0
      fi
      if [ -f "$dir/sshd.service" ] && [ ! -L "$dir/sshd.service" ]; then
        printf '%s\n' "sshd"
        return 0
      fi
    done
  fi

  if [ -x /etc/init.d/ssh ]; then
    printf '%s\n' "ssh"
  elif [ -x /etc/init.d/sshd ]; then
    printf '%s\n' "sshd"
  else
    printf '%s\n' "ssh"
  fi
}

restart_ssh_engine() {
  local svc
  svc="$(ssh_service)"

  if have systemctl; then
    if [ "${SOCKET_MODE:-0}" = "1" ] || systemctl is-active --quiet ssh.socket 2>/dev/null; then
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl reset-failed ssh.socket >/dev/null 2>&1 || true
      systemctl reset-failed "$svc" >/dev/null 2>&1 || true
      # 仅在 KillMode=process（不中断已建立用户会话）时先释放主监听 daemon 的旧 socket fd，防止 EADDRINUSE
      local _km=""
      _km="$(_systemd_prop KillMode "${svc}.service" || true)"
      if [ "$_km" = "process" ] && systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
        systemctl stop "${svc}.service" >/dev/null 2>&1 || true
      fi
      if systemctl restart ssh.socket >/dev/null 2>&1; then
        return 0
      fi
      # 兜底尝试直接启动 ssh.socket
      systemctl start ssh.socket >/dev/null 2>&1 && return 0
      return 1
    fi

    systemctl reload "$svc" >/dev/null 2>&1 && return 0
    systemctl reload sshd >/dev/null 2>&1 && return 0
    systemctl reload ssh >/dev/null 2>&1 && return 0

    systemctl reset-failed "$svc" >/dev/null 2>&1 || true
    systemctl reset-failed sshd   >/dev/null 2>&1 || true
    systemctl reset-failed ssh    >/dev/null 2>&1 || true

    systemctl restart "$svc" >/dev/null 2>&1 && return 0
    systemctl restart sshd   >/dev/null 2>&1 && return 0
    systemctl restart ssh    >/dev/null 2>&1 && return 0
  else
    service "$svc" reload >/dev/null 2>&1 && return 0
    service sshd reload >/dev/null 2>&1 && return 0
    service ssh reload >/dev/null 2>&1 && return 0

    service "$svc" restart >/dev/null 2>&1 && return 0
    service sshd restart   >/dev/null 2>&1 && return 0
    service ssh restart    >/dev/null 2>&1 && return 0
  fi
  return 1
}

# ── 端口检测 ──────────────────────────────────────────────────────────────────
port_in_use() {
  local p="$1"
  local checked=0
  if have ss; then
    checked=1
    ss -H -lnt 2>/dev/null | awk -v p="$p" '{n=split($4,a,":"); if(a[n]==p){f=1;exit}} END{exit(f?0:1)}' && return 0 || true
  fi
  if have netstat; then
    checked=1
    netstat -lnt 2>/dev/null | awk -v p="$p" '{n=split($4,a,":"); if(a[n]==p){f=1;exit}} END{exit(f?0:1)}' && return 0 || true
  fi
  local hex_port
  hex_port="$(printf '%04X' "$p")"
  if [ -r /proc/net/tcp ] || [ -r /proc/net/tcp6 ]; then
    checked=1
    awk -v hp="$hex_port" 'NR>1 && $4=="0A" {split($2,a,":"); if(a[2]==hp){found=1;exit}} END {exit(found ? 0 : 1)}' /proc/net/tcp /proc/net/tcp6 2>/dev/null && return 0 || true
  fi
  [ "$checked" -eq 1 ] && return 1
  return 2
}

_is_ssh_socket_active() {
  have systemctl && systemctl is-active --quiet ssh.socket 2>/dev/null
}

is_listening_ssh() {
  local p="$1"
  local allow_systemd=0
  _is_ssh_socket_active && allow_systemd=1 || true

  if have ss; then
    local ss_out=""
    ss_out="$(ss -H -lntp 2>/dev/null || true)"
    awk -v p="$p" -v sd="$allow_systemd" '
      {
        is_ssh = ($0 ~ /users:\(\ (("sshd"|"sshd-session"|sshd|sshd-session),/)
        is_sd1 = (sd == 1 && $0 ~ /users:\(\ (("systemd"|systemd),pid=1,/)
        if (is_ssh || is_sd1) {
          n = split($4, a, ":")
          if (a[n] == p) { f = 1; exit }
        }
      }
      END { exit(f ? 0 : 1) }
    ' <<<"$ss_out"
  elif have netstat; then
    local ns_out=""
    ns_out="$(netstat -lntp 2>/dev/null || true)"
    awk -v p="$p" -v sd="$allow_systemd" '
      {
        prog = $NF
        is_ssh = (prog ~ /^[0-9]+\/(sshd|sshd-session)$/)
        is_sd1 = (sd == 1 && prog == "1/systemd")
        if (is_ssh || is_sd1) {
          n = split($4, a, ":")
          if (a[n] == p) { f = 1; exit }
        }
      }
      END { exit(f ? 0 : 1) }
    ' <<<"$ns_out"
  else
    local hex_port
    hex_port="$(printf '%04X' "$p")"
    awk -v hp="$hex_port" 'NR>1 && $4=="0A" {split($2,a,":"); if(a[2]==hp){found=1;exit}} END {exit(found ? 0 : 1)}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
  fi
}

wait_for_ssh_port() {
  local p="$1" max_tries="${2:-12}" i=0
  while [ "$i" -lt "$max_tries" ]; do
    if is_listening_ssh "$p"; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
}

wait_for_ssh_port_closed() {
  local p="$1" max_tries="${2:-12}" i=0
  while [ "$i" -lt "$max_tries" ]; do
    if ! is_listening_ssh "$p"; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  return 1
}

current_ssh_port() {
  local p=""
  # 优先读取当前会话端口，但须通过实时监听复核（防 tmux/screen 复用旧会话环境变量）
  if [ -n "${SSH_CONNECTION:-}" ]; then
    p="$(printf '%s\n' "$SSH_CONNECTION" | awk '{print $4}')"
    if [[ "$p" =~ ^[0-9]+$ ]] && is_listening_ssh "$p"; then
      printf '%s\n' "$p"
      return 0
    fi
  fi
  if [ -n "${SSH_CLIENT:-}" ]; then
    p="$(printf '%s\n' "$SSH_CLIENT" | awk '{print $3}')"
    if [[ "$p" =~ ^[0-9]+$ ]] && is_listening_ssh "$p"; then
      printf '%s\n' "$p"
      return 0
    fi
  fi

  # 若运行于 ssh.socket 模式，直接从 systemd 单元 Listen 属性精准提取 SSH 监听端口
  if _is_ssh_socket_active; then
    local listen_out=""
    listen_out="$(systemctl show -p Listen ssh.socket 2>/dev/null || true)"
    p="$(awk '
      /^Listen=/ {
        sub(/^Listen=/, "")
        sub(/[[:space:]].*$/, "")
        n = split($0, a, ":")
        if (a[n] ~ /^[0-9]+$/) {
          v = a[n] + 0
          if (min == 0 || v < min) min = v
        }
      }
      END { if (min > 0) print min }
    ' <<<"$listen_out")"
    if [[ "$p" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$p"
      return 0
    fi
  fi

  local _p=""
  if have ss; then
    local ss_out=""
    ss_out="$(ss -H -lntp 2>/dev/null || true)"
    _p="$(awk '
      /users:\(\ (("sshd"|"sshd-session"|sshd|sshd-session),/ {
        n = split($4, a, ":")
        if (a[n] ~ /^[0-9]+$/) {
          v = a[n] + 0
          if (min == 0 || v < min) min = v
        }
      }
      END { if (min > 0) print min }
    ' <<<"$ss_out")"
  elif have netstat; then
    local ns_out=""
    ns_out="$(netstat -lntp 2>/dev/null || true)"
    _p="$(awk '
      $NF ~ /^[0-9]+\/(sshd|sshd-session)$/ {
        n = split($4, a, ":")
        if (a[n] ~ /^[0-9]+$/) {
          v = a[n] + 0
          if (min == 0 || v < min) min = v
        }
      }
      END { if (min > 0) print min }
    ' <<<"$ns_out")"
  fi

  if [[ "${_p:-}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$_p"
    return 0
  fi

  # 兜底：通过 sshd -T 解析当前配置端口
  local sshd_t_out=""
  sshd_t_out="$(sshd -T 2>/dev/null || true)"
  _p="$(awk '$1 == "port" && $2 ~ /^[0-9]+$/ { print $2; exit }' <<<"$sshd_t_out")"
  if [[ "${_p:-}" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$_p"
    return 0
  fi
  return 1
}

# ── 防火墙策略管理 ────────────────────────────────────────────────────────────
_ufw_is_active() {
  have ufw || return 1
  local _st=""
  _st="$(LC_ALL=C ufw status 2>/dev/null || true)"
  case "$_st" in
    "Status: active"|"Status: active"$'\n'*) return 0 ;;
    *) return 1 ;;
  esac
}

_selinux_has_ssh_port() {
  local p="$1" out=""
  have semanage || return 1
  out="$(LC_ALL=C semanage port -l 2>/dev/null || true)"
  awk -v p="$p" '
    $1 == "ssh_port_t" && $2 == "tcp" {
      for (i = 3; i <= NF; i++) {
        gsub(/,/, "", $i)
        if ($i == p) {
          found = 1
        } else if ($i ~ /^[0-9]+-[0-9]+$/) {
          split($i, r, "-")
          if (p + 0 >= r[1] + 0 && p + 0 <= r[2] + 0) found = 1
        }
      }
    }
    END { exit(found ? 0 : 1) }
  ' <<<"$out"
}

_nft_find_handles() {
  local p="$1" chain_out=""
  chain_out="$(nft -n -a list chain inet filter input 2>/dev/null || true)"
  [ -n "$chain_out" ] || return 0
  awk -v p="$p" '
    index($0, "linus-ssh-safeswitch") > 0 {
      matched = 0
      for (i = 1; i <= NF - 2; i++) {
        if ($i == "tcp" && $(i + 1) == "dport" && $(i + 2) == p) {
          matched = 1
          break
        }
      }
      if (matched) {
        for (j = 1; j <= NF - 1; j++) {
          if ($j == "handle" && $(j + 1) ~ /^[0-9]+$/) {
            print $(j + 1)
          }
        }
      }
    }
  ' <<<"$chain_out"
}

_persist_nftables() {
  local back="${1:-}"
  local conf="/etc/nftables.conf"
  if [ ! -f "$conf" ]; then
    yellow "⚠️  [防火墙] 未检测到 ${conf}，nftables 规则当前仅在内存中生效，重启前请手动持久化。"
    log "firewall: warn nftables persistence skipped (${conf} missing)"
    return 0
  fi
  if have systemctl && ! systemctl is-enabled --quiet nftables.service 2>/dev/null; then
    yellow "⚠️  [防火墙] nftables.service 未启用开机自启，跳过覆写 ${conf}，请确认重启后的持久化方式。"
    log "firewall: warn nftables persistence skipped (service not enabled)"
    return 0
  fi
  local tables_out=""
  tables_out="$(nft list tables 2>/dev/null || true)"
  if grep -Eiq '(fail2ban|f2b|docker)' <<<"$tables_out"; then
    yellow "⚠️  [防火墙] 检测到动态表（fail2ban/docker），为避免污染 ${conf} 未自动覆盖，请手动确认 ${conf} 已放行新 SSH 端口。"
    log "firewall: warn nftables persistence skipped (dynamic tables detected)"
    return 0
  fi
  if [ -n "$back" ] && [ -d "$back" ] && [ ! -f "$back/nftables.conf.bak" ]; then
    cp -a "$conf" "$back/nftables.conf.bak" 2>/dev/null || true
  fi
  local tmp_nft=""
  tmp_nft="$(mktemp /tmp/linus-nft.XXXXXX.conf)"
  {
    printf '%s\n' '#!/usr/sbin/nft -f'
    printf '%s\n' 'flush ruleset'
    nft list ruleset 2>/dev/null
  } > "$tmp_nft" || {
    rm -f "$tmp_nft"
    yellow "⚠️  [防火墙] 导出 nftables 规则集失败，原 ${conf} 未改动。"
    log "firewall: warn nftables export failed"
    return 0
  }
  if nft -c -f "$tmp_nft" >/dev/null 2>&1; then
    chmod --reference="$conf" "$tmp_nft" 2>/dev/null || chmod 755 "$tmp_nft" 2>/dev/null || true
    mv -f "$tmp_nft" "$conf"
    log "firewall: persisted nftables ruleset to ${conf}"
  else
    rm -f "$tmp_nft"
    yellow "⚠️  [防火墙] nftables 持久化预检（nft -c -f）未通过，已保留原 ${conf}，请手动检查持久化配置。"
    log "firewall: warn nft -c -f failed for ${conf}"
  fi
}

_iptables_open_bin() {
  local bin="$1" p="$2"
  if "$bin" -C INPUT -p tcp --dport "$p" -m comment --comment "linus-ssh-safeswitch" -j ACCEPT >/dev/null 2>&1; then
    return 0
  fi
  if "$bin" -I INPUT -p tcp --dport "$p" -m comment --comment "linus-ssh-safeswitch" -j ACCEPT >/dev/null 2>&1; then
    return 0
  fi
  if "$bin" -C INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1; then
    return 0
  fi
  "$bin" -I INPUT -p tcp --dport "$p" -j ACCEPT >/dev/null 2>&1
}

_iptables_close_bin() {
  local bin="$1" p="$2" removed=0 guard=0
  while [ "$guard" -lt 16 ] && "$bin" -D INPUT -p tcp --dport "$p" -m comment --comment "linus-ssh-safeswitch" -j ACCEPT >/dev/null 2>&1; do
    removed=$((removed + 1))
    guard=$((guard + 1))
  done
  printf '%s\n' "$removed"
  return 0
}

_persist_iptables() {
  if have netfilter-persistent; then
    if netfilter-persistent save >/dev/null 2>&1; then
      log "firewall: persisted iptables/ip6tables via netfilter-persistent"
      return 0
    fi
  fi
  local saved=0 tmp_rule=""
  if [ -d /etc/iptables ] && have iptables-save; then
    tmp_rule="$(mktemp /tmp/linus-ipt4.XXXXXX)"
    if iptables-save > "$tmp_rule" 2>/dev/null; then
      mv -f "$tmp_rule" /etc/iptables/rules.v4 && saved=1
    else
      rm -f "$tmp_rule"
    fi
    if [ -f /etc/iptables/rules.v6 ] && have ip6tables-save; then
      tmp_rule="$(mktemp /tmp/linus-ipt6.XXXXXX)"
      if ip6tables-save > "$tmp_rule" 2>/dev/null; then
        mv -f "$tmp_rule" /etc/iptables/rules.v6 || true
      else
        rm -f "$tmp_rule"
      fi
    fi
  elif [ -f /etc/sysconfig/iptables ] && have iptables-save; then
    tmp_rule="$(mktemp /tmp/linus-ipt4.XXXXXX)"
    if iptables-save > "$tmp_rule" 2>/dev/null; then
      mv -f "$tmp_rule" /etc/sysconfig/iptables && saved=1
    else
      rm -f "$tmp_rule"
    fi
    if [ -f /etc/sysconfig/ip6tables ] && have ip6tables-save; then
      tmp_rule="$(mktemp /tmp/linus-ipt6.XXXXXX)"
      if ip6tables-save > "$tmp_rule" 2>/dev/null; then
        mv -f "$tmp_rule" /etc/sysconfig/ip6tables || true
      else
        rm -f "$tmp_rule"
      fi
    fi
  fi
  if [ "$saved" -eq 1 ]; then
    log "firewall: persisted iptables/ip6tables rules to disk"
  else
    yellow "⚠️  [防火墙] 未检测到 netfilter-persistent 或持久化规则文件，iptables 规则当前仅在内存中生效（若默认策略为 DROP，重启前请务必持久化规则）。"
    log "firewall: warn iptables applied in-memory only (no persistence backend)"
  fi
}

open_port() {
  local p="$1" back="${2:-}"
  if have semanage; then
    if ! _selinux_has_ssh_port "$p"; then
      if semanage port -a -t ssh_port_t -p tcp "$p" >/dev/null 2>&1 || semanage port -m -t ssh_port_t -p tcp "$p" >/dev/null 2>&1; then
        [ -n "$back" ] && [ -d "$back" ] && echo "$p" >> "$back/selinux_added"
        log "firewall: selinux added ssh_port_t tcp/${p}"
      else
        yellow "⚠️  [SELinux] 为 TCP/${p} 添加 ssh_port_t 上下文失败，请检查 SELinux 策略。"
        log "firewall: warn selinux add ssh_port_t tcp/${p} failed"
      fi
    fi
  fi

  if _ufw_is_active; then
    if ufw allow "${p}/tcp" >/dev/null 2>&1; then
      cyan "🛡️  [内层防火墙] 已通过 UFW 放行 TCP/${p}"
      log "firewall: ufw allow ${p}/tcp"
    else
      yellow "⚠️  [内层防火墙] UFW 放行 TCP/${p} 失败，请手动检查 ufw status。"
      log "firewall: warn ufw allow ${p}/tcp failed"
    fi
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    if firewall-cmd --permanent --add-port="${p}/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1; then
      cyan "🛡️  [内层防火墙] 已通过 firewalld 永久放行 TCP/${p}"
      log "firewall: firewalld add ${p}/tcp"
    else
      yellow "⚠️  [内层防火墙] firewalld 放行 TCP/${p} 失败，请手动检查 firewall-cmd。"
      log "firewall: warn firewalld add ${p}/tcp failed"
    fi
  elif have nft && nft list chain inet filter input >/dev/null 2>&1; then
    if [ -z "$(_nft_find_handles "$p")" ]; then
      if nft insert rule inet filter input tcp dport "$p" accept comment '"linus-ssh-safeswitch"' >/dev/null 2>&1; then
        cyan "🛡️  [内层防火墙] 已通过 nftables（链首插入）放行 TCP/${p}"
        log "firewall: nft insert inet filter input tcp dport ${p}"
      else
        yellow "⚠️  [内层防火墙] nftables 插入 TCP/${p} 规则失败，请手动检查 inet filter input 链。"
        log "firewall: warn nft insert tcp dport ${p} failed"
      fi
    else
      log "firewall: nft rule for tcp/${p} already exists"
    fi
    _persist_nftables "$back"
  elif have iptables; then
    local v4_ok=0 v6_msg=""
    if _iptables_open_bin iptables "$p"; then
      v4_ok=1
    else
      yellow "⚠️  [内层防火墙] iptables 放行 TCP/${p} 失败，请手动检查规则。"
      log "firewall: warn iptables open ${p} failed"
    fi
    if have ip6tables && [ -r /proc/net/if_inet6 ]; then
      if _iptables_open_bin ip6tables "$p"; then
        v6_msg=" + ip6tables"
      else
        yellow "⚠️  [内层防火墙] ip6tables（IPv6）放行 TCP/${p} 失败，请检查 IPv6 防火墙。"
        log "firewall: warn ip6tables open ${p} failed"
      fi
    fi
    if [ "$v4_ok" -eq 1 ]; then
      cyan "🛡️  [内层防火墙] 已通过 iptables${v6_msg} 放行 TCP/${p}"
      log "firewall: iptables${v6_msg} allow tcp/${p}"
    fi
    _persist_iptables
  else
    log "firewall: no active host firewall detected for open ${p}"
  fi
}

close_port() {
  local p="$1" back="${2:-}"
  if have semanage; then
    if [ -n "$back" ] && [ -f "$back/selinux_added" ] && grep -qx "$p" "$back/selinux_added" >/dev/null 2>&1; then
      if semanage port -d -t ssh_port_t -p tcp "$p" >/dev/null 2>&1; then
        log "firewall: selinux removed ssh_port_t tcp/${p}"
      else
        log "firewall: warn selinux remove ssh_port_t tcp/${p} failed"
      fi
    fi
  fi

  if _ufw_is_active; then
    if ufw delete allow "${p}/tcp" >/dev/null 2>&1; then
      log "firewall: ufw delete allow ${p}/tcp"
    else
      log "firewall: ufw delete allow ${p}/tcp skipped or not found"
    fi
    if [ "$p" = "22" ]; then
      local _ufw_post=""
      _ufw_post="$(LC_ALL=C ufw status 2>/dev/null || true)"
      if grep -Eq '^[[:space:]]*OpenSSH([[:space:]]|\(v6\)|$)' <<<"$_ufw_post"; then
        yellow "⚠️  [内层防火墙] 检测到 UFW 中仍存在 OpenSSH 应用规则（放行 22 端口），如需彻底关闭请手动执行：ufw delete allow OpenSSH"
        log "firewall: warn ufw OpenSSH profile still active after closing 22/tcp"
      fi
    fi
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --remove-port="${p}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    log "firewall: firewalld removed ${p}/tcp"
  elif have nft && nft list chain inet filter input >/dev/null 2>&1; then
    local handles="" h="" deleted=0
    handles="$(_nft_find_handles "$p")"
    if [ -n "$handles" ]; then
      while IFS= read -r h; do
        if [ -n "$h" ] && nft delete rule inet filter input handle "$h" >/dev/null 2>&1; then
          deleted=$((deleted + 1))
        fi
      done <<<"$handles"
      log "firewall: nft deleted ${deleted} rule(s) for tcp/${p}"
      _persist_nftables "$back"
    else
      log "firewall: nft no managed rule found for tcp/${p}"
    fi
  elif have iptables; then
    local total_removed=0 r4=0 r6=0
    r4="$(_iptables_close_bin iptables "$p")"
    total_removed=$((total_removed + ${r4:-0}))
    if have ip6tables && [ -r /proc/net/if_inet6 ]; then
      r6="$(_iptables_close_bin ip6tables "$p")"
      total_removed=$((total_removed + ${r6:-0}))
    fi
    if [ "$total_removed" -gt 0 ]; then
      log "firewall: iptables/ip6tables removed ${total_removed} managed rule(s) for tcp/${p}"
      _persist_iptables
    else
      log "firewall: iptables/ip6tables no managed rule found for tcp/${p}"
    fi
  fi
}

write_dropin_ports() {
  local back="$1"
  shift
  local target_ports=("$@")
  local final_tmp="" tmp_main="" p=""

  mkdir -p "$DROPIN_DIR"
  final_tmp="$(mktemp /tmp/linus-ssh-safeswitch.XXXXXX.conf)"

  {
    printf '%s\n' "# BEGIN LINUS-SSH-SAFESWITCH"
    printf '%s\n' "# 统一独立托管配置文件，请勿手动污染修改本文件"
    for p in "${target_ports[@]}"; do printf 'Port %s\n' "$p"; done
    printf '%s\n' "# END LINUS-SSH-SAFESWITCH"
  } > "$final_tmp" || {
    red "❌ 错误：写入临时配置失败。"
    rm -f "$final_tmp"
    return 1
  }

  # 预检：将 Include 置顶（严格位于任何 Match 块之前），同时屏蔽原 Port 模拟真实生效态
  tmp_main="$(mktemp /tmp/linus-ssh-safeswitch-main.XXXXXX.conf)"
  {
    printf 'Include %s\n' "$final_tmp"
    sed -E 's/^([[:space:]]*Port[[:space:]]+[0-9]+)/# safeswitch-preview: \1/Ig' "$SSHD_CONFIG" \
      | grep -Eiv '^[[:space:]]*Include[[:space:]]' || true
  } > "$tmp_main"

  if ! sshd -t -f "$tmp_main" >/dev/null 2>&1; then
    red "❌ 错误：sshd 预检失败（当前 OpenSSH 可能不支持 Include 或配置存在冲突）。"
    rm -f "$final_tmp" "$tmp_main"
    return 1
  fi
  rm -f "$tmp_main"

  # 保留主配置修改前快照，便于本函数内即时回退
  if [ ! -f "$back/sshd_config.pre_safeswitch" ]; then
    cp -a "$SSHD_CONFIG" "$back/sshd_config.pre_safeswitch" >/dev/null 2>&1 || true
  fi

  mv -f "$final_tmp" "$DROPIN_FILE" || { rm -f "$final_tmp"; return 1; }
  chmod 644 "$DROPIN_FILE"
  echo "1" > "$back/created_dropin"

  # 确保主配置文件顶部（首个 Match 块之前）存在有效的 Include /etc/ssh/sshd_config.d/*.conf
  if ! _sshd_config_has_dropin_include "$SSHD_CONFIG"; then
    local tmp_inc=""
    tmp_inc="$(mktemp /tmp/linus-ssh-inc.XXXXXX.conf)"
    {
      printf 'Include %s/*.conf\n' "$DROPIN_DIR"
      cat "$SSHD_CONFIG"
    } > "$tmp_inc" || {
      rm -f "$tmp_inc" "$DROPIN_FILE"
      return 1
    }
    chmod --reference="$SSHD_CONFIG" "$tmp_inc" 2>/dev/null || chmod 644 "$tmp_inc" 2>/dev/null || true
    mv -f "$tmp_inc" "$SSHD_CONFIG" || {
      rm -f "$tmp_inc" "$DROPIN_FILE"
      return 1
    }
    echo "1" > "$back/modified_main"
    log "config: prepended Include ${DROPIN_DIR}/*.conf to ${SSHD_CONFIG}"
  fi

  if grep -Eiq '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_CONFIG" 2>/dev/null; then
    sed -i -E 's/^([[:space:]]*Port[[:space:]]+[0-9]+)/# safeswitch-migrated: \1/Ig' "$SSHD_CONFIG" || {
      [ -f "$back/sshd_config.pre_safeswitch" ] && cp -a "$back/sshd_config.pre_safeswitch" "$SSHD_CONFIG" >/dev/null 2>&1 || true
      rm -f "$DROPIN_FILE"
      return 1
    }
    echo "1" > "$back/modified_main"
  fi

  have restorecon && restorecon -RF /etc/ssh >/dev/null 2>&1 || true

  # 落盘后对真实系统配置执行最终 sshd -t 校验
  if ! sshd -t >/dev/null 2>&1; then
    red "❌ 错误：落盘后的真实 sshd -t 语法终检失败！"
    [ -f "$back/sshd_config.pre_safeswitch" ] && cp -a "$back/sshd_config.pre_safeswitch" "$SSHD_CONFIG" >/dev/null 2>&1 || true
    rm -f "$DROPIN_FILE"
    return 1
  fi

  # 校验 sshd -T 实际解析生效的端口集合是否完全匹配目标端口
  local eff_sorted="" exp_sorted=""
  eff_sorted="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -un || true)"
  exp_sorted="$(printf '%s\n' "${target_ports[@]}" | sort -un)"
  if [ -n "$eff_sorted" ] && [ "$eff_sorted" != "$exp_sorted" ]; then
    red "❌ 错误：sshd -T 生效端口校验不匹配（期望: $(printf '%s' "$exp_sorted" | tr '\n' ' ')，实际: $(printf '%s' "$eff_sorted" | tr '\n' ' ')）。"
    [ -f "$back/sshd_config.pre_safeswitch" ] && cp -a "$back/sshd_config.pre_safeswitch" "$SSHD_CONFIG" >/dev/null 2>&1 || true
    rm -f "$DROPIN_FILE"
    return 1
  fi
}

write_socket_ports() {
  local back="$1"
  shift
  local target_ports=("$@")
  local tmp_sock="" p=""

  mkdir -p "$SOCKET_DROPIN_DIR"
  tmp_sock="$(mktemp /tmp/linus-ssh-socket.XXXXXX.conf)"
  {
    printf '%s\n' "# BEGIN LINUS-SSH-SAFESWITCH"
    printf '%s\n' "# 统一独立托管 ssh.socket 监听配置，请勿手动污染修改本文件"
    printf '%s\n' "[Socket]"
    printf '%s\n' "ListenStream="
    for p in "${target_ports[@]}"; do
      printf 'ListenStream=%s\n' "$p"
    done
    printf '%s\n' "# END LINUS-SSH-SAFESWITCH"
  } > "$tmp_sock" || {
    red "❌ 错误：写入 ssh.socket 临时配置失败。"
    rm -f "$tmp_sock"
    return 1
  }

  mv -f "$tmp_sock" "$SOCKET_DROPIN_FILE" || { rm -f "$tmp_sock"; return 1; }
  chmod 644 "$SOCKET_DROPIN_FILE"
  echo "1" > "$back/created_socket_dropin"
  have restorecon && restorecon -RF "$SOCKET_DROPIN_DIR" >/dev/null 2>&1 || true
  log "config: updated ${SOCKET_DROPIN_FILE} ports=(${target_ports[*]})"
}

apply_ssh_ports() {
  local back="$1"
  shift
  write_dropin_ports "$back" "$@" || return 1
  if [ "${SOCKET_MODE:-0}" = "1" ]; then
    write_socket_ports "$back" "$@" || return 1
  fi
}

# ── 备份与持久化断电回滚机制 ──────────────────────────────────────────────────
backup_config() {
  local back="$1"
  mkdir -p "$back"
  tar czf "$back/ssh_full_backup.tgz" -C / etc/ssh >/dev/null 2>&1 || return 1
  chmod 600 "$back/ssh_full_backup.tgz" 2>/dev/null || true
  if [ -d "$SOCKET_DROPIN_DIR" ]; then
    tar czf "$back/ssh_socket_d_backup.tgz" -C / "${SOCKET_DROPIN_DIR#/}" >/dev/null 2>&1 || return 1
    chmod 600 "$back/ssh_socket_d_backup.tgz" 2>/dev/null || true
  fi
}

restore_config() {
  local back="$1"
  tar xzf "$back/ssh_full_backup.tgz" -C / >/dev/null 2>&1 || return 1
  if [ -f "$back/created_socket_dropin" ]; then
    rm -f "$SOCKET_DROPIN_FILE" 2>/dev/null || true
  fi
  if [ -f "$back/ssh_socket_d_backup.tgz" ]; then
    tar xzf "$back/ssh_socket_d_backup.tgz" -C / >/dev/null 2>&1 || return 1
  fi
  if [ -d "$SOCKET_DROPIN_DIR" ]; then
    rmdir "$SOCKET_DROPIN_DIR" 2>/dev/null || true
  fi
}

generate_rollback_script() {
  local back="$1"
  cat > "$back/emergency_rollback.sh" <<EOF
#!/usr/bin/env bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
if command -v flock >/dev/null 2>&1; then
  exec 8>>"${ROLLBACK_LOCK_FILE}"
  flock -w 30 8 || exit 1
fi
[ -f "${back}/pending" ] || exit 0

_reason="\${1:-reboot}"
echo "[\$(date '+%F %T')] [watchdog] \${_reason} rollback start" >> "${LOG_FILE}"

if [ -f "${back}/created_dropin" ]; then
  rm -f "${DROPIN_FILE}" 2>/dev/null || true
fi

if [ -f "${back}/created_socket_dropin" ]; then
  rm -f "${SOCKET_DROPIN_FILE}" 2>/dev/null || true
fi

if [ -f "${back}/ssh_full_backup.tgz" ]; then
  tar xzf "${back}/ssh_full_backup.tgz" -C / >/dev/null 2>&1 || exit 1
fi

if [ -f "${back}/ssh_socket_d_backup.tgz" ]; then
  tar xzf "${back}/ssh_socket_d_backup.tgz" -C / >/dev/null 2>&1 || true
fi
if [ -d "${SOCKET_DROPIN_DIR}" ]; then
  rmdir "${SOCKET_DROPIN_DIR}" 2>/dev/null || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl reset-failed sshd >/dev/null 2>&1 || true
  systemctl reset-failed ssh >/dev/null 2>&1 || true
  systemctl reset-failed ssh.socket >/dev/null 2>&1 || true
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
command -v restorecon >/dev/null 2>&1 && restorecon -RF /etc/ssh >/dev/null 2>&1 || true
[ -d "${SOCKET_DROPIN_DIR}" ] && command -v restorecon >/dev/null 2>&1 && restorecon -RF "${SOCKET_DROPIN_DIR}" >/dev/null 2>&1 || true

if command -v sshd >/dev/null 2>&1; then
  if sshd -t >/dev/null 2>&1; then
    if command -v systemctl >/dev/null 2>&1; then
      _svc=""
      for _cand in ssh.service sshd.service; do
        _load="\$(systemctl show -p LoadState "\$_cand" 2>/dev/null || true)"
        case "\$_load" in
          LoadState=loaded*)
            _id="\$(systemctl show -p Id "\$_cand" 2>/dev/null || true)"
            case "\$_id" in
              Id=*) _svc="\${_id#Id=}"; _svc="\${_svc%.service}" ;;
            esac
            [ -n "\$_svc" ] && break
            ;;
        esac
      done
      _svc="\${_svc:-sshd}"
      if [ -f "${back}/socket_mode" ] || systemctl is-active --quiet ssh.socket 2>/dev/null; then
        _km="\$(systemctl show -p KillMode "\${_svc}.service" 2>/dev/null || true)"
        if [ "\$_km" = "KillMode=process" ] && systemctl is-active --quiet "\${_svc}.service" 2>/dev/null; then
          systemctl stop "\${_svc}.service" >/dev/null 2>&1 || true
        fi
        systemctl restart ssh.socket >/dev/null 2>&1 || systemctl start ssh.socket >/dev/null 2>&1 || true
      else
        systemctl reload "\$_svc" >/dev/null 2>&1 || systemctl restart "\$_svc" >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || true
      fi
    else
      service sshd reload >/dev/null 2>&1 || service sshd restart >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || service ssh restart >/dev/null 2>&1 || true
    fi
  else
    echo "[\$(date '+%F %T')] [watchdog] ERROR: sshd -t validation failed after restore! Aborting restart to keep existing memory process." >> "${LOG_FILE}"
  fi
fi

if [ -f "${back}/new_port" ]; then
  _np="\$(cat "${back}/new_port" 2>/dev/null || true)"
  if [ -n "\$_np" ]; then
    if [ -f "${back}/selinux_added" ] && grep -qx "\$_np" "${back}/selinux_added" >/dev/null 2>&1; then
      command -v semanage >/dev/null 2>&1 && semanage port -d -t ssh_port_t -p tcp "\$_np" >/dev/null 2>&1 || true
    fi
    _ufw_st=""
    command -v ufw >/dev/null 2>&1 && _ufw_st="\$(LC_ALL=C ufw status 2>/dev/null || true)"
    case "\$_ufw_st" in
      "Status: active"|"Status: active"\$'\\n'*)
        ufw delete allow "\$_np/tcp" >/dev/null 2>&1 || true
        echo "[\$(date '+%F %T')] [watchdog] firewall ufw delete \${_np}/tcp" >> "${LOG_FILE}"
        ;;
      *)
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
          firewall-cmd --permanent --remove-port="\$_np/tcp" >/dev/null 2>&1 || true
          firewall-cmd --reload >/dev/null 2>&1 || true
          echo "[\$(date '+%F %T')] [watchdog] firewall firewalld remove \${_np}/tcp" >> "${LOG_FILE}"
        elif command -v nft >/dev/null 2>&1 && nft list chain inet filter input >/dev/null 2>&1; then
          _nft_out="\$(nft -n -a list chain inet filter input 2>/dev/null || true)"
          _nft_handles="\$(awk -v p="\$_np" '
            index(\$0, "linus-ssh-safeswitch") > 0 {
              m = 0
              for (i = 1; i <= NF - 2; i++) {
                if (\$i == "tcp" && \$(i + 1) == "dport" && \$(i + 2) == p) { m = 1; break }
              }
              if (m) {
                for (j = 1; j <= NF - 1; j++) {
                  if (\$j == "handle" && \$(j + 1) ~ /^[0-9]+$/) print \$(j + 1)
                }
              }
            }
          ' <<<"\${_nft_out}")"
          if [ -n "\$_nft_handles" ]; then
            while IFS= read -r _h; do
              [ -n "\$_h" ] && nft delete rule inet filter input handle "\$_h" >/dev/null 2>&1 || true
            done <<<"\${_nft_handles}"
          fi
          if [ -f "${back}/nftables.conf.bak" ] && [ -f /etc/nftables.conf ]; then
            cp -a "${back}/nftables.conf.bak" /etc/nftables.conf >/dev/null 2>&1 || true
          fi
          echo "[\$(date '+%F %T')] [watchdog] firewall nft cleanup tcp/\${_np}" >> "${LOG_FILE}"
        elif command -v iptables >/dev/null 2>&1; then
          _g=0
          while [ "\$_g" -lt 16 ] && iptables -D INPUT -p tcp --dport "\$_np" -m comment --comment "linus-ssh-safeswitch" -j ACCEPT >/dev/null 2>&1; do
            _g=\$((_g + 1))
          done
          if command -v ip6tables >/dev/null 2>&1 && [ -r /proc/net/if_inet6 ]; then
            _g=0
            while [ "\$_g" -lt 16 ] && ip6tables -D INPUT -p tcp --dport "\$_np" -m comment --comment "linus-ssh-safeswitch" -j ACCEPT >/dev/null 2>&1; do
              _g=\$((_g + 1))
            done
          fi
          if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
          elif [ -f /etc/iptables/rules.v4 ] && command -v iptables-save >/dev/null 2>&1; then
            _tr="\$(mktemp /tmp/linus-rb-ipt4.XXXXXX)"
            if iptables-save > "\$_tr" 2>/dev/null; then mv -f "\$_tr" /etc/iptables/rules.v4 || true; else rm -f "\$_tr"; fi
            if [ -f /etc/iptables/rules.v6 ] && command -v ip6tables-save >/dev/null 2>&1; then
              _tr="\$(mktemp /tmp/linus-rb-ipt6.XXXXXX)"
              if ip6tables-save > "\$_tr" 2>/dev/null; then mv -f "\$_tr" /etc/iptables/rules.v6 || true; else rm -f "\$_tr"; fi
            fi
          elif [ -f /etc/sysconfig/iptables ] && command -v iptables-save >/dev/null 2>&1; then
            _tr="\$(mktemp /tmp/linus-rb-ipt4.XXXXXX)"
            if iptables-save > "\$_tr" 2>/dev/null; then mv -f "\$_tr" /etc/sysconfig/iptables || true; else rm -f "\$_tr"; fi
            if [ -f /etc/sysconfig/ip6tables ] && command -v ip6tables-save >/dev/null 2>&1; then
              _tr="\$(mktemp /tmp/linus-rb-ipt6.XXXXXX)"
              if ip6tables-save > "\$_tr" 2>/dev/null; then mv -f "\$_tr" /etc/sysconfig/ip6tables || true; else rm -f "\$_tr"; fi
            fi
          fi
          echo "[\$(date '+%F %T')] [watchdog] firewall iptables/ip6tables cleanup tcp/\${_np}" >> "${LOG_FILE}"
        fi
        ;;
    esac
  fi
fi

rm -f "${back}/pending"

if command -v systemctl >/dev/null 2>&1; then
  systemctl disable linus-ssh-rollback.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/linus-ssh-rollback.service
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
if command -v crontab >/dev/null 2>&1; then
  _tmpcron="\$(mktemp /tmp/cron.XXXXXX)"
  crontab -l > "\$_tmpcron" 2>/dev/null || true
  if grep -q "linus-ssh-rollback" "\$_tmpcron" 2>/dev/null; then
    grep -v "linus-ssh-rollback" "\$_tmpcron" > "\${_tmpcron}.new" 2>/dev/null || true
    crontab "\${_tmpcron}.new" 2>/dev/null || true
  fi
  rm -f "\$_tmpcron" "\${_tmpcron}.new" 2>/dev/null || true
fi
rm -f "${back}/emergency_rollback.sh"
echo "[\$(date '+%F %T')] [watchdog] \${_reason} rollback done" >> "${LOG_FILE}"
EOF
  chmod 700 "$back/emergency_rollback.sh"
}

register_survival_watchdog() {
  local back="$1"
  generate_rollback_script "$back"

  if have systemctl; then
    cat > /etc/systemd/system/linus-ssh-rollback.service <<EOF
[Unit]
Description=Linus SSH SafeSwitch Emergency Rollback
After=network.target ssh.socket sshd.service ssh.service
[Service]
Type=oneshot
ExecStart=/bin/bash $back/emergency_rollback.sh reboot
[Install]
WantedBy=multi-user.target
EOF
    have restorecon && restorecon /etc/systemd/system/linus-ssh-rollback.service >/dev/null 2>&1 || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable linus-ssh-rollback.service >/dev/null 2>&1 || true
  elif have crontab; then
    local _tmpcron
    _tmpcron="$(mktemp /tmp/cron.XXXXXX)"
    crontab -l > "$_tmpcron" 2>/dev/null || true
    grep -v "linus-ssh-rollback" "$_tmpcron" > "${_tmpcron}.new" 2>/dev/null || true
    echo "@reboot /bin/bash $back/emergency_rollback.sh reboot # linus-ssh-rollback" >> "${_tmpcron}.new"
    crontab "${_tmpcron}.new" 2>/dev/null || true
    rm -f "$_tmpcron" "${_tmpcron}.new" 2>/dev/null || true
  fi
}

unregister_survival_watchdog() {
  if have systemctl; then
    systemctl disable linus-ssh-rollback.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/linus-ssh-rollback.service
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if have crontab; then
    local _tmpcron
    _tmpcron="$(mktemp /tmp/cron.XXXXXX)"
    crontab -l > "$_tmpcron" 2>/dev/null || true
    if grep -q "linus-ssh-rollback" "$_tmpcron" 2>/dev/null; then
      grep -v "linus-ssh-rollback" "$_tmpcron" > "${_tmpcron}.new" 2>/dev/null || true
      crontab "${_tmpcron}.new" 2>/dev/null || true
    fi
    rm -f "$_tmpcron" "${_tmpcron}.new" 2>/dev/null || true
  fi
}

async_watchdog_worker() {
  local back="$1" ts="$2"
  sleep "$ts" &
  local sleep_pid=$!
  trap 'kill "$sleep_pid" 2>/dev/null || true; exit 0' TERM INT
  wait "$sleep_pid" 2>/dev/null || true
  if [ -f "$back/pending" ] && [ -f "$back/emergency_rollback.sh" ]; then
    /bin/bash "$back/emergency_rollback.sh" "timeout"
  fi
}

start_watchdog() {
  local back="$1"
  register_survival_watchdog "$back"
  nohup bash -c "$(declare -f async_watchdog_worker); async_watchdog_worker \"\$1\" \"\$2\"" _ "$back" "$TIMEOUT_SEC" >/dev/null 2>&1 9>&- 8>&- &
  WATCHDOG_PID=$!
}

stop_watchdog() {
  if [ -n "${WATCHDOG_PID:-}" ]; then
    kill "$WATCHDOG_PID" >/dev/null 2>&1 || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
    WATCHDOG_PID=""
  fi
}

do_rollback() {
  local back="$1"
  local _rb_rc=0

  (
    if have flock; then
      exec 8>>"$ROLLBACK_LOCK_FILE"
      flock -w 30 8 || exit 1
    fi
    [ -f "$back/pending" ] || exit 0

    if [ -f "$back/created_dropin" ]; then rm -f "$DROPIN_FILE" 2>/dev/null || true; fi

    restore_config "$back" || exit 1

    if [ -f "$back/new_port" ]; then
      local np=""
      np="$(cat "$back/new_port" 2>/dev/null || true)"
      [ -n "$np" ] && close_port "$np" "$back"
    fi

    have restorecon && restorecon -RF /etc/ssh >/dev/null 2>&1 || true

    if ! sshd -t >/dev/null 2>&1; then
      echo "[$(date '+%F %T')] [on_exit] ERROR: sshd -t validation failed during emergency exit! Retaining memory status." >> "$LOG_FILE" 2>/dev/null || true
      exit 1
    fi

    restart_ssh_engine || exit 1
    rm -f "$back/pending"

    unregister_survival_watchdog
    rm -f "$back/emergency_rollback.sh" 2>/dev/null || true
  ) || _rb_rc=$?

  stop_watchdog
  return "$_rb_rc"
}

# ── EXIT & Signal traps ───────────────────────────────────────────────────────
on_signal() {
  local sig="$1" code="$2"
  [ -n "${ROLLBACK_REASON:-}" ] || ROLLBACK_REASON="收到信号 SIG${sig} 中断"
  exit "$code"
}

on_exit() {
  local rc=$?
  set +e
  trap - EXIT HUP TERM INT
  if [ "${_IN_ON_EXIT:-0}" = "1" ]; then
    exit "$rc"
  fi
  _IN_ON_EXIT="1"
  if [ "$NEED_ROLLBACK" = "1" ] && [ -n "$BACKUP_PATH" ] && [ -f "$BACKUP_PATH/pending" ]; then
    echo "[$(date '+%F %T')] [on_exit] 触发异常退出回滚(code:$rc) | 原因: ${ROLLBACK_REASON:-未知断开}" >> "$LOG_FILE" 2>/dev/null || true
    do_rollback "$BACKUP_PATH" >> "$LOG_FILE" 2>&1
  fi
  exit "$rc"
}

# ── Fail2ban 提示 ─────────────────────────────────────────────────────────────
_detect_f2b_actions() {
  if _ufw_is_active; then
    printf '%s\n' "ufw|ufw|"
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
    printf '%s\n' "firewallcmd-rich-rules|firewallcmd-rich-rules|"
  elif have nft && nft list chain inet filter input >/dev/null 2>&1; then
    printf '%s\n' "nftables-multiport|nftables-allports|"
  else
    printf '%s\n' "iptables-multiport|iptables-allports| iptables"
  fi
}

print_fail2ban_hint() {
  local hint_port="${1:-}"
  local target_port="22"
  if [[ "$hint_port" =~ ^[0-9]+$ ]]; then
    target_port="$hint_port"
  else
    target_port="$(current_ssh_port 2>/dev/null || echo '22')"
    [[ "$target_port" =~ ^[0-9]+$ ]] || target_port="22"
  fi

  local target_backend="auto"
  if have journalctl; then
    target_backend="systemd"
  fi

  local _real_svc=""
  _real_svc="$(ssh_service)"
  local target_unit="${_real_svc}.service"

  local _act_spec="" ban_action="" ban_allports="" extra_pkg=""
  _act_spec="$(_detect_f2b_actions)"
  IFS='|' read -r ban_action ban_allports extra_pkg <<<"$_act_spec"

  echo
  cyan "══════════════════════════════════════════════════════"
  cyan "  可选跟进：配置 Fail2ban（推荐）"
  cyan "══════════════════════════════════════════════════════"
  echo
  green "👉 请直接整段复制以下横线框内的所有命令："
  yellow "⚠️  【关键盲操提示】："
  yellow "    代码块外层已采用 { ... } 复合语句防截断保护；粘贴整段多行命令后，若光标停在最后的 '}' 处闪烁，"
  yellow "    表示 Bash 已将整段命令完整读入内存并等待结尾换行信号，只需手动敲一下回车键 (Enter) 即可整块激活运行！"
  cyan "📌 本次将同步 Fail2ban 端口为：${target_port}（日志单元：${target_unit}，后端：${target_backend}，封禁动作：${ban_action}）"
  echo "----------------------------------------------------------------------"
  sed \
    -e "s|__F2B_PORT__|${target_port}|g" \
    -e "s|__F2B_BACKEND__|${target_backend}|g" \
    -e "s|__F2B_UNIT__|${target_unit}|g" \
    -e "s|__F2B_BANACTION__|${ban_action}|g" \
    -e "s|__F2B_BANACTION_ALL__|${ban_allports}|g" \
    -e "s|__F2B_EXTRA_PKG__|${extra_pkg}|g" <<'F2B_HINT_EOF'
{
  if ! command -v fail2ban-client >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban python3-systemd__F2B_EXTRA_PKG__
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y epel-release || true
      dnf install -y fail2ban__F2B_EXTRA_PKG__
    elif command -v yum >/dev/null 2>&1; then
      yum install -y epel-release || true
      yum install -y fail2ban__F2B_EXTRA_PKG__
    fi
  fi
  mkdir -p /etc/fail2ban/jail.d
  if [ -f /etc/fail2ban/jail.d/sshd.local ]; then
    cp -a /etc/fail2ban/jail.d/sshd.local "/etc/fail2ban/jail.d/sshd.local.bak.$(date +%Y%m%d-%H%M%S)"
  fi
  cat <<'EOF' > /etc/fail2ban/jail.d/sshd.local.tmp && mv -f /etc/fail2ban/jail.d/sshd.local.tmp /etc/fail2ban/jail.d/sshd.local
# 提示：如将来再次修改 SSH 端口，只需修改下方 port 数值后重启 fail2ban 即可
[sshd]
enabled  = true
port     = __F2B_PORT__
backend  = __F2B_BACKEND__
journalmatch = _SYSTEMD_UNIT=__F2B_UNIT__ + _COMM=sshd
banaction = __F2B_BANACTION__
banaction_allports = __F2B_BANACTION_ALL__
ignoreip = 127.0.0.1/8 ::1
maxretry = 5
bantime  = 3600
findtime = 600
EOF
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reset-failed fail2ban >/dev/null 2>&1 || true
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    echo "等待 3 秒让 Fail2ban 守护进程初始化..."
    sleep 3
    fail2ban-client status sshd
  else
    service fail2ban restart
  fi
}
F2B_HINT_EOF
  echo "----------------------------------------------------------------------"
  echo
}

# ── 主流程 ────────────────────────────────────────────────────────────────────
main() {
  local new_port="" auto_mode=0 force_install=0 arg=""
  while [ "$#" -gt 0 ]; do
    arg="$1"
    case "$arg" in
      -h|--help)
        print_usage
        exit 0
        ;;
      -v|--version)
        printf '%s v%s\n' "$APP_NAME" "$APP_VERSION"
        exit 0
        ;;
      --install)
        force_install=1
        ;;
      *)
        if [[ "$arg" =~ ^[0-9]+$ ]] && [ -z "$new_port" ]; then
          new_port="$arg"
          auto_mode=1
        else
          red "❌ 无效参数：${arg}"
          print_usage >&2
          exit 2
        fi
        ;;
    esac
    shift
  done

  need_root
  require_runtime_tools
  acquire_lock
  detect_operational_config
  detect_include_port_conflicts

  if _is_ssh_socket_active; then
    SOCKET_MODE="1"
    cyan "🔌 检测到 Systemd Socket Activation 模式（ssh.socket），已自动启用 ssh.socket.d + sshd_config.d 双层同步切换。"
    log "mode: systemd socket activation (ssh.socket)"
  fi

  mkdir -p -m 700 "$BACKUP_DIR"
  touch "$LOG_FILE" 2>/dev/null || true
  chmod 600 "$LOG_FILE" 2>/dev/null || true

  local _self_real="" _install_real="" _install_notice=0
  _self_real="$(realpath "${BASH_SOURCE[0]:-$0}" 2>/dev/null || readlink -f "${BASH_SOURCE[0]:-$0}" 2>/dev/null || true)"
  _install_real="$(realpath "$INSTALL_PATH" 2>/dev/null || readlink -f "$INSTALL_PATH" 2>/dev/null || true)"
  if [ -n "$_self_real" ] && [ -f "$_self_real" ] && [ "$_self_real" != "$_install_real" ]; then
    if [ ! -e "$INSTALL_PATH" ] || [ "$force_install" -eq 1 ]; then
      if cp -f "$_self_real" "$INSTALL_PATH" 2>/dev/null && chmod 700 "$INSTALL_PATH" 2>/dev/null; then
        cyan "📦 已将 v${APP_VERSION} 安装/更新至 ${INSTALL_PATH}"
        log "install: updated ${INSTALL_PATH} from ${_self_real}"
      fi
    else
      _install_notice=1
    fi
  fi

  echo
  cyan "═══ $APP_NAME v$APP_VERSION ═══"
  echo

  if [ "$auto_mode" -eq 1 ]; then
    printf '\033[36m>> 目标端口：%s\033[0m\n' "$new_port"
  fi

  if [ -z "$new_port" ]; then
    read -r -p '请输入新的 SSH 端口号（1-65535）：' new_port
    new_port="$(_trim "$new_port")"
  fi

  [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ] || { red "端口不合法。"; exit 1; }

  if [ "$new_port" -lt 1024 ] && [ "$new_port" -ne 22 ]; then
    yellow "⚠️  提示：端口 ${new_port} 属于系统知名端口区间（1-1023），易与常见基础服务冲突；生产环境通常建议使用 10000-60000 高位端口。"
  fi

  local old_port
  old_port="$(current_ssh_port || true)"
  [ -n "$old_port" ] || { red "❌ 错误：无法探测当前 SSH 监听端口。"; exit 1; }
  [ "$new_port" = "$old_port" ] && { red "新旧端口相同，无需修改。"; exit 0; }

  local _use_rc=0
  port_in_use "$new_port" && _use_rc=0 || _use_rc=$?
  if [ "$_use_rc" -eq 0 ]; then
    red "端口 $new_port 已被占用。"
    exit 1
  elif [ "$_use_rc" -eq 2 ]; then
    red "无法可靠判断端口是否占用，已强行阻断。"
    exit 1
  fi

  echo
  yellow "当前 SSH 端口：$old_port"
  yellow "目标 SSH 端口：$new_port"
  echo

  if [ "$auto_mode" -eq 0 ]; then
    read -r -p '输入YES 继续：' _c
    _c="$(_trim "${_c:-}")"
    [ "$_c" = 'YES' ] || exit 0
  fi

  local back
  back="$BACKUP_DIR/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$back"
  backup_config "$back" || exit 1
  echo "$old_port" > "$back/old_port"
  echo "$new_port" > "$back/new_port"
  [ "$SOCKET_MODE" = "1" ] && echo "1" > "$back/socket_mode"
  touch "$back/pending"
  NEED_ROLLBACK="1"
  BACKUP_PATH="$back"
  trap on_exit EXIT
  trap 'on_signal HUP 129' HUP
  trap 'on_signal INT 130' INT
  trap 'on_signal TERM 143' TERM

  open_port "$new_port" "$back"
  apply_ssh_ports "$back" "$old_port" "$new_port" || { ROLLBACK_REASON="写入双端口失败。"; exit 1; }
  restart_ssh_engine || { ROLLBACK_REASON="SSH 重启失败。"; exit 1; }

  wait_for_ssh_port "$new_port" 12 || { ROLLBACK_REASON="没有检测到新端口处于 SSH 监听状态，触发回滚..."; exit 1; }
  wait_for_ssh_port "$old_port" 6  || { ROLLBACK_REASON="旧端口的原 SSH 监听中断，触发回滚..."; exit 1; }

  start_watchdog "$back"

  local _disp_host="" _disp_user=""
  _disp_host="$(_detect_display_host)"
  _disp_user="${SUDO_USER:-root}"

  echo
  green "双端口监听已完成。"
  yellow "请另开终端测试：ssh -p $new_port ${_disp_user}@${_disp_host}"
  echo
  yellow "⚠️  【云服务提供商外部安全组关键核关】"
  yellow "    请【务必】登录云服务提供商控制台网页，手动放行新端口 ${new_port} 的 TCP 传入流量！"
  cyan   "    💡  [安全加固提示] 待新端口成功切换后，建议在云服务提供商后台封锁默认的 22 端口：若网页安全组默认为[全拦截]，直接【删除】22端口规则；若默认为[全放行]，需手动【添加】一条针对22端口的 DROP 阻断规则。"
  echo
  yellow "⏱️  请在 $((TIMEOUT_SEC / 60)) 分钟内完成验证，超时或断电重启均将触发自动回滚。"
  echo

  read -r -p "确认新端口可登录？输入YES 继续：" _c2 || true
  _c2="$(_trim "${_c2:-}")"
  [ "$_c2" = 'YES' ] || { ROLLBACK_REASON="用户取消。"; exit 1; }

  # 持回滚互斥锁检查 pending 并先行拆除异步超时看门狗，防止最终提交瞬间与看门狗撞车
  local _still_pending=0
  (
    if have flock; then
      exec 8>>"$ROLLBACK_LOCK_FILE"
      flock -w 30 8 || exit 2
    fi
    [ -f "$back/pending" ] || exit 1
  ) && _still_pending=1 || _still_pending=0
  if [ "$_still_pending" -ne 1 ]; then
    NEED_ROLLBACK="0"
    stop_watchdog
    red "❌ 错误：检测到看门狗已介入回滚！操作已被拦截阻止。"
    exit 1
  fi

  stop_watchdog

  apply_ssh_ports "$back" "$new_port" || { ROLLBACK_REASON="写入最终配置失败。"; exit 1; }
  restart_ssh_engine || { ROLLBACK_REASON="最终 SSH 重启失败。"; exit 1; }

  wait_for_ssh_port "$new_port" 12 || { ROLLBACK_REASON="最终验证失败：新端口未监听，触发回滚..."; exit 1; }
  wait_for_ssh_port_closed "$old_port" 12 || { ROLLBACK_REASON="最终验证失败：旧端口仍处于监听状态，触发回滚..."; exit 1; }

  close_port "$old_port" "$back"
  (
    if have flock; then
      exec 8>>"$ROLLBACK_LOCK_FILE"
      flock -w 30 8 || true
    fi
    rm -f "$back/pending"
    unregister_survival_watchdog
    rm -f "$back/emergency_rollback.sh" 2>/dev/null || true
  )
  NEED_ROLLBACK="0"
  trap - EXIT HUP TERM INT

  echo
  green "✅ SSH 端口已成功切换：$old_port → $new_port"
  if [ "$_install_notice" -eq 1 ]; then
    yellow "ℹ️  当前为独立路径测试运行，未覆盖原有 ${INSTALL_PATH}；如需更新正式脚本请执行："
    yellow "    bash ${_self_real} --install"
  fi
  echo "工具路径：$INSTALL_PATH"
  echo "常规快捷启动提示：bash $INSTALL_PATH"
  echo
  echo "快捷传参用法（下次换端口可跳过输入提示）："
  echo "bash $INSTALL_PATH <新端口号>"
  echo

  local _cleaned
  _cleaned="$(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +30 2>/dev/null)"
  if [ -n "$_cleaned" ]; then
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true
    yellow "🗂️  已自动清理 30 天前的历史备份。"
  fi

  local _client_ip
  _client_ip="$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $1}')"
  log "success: old=$old_port new=$new_port client=${_client_ip:-unknown}"
  print_fail2ban_hint "$new_port"
}

main "$@"
