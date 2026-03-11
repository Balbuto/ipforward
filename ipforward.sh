#!/bin/bash
# ==============================================
# IPTABLES FORWARDING MANAGER v1.1 (Fail2Ban Integration)
# ==============================================
set -euo pipefail

# --- ЦВЕТА ---
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r CYAN='\033[0;36m'
declare -r YELLOW='\033[1;33m'
declare -r MAGENTA='\033[0;35m'
declare -r WHITE='\033[1;37m'
declare -r BLUE='\033[0;34m'
declare -r NC='\033[0m'

# --- КОНФИГУРАЦИЯ ---
declare -r SCRIPT_NAME="ipforward"
declare -r BACKUP_DIR="/root/iptables-backups"
declare -r LOG_FILE="/var/log/port-forwarding.log"
declare -r MAX_LOG_SIZE=10485760
declare -r LOCK_FILE="/var/run/${SCRIPT_NAME}.lock"
declare -r F2B_BACKUP_DIR="/root/iptables-backups/fail2ban"

# --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
declare _lock_fd=""

# ==============================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==============================================

log() {
    local _log_level="$1"
    local _log_message="$2"
    local _log_timestamp
    _log_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${_log_timestamp}] [${_log_level}] ${_log_message}" >> "$LOG_FILE"
}

cleanup() {
    local _exit_code=$?
    # Закрываем lock file descriptor
    if [[ -n "$_lock_fd" ]]; then
        exec {_lock_fd}>&- 2>/dev/null || true
    fi
    # Удаляем lock файл при выходе
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE" 2>/dev/null || true
    fi
    exit $_exit_code
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}[ERROR] Запустите скрипт с правами root!${NC}"
        exit 1
    fi
}

check_bash_version() {
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]] || [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 3 ]]; then
        echo -e "${RED}[ERROR] Требуется Bash 4.3+ (у вас ${BASH_VERSION})${NC}"
        exit 1
    fi
}

acquire_lock() {
    exec {_lock_fd}>"$LOCK_FILE"
    if ! flock -n "$_lock_fd"; then
        echo -e "${RED}[ERROR] Скрипт уже запущен${NC}"
        _lock_fd=""
        exit 1
    fi
}

set_file_permissions() {
    local _file="$1"
    local _mode="$2"
    local _chmod_ok=0
    local _chown_ok=0
    
    if [[ -f "$_file" ]]; then
        chmod "$_mode" "$_file" 2>/dev/null && _chmod_ok=1 || log "WARN" "Не удалось chmod $_file"
        chown root:root "$_file" 2>/dev/null && _chown_ok=1 || log "WARN" "Не удалось chown $_file"
        
        [[ $_chmod_ok -eq 1 ]] && return 0 || return 1
    fi
    return 0
}

check_dependencies() {
    local _deps=("iptables" "ip" "grep" "awk" "sed" "ss" "nc" "timeout" "readlink" "stat")
    local _missing=()
    
    for _dep in "${_deps[@]}"; do
        command -v "$_dep" &> /dev/null || _missing+=("$_dep")
    done
    
    if [[ ${#_missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Устанавливаю: ${_missing[*]}${NC}"
        export DEBIAN_FRONTEND=noninteractive
        
        echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections 2>/dev/null || true
        echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections 2>/dev/null || true
        
        apt-get update -y > /dev/null 2>&1 || true
        apt-get install -y \
            iptables \
            iptables-persistent \
            netfilter-persistent \
            iproute2 \
            netcat-openbsd \
            coreutils \
            > /dev/null 2>&1 || {
            echo -e "${RED}Ошибка установки${NC}"
            exit 1
        }
    fi
    
    local _critical=("iptables" "iptables-save" "ip" "ss" "nc" "timeout")
    for _cmd in "${_critical[@]}"; do
        command -v "$_cmd" &> /dev/null || {
            echo -e "${RED}Критическая зависимость отсутствует: $_cmd${NC}"
            exit 1
        }
    done
}

backup_rules() {
    local _old_umask
    _old_umask=$(umask)
    umask 077
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        chown root:root "$BACKUP_DIR" 2>/dev/null || true
    fi
    
    local _backup_file="$BACKUP_DIR/iptables-$(date +%Y%m%d-%H%M%S).rules"
    if command -v iptables-save &> /dev/null; then
        if iptables-save > "$_backup_file" 2>/dev/null; then
            if [[ -s "$_backup_file" ]] && grep -q "^\*" "$_backup_file" 2>/dev/null; then
                chmod 600 "$_backup_file"
                chown root:root "$_backup_file" 2>/dev/null || true
                echo -e "${GREEN}✅ Бэкап: $_backup_file${NC}"
                log "INFO" "Бэкап: $_backup_file"
                umask "$_old_umask"
                return 0
            else
                rm -f "$_backup_file" 2>/dev/null || true
                echo -e "${RED}❌ Бэкап пустой или невалидный${NC}"
            fi
        fi
    fi
    
    umask "$_old_umask"
    echo -e "${RED}❌ Ошибка бэкапа${NC}"
    return 1
}

# ==============================================
# FAIL2BAN INTEGRATION FUNCTIONS
# ==============================================

is_fail2ban_installed() {
    command -v fail2ban-client &> /dev/null && \
    command -v fail2ban-server &> /dev/null
}

is_fail2ban_running() {
    if is_fail2ban_installed; then
        fail2ban-client ping &>/dev/null 2>&1
        return $?
    fi
    return 1
}

get_fail2ban_chains() {
    # Получаем список цепочек fail2ban из iptables
    iptables -L 2>/dev/null | grep -E "^Chain f2b-|^Chain fail2ban" | awk '{print $2}' | sort -u
}

get_fail2ban_rules() {
    # Сохраняем правила fail2ban в отдельный файл
    local _output_file="$1"
    local _chains
    local _chain
    
    _chains=$(get_fail2ban_chains)
    
    if [[ -z "$_chains" ]]; then
        return 1
    fi
    
    # Создаём директорию для бэкапов fail2ban
    if [[ ! -d "$F2B_BACKUP_DIR" ]]; then
        mkdir -p "$F2B_BACKUP_DIR"
        chmod 700 "$F2B_BACKUP_DIR"
        chown root:root "$F2B_BACKUP_DIR" 2>/dev/null || true
    fi
    
    # Сохраняем только fail2ban цепочки
    {
        echo "# Fail2Ban rules backup created: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Chains: $_chains"
        echo ""
        
        for _chain in $_chains; do
            # Сохраняем правила цепочки
            iptables -S "$_chain" 2>/dev/null || true
            echo ""
        done
        
        # Сохраняем ссылки на fail2ban цепочки из INPUT/FORWARD
        iptables -S INPUT 2>/dev/null | grep -E "f2b-|fail2ban" || true
        iptables -S FORWARD 2>/dev/null | grep -E "f2b-|fail2ban" || true
    } > "$_output_file"
    
    chmod 600 "$_output_file"
    return 0
}

restore_fail2ban_rules() {
    local _backup_file="$1"
    
    if [[ ! -f "$_backup_file" ]]; then
        log "WARN" "Fail2Ban backup file not found: $_backup_file"
        return 1
    fi
    
    echo -e "${YELLOW}[*] Восстановление правил Fail2Ban...${NC}"
    
    # Проверяем что fail2ban запущен, если нет — запускаем
    if ! is_fail2ban_running; then
        if is_fail2ban_installed; then
            echo -e "${YELLOW}⚠️  Fail2Ban не запущен, попытка запуска...${NC}"
            systemctl start fail2ban 2>/dev/null || service fail2ban start 2>/dev/null || true
            sleep 2
        fi
    fi
    
    # Если fail2ban запущен — перезагружаем его правила корректно
    if is_fail2ban_running; then
        echo -e "${CYAN}Перезагрузка Fail2Ban через client...${NC}"
        fail2ban-client reload 2>/dev/null || fail2ban-client restart 2>/dev/null || {
            log "WARN" "Не удалось перезагрузить Fail2Ban через client"
        }
        return 0
    fi
    
    # Если fail2ban не запущен или reload не сработал — восстанавливаем вручную
    echo -e "${YELLOW}Восстановление правил вручную из бэкапа...${NC}"
    
    # Создаём цепочки если они не существуют
    local _chains
    _chains=$(grep "^-N f2b-" "$_backup_file" 2>/dev/null | awk '{print $2}' || true)
    
    for _chain in $_chains; do
        if ! iptables -L "$_chain" -n &>/dev/null; then
            iptables -N "$_chain" 2>/dev/null || true
        fi
    done
    
    # Применяем правила из бэкапа (кроме создания цепочек)
    grep "^-A f2b-" "$_backup_file" 2>/dev/null | while read -r rule; do
        eval "iptables $rule" 2>/dev/null || true
    done
    
    # Восстанавливаем ссылки из INPUT
    grep "^-A INPUT.*f2b-" "$_backup_file" 2>/dev/null | while read -r rule; do
        # Проверяем что правило ещё не существует
        local _chain_name
        _chain_name=$(echo "$rule" | grep -oE 'f2b-[^[:space:]]+' | head -1)
        if [[ -n "$_chain_name" ]]; then
            if ! iptables -C INPUT -j "$_chain_name" &>/dev/null; then
                eval "iptables $rule" 2>/dev/null || true
            fi
        fi
    done
    
    log "INFO" "Fail2Ban rules restored from backup"
    echo -e "${GREEN}✅ Правила Fail2Ban восстановлены${NC}"
    return 0
}

unban_ip_fail2ban() {
    # Разбан IP во всех jail'ах fail2ban
    local _ip="$1"
    
    if ! is_fail2ban_running; then
        return 1
    fi
    
    local _jails
    _jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list://' | tr ',' ' ' || true)
    
    for _jail in $_jails; do
        _jail=$(echo "$_jail" | xargs)  # trim
        [[ -z "$_jail" ]] && continue
        fail2ban-client set "$_jail" unbanip "$_ip" &>/dev/null || true
    done
}

ban_ip_fail2ban() {
    # Бан IP во всех jail'ах fail2ban
    local _ip="$1"
    
    if ! is_fail2ban_running; then
        return 1
    fi
    
    local _jails
    _jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list://' | tr ',' ' ' || true)
    
    for _jail in $_jails; do
        _jail=$(echo "$_jail" | xargs)  # trim
        [[ -z "$_jail" ]] && continue
        fail2ban-client set "$_jail" banip "$_ip" &>/dev/null || true
    done
}

save_fail2ban_state() {
    # Сохраняем текущее состояние fail2ban перед операциями
    if ! is_fail2ban_running; then
        return 0
    fi
    
    local _state_file="$F2B_BACKUP_DIR/fail2ban-state-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "# Fail2Ban state: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# Status:"
        fail2ban-client status 2>/dev/null || true
        echo ""
        echo "# Banned IPs by jail:"
        local _jails
        _jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list://' | tr ',' ' ' || true)
        for _jail in $_jails; do
            _jail=$(echo "$_jail" | xargs)
            [[ -z "$_jail" ]] && continue
            echo ""
            echo "[$_jail]"
            fail2ban-client status "$_jail" 2>/dev/null | grep "Banned IP list:" || true
        done
    } > "$_state_file"
    
    chmod 600 "$_state_file"
    log "INFO" "Fail2Ban state saved to $_state_file"
}

# ==============================================
# CORE FUNCTIONS
# ==============================================

is_container() {
    [[ -f /.dockerenv ]] || \
    [[ -f /proc/vz/version ]] || \
    [[ "$(cat /proc/1/cgroup 2>/dev/null)" =~ docker ]] || \
    [[ "$(systemd-detect-virt 2>/dev/null)" =~ lxc|openvz ]]
}

get_default_interface() {
    local _iface=""
    _iface=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    
    if [[ -z "$_iface" ]]; then
        _iface=$(ip -4 -o addr show 2>/dev/null | grep -v -E 'lo:|docker|br-|veth|tun|wg|vmbr|virbr' | awk '{print $2}' | head -1)
    fi
    
    if [[ -n "$_iface" ]] && ip link show "$_iface" &>/dev/null; then
        echo "$_iface"
        return 0
    fi
    
    log "ERROR" "Не удалось определить интерфейс"
    return 1
}

check_port_available() {
    local _port="$1"
    local _proto="$2"
    
    if ! [[ "$_port" =~ ^[0-9]+$ ]] || [[ "$_port" -lt 1 ]] || [[ "$_port" -gt 65535 ]]; then
        return 2
    fi
    
    if ss -tuln 2>/dev/null | grep -qE "${_proto}.*(0\.0\.0\.0|:::|\*):${_port}\s"; then
        return 1
    fi
    return 0
}

validate_ip() {
    local _ip="$1"
    local _IFS='.'
    local -a _octets=()
    
    [[ -z "$_ip" ]] && return 1
    [[ "$_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    read -ra _octets <<< "$_ip"
    [[ ${#_octets[@]} -eq 4 ]] || return 1
    
    for _octet in "${_octets[@]}"; do
        [[ "$_octet" =~ ^[0-9]+$ ]] || return 1
        _octet=$((10#$_octet))
        ((_octet >= 0 && _octet <= 255)) || return 1
    done
    
    local _first="${_octets[0]}"
    local _second="${_octets[1]}"
    
    [[ $_first -eq 0 ]] && return 1
    [[ $_first -eq 127 ]] && return 1
    [[ $_first -ge 224 ]] && return 1
    [[ $_first -eq 255 ]] && return 1
    [[ $_first -eq 169 && $_second -eq 254 ]] && return 1
    
    return 0
}

validate_target() {
    local _target="$1"
    [[ "$_target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]] || return 1
    
    local _ip="${_target%:*}"
    local _port="${_target#*:}"
    local _IFS='.'
    local -a _octets=()
    read -ra _octets <<< "$_ip"
    
    for _octet in "${_octets[@]}"; do
        _octet=$((10#$_octet))
        ((_octet >= 0 && _octet <= 255)) || return 1
    done
    
    _port=$((10#$_port))
    ((_port >= 1 && _port <= 65535)) || return 1
    
    return 0
}

validate_port() {
    local _port="$1"
    [[ -n "$_port" ]] && [[ "$_port" =~ ^[0-9]+$ ]] && [[ "$_port" -ge 1 ]] && [[ "$_port" -le 65535 ]]
}

check_rule_exists() {
    local _proto="$1"
    local _port="$2"
    local _target="$3"
    iptables -w -t nat -C PREROUTING -p "$_proto" --dport "$_port" -j DNAT --to-destination "$_target" &>/dev/null
}

parse_nat_rules() {
    local -n ___pr_rules_array=$1
    local -n ___pr_raw_array=$2
    
    local ___pr_i=1
    local ___pr_output
    
    ___pr_output=$(iptables-save -t nat 2>/dev/null) || return 1
    
    while IFS= read -r ___pr_line; do
        [[ "$___pr_line" != *"DNAT"* ]] && continue
        
        local ___pr_proto ___pr_dport ___pr_dest
        if [[ "$___pr_line" =~ -p[[:space:]]+([^[:space:]]+).*--dport[[:space:]]+([0-9]+).*--to-destination[[:space:]]+([0-9.:]+) ]]; then
            ___pr_proto="${BASH_REMATCH[1]}"
            ___pr_dport="${BASH_REMATCH[2]}"
            ___pr_dest="${BASH_REMATCH[3]}"
            
            ___pr_rules_array[$___pr_i]="$___pr_proto:$___pr_dport:$___pr_dest"
            ___pr_raw_array[$___pr_i]="$___pr_line"
            ((___pr_i++)) || true
        fi
    done <<< "$___pr_output"
}

enable_bbr() {
    if is_container; then
        log "INFO" "Контейнер обнаружен, пропускаем BBR"
        return 0
    fi
    
    if modprobe tcp_bbr 2>/dev/null; then
        if [[ -d /etc/modules-load.d ]]; then
            echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true
        fi
        
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf 2>/dev/null || true
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf 2>/dev/null || true
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        echo -e "${GREEN}✅ BBR активирован (с персистентностью)${NC}"
        return 0
    fi
    return 1
}

setup_log_rotation() {
    if [[ -f "$LOG_FILE" ]]; then
        local _log_size
        _log_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "$_log_size" -gt $MAX_LOG_SIZE ]]; then
            local _old_umask
            _old_umask=$(umask)
            umask 077
            mv "$LOG_FILE" "${LOG_FILE}.old"
            touch "$LOG_FILE"
            umask "$_old_umask"
            set_file_permissions "${LOG_FILE}.old" "600" || true
            set_file_permissions "$LOG_FILE" "600" || true
        fi
    fi
}

prepare_system() {
    setup_log_rotation
    log "INFO" "Подготовка системы"
    
    local _script_path
    _script_path=$(readlink -f "$0" 2>/dev/null) || _script_path="$0"
    
    if [[ -f "$_script_path" ]] && [[ "$_script_path" != "/usr/local/bin/$SCRIPT_NAME" ]]; then
        if cp -f "$_script_path" "/usr/local/bin/$SCRIPT_NAME" 2>/dev/null; then
            chmod +x "/usr/local/bin/$SCRIPT_NAME"
            echo -e "${GREEN}✅ Команда: $SCRIPT_NAME${NC}"
        else
            echo -e "${YELLOW}⚠️  Не удалось создать команду${NC}"
        fi
    fi
    
    sysctl -w net.ipv4.ip_forward=1 &>/dev/null || true
    sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    
    enable_bbr || true
    sysctl -p &>/dev/null || true
    
    check_dependencies
    
    touch "$LOG_FILE" 2>/dev/null || true
    set_file_permissions "$LOG_FILE" "600" || true
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"
        chown root:root "$BACKUP_DIR" 2>/dev/null || true
    fi
    
    # Создаём директорию для бэкапов fail2ban
    if [[ ! -d "$F2B_BACKUP_DIR" ]]; then
        mkdir -p "$F2B_BACKUP_DIR"
        chmod 700 "$F2B_BACKUP_DIR"
        chown root:root "$F2B_BACKUP_DIR" 2>/dev/null || true
    fi
    
    [[ -d /etc/iptables ]] || mkdir -p /etc/iptables 2>/dev/null || true
    log "INFO" "Система готова"
}

show_instructions() {
    clear
    echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║             📚 ИНСТРУКЦИЯ                                    ║${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}1. Получите IP и порт зарубежного сервера${NC}"
    echo -e "${CYAN}2. Выберите пункт меню 1-5 и введите данные${NC}"
    echo -e "${CYAN}3. В клиенте укажите IP ЭТОГО сервера и входящий порт${NC}"
    echo ""
    read -rp "Нажмите Enter..."
}

delete_rule_by_params() {
    local _proto="$1"
    local _port="$2"
    local _target="$3"
    
    if [[ "$_target" != *":"* ]]; then
        log "ERROR" "Некорректный target: $_target"
        return 1
    fi
    
    local _target_ip="${_target%:*}"
    local _target_port="${_target#*:}"
    local _rule_existed=0
    local _rule_deleted=0
    
    if iptables -w -t nat -C PREROUTING -p "$_proto" --dport "$_port" -j DNAT --to-destination "$_target" &>/dev/null; then
        _rule_existed=1
        iptables -w -t nat -D PREROUTING -p "$_proto" --dport "$_port" -j DNAT --to-destination "$_target" 2>/dev/null && _rule_deleted=1
    fi
    
    iptables -w -D INPUT -p "$_proto" --dport "$_port" -j ACCEPT 2>/dev/null || true
    iptables -w -D FORWARD -p "$_proto" -d "$_target_ip" --dport "$_target_port" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    iptables -w -D FORWARD -p "$_proto" -s "$_target_ip" --sport "$_target_port" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    
    # Возвращаем ошибку только если правило существовало но не удалилось
    if [[ $_rule_existed -eq 1 && $_rule_deleted -eq 0 ]]; then
        return 1
    fi
    return 0
}

check_masquerade_exists() {
    local _iface="$1"
    # Проверяем что есть MASQUERADE для этого интерфейса (с любыми доп. параметрами)
    iptables-save -t nat 2>/dev/null | grep -qE "^-A POSTROUTING.*-o ${_iface}.*-j MASQUERADE(\s|$)"
}

apply_iptables_rules() {
    local _proto="$1"
    local _in_port="$2"
    local _out_port="$3"
    local _target_ip="$4"
    local _name="$5"
    local _iface
    
    _iface=$(get_default_interface) || { echo -e "${RED}[ERROR] Нет интерфейса!${NC}"; return 1; }
    
    check_port_available "$_in_port" "$_proto"
    local _port_status=$?
    
    if [[ "$_port_status" -eq 2 ]]; then
        echo -e "${RED}Ошибка: порт $_in_port вне диапазона 1-65535${NC}"
        return 1
    elif [[ "$_port_status" -eq 1 ]]; then
        echo -e "${RED}❌ Порт $_in_port занят другим сервисом!${NC}"
        echo -e "${YELLOW}DNAT не может быть создан на занятом порту${NC}"
        return 1
    fi
    
    local _target="$_target_ip:$_out_port"
    
    if ! validate_target "$_target"; then
        echo -e "${RED}Ошибка: некорректный target${NC}"
        return 1
    fi
    
    if check_rule_exists "$_proto" "$_in_port" "$_target"; then
        echo -e "${YELLOW}⚠️  Правило существует!${NC}"
        read -rp "Перезаписать? (y/n): " _c
        [[ "$_c" != "y" ]] && return 1
        delete_rule_by_params "$_proto" "$_in_port" "$_target" || true
    fi
    
    backup_rules || true
    echo -e "${YELLOW}[*] Применение...${NC}"
    log "INFO" "$_proto $_in_port -> $_target_ip:$_out_port"
    
    iptables -w -A INPUT -p "$_proto" --dport "$_in_port" -j ACCEPT
    iptables -w -t nat -A PREROUTING -p "$_proto" --dport "$_in_port" -j DNAT --to-destination "$_target"
    
    if ! check_masquerade_exists "$_iface"; then
        iptables -w -t nat -A POSTROUTING -o "$_iface" -j MASQUERADE
    fi
    
    iptables -w -A FORWARD -p "$_proto" -d "$_target_ip" --dport "$_out_port" -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -w -A FORWARD -p "$_proto" -s "$_target_ip" --sport "$_out_port" -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    if command -v ufw &> /dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "${YELLOW}⚠️  UFW активен${NC}"
        read -rp "Добавить правило в UFW? (y/n): " _uc
        [[ "$_uc" == "y" ]] && ufw allow "$_in_port"/"$_proto" >/dev/null 2>&1 || true
    fi
    
    command -v netfilter-persistent &> /dev/null && netfilter-persistent save >/dev/null 2>&1 || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    
    echo -e "${GREEN}✅ $_name настроен!${NC}"
    echo -e "${CYAN}📊 $_proto:$_in_port -> $_target_ip:$_out_port${NC}"
    log "INFO" "Применено"
    
    if iptables -w -t nat -C PREROUTING -p "$_proto" --dport "$_in_port" -j DNAT --to-destination "$_target" &>/dev/null; then
        echo -e "${GREEN}✅ Правило активно в iptables${NC}"
    fi
    
    sleep 1
    read -rp "Нажмите Enter..."
}

configure_rule() {
    local _proto="$1"
    local _name="$2"
    local _target_ip=""
    local _port=""
    
    echo -e "\n${CYAN}--- $_name ($_proto) ---${NC}"
    
    while true; do
        read -rp "IP адрес: " _target_ip
        [[ -z "$_target_ip" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_ip "$_target_ip" && break
        echo -e "${RED}Ошибка IP! Используйте формат xxx.xxx.xxx.xxx (не localhost)${NC}"
    done
    
    while true; do
        read -rp "Порт (1-65535): " _port
        [[ -z "$_port" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_port "$_port" && break
        echo -e "${RED}Ошибка порта! Диапазон 1-65535${NC}"
    done
    
    apply_iptables_rules "$_proto" "$_port" "$_port" "$_target_ip" "$_name"
}

configure_both_rule() {
    local _target_ip=""
    local _port=""
    
    echo -e "\n${CYAN}--- WireGuard Full (UDP+TCP fallback) ---${NC}"
    
    while true; do
        read -rp "IP: " _target_ip
        [[ -z "$_target_ip" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_ip "$_target_ip" && break
        echo -e "${RED}Ошибка IP!${NC}"
    done
    
    while true; do
        read -rp "Порт (1-65535): " _port
        [[ -z "$_port" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_port "$_port" && break
        echo -e "${RED}Ошибка порта!${NC}"
    done
    
    # Проверка портов перед применением
    check_port_available "$_port" "tcp"
    local _tcp_status=$?
    check_port_available "$_port" "udp"
    local _udp_status=$?
    
    if [[ "$_tcp_status" -eq 2 ]] || [[ "$_udp_status" -eq 2 ]]; then
        echo -e "${RED}❌ Порт $_port вне диапазона${NC}"
        return 1
    fi
    
    if [[ "$_tcp_status" -eq 1 ]] || [[ "$_udp_status" -eq 1 ]]; then
        echo -e "${RED}❌ Порт $_port занят одним из протоколов (TCP/UDP)!${NC}"
        return 1
    fi
    
    # Проверка существования правил
    local _target="$_target_ip:$_port"
    if check_rule_exists "tcp" "$_port" "$_target" || check_rule_exists "udp" "$_port" "$_target"; then
        echo -e "${YELLOW}⚠️  Одно из правил уже существует${NC}"
        read -rp "Перезаписать оба? (y/n): " _c
        [[ "$_c" != "y" ]] && return 1
    fi
    
    backup_rules || true
    
    # Применяем оба с отслеживанием
    local _tcp_applied=0 _udp_applied=0
    
    if apply_iptables_rules "tcp" "$_port" "$_port" "$_target_ip" "TCP" 2>/dev/null; then
        _tcp_applied=1
    fi
    
    if apply_iptables_rules "udp" "$_port" "$_port" "$_target_ip" "UDP" 2>/dev/null; then
        _udp_applied=1
    fi
    
    # Rollback при частичном применении
    if [[ $_tcp_applied -eq 1 && $_udp_applied -eq 0 ]]; then
        echo -e "${YELLOW}⚠️  UDP не удалось, откатываем TCP...${NC}"
        delete_rule_by_params "tcp" "$_port" "$_target" || true
        echo -e "${RED}❌ Операция отменена (rollback выполнен)${NC}"
        return 1
    elif [[ $_tcp_applied -eq 0 && $_udp_applied -eq 1 ]]; then
        echo -e "${YELLOW}⚠️  TCP не удалось, откатываем UDP...${NC}"
        delete_rule_by_params "udp" "$_port" "$_target" || true
        echo -e "${RED}❌ Операция отменена (rollback выполнен)${NC}"
        return 1
    elif [[ $_tcp_applied -eq 0 && $_udp_applied -eq 0 ]]; then
        echo -e "${RED}❌ Оба протокола не удалось применить${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Оба правила (TCP+UDP) применены успешно${NC}"
}

configure_custom_rule() {
    local _proto=""
    local _target_ip=""
    local _in_port=""
    local _out_port=""
    
    echo -e "\n${CYAN}--- Кастомное правило ---${NC}"
    
    while true; do
        read -rp "Протокол (tcp/udp): " _proto
        [[ -z "$_proto" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        [[ "$_proto" == "tcp" || "$_proto" == "udp" ]] && break
        echo -e "${RED}Ошибка! Введите tcp или udp${NC}"
    done
    
    while true; do
        read -rp "IP: " _target_ip
        [[ -z "$_target_ip" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_ip "$_target_ip" && break
        echo -e "${RED}Ошибка IP!${NC}"
    done
    
    while true; do
        read -rp "Входящий порт: " _in_port
        [[ -z "$_in_port" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_port "$_in_port" && break
        echo -e "${RED}Ошибка! Диапазон 1-65535${NC}"
    done
    
    while true; do
        read -rp "Исходящий порт: " _out_port
        [[ -z "$_out_port" ]] && { echo -e "${RED}Пустой ввод!${NC}"; continue; }
        validate_port "$_out_port" && break
        echo -e "${RED}Ошибка! Диапазон 1-65535${NC}"
    done
    
    # Проверка на существование правила
    local _target="$_target_ip:$_out_port"
    if check_rule_exists "$_proto" "$_in_port" "$_target"; then
        echo -e "${YELLOW}⚠️  Правило уже существует!${NC}"
        read -rp "Перезаписать? (y/n): " _c
        [[ "$_c" != "y" ]] && return 1
    fi
    
    apply_iptables_rules "$_proto" "$_in_port" "$_out_port" "$_target_ip" "Custom"
}

list_active_rules() {
    local -a _rules_list=()
    local -a _raw_list=()
    
    parse_nat_rules _rules_list _raw_list || true
    
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}              АКТИВНЫЕ ПРАВИЛА                                  ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    
    [[ ${#_rules_list[@]} -eq 0 ]] && { echo -e "${YELLOW}Нет правил${NC}"; read -rp "Enter..."; return; }
    
    printf "${WHITE}%-5s | %-8s | %-10s | %-21s${NC}\n" "№" "Протокол" "Порт" "Назначение"
    echo -e "${CYAN}---------------------------------------------------------------${NC}"
    
    local _i=1
    for _rule in "${_rules_list[@]}"; do
        IFS=':' read -r _r_proto _r_port _r_dest <<< "$_rule"
        printf "${GREEN}%-5s${NC} | %-8s | %-10s | %-21s\n" "$_i" "$_r_proto" "$_r_port" "$_r_dest"
        ((_i++)) || true
    done
    
    read -rp "Enter..."
}

delete_single_rule() {
    local -a _rules_list=()
    local -a _raw_list=()
    
    parse_nat_rules _rules_list _raw_list || true
    
    echo -e "\n${CYAN}--- Удаление ---${NC}"
    [[ ${#_rules_list[@]} -eq 0 ]] && { echo -e "${RED}Нет правил${NC}"; read -rp "Enter..."; return; }
    
    local _i=1
    for _rule in "${_rules_list[@]}"; do
        IFS=':' read -r _r_proto _r_port _r_dest <<< "$_rule"
        echo -e "${YELLOW}[$_i]${NC} $_r_proto:$_r_port -> $_r_dest"
        ((_i++)) || true
    done
    
    read -rp "Номер (0 отмена): " _num
    [[ "$_num" == "0" ]] && return
    [[ ! "$_num" =~ ^[0-9]+$ ]] || [[ -z "${_rules_list[$_num]:-}" ]] && { echo -e "${RED}Ошибка!${NC}"; read -rp "Enter..."; return; }
    
    backup_rules || true
    IFS=':' read -r _d_proto _d_port _d_dest <<< "${_rules_list[$_num]}"
    echo -e "${YELLOW}Удаляю: $_d_proto:$_d_port -> $_d_dest${NC}"
    
    delete_rule_by_params "$_d_proto" "$_d_port" "$_d_dest" && {
        command -v netfilter-persistent &> /dev/null && netfilter-persistent save >/dev/null 2>&1 || true
        echo -e "${GREEN}✅ Удалено${NC}"
        log "INFO" "Удалено: $_d_proto:$_d_port"
    } || echo -e "${RED}⚠️  Проблемы при удалении${NC}"
    
    read -rp "Enter..."
}

# ==============================================
# FAIL2BAN-AWARE FLUSH FUNCTION
# ==============================================

flush_rules() {
    echo -e "\n${RED}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}!!! ВНИМАНИЕ !!! УДАЛЕНИЕ ВСЕХ ПРАВИЛ !!!${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
    
    list_active_rules
    echo -e "${YELLOW}Рекомендуется бэкап перед очисткой.${NC}"
    read -rp "Сделать бэкап? (y/n): " _bc
    [[ "$_bc" == "y" ]] && backup_rules || true
    
    # === FAIL2BAN INTEGRATION ===
    local _f2b_backup_file=""
    local _f2b_was_running=0
    local _f2b_chains=""
    
    if is_fail2ban_installed; then
        echo -e "\n${CYAN}--- Проверка Fail2Ban ---${NC}"
        
        if is_fail2ban_running; then
            _f2b_was_running=1
            _f2b_chains=$(get_fail2ban_chains)
            
            if [[ -n "$_f2b_chains" ]]; then
                echo -e "${YELLOW}⚠️  Обнаружен активный Fail2Ban со следующими цепочками:${NC}"
                echo "$_f2b_chains" | while read -r chain; do
                    echo -e "   ${CYAN}- $chain${NC}"
                done
                
                # Сохраняем состояние fail2ban
                save_fail2ban_state
                
                # Создаём бэкап правил iptables для fail2ban
                _f2b_backup_file="$F2B_BACKUP_DIR/fail2ban-$(date +%Y%m%d-%H%M%S).rules"
                if get_fail2ban_rules "$_f2b_backup_file"; then
                    echo -e "${GREEN}✅ Бэкап Fail2Ban создан: $_f2b_backup_file${NC}"
                    log "INFO" "Fail2Ban backup created before flush: $_f2b_backup_file"
                else
                    echo -e "${YELLOW}⚠️  Не удалось создать бэкап правил Fail2Ban${NC}"
                    _f2b_backup_file=""
                fi
                
                echo -e "\n${YELLOW}Варианты обработки Fail2Ban:${NC}"
                echo -e "1) ${GREEN}Остановить Fail2Ban${NC} (рекомендуется) — правила будут удалены автоматически"
                echo -e "2) ${CYAN}Сохранить и восстановить${NC} — попытка сохранить баны"
                echo -e "3) ${RED}Пропустить${NC} — Fail2Ban правила будут потеряны!"
                
                read -rp "Выбор (1-3): " _f2b_choice
                
                case "$_f2b_choice" in
                    1)
                        echo -e "${YELLOW}Остановка Fail2Ban...${NC}"
                        systemctl stop fail2ban 2>/dev/null || service fail2ban stop 2>/dev/null || true
                        sleep 1
                        if ! is_fail2ban_running; then
                            echo -e "${GREEN}✅ Fail2Ban остановлен${NC}"
                            _f2b_was_running=0
                        else
                            echo -e "${RED}❌ Не удалось остановить Fail2Ban${NC}"
                        fi
                        ;;
                    2)
                        echo -e "${CYAN}Fail2Ban правила будут восстановлены после очистки${NC}"
                        ;;
                    3)
                        echo -e "${RED}⚠️  ПРЕДУПРЕЖДЕНИЕ: Fail2Ban правила будут потеряны!${NC}"
                        read -rp "Продолжить? (yes/no): " _confirm
                        [[ "$_confirm" != "yes" ]] && { echo -e "${GREEN}Отменено${NC}"; return; }
                        _f2b_backup_file=""
                        ;;
                    *)
                        echo -e "${RED}Неверный выбор, отмена операции${NC}"
                        return
                        ;;
                esac
            else
                echo -e "${CYAN}Fail2Ban установлен, но нет активных цепочек в iptables${NC}"
            fi
        else
            echo -e "${CYAN}Fail2Ban установлен, но не запущен${NC}"
        fi
    else
        echo -e "${CYAN}Fail2Ban не обнаружен в системе${NC}"
    fi
    # === END FAIL2BAN INTEGRATION ===
    
    echo -e "\n${RED}⚠️  ВНИМАНИЕ: Это удалит ВСЕ правила INPUT/FORWARD/NAT!${NC}"
    echo -e "${RED}   Включая SSH и другие защитные правила!${NC}"
    echo -e "${YELLOW}   Убедитесь, что у вас есть альтернативный доступ (KVM/IPMI)${NC}"
    read -rp "Для продолжения введите 'DELETE ALL': " _c
    
    [[ "$_c" != "DELETE ALL" ]] && { echo -e "${GREEN}Отменено${NC}"; read -rp "Enter..."; return; }
    
    echo -e "${YELLOW}Очистка...${NC}"
    log "WARN" "Очистка всех правил (Fail2Ban backup: ${_f2b_backup_file:-none})"
    
    # Сохраняем полный бэкап перед очисткой
    local _full_backup="$BACKUP_DIR/iptables-pre-flush-$(date +%Y%m%d-%H%M%S).rules"
    iptables-save > "$_full_backup" 2>/dev/null || true
    
    # Очистка правил
    iptables -w -t nat -F 2>/dev/null || true
    iptables -w -t mangle -F 2>/dev/null || true
    iptables -w -F FORWARD 2>/dev/null || true
    iptables -w -F INPUT 2>/dev/null || true
    iptables -w -P FORWARD DROP 2>/dev/null || true
    iptables -w -P INPUT ACCEPT 2>/dev/null || true
    iptables -w -P OUTPUT ACCEPT 2>/dev/null || true
    
    echo -e "${GREEN}✅ Очищено (FORWARD=DROP, INPUT=ACCEPT)${NC}"
    log "INFO" "Очищено"
    
    # === RESTORE FAIL2BAN IF NEEDED ===
    if [[ -n "$_f2b_backup_file" ]] && [[ "$_f2b_choice" == "2" ]]; then
        echo -e "\n${CYAN}--- Восстановление Fail2Ban ---${NC}"
        restore_fail2ban_rules "$_f2b_backup_file"
        
        # Перезапускаем fail2ban если он был запущен
        if [[ $_f2b_was_running -eq 1 ]]; then
            echo -e "${YELLOW}Перезапуск Fail2Ban...${NC}"
            systemctl start fail2ban 2>/dev/null || service fail2ban start 2>/dev/null || true
            sleep 2
            if is_fail2ban_running; then
                echo -e "${GREEN}✅ Fail2Ban перезапущен${NC}"
            else
                echo -e "${RED}⚠️  Не удалось перезапустить Fail2Ban${NC}"
                echo -e "${YELLOW}   Попробуйте вручную: systemctl start fail2ban${NC}"
            fi
        fi
    fi
    # === END RESTORE ===
    
    command -v netfilter-persistent &> /dev/null && netfilter-persistent save >/dev/null 2>&1 || true
    
    read -rp "Enter..."
}

show_statistics() {
    local -a _rules_list=()
    local -a _raw_list=()
    
    parse_nat_rules _rules_list _raw_list || true
    
    echo -e "\n${CYAN}--- Статистика ---${NC}"
    [[ ${#_rules_list[@]} -eq 0 ]] && { echo -e "${YELLOW}Нет правил${NC}"; read -rp "Enter..."; return; }
    
    local _i=1
    for _rule in "${_rules_list[@]}"; do
        IFS=':' read -r _r_proto _r_port _r_dest <<< "$_rule"
        echo -e "${YELLOW}#$_i ($_r_proto:$_r_port -> ${_r_dest%:*})${NC}"
        iptables -w -L FORWARD -v -n 2>/dev/null | grep -E "dpt:${_r_port}\b|spt:$(echo "${_r_dest#*:}" | cut -d: -f1)\b" | head -2 || echo "  Нет данных"
        ((_i++)) || true
    done
    
    read -rp "Enter..."
}

test_connection() {
    local -a _rules_list=()
    local -a _raw_list=()
    
    parse_nat_rules _rules_list _raw_list || true
    
    echo -e "\n${CYAN}--- Проверка ---${NC}"
    [[ ${#_rules_list[@]} -eq 0 ]] && { echo -e "${YELLOW}Нет правил${NC}"; read -rp "Enter..."; return; }
    
    local _i=1
    for _rule in "${_rules_list[@]}"; do
        IFS=':' read -r _r_proto _r_port _r_dest <<< "$_rule"
        echo -e "${YELLOW}[$_i]${NC} $_r_proto:$_r_port -> $_r_dest"
        ((_i++)) || true
    done
    
    read -rp "Номер (0 отмена): " _num
    [[ "$_num" == "0" ]] && return
    [[ ! "$_num" =~ ^[0-9]+$ ]] || [[ -z "${_rules_list[$_num]:-}" ]] && { echo -e "${RED}Ошибка!${NC}"; read -rp "Enter..."; return; }
    
    IFS=':' read -r _test_proto _test_port _test_dest <<< "${_rules_list[$_num]}"
    local _test_ip="${_test_dest%:*}"
    local _test_dport="${_test_dest#*:}"
    
    echo -e "${YELLOW}Проверка $_test_ip:$_test_dport ($_test_proto)...${NC}"
    local _nc_result=1
    
    if [[ "$_test_proto" == "tcp" ]]; then
        timeout 5 nc -zv -w3 "$_test_ip" "$_test_dport" 2>&1 && _nc_result=0 || true
    else
        echo -e "${YELLOW}⚠️  UDP тест ненадёжен (connectionless протокол)${NC}"
        echo -e "${YELLOW}   'Успех' = пакет отправлен, но не факт что сервис ответил${NC}"
        timeout 5 nc -zuv -w3 "$_test_ip" "$_test_dport" 2>&1 && _nc_result=0 || true
    fi
    
    [[ $_nc_result -eq 0 ]] && echo -e "${GREEN}✅ Успех${NC}" || echo -e "${RED}❌ Не удалось${NC}"
    read -rp "Enter..."
}

# ==============================================
# FAIL2BAN MANAGEMENT MENU
# ==============================================

show_fail2ban_menu() {
    local _choice
    while true; do
        clear
        echo -e "${MAGENTA}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${MAGENTA}║         FAIL2BAN ИНТЕГРАЦИЯ v1.0                             ║${NC}"
        echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        if is_fail2ban_installed; then
            if is_fail2ban_running; then
                echo -e "${GREEN}● Статус: Запущен${NC}"
                local _jails
                _jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list://' | tr ',' '\n' | wc -l)
                echo -e "${CYAN}● Активных jail'ов: $_jails${NC}"
            else
                echo -e "${YELLOW}● Статус: Остановлен${NC}"
            fi
        else
            echo -e "${RED}● Статус: Не установлен${NC}"
        fi
        
        echo ""
        echo -e "1) ${CYAN}Показать статус${NC}"
        echo -e "2) ${CYAN}Показать активные цепочки в iptables${NC}"
        echo -e "3) ${GREEN}Запустить Fail2Ban${NC}"
        echo -e "4) ${YELLOW}Остановить Fail2Ban${NC}"
        echo -e "5) ${CYAN}Перезапустить Fail2Ban${NC}"
        echo -e "6) ${CYAN}Создать бэкап правил${NC}"
        echo -e "7) ${CYAN}Восстановить правила из бэкапа${NC}"
        echo -e "8) ${CYAN}Показать забаненные IP${NC}"
        echo -e "9) ${YELLOW}Разбанить IP${NC}"
        echo -e "0) ${WHITE}Назад в главное меню${NC}"
        echo -e "------------------------------------------------------"
        read -rp "Выбор: " _choice
        
        case $_choice in
            1)
                if is_fail2ban_installed; then
                    echo -e "\n${CYAN}--- Статус Fail2Ban ---${NC}"
                    fail2ban-client status 2>/dev/null || echo -e "${RED}Не удалось получить статус${NC}"
                else
                    echo -e "${RED}Fail2Ban не установлен${NC}"
                fi
                read -rp "Enter..."
                ;;
            2)
                echo -e "\n${CYAN}--- Цепочки Fail2Ban в iptables ---${NC}"
                local _chains
                _chains=$(get_fail2ban_chains)
                if [[ -n "$_chains" ]]; then
                    echo "$_chains" | while read -r chain; do
                        echo -e "\n${YELLOW}Цепочка: $chain${NC}"
                        iptables -L "$chain" -n --line-numbers 2>/dev/null | head -10 || echo "  (пусто)"
                    done
                else
                    echo -e "${YELLOW}Цепочки Fail2Ban не найдены${NC}"
                fi
                read -rp "Enter..."
                ;;
            3)
                if is_fail2ban_installed; then
                    systemctl start fail2ban 2>/dev/null || service fail2ban start 2>/dev/null || true
                    sleep 1
                    if is_fail2ban_running; then
                        echo -e "${GREEN}✅ Fail2Ban запущен${NC}"
                    else
                        echo -e "${RED}❌ Не удалось запустить${NC}"
                    fi
                else
                    echo -e "${RED}Fail2Ban не установлен. Установите: apt install fail2ban${NC}"
                fi
                read -rp "Enter..."
                ;;
            4)
                if is_fail2ban_running; then
                    systemctl stop fail2ban 2>/dev/null || service fail2ban stop 2>/dev/null || true
                    echo -e "${GREEN}✅ Fail2Ban остановлен${NC}"
                else
                    echo -e "${YELLOW}Fail2Ban уже остановлен${NC}"
                fi
                read -rp "Enter..."
                ;;
            5)
                if is_fail2ban_installed; then
                    systemctl restart fail2ban 2>/dev/null || service fail2ban restart 2>/dev/null || true
                    sleep 2
                    if is_fail2ban_running; then
                        echo -e "${GREEN}✅ Fail2Ban перезапущен${NC}"
                    else
                        echo -e "${RED}❌ Не удалось перезапустить${NC}"
                    fi
                else
                    echo -e "${RED}Fail2Ban не установлен${NC}"
                fi
                read -rp "Enter..."
                ;;
            6)
                local _backup="$F2B_BACKUP_DIR/fail2ban-manual-$(date +%Y%m%d-%H%M%S).rules"
                if get_fail2ban_rules "$_backup"; then
                    echo -e "${GREEN}✅ Бэкап создан: $_backup${NC}"
                else
                    echo -e "${YELLOW}⚠️  Нет активных цепочек для бэкапа${NC}"
                fi
                read -rp "Enter..."
                ;;
            7)
                echo -e "\n${CYAN}--- Доступные бэкапы ---${NC}"
                if [[ -d "$F2B_BACKUP_DIR" ]]; then
                    ls -1t "$F2B_BACKUP_DIR"/fail2ban-*.rules 2>/dev/null | head -10 | nl
                    read -rp "Введите номер бэкапа (0 отмена): " _bnum
                    if [[ "$_bnum" =~ ^[0-9]+$ ]] && [[ "$_bnum" -gt 0 ]]; then
                        local _selected
                        _selected=$(ls -1t "$F2B_BACKUP_DIR"/fail2ban-*.rules 2>/dev/null | head -10 | sed -n "${_bnum}p")
                        if [[ -f "$_selected" ]]; then
                            restore_fail2ban_rules "$_selected"
                        else
                            echo -e "${RED}Бэкап не найден${NC}"
                        fi
                    fi
                else
                    echo -e "${YELLOW}Директория бэкапов не найдена${NC}"
                fi
                read -rp "Enter..."
                ;;
            8)
                if is_fail2ban_running; then
                    echo -e "\n${CYAN}--- Забаненные IP ---${NC}"
                    local _jails
                    _jails=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list://' | tr ',' ' ' || true)
                    for _jail in $_jails; do
                        _jail=$(echo "$_jail" | xargs)
                        [[ -z "$_jail" ]] && continue
                        echo -e "\n${YELLOW}[$_jail]${NC}"
                        fail2ban-client status "$_jail" 2>/dev/null | grep "Currently banned:" || echo "  Нет данных"
                    done
                else
                    echo -e "${YELLOW}Fail2Ban не запущен${NC}"
                fi
                read -rp "Enter..."
                ;;
            9)
                if is_fail2ban_running; then
                    read -rp "Введите IP для разбана: " _unban_ip
                    if [[ -n "$_unban_ip" ]]; then
                        unban_ip_fail2ban "$_unban_ip"
                        echo -e "${GREEN}✅ IP $_unban_ip разбанен (если был в jail'ах)${NC}"
                    fi
                else
                    echo -e "${YELLOW}Fail2Ban не запущен${NC}"
                fi
                read -rp "Enter..."
                ;;
            0) return ;;
            *) echo -e "${RED}Ошибка! Неверный пункт меню${NC}"; sleep 1 ;;
        esac
    done
}

show_menu() {
    local _choice
    while true; do
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║         IPTABLES FORWARDING MANAGER v1.1 (Fail2Ban)           ║${NC}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
        
        # Показываем статус Fail2Ban если установлен
        if is_fail2ban_installed; then
            if is_fail2ban_running; then
                echo -e "${GREEN}● Fail2Ban: активен${NC}"
            else
                echo -e "${YELLOW}● Fail2Ban: неактивен${NC}"
            fi
        fi
        
        echo ""
        echo -e "1) ${GREEN}AmneziaWG/WireGuard${NC} (UDP)"
        echo -e "2) ${GREEN}VLESS/XRay${NC} (TCP)"
        echo -e "3) ${GREEN}TProxy/MTProto${NC} (TCP)"
        echo -e "4) ${GREEN}WireGuard Full${NC} (UDP+TCP fallback)"
        echo -e "5) ${YELLOW}🛠 Кастомное${NC}"
        echo -e "6) ${CYAN}📋 Список правил${NC}"
        echo -e "7) ${RED}🗑 Удалить правило${NC}"
        echo -e "8) ${RED}⚠️  Сброс ВСЕХ правил${NC} (с защитой Fail2Ban)"
        echo -e "9) ${MAGENTA}📚 Инструкция${NC}"
        echo -e "10) ${BLUE}📊 Статистика${NC}"
        echo -e "11) ${BLUE}🔌 Проверка соединения${NC}"
        echo -e "12) ${MAGENTA}🛡️  Fail2Ban меню${NC}"
        echo -e "0) ${WHITE}Выход${NC}"
        echo -e "------------------------------------------------------"
        read -rp "Выбор: " _choice
        case $_choice in
            1) configure_rule "udp" "AmneziaWG" ;;
            2) configure_rule "tcp" "VLESS" ;;
            3) configure_rule "tcp" "MTProto" ;;
            4) configure_both_rule ;;
            5) configure_custom_rule ;;
            6) list_active_rules ;;
            7) delete_single_rule ;;
            8) flush_rules ;;
            9) show_instructions ;;
            10) show_statistics ;;
            11) test_connection ;;
            12) show_fail2ban_menu ;;
            0) echo -e "${GREEN}Пока!${NC}"; log "INFO" "Завершён"; exit 0 ;;
            *) echo -e "${RED}Ошибка! Неверный пункт меню${NC}"; sleep 1 ;;
        esac
    done
}

main() {
    check_bash_version
    trap 'echo -e "${RED}Прерывание...${NC}"; exit 130' INT
    trap 'cleanup' EXIT
    check_root
    acquire_lock
    prepare_system
    clear
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     IPTABLES FORWARDING MANAGER v3.5 (Fail2Ban)               ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}Лог: $LOG_FILE${NC}\n${YELLOW}Бэкапы: $BACKUP_DIR${NC}"
    if is_fail2ban_installed; then
        echo -e "${MAGENTA}Fail2Ban интеграция: активна${NC}"
    fi
    sleep 1
    show_menu
}

main "$@"