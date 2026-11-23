#!/usr/bin/env bash
# ==============================================================================
#  Локальный тестовый фреймворк для ipforward.sh
# ==============================================================================
#  Запускается БЕЗ root и БЕЗ iptables: в PATH подкладываются mock-утилиты,
#  которые ведут «виртуальную» таблицу правил в $TEST_TMP/*. Благодаря этому
#  можно проверять логику скрипта (валидацию, идемпотентность, откаты, удаление)
#  на любом Linux/macOS с bash >= 4.3 и без риска для реального firewall.
#
#  Использование:
#      bash tests/run-tests.sh            # все тесты
#      bash tests/run-tests.sh -v         # с выводом каждого шага
#      SHELLCHECK=/path/to/shellcheck bash tests/run-tests.sh
# ==============================================================================
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
SCRIPT="$REPO_DIR/ipforward.sh"

TEST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/ipforward-tests.XXXXXX")
MOCK_DIR="$TEST_TMP/bin"
RULES_DIR="$TEST_TMP/rules"
BACKUP_DIR="$TEST_TMP/backups"
export TEST_TMP MOCK_DIR RULES_DIR BACKUP_DIR
export MOCK_LOG="$TEST_TMP/calls.log"
export MOCK_LOG_PATH="$TEST_TMP/calls.log"
export MOCK_RULES_DIR="$TEST_TMP/rules"
mkdir -p "$MOCK_DIR" "$RULES_DIR" "$BACKUP_DIR"
: > "$MOCK_LOG"

VERBOSE=0
VERBOSE="${VERBOSE:-0}"
[[ "${1:-}" == "-v" ]] && VERBOSE=1
export VERBOSE

PASS_FILE="$TEST_TMP/.pass"
FAIL_FILE="$TEST_TMP/.fail"
NAMES_FILE="$TEST_TMP/.failed"
: > "$PASS_FILE"; : > "$FAIL_FILE"; : > "$NAMES_FILE"

# ---------------------------------------------------------------- утилиты
c_red=$'\033[0;31m'; c_green=$'\033[0;32m'; c_yellow=$'\033[1;33m'; c_nc=$'\033[0m'
if [[ ! -t 1 ]]; then c_red=""; c_green=""; c_yellow=""; c_nc=""; fi

ok()  { echo x >> "$PASS_FILE"; printf "  ${c_green}✔${c_nc} %s\n" "$1"; }
bad() { echo x >> "$FAIL_FILE"; echo "$1" >> "$NAMES_FILE"; printf "  ${c_red}✘${c_nc} %s%s\n" "$1" "${2:+ — $2}"; }
pass_count() { wc -l < "$PASS_FILE" | tr -d ' '; }
fail_count() { wc -l < "$FAIL_FILE" | tr -d ' '; }
section() { printf "\n${c_yellow}%s${c_nc}\n" "$1"; }

assert_eq() {
    local _name="$1" _got="$2" _want="$3"
    if [[ "$_got" == "$_want" ]]; then ok "$_name"; else bad "$_name" "получено '$_got', ожидалось '$_want'"; fi
}

assert_contains() {
    local _name="$1" _hay="$2" _needle="$3"
    if [[ "$_hay" == *"$_needle"* ]]; then ok "$_name"; else bad "$_name" "нет '$_needle' в выводе"; fi
}

db() { echo "$RULES_DIR/rules"; }
db_count() { grep -c -- "$1" "$RULES_DIR/rules" 2>/dev/null || true; }
db_reset() { : > "$RULES_DIR/rules"; }
backups_reset() { rm -rf "${BACKUP_DIR:?}"/* 2>/dev/null || true; }
backups_count() { ls -1 "$BACKUP_DIR" 2>/dev/null | wc -l | tr -d ' '; }
calls_reset() { : > "$MOCK_LOG"; }

# Вспомогательные «тулзы» для тестов, чтобы не зависеть от системных
require_cmds() {
    local _c
    for _c in "$@"; do
        command -v "$_c" >/dev/null 2>&1 || { printf "  %s•%s нет утилиты %s — тест будет неполным\n" "$c_yellow" "$c_nc" "$_c"; }
    done
}
sleep() { :; }   # ускоряем тесты (скрипт делает sleep 1 после применения)

# ---------------------------------------------------------------- mock-утилиты
_write_mocks() {
    # iptables: -A/-D/-C с учётом таблицы и цепочки, база — плоский файл
    cat > "$MOCK_DIR/iptables" <<MOCK
#!/bin/bash
echo "iptables \$*" >> "$MOCK_LOG_PATH"
TABLE=filter; CHAIN=""; OP=""; RULE=()
args=("\$@"); idx=0
while [[ \$idx -lt \${#args[@]} ]]; do
    a="\${args[\$idx]}"
    case "\$a" in
        -t) idx=\$((idx + 1)); TABLE="\${args[\$idx]}" ;;
        -C|-D|-A|-F) OP="\$a" ;;
        -p|-j|--dport|--to-destination|-o|-s|-d|--sport|-m|--state) RULE+=("\$a"); idx=\$((idx + 1)); RULE+=("\${args[\$idx]}") ;;
        -w|--) : ;;
        *) [[ -z "\$CHAIN" ]] && CHAIN="\$a" ;;
    esac
    idx=\$((idx + 1))
done
KEY="\${TABLE}|\${CHAIN}|\${RULE[*]}"
DB="\$MOCK_RULES_DIR/rules"
touch "\$DB"
if [[ -n "\${MOCK_FAIL_UDP_A:-}" && "\$KEY" == *"nat|PREROUTING"* && "\$KEY" == *"|-p udp "* ]]; then
    echo "iptables \$* (FAIL simulated)" >> "\$MOCK_LOG_PATH"; exit 1
fi
case "\$OP" in
    -C) grep -qxF -- "\$KEY" "\$DB" && exit 0 || exit 1 ;;
    -D) grep -vxF -- "\$KEY" "\$DB" > "\$DB.tmp" 2>/dev/null; mv "\$DB.tmp" "\$DB"; exit 0 ;;
    -A) grep -qxF -- "\$KEY" "\$DB" || echo "\$KEY" >> "\$DB"; exit 0 ;;
    -F)
        if [[ -z "\$CHAIN" ]]; then
            grep -v "^\${TABLE}|" "\$DB" > "\$DB.tmp" 2>/dev/null; mv "\$DB.tmp" "\$DB"
        else
            grep -vF -- "\${TABLE}|\${CHAIN}|" "\$DB" > "\$DB.tmp" 2>/dev/null; mv "\$DB.tmp" "\$DB"
        fi
        exit 0 ;;
    -P|"") exit 0 ;;
esac
exit 0
MOCK

    cat > "$MOCK_DIR/iptables-save" <<MOCK
#!/bin/bash
echo "iptables-save \$*" >> "$MOCK_LOG_PATH"
[[ -n "\${MOCK_FAIL_SAVE:-}" ]] && exit 1
if [[ " \$* " == *" -t nat "* ]]; then
    echo "*nat"
    grep '^nat|' "\$MOCK_RULES_DIR/rules" 2>/dev/null | while IFS='|' read -r _t _c _r; do
        echo "-A \${_c} \${_r}"
    done
    echo "COMMIT"
else
    echo "*filter"
    grep '^filter|' "\$MOCK_RULES_DIR/rules" 2>/dev/null | while IFS='|' read -r _t _c _r; do
        echo "-A \${_c} \${_r}"
    done
    echo "COMMIT"
fi
exit 0
MOCK

    local _nm
    for _nm in netfilter-persistent ufw modprobe sysctl nc; do
        printf '#!/bin/bash\necho "%s $*" >> "%s"\nexit 0\n' "$_nm" "$MOCK_LOG" > "$MOCK_DIR/$_nm"
    done
    # ss: только ssh на 22 — для проверки «порт занят»
    cat > "$MOCK_DIR/ss" <<'MOCK'
#!/bin/bash
echo "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*"
echo "tcp   LISTEN 0      128             [::]:22           [::]:*"
MOCK
    chmod +x "$MOCK_DIR"/*
}

# ---------------------------------------------------------------- загрузка скрипта
_load_lib() {
    # Подменяем пути и грузим функции скрипта как библиотеку (main не стартует).
    #
    # Важная тонкость bash: `source` внутри функции + `declare -r` внутри
    # sourced-файла создаёт ЛОКАЛЬНЫЕ readonly-переменные, и после возврата из
    # функции констант (${RED}, ${BACKUP_DIR}, ...) уже нет — под `set -u`
    # любая функция скрипта падает на первом обращении. Поэтому в копии для
    # тестов `declare -r` -> `declare -gr`, а обычные `declare` -> `declare -g`,
    # чтобы переменные создавались глобально, даже находясь внутри функции.
    sed -e "s|/root/iptables-backups|$BACKUP_DIR|" \
        -e "s|/var/log/port-forwarding.log|$TEST_TMP/port-forwarding.log|" \
        -e "s|/usr/local/bin/|$TEST_TMP/bin-install/|" \
        -e "s|/var/run/|$TEST_TMP/|" \
        -e "s|/proc/sys/net/ipv4/ip_forward|$TEST_TMP/ip_forward|" \
        -e 's/^declare -r /declare -gr /' \
        -e 's/^declare /declare -g /' \
        "$SCRIPT" > "$TEST_TMP/ipforward-lib.sh"
    # shellcheck source=/dev/null
    source "$TEST_TMP/ipforward-lib.sh"
    # RULE_FILE читает sourced-копия скрипта
    # shellcheck disable=SC2034
    RULE_FILE="$RULES_DIR/rules"
}

# ---------------------------------------------------------------- тесты
test_static() {
    section "1. Статический анализ"
    bash -n "$SCRIPT" && ok "bash -n: синтаксис" || bad "bash -n: синтаксис"

    local sc="${SHELLCHECK:-}"
    if [[ -z "$sc" ]] && command -v shellcheck &>/dev/null; then sc="shellcheck"; fi
    if [[ -n "$sc" && -x "$sc" || -n "$sc" && "$sc" != "" ]]; then
        if "$sc" -S warning "$SCRIPT" > "$TEST_TMP/shellcheck.log" 2>&1; then
            ok "shellcheck (warning+): чисто"
        else
            bad "shellcheck" "$(head -3 "$TEST_TMP/shellcheck.log" | tr '\n' ' ')"
        fi
    else
        printf "  %s•%s shellcheck не найден — пропуск\n" "$c_yellow" "$c_nc"
    fi

    # обязательные маркеры
    grep -q '^#!/bin/bash' "$SCRIPT" && ok "shebang" || bad "shebang"
    grep -q 'SCRIPT_VERSION=' "$SCRIPT" && ok "версия объявлена" || bad "версия объявлена"
}

test_cli() {
    section "2. CLI (--help / --version / неизвестная команда)"
    assert_contains "--version" "$("$SCRIPT" --version 2>&1)" "ipforward"
    assert_contains "--help" "$("$SCRIPT" --help 2>&1)" "Использование"
    "$SCRIPT" --help >/dev/null 2>&1; assert_eq "--help rc" "$?" "0"
    "$SCRIPT" definitely-not-a-command >/dev/null 2>&1; assert_eq "неизвестная команда rc=2" "$?" "2"
}

test_validation() {
    section "3. Валидация ввода"
    _load_lib

    validate_ip "203.0.113.50" && ok "валидный IP" || bad "валидный IP"
    validate_ip "8.8.8.8" && ok "валидный IP 8.8.8.8" || bad "валидный IP 8.8.8.8"
    validate_ip "10.0.0.1" && ok "валидный IP 10.0.0.1" || bad "валидный IP 10.0.0.1"

    local ip
    for ip in "0.1.2.3" "127.0.0.1" "224.0.0.1" "255.255.255.255" "169.254.1.1" "300.1.1.1" "1.2.3" "abc" "" "1.2.3.4.5"; do
        if validate_ip "$ip"; then bad "отклонение [$ip]" "принят"; else ok "отклонение [$ip]"; fi
    done

    validate_target "203.0.113.50:51820" && ok "валидный target" || bad "валидный target"
    validate_target "203.0.113.50:0" && bad "порт 0 в target" "принят" || ok "порт 0 в target отклонён"
    validate_target "203.0.113.50:70000" && bad "порт 70000 в target" "принят" || ok "порт 70000 в target отклонён"

    validate_port "1" && ok "порт 1" || bad "порт 1"
    validate_port "65535" && ok "порт 65535" || bad "порт 65535"
    validate_port "65536" && bad "порт 65536" "принят" || ok "порт 65536 отклонён"
    validate_port "08" && ok "порт с ведущим нулём" || bad "порт с ведущим нулём"
    validate_port "abc" && bad "порт abc" "принят" || ok "порт abc отклонён"
}

test_create_idempotent() {
    section "4. Создание правил и идемпотентность"
    require_cmds iptables-save sed grep
    _load_lib
    db_reset; backups_reset

    confirm_and_apply udp 51820 51820 203.0.113.50 "WG" <<< "" >/dev/null 2>&1
    assert_eq "DNAT создан"        "$(db_count 'nat|PREROUTING')" "1"
    assert_eq "INPUT создан"       "$(db_count 'filter|INPUT')" "1"
    assert_eq "FORWARD (2 правила)" "$(db_count 'filter|FORWARD')" "2"
    assert_eq "бэкап один"         "$(backups_count)" "1"

    confirm_and_apply udp 51820 51820 203.0.113.50 "WG" <<< "" >/dev/null 2>&1
    assert_eq "повтор: DNAT не дублируется"    "$(db_count 'nat|PREROUTING')" "1"
    assert_eq "повтор: FORWARD не дублируется" "$(db_count 'filter|FORWARD')" "2"
    assert_eq "повтор: один новый бэкап"       "$(backups_count)" "2"
}

test_conflicts() {
    section "5. Конфликты и занятые порты"
    _load_lib
    db_reset; backups_reset
    confirm_and_apply udp 51820 51820 203.0.113.50 "WG" <<< "" >/dev/null 2>&1
    backups_reset

    local out
    out=$(confirm_and_apply udp 51820 51820 203.0.113.99 "X" <<< "" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    assert_contains "второй DNAT на тот же порт заблокирован" "$out" "уже есть DNAT"
    assert_eq "второй DNAT не создан" "$(db_count 'nat|PREROUTING')" "1"

    out=$(confirm_and_apply tcp 22 22 203.0.113.70 "V" <<< "" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    assert_contains "занятый порт заблокирован" "$out" "Порт 22 занят"
    assert_eq "бэкап не создаётся для отклонённой операции" "$(backups_count)" "0"
}

test_both_rollback() {
    section "6. «WireGuard Full»: транзакция и откат"
    _load_lib
    db_reset; backups_reset

    configure_both_rule <<< $'203.0.113.60\n51821\n' >/dev/null 2>&1
    assert_eq "оба протокола применены" "$(db_count 'nat|PREROUTING')" "2"

    # откат: ломаем UDP на уровне mock-iptables
    db_reset; backups_reset
    MOCK_FAIL_UDP_A=1
    export MOCK_FAIL_UDP_A
    configure_both_rule <<< $'203.0.113.60\n51821\n' >/dev/null 2>&1
    unset MOCK_FAIL_UDP_A
    assert_eq "после сбоя UDP: DNAT TCP откатан" "$(db_count 'nat|PREROUTING')" "0"
    assert_eq "после сбоя UDP: INPUT откатан"    "$(db_count 'filter|INPUT')" "0"

    # сценарий «правило уже было» — откат не должен его удалять
    db_reset
    confirm_and_apply tcp 51821 51821 203.0.113.60 "Old" <<< "" >/dev/null 2>&1
    local before
    before=$(db_count 'nat|PREROUTING')
    MOCK_FAIL_UDP_A=1
    export MOCK_FAIL_UDP_A
    configure_both_rule <<< $'203.0.113.60\n51821\ny\n' >/dev/null 2>&1
    unset MOCK_FAIL_UDP_A
    assert_eq "откат не удалил существовавшее правило" "$(db_count 'nat|PREROUTING')" "$before"
}

test_custom() {
    section "7. Кастомное правило (разные вх/исх порты)"
    _load_lib
    db_reset; backups_reset
    configure_custom_rule <<< $'tcp\n198.51.100.10\n8080\n3128\n' >/dev/null 2>&1
    assert_eq "DNAT на входящий 8080" "$(db_count 'nat|PREROUTING|-p tcp --dport 8080')" "1"
    assert_eq "цель — порт 3128"      "$(db_count 'to-destination 198.51.100.10:3128')" "1"
}

test_list_delete_flush() {
    section "8. Список, удаление, полный сброс"
    _load_lib
    db_reset; backups_reset
    confirm_and_apply udp 51820 51820 203.0.113.50 "WG" <<< "" >/dev/null 2>&1
    configure_both_rule <<< $'203.0.113.60\n51821\n' >/dev/null 2>&1
    configure_custom_rule <<< $'tcp\n198.51.100.10\n8080\n3128\n' >/dev/null 2>&1
    assert_eq "всего 4 правила" "$(db_count 'nat|PREROUTING')" "4"

    local list_out
    list_out=$(list_active_rules <<< "" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    assert_eq "список: 4 строки" "$(echo "$list_out" | grep -cE '^[0-9]+ +\|')" "4"

    # удаление правила №1 (udp 51820)
    delete_single_rule <<< $'1\n' >/dev/null 2>&1
    assert_eq "после удаления осталось 3" "$(db_count 'nat|PREROUTING')" "3"
    assert_eq "INPUT удалён вместе с правилом" "$(db_count 'filter|INPUT')" "3"

    # правило с диапазоном портов (создано вручную) — удаление честное
    db_reset
    echo "nat|PREROUTING|-p tcp --dport 40000:50000 -j DNAT --to-destination 203.0.113.50:40000" >> "$RULES_DIR/rules"
    delete_single_rule <<< $'1\n' >/dev/null 2>&1
    assert_eq "правило с диапазоном удалено" "$(db_count 'nat|PREROUTING')" "0"

    # flush
    confirm_and_apply udp 51821 51821 203.0.113.60 "WG" <<< "" >/dev/null 2>&1
    flush_rules <<< $'n\nDELETE ALL\n' >/dev/null 2>&1
    assert_eq "flush удалил все DNAT" "$(db_count 'nat|PREROUTING')" "0"
}

test_eof_menu() {
    section "9. EOF / неинтерактивный ввод"
    _load_lib
    db_reset
    local out rc
    out=$(timeout 10 bash -c 'source "$1"; show_menu; echo "[menu returned]"' _ "$TEST_TMP/ipforward-lib.sh" < /dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    rc=$?
    assert_eq "меню завершилось по EOF (rc=0)" "$rc" "0"
    assert_contains "меню не ушло в busy-loop" "$out" "Пока"
    if [[ $(echo "$out" | wc -l) -lt 100 ]]; then ok "нет разрастания вывода"; else bad "нет разрастания вывода"; fi
}

test_eof_input() {
    section "10. EOF при вводе IP (пункт меню)"
    _load_lib
    db_reset
    local out rc
    out=$(printf '1\n' | timeout 10 bash -c 'source "$1"; configure_rule udp WG; echo "[returned from configure_rule]"' _ "$TEST_TMP/ipforward-lib.sh" 2>&1)
    rc=$?
    assert_eq "выход без зависания (rc=0)" "$rc" "0"
    assert_contains "вернулись из configure_rule" "$out" "returned from configure_rule"
    if [[ $(echo "$out" | grep -c "Пустой ввод") -lt 5 ]]; then ok "нет циклов «Пустой ввод»"; else bad "нет циклов «Пустой ввод»"; fi
}

test_backup_fail() {
    section "11. Сбой iptables-save"
    _load_lib
    db_reset; backups_reset
    MOCK_FAIL_SAVE=1
    export MOCK_FAIL_SAVE
    local out
    out=$(backup_rules 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
    unset MOCK_FAIL_SAVE
    assert_contains "сообщение об ошибке" "$out" "Ошибка бэкапа"
    backup_rules >/dev/null 2>&1; assert_eq "при успехе rc=0" "$?" "0"
    assert_eq "бэкап-файл создан" "$(backups_count)" "1"
}

test_lock() {
    section "12. Блокировка параллельного запуска"
    local out
    out=$(timeout 10 bash -c '
        source "$1"
        exec 9>"$TEST_TMP/ipforward.lock"
        flock -n 9 || exit 2
        ( source "$1"; acquire_lock ) >/dev/null 2>&1
        ( source "$1"; acquire_lock ) >/dev/null 2>&1; echo "third_rc=$?"
    ' _ "$TEST_TMP/ipforward-lib.sh" 2>&1)
    assert_contains "второй экземпляр заблокирован" "$out" "third_rc=1"
}

test_persist_paths() {
    section "13. Файлы и пути"
    _load_lib
    assert_eq "LOCK_FILE подменён для тестов" "$(dirname "$LOCK_FILE")" "$TEST_TMP"
    assert_eq "BACKUP_DIR подменён для тестов" "$BACKUP_DIR" "$BACKUP_DIR"
}

# ---------------------------------------------------------------- main
main() {
    printf "ipforward test suite\n"
    printf "скрипт: %s\n" "$SCRIPT"
    printf "временная директория: %s\n" "$TEST_TMP"
    command -v flock >/dev/null || { echo "flock не найден — часть тестов будет пропущена"; }

    _write_mocks
    # PATH с mock-утилитами; при этом оставляем системные sed/awk/grep
    export PATH="$MOCK_DIR:$PATH"

    # Каждый тест — отдельный подпроцесс: скрипт объявляет константы через
    # declare -r, повторный source в той же оболочке невозможен.
    local _t
    local -a _tests=(
        test_static test_cli test_validation test_create_idempotent
        test_conflicts test_both_rollback test_custom test_list_delete_flush
        test_eof_menu test_eof_input test_backup_fail test_lock test_persist_paths
    )
    for _t in "${_tests[@]}"; do
        [[ -n "${RUN_TESTS:-}" && " $RUN_TESTS " != *" $_t "* ]] && continue
        ( "$_t" )
    done

    local _pass _fail
    _pass=$(pass_count); _fail=$(fail_count)
    printf "\n===============================================\n"
    printf "Пройдено: %d, провалено: %d\n" "$_pass" "$_fail"
    if [[ $_fail -gt 0 ]]; then
        printf "%sПровалившиеся тесты:%s\n" "$c_red" "$c_nc"
        sed 's/^/  - /' "$NAMES_FILE"
        [[ -n "${KEEP_TMP:-}" ]] || rm -rf "$TEST_TMP"
        exit 1
    fi
    printf "%sВсе тесты пройдены%s\n" "$c_green" "$c_nc"
    [[ -n "${KEEP_TMP:-}" ]] || rm -rf "$TEST_TMP"
    exit 0
}

main "$@"
