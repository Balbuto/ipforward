# 🚀 IPTables Forwarding Manager v1.1.0

[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-4.3%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.kernel.org/)
[![Tests](https://img.shields.io/badge/tests-64%2F64-brightgreen.svg)](tests/run-tests.sh)
[![ShellCheck](https://img.shields.io/badge/shellcheck-clean-brightgreen.svg)](https://www.shellcheck.net/)

Production-ready инструмент для управления правилами iptables port forwarding: атомарные операции, автоматический откат при частичном применении, бэкапы перед каждым изменением и встроенная диагностика.

> **Версия 1.1.0 — крупное исправление надёжности.** Закрыты 12 критических и 11 серьёзных дефектов версии 1.0, из-за которых скрипт отклонял валидные IP-адреса, зависал при EOF, удалял чужие правила при откате и не мог корректно снять блокировку. Полный разбор — в [docs/AUDIT.md](docs/AUDIT.md), список изменений — в [CHANGELOG.md](CHANGELOG.md).

---

## 📋 Описание

`ipforward` — менеджер правил DNAT (Destination NAT) в iptables. Предназначен для проброса портов с внешнего адреса сервера на внутренние хосты или удалённые серверы: VPN-туннели, прокси, Telegram MTProto и произвольные комбинации портов.

### Особенности

- 🛡️ **Атомарные операции** — при сбое любого шага уже созданные правила откатываются, существовавшие ранее правила не затрагиваются
- 🔒 **Блокировка параллельного запуска** — `flock` с корректным освобождением и обработкой устаревших lock-файлов
- 💾 **Автоматические бэкапы** — перед каждым изменением, с уникальными именами файлов
- ✅ **Строгая валидация** — IP-адреса, порты, диапазоны портов и формат target
- 🔍 **Проверка конфликтов** — второй DNAT на тот же порт и занятые локальные порты отсекаются до создания бэкапа
- 📊 **Статистика и диагностика** — счётчики пакетов, проверка соединения, команда `ipforward diag`
- 🔄 **Персистентность** — сохранение правил между перезагрузками через `netfilter-persistent` с fallback на `iptables-save`
- 🤖 **CLI-режим** — `--help`, `--version`, `list`, `diag` для скриптов и мониторинга
- 🌈 **Цветной интерфейс** — интерактивное меню

---

## 🎯 Поддерживаемые сервисы

| Пункт меню | Протокол | Назначение | Описание |
|-----------|----------|-----------|----------|
| 1 | UDP | AmneziaWG / WireGuard | VPN-туннели на базе WireGuard |
| 2 | TCP | VLESS / XRay | Прокси-протоколы для обхода блокировок |
| 3 | TCP | MTProto | Протокол Telegram для проксирования |
| 4 | UDP+TCP | WireGuard Full | Резервирование UDP + TCP fallback |
| 5 | Любой | Кастомное правило | Произвольные входящие/исходящие порты и протоколы |

---

## ⚡ Установка

### Быстрая установка

```bash
curl -O https://github.com/Balbuto/ipforward/raw/refs/heads/main/ipforward.sh
chmod +x ipforward.sh

# Первый запуск требует прав root
sudo ./ipforward.sh
```

При первом запуске скрипт:

- копирует себя в `/usr/local/bin/ipforward`;
- создаёт директории для логов и бэкапов;
- проверяет наличие зависимостей (`iptables`, `iproute2`, `netcat`, `netfilter-persistent`) и предлагает установить отсутствующие.

После установки доступна команда:

```bash
sudo ipforward
```

### Ручная установка

```bash
git clone https://github.com/Balbuto/ipforward.git
cd ipforward

sudo install -m 755 ipforward.sh /usr/local/bin/ipforward

# Проверка
ipforward --version   # ipforward 1.1.0
```

### Из патча

Если удобнее применить готовый дифф `v1.0 → v1.1.0` к своему клону:

```bash
git clone https://github.com/Balbuto/ipforward.git
cd ipforward
patch -p1 --dry-run < ipforward.patch   # проверка
patch -p1 < ipforward.patch             # применение
```

### Обновление с версии 1.0

Правила, созданные старой версией, полностью совместимы — формат правил не изменился. Достаточно заменить файл:

```bash
sudo install -m 755 ipforward.sh /usr/local/bin/ipforward
sudo ipforward diag        # быстрая проверка окружения после обновления
```

---

## 📖 Использование

### Интерактивный режим

```bash
sudo ipforward
```

```plain
╔══════════════════════════════════════════════════════════════╗
║         IPTABLES FORWARDING MANAGER v1.1.0                   ║
╚══════════════════════════════════════════════════════════════╝

1) AmneziaWG/WireGuard (UDP)
2) VLESS/XRay (TCP)
3) TProxy/MTProto (TCP)
4) WireGuard Full (UDP+TCP fallback)
5) 🛠 Кастомное
6) 📋 Список правил
7) 🗑 Удалить правило
8) ⚠️  Сброс ВСЕХ правил
9) 📚 Инструкция
10) 📊 Статистика
11) 🔌 Проверка соединения
0) Выход
```

### CLI-режим

```bash
ipforward --help          # справка
ipforward --version       # версия
ipforward list            # активные правила (таблицей)
ipforward list --raw      # активные правила в машиночитаемом виде
ipforward diag            # диагностика окружения, rc=1 при проблемах
```

Пример для мониторинга:

```bash
#!/bin/bash
# Проверяем, что проброс на 51820 жив
if ! ipforward list --raw | grep -q 'udp:51820'; then
    echo "Правило udp:51820 пропало!" | mail -s "ipforward alarm" admin@example.com
fi
```

### Примеры

**Создание правила для WireGuard**

```bash
$ sudo ipforward
# Выбираем пункт 1

--- AmneziaWG (UDP) ---
IP адрес: 203.0.113.50
Порт (1-65535): 51820

[*] Применение...
✅ AmneziaWG настроен!
📊 udp:51820 -> 203.0.113.50:51820
✅ Правило активно в iptables
```

**Просмотр активных правил**

```bash
$ sudo ipforward
# Выбираем пункт 6

═══════════════════════════════════════════════════════════════
              АКТИВНЫЕ ПРАВИЛА
═══════════════════════════════════════════════════════════════
№     | Протокол | Порт       | Назначение
---------------------------------------------------------------
1     | udp      | 51820      | 203.0.113.50:51820
2     | tcp      | 443        | 198.51.100.10:443
3     | tcp      | 8080       | 192.168.1.50:3128
```

**Удаление правила**

```bash
$ sudo ipforward
# Выбираем пункт 7

--- Удаление ---
[1] udp:51820 -> 203.0.113.50:51820
[2] tcp:443 -> 198.51.100.10:443
Номер (0 отмена): 1

Удаляю: udp:51820 -> 203.0.113.50:51820
✅ Удалено
```

**Проверка соединения**

```bash
$ sudo ipforward
# Выбираем пункт 11

--- Проверка ---
[1] udp:51820 -> 203.0.113.50:51820
Номер (0 отмена): 1

Проверка 203.0.113.50:51820 (udp)...
⚠️  UDP тест ненадёжен (connectionless протокол)
   'Успех' = пакет отправлен, но не факт что сервис ответил
Connection to 203.0.113.50 51820 port [udp/*] succeeded!
✅ Успех
```

---

## 🏗️ Архитектура безопасности

```plain
┌──────────────────────────────────────────────┐
│  0. preflight — проверки ДО любых изменений  │
│     ├── валидация IP / портов / target       │
│     ├── конфликтующий DNAT на тот же порт    │
│     └── занятый локальный порт (ss)          │
├──────────────────────────────────────────────┤
│  1. Проверка root + flock (блокировка)       │
│     └── lock освобождается только владельцем │
├──────────────────────────────────────────────┤
│  2. Бэкап правил                             │
│     └── /root/iptables-backups/              │
│         iptables-YYYYMMDD-HHMMSS[-n].rules   │
│         (пустой/битый бэкап => abort)        │
├──────────────────────────────────────────────┤
│  3. Применение правила (транзакция)          │
│     ├── PREROUTING (DNAT)                    │
│     ├── INPUT (ACCEPT)                       │
│     ├── FORWARD (conntrack, 2 правила)       │
│     └── POSTROUTING (MASQUERADE)             │
├──────────────────────────────────────────────┤
│  4. Верификация применения                   │
│     └── -C по каждой цепочке с -t nat        │
├──────────────────────────────────────────────┤
│  5. Откат при сбое                           │
│     └── удаляются только созданные правила,  │
│         старая цель DNAT восстанавливается   │
├──────────────────────────────────────────────┤
│  6. Персистентность                          │
│     └── netfilter-persistent / iptables-save │
└──────────────────────────────────────────────┘
```

Подробный разбор каждого механизма — в [docs/AUDIT.md](docs/AUDIT.md).

---

## ⚙️ Технические детали

### Создаваемые правила iptables

Для правила `udp:51820 -> 203.0.113.50:51820` создаются:

```bash
# 1. DNAT — перенаправление входящих пакетов
iptables -t nat -A PREROUTING \
  -p udp --dport 51820 \
  -j DNAT --to-destination 203.0.113.50:51820

# 2. Разрешение входящих соединений
iptables -A INPUT \
  -p udp --dport 51820 \
  -j ACCEPT

# 3. FORWARD — новые соединения к целевому хосту
iptables -A FORWARD \
  -p udp -d 203.0.113.50 --dport 51820 \
  -m state --state NEW,ESTABLISHED,RELATED \
  -j ACCEPT

# 4. FORWARD — ответы от целевого хоста
iptables -A FORWARD \
  -p udp -s 203.0.113.50 --sport 51820 \
  -m state --state ESTABLISHED,RELATED \
  -j ACCEPT

# 5. MASQUERADE — подмена source IP (SNAT)
iptables -t nat -A POSTROUTING \
  -o eth0 \
  -j MASQUERADE
```

Все операции идемпотентны: повторное применение того же правила не создаёт дублей.

### Системные настройки

```bash
# IP forwarding (персистентно)
net.ipv4.ip_forward=1

# BBR congestion control (если не контейнер)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
```

### Зависимости

Обязательные: `iptables`, `iproute2` (команда `ip`), `coreutils`.

Опциональные: `netfilter-persistent` / `iptables-persistent` (сохранение правил), `netcat-openbsd` (проверка соединения), `curl` (определение внешнего IP).

### Файлы и директории

| Путь | Назначение | Права |
| ------------------------------------------------------- | ------------------- | ----- |
| `/usr/local/bin/ipforward` | Исполняемый скрипт | 755 |
| `/var/log/port-forwarding.log` | Логи операций | 600 |
| `/var/log/port-forwarding.log.old` | Ротированный лог | 600 |
| `/root/iptables-backups/` | Директория бэкапов | 700 |
| `/root/iptables-backups/iptables-YYYYMMDD-HHMMSS.rules` | Бэкап правил | 600 |
| `/var/run/ipforward.lock` | Lock-файл | 644 |
| `/etc/iptables/rules.v4` | Сохранённые правила | 600 |

---

## ⚠️ Важные предупреждения

### 🔴 Сброс ВСЕХ правил (пункт 8)

Опасная операция. Требует ввода `DELETE ALL` для подтверждения и предлагает сделать бэкап.

Что сбрасывается:

- все правила цепочки INPUT;
- все правила цепочки FORWARD;
- все правила таблицы nat (PREROUTING, POSTROUTING);
- все правила таблицы mangle.

Последствия:

- потеря SSH-доступа, если были собственные правила INPUT;
- остановка всех сервисов, зависящих от форвардинга;
- политики по умолчанию: FORWARD=DROP, INPUT=ACCEPT.

Требуется физический доступ к серверу (KVM/IPMI/ILO) или альтернативный канал управления.

### 🟡 Проверка портов

Занятость порта проверяется через `ss -tuln` с учётом IPv6-сокетов (`[::]:PORT`). Нюансы:

- ложные срабатывания возможны, если порт слушает только `localhost` — DNAT при этом может работать;
- для UDP проверка менее надёжна, чем для TCP.

### 🟢 Бэкапы

Бэкапы создаются автоматически перед каждым изменением в `/root/iptables-backups/`. Если `iptables-save` вернул ошибку или пустой вывод, операция прерывается, а файл-мусор удаляется.

Восстановление вручную:

```bash
iptables-restore < /root/iptables-backups/iptables-20240315-143022.rules
```

---

## 🧪 Тестирование

В репозитории есть rootless-набор из 64 проверок на mock-утилитах (`iptables`, `iptables-save`, `ss`, `nc`, `netfilter-persistent`, `modprobe`, `sysctl`). Root-права и реальный iptables не нужны — тесты не трогают систему.

```bash
git clone https://github.com/Balbuto/ipforward.git
cd ipforward

# Полный прогон
bash tests/run-tests.sh

# С shellcheck (если установлен)
SHELLCHECK=shellcheck bash tests/run-tests.sh

# Один тест
RUN_TESTS=test_custom bash tests/run-tests.sh

# Оставить временную директорию для разбора
KEEP_TMP=1 bash tests/run-tests.sh
```

Покрытие: статический анализ, CLI, валидация, идемпотентность, конфликты портов, транзакция и откат WireGuard Full, кастомные правила, список/удаление/flush, поведение при EOF, сбой `iptables-save`, блокировка параллельного запуска.

---

## 🛠️ Требования

**Минимальные:** Linux kernel 3.0+, Bash 4.3+, root-доступ, ~1 MB свободного места.

**Рекомендуемые:** Debian 10+ / Ubuntu 18.04+ / CentOS 7+ / RHEL 8+, iptables (legacy или nftables backend), iproute2.

---

## 🐛 Устранение неполадок

| Симптом | Причина | Решение |
|---------|---------|---------|
| `Другой экземпляр уже запущен` | Остался lock-файл от убитого процесса | `sudo rm -f /var/run/ipforward.lock` |
| `Ошибка бэкапа` | Нет места на диске или `iptables-save` недоступен | Проверить `df -h /root`, `iptables-save -t nat` вручную |
| Правило есть в списке, но не работает | Не включён `ip_forward` | `sysctl net.ipv4.ip_forward` → должно быть `1` |
| После перезагрузки правил нет | `netfilter-persistent` не установлен | `apt install iptables-persistent` |
| `Порт N занят` | Порт слушает локальный сервис | Сменить порт или остановить сервис |
| Правила не видны | Смотрим другую таблицу/цепочку | `ipforward diag`, `iptables -t nat -L PREROUTING -n -v` |

Диагностика одной командой:

```bash
sudo ipforward diag
```

---

## 🤝 Участие в разработке

См. [CONTRIBUTING.md](CONTRIBUTING.md). Перед отправкой PR прогоняйте `bash tests/run-tests.sh` и `shellcheck -S warning ipforward.sh`.

Уязвимости и проблемы безопасности — по инструкции в [SECURITY.md](SECURITY.md), не через публичные issue.

---

## 📄 Лицензия

MIT © 2026 Balbuto. См. [LICENSE](LICENSE).
