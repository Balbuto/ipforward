# 🚀 IPTables Forwarding Manager v3.4

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bash](https://img.shields.io/badge/Bash-4.3%2B-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg)](https://www.kernel.org/)

&gt; Production-ready CLI инструмент для управления правилами iptables port forwarding с атомарными операциями, автоматическим откатом и комплексными проверками безопасности.

---

## 📋 Описание

`ipforward` — интерактивный менеджер для создания и управления правилами DNAT (Destination NAT) в iptables. Предназначен для проброса портов с внешнего IP сервера на внутренние хосты или удалённые серверы.

### Особенности

- 🛡️ **Атомарные операции** — автоматический rollback при частичном применении
- 🔒 **Блокировка параллельного запуска** — через механизм `flock`
- 💾 **Автоматические бэкапы** — перед каждым изменением конфигурации
- ✅ **Валидация входных данных** — проверка IP-адресов, портов и формата target
- 📊 **Статистика и тестирование** — проверка соединений через netcat
- 🔄 **Персистентность** — автосохранение правил между перезагрузками
- 🌈 **Цветной интерфейс** — интуитивное меню с цветовой индикацией

---

## 🎯 Поддерживаемые сервисы

| Пункт меню | Протокол | Назначение | Описание |
|-----------|----------|-----------|----------|
| 1 | UDP | AmneziaWG / WireGuard | VPN-туннели на базе WireGuard |
| 2 | TCP | VLESS / XRay | Прокси-протоколы для обхода блокировок |
| 3 | TCP | MTProto | Протокол Telegram для проксирования |
| 4 | UDP+TCP | WireGuard Full | Резервирование UDP+TCP fallback |
| 5 | Любой | Кастомное правило | Произвольные порты и протоколы |

---

## ⚡ Установка

### Быстрая установка

```bash
# Скачать скрипт
curl -O https://raw.githubusercontent.com/yourusername/ipforward/main/ipforward.sh
chmod +x ipforward.sh

# Первый запуск (требуются права root)
sudo ./ipforward.sh
```

### При первом запуске скрипт автоматически:
* Установит себя в /usr/local/bin/ipforward
* Создаст необходимые директории
* Настроит логирование и бэкапы
* Установит зависимости (если нужно)

После установки доступна команда:
```bash
sudo ipforward
```
## Ручная установка
```bash
# Клонирование репозитория
git clone https://github.com/yourusername/ipforward.git
cd ipforward

# Копирование в систему
sudo cp ipforward.sh /usr/local/bin/ipforward
sudo chmod +x /usr/local/bin/ipforward

# Проверка установки
which ipforward
# Должно вывести: /usr/local/bin/ipforward
```
## 📖 Использование
## Запуск интерфейса

```bash
sudo ipforward
```
## Главное меню

```plain
╔══════════════════════════════════════════════════════════════╗
║        IPTABLES FORWARDING MANAGER v3.4 (Final)              ║
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
## Примеры использования

### Создание правила для WireGuard

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

### Просмотр активных правил

```bash
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

### Удаление правила

```bash
# Выбираем пункт 7

--- Удаление ---
[1] udp:51820 -> 203.0.113.50:51820
[2] tcp:443 -> 198.51.100.10:443
Номер (0 отмена): 1

Удаляю: udp:51820 -> 203.0.113.50:51820
✅ Удалено
```

### Проверка соединения

```bash
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

## 🏗️ Архитектура безопасности

```plain
┌─────────────────────────────────────────┐
│  1. Проверка root + flock (блокировка)  │
│     └── Предотвращение параллельного    │
│         запуска                         │
├─────────────────────────────────────────┤
│  2. Валидация входных данных            │
│     ├── IP-адрес (не localhost/сеть)    │
│     ├── Порт (1-65535)                  │
│     └── Формат target (IP:port)         │
├─────────────────────────────────────────┤
│  3. Проверка занятости порта            │
│     └── ss -tuln (сокеты в состоянии    │
│         LISTEN)                         │
├─────────────────────────────────────────┤
│  4. Создание бэкапа правил              │
│     └── /root/iptables-backups/         │
│         iptables-YYYYMMDD-HHMMSS.rules  │
├─────────────────────────────────────────┤
│  5. Применение правила                  │
│     ├── PREROUTING (DNAT)               │
│     ├── INPUT (ACCEPT)                  │
│     ├── FORWARD (conntrack)             │
│     └── POSTROUTING (MASQUERADE)        │
├─────────────────────────────────────────┤
│  6. Верификация применения              │
│     └── Проверка существования в        │
│         iptables                        │
├─────────────────────────────────────────┤
│  7. Rollback при ошибке (атомарность)   │
│     └── Для WireGuard Full: если UDP    │
│         не удалось — откатываем TCP     │
└─────────────────────────────────────────┘
```

## ⚙️ Технические детали

### Создаваемые правила iptables

При настройке правила udp:51820 -> 203.0.113.50:51820 создаются:

```bash
# 1. DNAT — перенаправление входящих пакетов
iptables -t nat -A PREROUTING \
  -p udp --dport 51820 \
  -j DNAT --to-destination 203.0.113.50:51820

# 2. Разрешение входящих соединений
iptables -A INPUT \
  -p udp --dport 51820 \
  -j ACCEPT

# 3. FORWARD — разрешение прохождения пакетов
# Новые соединения к целевому хосту
iptables -A FORWARD \
  -p udp -d 203.0.113.50 --dport 51820 \
  -m state --state NEW,ESTABLISHED,RELATED \
  -j ACCEPT

# Ответы от целевого хоста
iptables -A FORWARD \
  -p udp -s 203.0.113.50 --sport 51820 \
  -m state --state ESTABLISHED,RELATED \
  -j ACCEPT

# 4. MASQUERADE — подмена source IP (SNAT)
iptables -t nat -A POSTROUTING \
  -o eth0 \
  -j MASQUERADE
  ```
  
  ## Системные настройки
  
  ### Включаемые параметры:
  
  ```bash
  # IP forwarding (с персистентностью)
net.ipv4.ip_forward=1

# BBR congestion control (если не контейнер)
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
```

### Устанавливаемые пакеты (при необходимости):

* iptables — основной инструмент
* iptables-persistent / netfilter-persistent — сохранение правил
* iproute2 — команда ip
* netcat-openbsd — тестирование соединений
* coreutils — базовые утилиты

## 📁 Файлы и директории

```table
| Путь                                                    | Назначение          | Права |
| ------------------------------------------------------- | ------------------- | ----- |
| `/usr/local/bin/ipforward`                              | Исполняемый скрипт  | 755   |
| `/var/log/port-forwarding.log`                          | Логи операций       | 600   |
| `/var/log/port-forwarding.log.old`                      | Ротированный лог    | 600   |
| `/root/iptables-backups/`                               | Директория бэкапов  | 700   |
| `/root/iptables-backups/iptables-YYYYMMDD-HHMMSS.rules` | Бэкап правил        | 600   |
| `/var/run/ipforward.lock`                               | Lock-файл           | 644   |
| `/etc/iptables/rules.v4`                                | Сохранённые правила | 600   |

```

## ⚠️ Важные предупреждения

### 🔴 Операция "Сброс ВСЕХ правил" (пункт 8)

Опасная операция! Требует ввода DELETE ALL для подтверждения.

Что сбрасывается:

* Все правила цепочки INPUT
* Все правила цепочки FORWARD
* Все правила таблицы nat (PREROUTING, POSTROUTING)
* Все правила таблицы mangle

Последствия:

* Потеря SSH-доступа (если были кастомные правила INPUT)
* Остановка всех сервисов, зависящих от форвардинга
* Сброс политик по умолчанию (FORWARD=DROP, INPUT=ACCEPT)
 
## Требования:

* Физический доступ к серверу (KVM/IPMI/ILO)
* Или альтернативный канал управления
 
### 🟡 Проверка портов
Скрипт проверяет занятость порта через ss -tuln, но есть нюансы:

* Ложные срабатывания: DNAT может работать даже если порт "занят" другим сервисом на другом интерфейсе (например, localhost)
* UDP: Проверка менее надёжна, чем для TCP (connectionless протокол)
 
🟢 Бэкапы

* Бэкапы создаются автоматически перед каждым изменением
* Хранятся в /root/iptables-backups/
* Для восстановления вручную:
```bash
iptables-restore < /root/iptables-backups/iptables-20240315-143022.rules
```

## 🛠️ Требования

### Минимальные

Linux kernel 3.0+

Bash 4.3+

Root-доступ (sudo)

1 MB свободного места

### Рекомендуемые
Debian 10+ / Ubuntu 18.04+ / CentOS 7+ / RHEL 8+

iptables (legacy или nftables backend)

iproute2 (пакет iproute2)

netcat-openbsd или netcat-traditional

### Проверка зависимостей

```bash
# Проверка Bash версии
bash --version  # Должно быть 4.3+

# Проверка iptables
iptables --version
iptables-save --version

# Проверка iproute2
ip -V

# Проверка netcat
nc -h
```

## 🐛 Устранение неполадок

### Скрипт не запускается
```bash
# Проверка прав
sudo -i
whoami  # Должно быть root

# Проверка Bash
echo $BASH_VERSION  # Должно быть 4.3+

# Проверка lock-файла
ls -la /var/run/ipforward.lock
# Если завис — удалить вручную:
rm -f /var/run/ipforward.lock
```

### Правило не работает
```bash
# Проверка существования правила
sudo iptables -t nat -L PREROUTING -n -v | grep 51820

# Проверка IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Должно быть 1

# Проверка MASQUERADE
sudo iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE

# Проверка conntrack
lsmod | grep conntrack
```

### Порт занят, но DNAT нужен
```bash
# Проверить что именно слушает порт
sudo ss -tulnp | grep 51820

# Если это другой сервис — изменить входящий порт в DNAT
# Исходящий порт (target) остаётся прежним
```

### Проблемы с UFW

Если используется UFW, скрипт предложит добавить правило автоматически. 

Для ручного добавления:
```bash
sudo ufw allow 51820/udp
```

