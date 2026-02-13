#!/bin/bash


set -e

if [ "$EUID" -ne 0 ]; then
    echo "Запустите скрипт с правами root: sudo $0"
    exit 1
fi

# --- Определение IP и интерфейса ---
MAIN_INTERFACE=$(ip -o route get 1 2>/dev/null | grep -oP 'dev \K\S+' || ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
if [ -z "$MAIN_INTERFACE" ]; then
    echo "Не удалось определить основной сетевой интерфейс."
    exit 1
fi

SERVER_IP=$(ip -4 addr show dev "$MAIN_INTERFACE" 2>/dev/null | grep -oP '(?<=inet )[\d.]+' | head -1)
if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(ip -o route get 1 2>/dev/null | grep -oP 'src \K\S+')
fi
if [ -z "$SERVER_IP" ]; then
    echo "Не удалось определить IP-адрес сервера."
    exit 1
fi

echo "Интерфейс: $MAIN_INTERFACE, IP: $SERVER_IP"

# --- Порт SSH (не трогать) ---
SSH_PORT=$(grep -E '^Port[[:space:]]+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
[ -z "$SSH_PORT" ] && SSH_PORT=22

# --- Случайный свободный порт для VPN (10000–65535, не SSH и не занятый) ---
port_in_use() {
    local p="$1"
    ss -ulnp 2>/dev/null | grep -q ":$p " && return 0
    ss -tlnp 2>/dev/null | grep -q ":$p " && return 0
    return 1
}
LISTEN_PORT=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    candidate=$((10000 + RANDOM % 55536))
    [ "$candidate" -eq "$SSH_PORT" ] && continue
    port_in_use "$candidate" && continue
    LISTEN_PORT=$candidate
    break
done
if [ -z "$LISTEN_PORT" ]; then
    echo "Не удалось подобрать свободный порт для VPN."
    exit 1
fi
echo "Порт VPN (UDP): $LISTEN_PORT (SSH исключён: $SSH_PORT)"

# --- Параметры VPN ---
VPN_SUBNET="10.8.1.0/24"
VPN_SERVER_IP="10.8.1.1"
CONF_DIR="/etc/amnezia/amneziawg"
KEYS_DIR="$CONF_DIR/keys"

# --- Установка AmneziaWG ---
if ! command -v awg &>/dev/null; then
    echo "Установка AmneziaWG..."
    apt-get update -qq
    apt-get install -y software-properties-common
    add-apt-repository -y ppa:amnezia/ppa
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y amneziawg
fi

# --- IP forward ---
mkdir -p /etc/sysctl.d
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/00-amnezia.conf
sysctl -p /etc/sysctl.d/00-amnezia.conf

# --- Директории и ключи ---
mkdir -p "$KEYS_DIR"
chmod 700 "$KEYS_DIR"

if [ ! -f "$KEYS_DIR/server_privatekey" ]; then
    awg genkey | tee "$KEYS_DIR/server_privatekey" | awg pubkey > "$KEYS_DIR/server_publickey"
    awg genkey | tee "$KEYS_DIR/client_privatekey" | awg pubkey > "$KEYS_DIR/client_publickey"
    awg genpsk > "$KEYS_DIR/presharedkey"
    chmod 600 "$KEYS_DIR"/*
fi

# --- Параметры обфускации (ASC) ---
JC=$((4 + RANDOM % 9))
JMIN=8
JMAX=$((JMIN + 50 + RANDOM % 200))
S1=$((10 + RANDOM % 100))
S2=$((10 + RANDOM % 100))
H1=$((RANDOM * 65536 + RANDOM))
H2=$((RANDOM * 65536 + RANDOM))
H3=$((RANDOM * 65536 + RANDOM))
H4=$((RANDOM * 65536 + RANDOM))

SERVER_PRIV=$(tr -d '\n' < "$KEYS_DIR/server_privatekey")
CLIENT_PUB=$(tr -d '\n' < "$KEYS_DIR/client_publickey")
PRESHARED=$(tr -d '\n' < "$KEYS_DIR/presharedkey")

# --- Конфиг сервера (с PostUp/PostDown для NAT и фаервола) ---
cat > "$CONF_DIR/awg0.conf" << EOF
[Interface]
PrivateKey = $SERVER_PRIV
Address = ${VPN_SERVER_IP}/24
ListenPort = $LISTEN_PORT
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
PostUp = iptables -A INPUT -i $MAIN_INTERFACE -p udp --dport $LISTEN_PORT -j ACCEPT; iptables -A FORWARD -i awg0 -o $MAIN_INTERFACE -j ACCEPT; iptables -A FORWARD -i $MAIN_INTERFACE -o awg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o $MAIN_INTERFACE -j MASQUERADE
PostDown = iptables -D INPUT -i $MAIN_INTERFACE -p udp --dport $LISTEN_PORT -j ACCEPT; iptables -D FORWARD -i awg0 -o $MAIN_INTERFACE -j ACCEPT; iptables -D FORWARD -i $MAIN_INTERFACE -o awg0 -m state --state RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -s $VPN_SUBNET -o $MAIN_INTERFACE -j MASQUERADE

[Peer]
PresharedKey = $PRESHARED
PublicKey = $CLIENT_PUB
AllowedIPs = 10.8.1.2/32
EOF

# --- Первый клиентский конфиг ---
SERVER_PUB=$(tr -d '\n' < "$KEYS_DIR/server_publickey")
CLIENT_PRIV=$(tr -d '\n' < "$KEYS_DIR/client_privatekey")

mkdir -p "$CONF_DIR/clients"
cat > "$CONF_DIR/clients/awg0-client-initial.conf" << EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.8.1.2/24
DNS = 8.8.8.8, 8.8.4.4
Jc = $JC
Jmin = $JMIN
Jmax = $JMAX
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4

[Peer]
PresharedKey = $PRESHARED
PublicKey = $SERVER_PUB
Endpoint = ${SERVER_IP}:${LISTEN_PORT}
AllowedIPs = 0.0.0.0/0
EOF
chmod 600 "$CONF_DIR/clients/awg0-client-initial.conf"

# --- Скрипт добавления клиентов ---
cat > "$CONF_DIR/generate_awg_config.sh" << 'GENSCRIPT'
#!/bin/bash
set -e
if [ "$EUID" -ne 0 ]; then
    echo "Запуск: sudo $0 [имя_клиента]"
    exit 1
fi
CONF_DIR="/etc/amnezia/amneziawg"
SERVER_CONF="$CONF_DIR/awg0.conf"
CLIENT_NAME="${1:-client}"
CLIENT_CONF_FILE="$CONF_DIR/clients/awg0-client-${CLIENT_NAME}.conf"
mkdir -p "$CONF_DIR/clients"

SERVER_PRIVATE_KEY=$(grep "^PrivateKey" "$SERVER_CONF" | head -1 | awk '{print $3}')
SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | awg pubkey)
LISTEN_PORT=$(grep "^ListenPort" "$SERVER_CONF" | awk '{print $3}')
for key in Jc Jmin Jmax S1 S2 H1 H2 H3 H4; do
    val=$(grep "^$key" "$SERVER_CONF" | head -1 | awk '{print $3}')
    eval "$key=\$val"
done
SERVER_IP=$(ip -4 addr show $(ip -o route get 1 | grep -oP 'dev \K\S+') 2>/dev/null | grep -oP '(?<=inet )[\d.]+' | head -1)
[ -z "$SERVER_IP" ] && SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

EXISTING_IPS=$(grep "AllowedIPs" "$SERVER_CONF" | awk '{print $3}' | grep -oP '\d+\.\d+\.\d+\.\K\d+' 2>/dev/null || true)
LAST_IP=2
for ip in $EXISTING_IPS; do
    [ "$ip" -ge "$LAST_IP" ] && LAST_IP=$((ip + 1))
done
CLIENT_IP="10.8.1.${LAST_IP}"

CLIENT_PRIVATE_KEY=$(awg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | awg pubkey)
PRESHARED_KEY=$(awg genpsk)

cat > "$CLIENT_CONF_FILE" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = ${CLIENT_IP}/24
DNS = 8.8.8.8, 8.8.4.4
Jc = $Jc
Jmin = $Jmin
Jmax = $Jmax
S1 = $S1
S2 = $S2
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4

[Peer]
PresharedKey = $PRESHARED_KEY
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ${SERVER_IP}:${LISTEN_PORT}
AllowedIPs = 0.0.0.0/0
EOF
chmod 600 "$CLIENT_CONF_FILE"

cat >> "$SERVER_CONF" << EOF

[Peer]
PresharedKey = $PRESHARED_KEY
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = ${CLIENT_IP}/32
EOF

awg-quick down awg0 2>/dev/null || true
awg-quick up "$SERVER_CONF"

echo "Клиент: $CLIENT_CONF_FILE (IP: $CLIENT_IP)"
echo "Импортируйте этот файл в приложение AmneziaWG."
GENSCRIPT
chmod +x "$CONF_DIR/generate_awg_config.sh"

# --- Отключить UFW, если активен ---
# UFW несовместим с AmneziaWG при нескольких клиентах за одним NAT:
# conntrack помечает часть UDP-пакетов как INVALID, а UFW их дропает.
# Защита сервера обеспечивается правилами iptables в PostUp/PostDown.
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo "Отключение UFW (несовместим с AmneziaWG)..."
    ufw disable 2>/dev/null || true
fi

# --- Поднять интерфейс и включить автозапуск ---
awg-quick down awg0 2>/dev/null || true
awg-quick up awg0
systemctl enable awg-quick@awg0

# --- Сохранить iptables при наличии netfilter-persistent ---
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save 2>/dev/null || true
fi

# --- Установка awg-manager.py в домашнюю папку пользователя ---
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
REAL_HOME=$(eval echo "~$REAL_USER")
MANAGER_DIR="$REAL_HOME/AmneziaWG"
mkdir -p "$MANAGER_DIR"

cat > "$MANAGER_DIR/awg-manager.py" << 'MANAGERPY'
#!/usr/bin/env python3
"""
AmneziaWG Client Manager
Управление клиентами AmneziaWG: создание, удаление, просмотр, содержимое конфигов.
Запуск: sudo python3 awg-manager.py
"""

import subprocess
import sys
import os
import re
import textwrap

CONF_DIR = "/etc/amnezia/amneziawg"
SERVER_CONF = f"{CONF_DIR}/awg0.conf"
CLIENTS_DIR = f"{CONF_DIR}/clients"
KEYS_DIR = f"{CONF_DIR}/keys"
INTERFACE = "awg0"
SUBNET_PREFIX = "10.8.1"


class C:
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def color(text, c):
    return f"{c}{text}{C.RESET}"


def run(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        return ""
    return r.stdout.strip()


def read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError):
        return ""


def parse_server_conf():
    text = read_file(SERVER_CONF)
    if not text:
        return {}
    params = {}
    for line in text.splitlines():
        m = re.match(r"^(\w+)\s*=\s*(.+)$", line)
        if m:
            params[m.group(1)] = m.group(2).strip()
    return params


def get_server_params():
    p = parse_server_conf()
    keys = ["ListenPort", "Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"]
    return {k: p.get(k, "") for k in keys}


def get_server_public_key():
    priv = read_file(f"{KEYS_DIR}/server_privatekey").strip()
    if not priv:
        return ""
    return run(f"echo '{priv}' | awg pubkey")


def get_server_ip():
    ip = run("ip -4 addr show $(ip -o route get 1 | grep -oP 'dev \\K\\S+') | grep -oP '(?<=inet )[\\d.]+' | head -1")
    if not ip:
        ip = run("hostname -I | awk '{print $1}'")
    return ip


def get_used_ips():
    text = read_file(SERVER_CONF)
    octets = set()
    octets.add(1)
    for m in re.finditer(r"AllowedIPs\s*=\s*10\.8\.1\.(\d+)/32", text):
        octets.add(int(m.group(1)))
    return octets


def next_free_ip():
    used = get_used_ips()
    for i in range(2, 255):
        if i not in used:
            return f"{SUBNET_PREFIX}.{i}"
    return None


def list_peers_from_conf():
    text = read_file(SERVER_CONF)
    if not text:
        return []
    peers = []
    blocks = re.split(r"\n(?=\[Peer\])", text)
    for block in blocks:
        if not block.strip().startswith("[Peer]"):
            continue
        peer = {}
        for line in block.splitlines():
            m = re.match(r"^(\w+)\s*=\s*(.+)$", line)
            if m:
                peer[m.group(1)] = m.group(2).strip()
            cm = re.match(r"^#\s*client:\s*(.+)", line)
            if cm:
                peer["_name"] = cm.group(1).strip()
        if peer:
            peers.append(peer)
    return peers


def find_client_name_by_pubkey(pubkey):
    if not os.path.isdir(CLIENTS_DIR):
        return None
    for fname in os.listdir(CLIENTS_DIR):
        if not fname.endswith(".conf"):
            continue
        text = read_file(os.path.join(CLIENTS_DIR, fname))
        priv_match = re.search(r"PrivateKey\s*=\s*(\S+)", text)
        if priv_match:
            priv = priv_match.group(1)
            pub = run(f"echo '{priv}' | awg pubkey")
            if pub == pubkey:
                nm = re.match(r"awg0-client-(.+)\.conf", fname)
                if nm:
                    return nm.group(1)
    return None


def get_awg_show():
    raw = run("awg show")
    if not raw:
        return []
    peers = []
    current = None
    for line in raw.splitlines():
        if line.startswith("peer:"):
            if current:
                peers.append(current)
            current = {"pubkey": line.split(":", 1)[1].strip()}
        elif current and ":" in line:
            key, val = line.split(":", 1)
            current[key.strip()] = val.strip()
    if current:
        peers.append(current)
    return peers


def action_list():
    peers_conf = list_peers_from_conf()
    peers_live = get_awg_show()
    live_map = {p["pubkey"]: p for p in peers_live}
    if not peers_conf:
        print(color("  Нет клиентов.", C.DIM))
        return
    print()
    for i, peer in enumerate(peers_conf, 1):
        pubkey = peer.get("PublicKey", "?")
        allowed = peer.get("AllowedIPs", "?")
        name = peer.get("_name", "")
        if not name:
            name = find_client_name_by_pubkey(pubkey) or ""
        ip_display = allowed.replace("/32", "")
        live = live_map.get(pubkey, {})
        endpoint = live.get("endpoint", "")
        handshake = live.get("latest handshake", "")
        transfer_rx = live.get("transfer", "")
        status = color("offline", C.DIM)
        if handshake and handshake != "(none)":
            total_sec = 0
            for part in re.finditer(r"(\d+)\s+(hour|minute|second|day)", handshake):
                val = int(part.group(1))
                unit = part.group(2)
                if unit == "day":
                    total_sec += val * 86400
                elif unit == "hour":
                    total_sec += val * 3600
                elif unit == "minute":
                    total_sec += val * 60
                else:
                    total_sec += val
            if total_sec < 180:
                status = color("online", C.GREEN)
            else:
                status = color(f"seen {handshake}", C.YELLOW)
        label = color(name, C.BOLD) if name else color(f"peer-{i}", C.BOLD)
        print(f"  {i}. {label}")
        print(f"     IP: {color(ip_display, C.CYAN)}  |  Статус: {status}")
        if endpoint:
            print(f"     Endpoint: {endpoint}")
        if transfer_rx:
            print(f"     Трафик: {transfer_rx}")
        print()


def action_create():
    name = input(f"\n  Имя клиента: ").strip()
    if not name:
        print(color("  Имя не может быть пустым.", C.RED))
        return
    name = re.sub(r"[^a-zA-Z0-9_-]", "", name.lower().replace(" ", "_"))
    if not name:
        print(color("  Имя содержит только недопустимые символы.", C.RED))
        return
    conf_file = os.path.join(CLIENTS_DIR, f"awg0-client-{name}.conf")
    if os.path.exists(conf_file):
        print(color(f"  Клиент '{name}' уже существует.", C.RED))
        return
    client_ip = next_free_ip()
    if not client_ip:
        print(color("  Нет свободных IP в подсети.", C.RED))
        return
    server_pub = get_server_public_key()
    server_ip = get_server_ip()
    sp = get_server_params()
    if not server_pub or not server_ip or not sp.get("ListenPort"):
        print(color("  Не удалось прочитать серверные параметры.", C.RED))
        return
    client_priv = run("awg genkey")
    client_pub = run(f"echo '{client_priv}' | awg pubkey")
    psk = run("awg genpsk")
    client_conf = textwrap.dedent(f"""\
        [Interface]
        PrivateKey = {client_priv}
        Address = {client_ip}/24
        DNS = 8.8.8.8, 8.8.4.4
        Jc = {sp['Jc']}
        Jmin = {sp['Jmin']}
        Jmax = {sp['Jmax']}
        S1 = {sp['S1']}
        S2 = {sp['S2']}
        H1 = {sp['H1']}
        H2 = {sp['H2']}
        H3 = {sp['H3']}
        H4 = {sp['H4']}

        [Peer]
        PresharedKey = {psk}
        PublicKey = {server_pub}
        Endpoint = {server_ip}:{sp['ListenPort']}
        AllowedIPs = 0.0.0.0/0
    """)
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    with open(conf_file, "w") as f:
        f.write(client_conf)
    os.chmod(conf_file, 0o600)
    peer_block = textwrap.dedent(f"""\

        # client: {name}
        [Peer]
        PresharedKey = {psk}
        PublicKey = {client_pub}
        AllowedIPs = {client_ip}/32
    """)
    with open(SERVER_CONF, "a") as f:
        f.write(peer_block)
    print(f"\n  Перезапуск {INTERFACE}...")
    run(f"awg-quick down {INTERFACE} 2>/dev/null || true", check=False)
    run(f"awg-quick up {INTERFACE}")
    print(color(f"\n  Клиент '{name}' создан!", C.GREEN))
    print(f"  IP:     {color(client_ip, C.CYAN)}")
    print(f"  Конфиг: {color(conf_file, C.CYAN)}")
    print()


def action_delete():
    peers = list_peers_from_conf()
    if not peers:
        print(color("  Нет клиентов для удаления.", C.DIM))
        return
    print()
    names = []
    for i, peer in enumerate(peers, 1):
        pubkey = peer.get("PublicKey", "?")
        allowed = peer.get("AllowedIPs", "?").replace("/32", "")
        name = peer.get("_name", "")
        if not name:
            name = find_client_name_by_pubkey(pubkey) or f"peer-{i}"
        names.append((name, peer))
        print(f"  {i}. {color(name, C.BOLD)}  ({allowed})")
    print()
    choice = input("  Номер клиента для удаления (0 = отмена): ").strip()
    if not choice.isdigit() or int(choice) == 0:
        print("  Отменено.")
        return
    idx = int(choice) - 1
    if idx < 0 or idx >= len(names):
        print(color("  Неверный номер.", C.RED))
        return
    name, peer = names[idx]
    pubkey = peer.get("PublicKey", "")
    confirm = input(f"  Удалить клиента '{color(name, C.BOLD)}'? (y/n): ").strip().lower()
    if confirm != "y":
        print("  Отменено.")
        return
    text = read_file(SERVER_CONF)
    lines = text.splitlines()
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "[Peer]":
            block_start = i
            if block_start > 0 and lines[block_start - 1].strip().startswith("# client:"):
                block_start -= 1
            block = []
            j = i
            while j < len(lines):
                block.append(lines[j])
                j += 1
                if j < len(lines) and (lines[j].strip().startswith("[") or lines[j].strip().startswith("# client:")):
                    break
            block_text = "\n".join(block)
            if pubkey and pubkey in block_text:
                while new_lines and new_lines[-1].strip() == "":
                    new_lines.pop()
                if new_lines and new_lines[-1].strip().startswith("# client:"):
                    new_lines.pop()
                i = j
                continue
        new_lines.append(line)
        i += 1
    with open(SERVER_CONF, "w") as f:
        f.write("\n".join(new_lines) + "\n")
    conf_file = os.path.join(CLIENTS_DIR, f"awg0-client-{name}.conf")
    if os.path.exists(conf_file):
        os.remove(conf_file)
    print(f"\n  Перезапуск {INTERFACE}...")
    run(f"awg-quick down {INTERFACE} 2>/dev/null || true", check=False)
    run(f"awg-quick up {INTERFACE}")
    print(color(f"\n  Клиент '{name}' удалён.", C.GREEN))
    print()


def action_show():
    if not os.path.isdir(CLIENTS_DIR):
        print(color("  Нет клиентских конфигов.", C.DIM))
        return
    files = sorted([f for f in os.listdir(CLIENTS_DIR) if f.endswith(".conf")])
    if not files:
        print(color("  Нет клиентских конфигов.", C.DIM))
        return
    print()
    names = []
    for i, fname in enumerate(files, 1):
        nm = re.match(r"awg0-client-(.+)\.conf", fname)
        name = nm.group(1) if nm else fname
        names.append((name, fname))
        print(f"  {i}. {color(name, C.BOLD)}")
    print()
    choice = input("  Номер конфига (0 = отмена): ").strip()
    if not choice.isdigit() or int(choice) == 0:
        print("  Отменено.")
        return
    idx = int(choice) - 1
    if idx < 0 or idx >= len(names):
        print(color("  Неверный номер.", C.RED))
        return
    name, fname = names[idx]
    path = os.path.join(CLIENTS_DIR, fname)
    content = read_file(path)
    print(f"\n  {color(f'── {name} ──', C.BOLD)}")
    print(f"  {color(path, C.DIM)}\n")
    print(content)
    print()


def main():
    if os.geteuid() != 0:
        print(color("Требуются права root. Запустите: sudo python3 awg-manager.py", C.RED))
        sys.exit(1)
    while True:
        print(f"\n{color('  AmneziaWG Manager', C.BOLD)}")
        print(f"  {color('─' * 30, C.DIM)}")
        print(f"  {color('1', C.CYAN)}. Список клиентов и статус")
        print(f"  {color('2', C.CYAN)}. Создать клиента")
        print(f"  {color('3', C.CYAN)}. Удалить клиента")
        print(f"  {color('4', C.CYAN)}. Показать конфиг клиента")
        print(f"  {color('0', C.CYAN)}. Выход")
        print()
        choice = input("  > ").strip()
        if choice == "1":
            action_list()
        elif choice == "2":
            action_create()
        elif choice == "3":
            action_delete()
        elif choice == "4":
            action_show()
        elif choice == "0":
            print(color("  Выход.", C.DIM))
            break
        else:
            print(color("  Неверный выбор.", C.RED))


if __name__ == "__main__":
    main()
MANAGERPY

chmod +x "$MANAGER_DIR/awg-manager.py"
chown -R "$REAL_USER:$REAL_USER" "$MANAGER_DIR"
echo "Менеджер клиентов: $MANAGER_DIR/awg-manager.py"

echo ""
echo "=== AmneziaWG развёрнут ==="
echo "Сервер: $SERVER_IP, порт: $LISTEN_PORT, интерфейс: $MAIN_INTERFACE"
echo "Первый клиент: $CONF_DIR/clients/awg0-client-initial.conf"
echo "Управление: sudo python3 $MANAGER_DIR/awg-manager.py"
echo ""
