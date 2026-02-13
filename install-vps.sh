#!/bin/bash
set -e

# Скрипт первичной настройки Linux-сервера
# Запускать от root

if [[ $EUID -ne 0 ]]; then
   echo "Запустите скрипт от root: sudo $0"
   exit 1
fi

# Без этого при apt upgrade вылезает диалог «оставить свой sshd_config или поставить из пакета»
export DEBIAN_FRONTEND=noninteractive

echo "=== Настройка нового сервера ==="
echo ""

# Запрос данных
read -p "Имя нового пользователя: " NEW_USER
if [[ -z "$NEW_USER" ]]; then
    echo "Имя пользователя не может быть пустым."
    exit 1
fi

read -p "Новый SSH порт (1024-65535, например 2222): " SSH_PORT
if [[ -z "$SSH_PORT" ]] || ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1024 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
    echo "Укажите корректный порт (1024-65535, порты 1-1023 зарезервированы)."
    exit 1
fi

echo "Вставьте публичный SSH ключ (одной строкой, затем Enter):"
read -r SSH_KEY
if [[ -z "$SSH_KEY" ]]; then
    echo "SSH ключ не указан."
    exit 1
fi

echo ""
echo "Будет выполнено:"
echo "  - Создан пользователь: $NEW_USER"
echo "  - SSH порт: $SSH_PORT"
echo "  - Root по SSH отключён, вход только под $NEW_USER"
echo "  - Отключена авторизация по паролю"
echo ""
read -p "Продолжить? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Отменено."
    exit 0
fi

# 0. Обновление списка пакетов
echo "[0/5] Обновление apt..."
apt-get update -qq

# 1. Создание пользователя
echo "[1/5] Создание пользователя $NEW_USER..."
useradd -m -s /bin/bash "$NEW_USER"

# 2. Права sudo
echo "[2/5] Добавление $NEW_USER в sudo..."
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$NEW_USER"
chmod 440 "/etc/sudoers.d/$NEW_USER"

# 3. SSH ключ
echo "[3/5] Настройка authorized_keys..."
mkdir -p "/home/$NEW_USER/.ssh"
echo "$SSH_KEY" >> "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"

# 4. Конфиг SSH (drop-in с префиксом 00 — загружается первым и не перезаписывается другими)
echo "[4/5] Настройка SSH..."
mkdir -p /etc/ssh/sshd_config.d
DROPIN="/etc/ssh/sshd_config.d/00-setup-server.conf"
cat > "$DROPIN" << EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
EOF
chmod 644 "$DROPIN"

# Бэкап и правки основного конфига на случай отсутствия Include
SSHD_CONF="/etc/ssh/sshd_config"
cp "$SSHD_CONF" "${SSHD_CONF}.bak"
sed -i "s/^#*Port .*/Port $SSH_PORT/" "$SSHD_CONF"
sed -i "s/^#*PermitRootLogin .*/PermitRootLogin no/" "$SSHD_CONF"
sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication no/" "$SSHD_CONF"
sed -i "s/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/" "$SSHD_CONF"

# 5. Перезапуск SSH (оставляем текущую сессию живой)
echo "[5/5] Перезапуск sshd..."
# Отключаем socket activation (слушает только 22); юнит может быть ssh.socket или sshd.socket
systemctl stop ssh.socket 2>/dev/null || true
systemctl stop sshd.socket 2>/dev/null || true
systemctl disable ssh.socket 2>/dev/null || true
systemctl disable sshd.socket 2>/dev/null || true
# Включаем сервис в автозагрузку и поднимаем (set -e не должен выйти из-за enable/start)
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true

echo ""
echo "=== Готово ==="
echo ""
