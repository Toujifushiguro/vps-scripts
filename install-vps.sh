#!/bin/bash
set -e

# Linux server initial setup script
# Run as root

if [[ $EUID -ne 0 ]]; then
   echo "Run as root: sudo $0"
   exit 1
fi

# Prevents apt upgrade from prompting about sshd_config
export DEBIAN_FRONTEND=noninteractive

echo "=== New server setup ==="
echo ""

# Prompt for data
read -p "New username: " NEW_USER
if [[ -z "$NEW_USER" ]]; then
    echo "Username cannot be empty."
    exit 1
fi

read -p "New SSH port (1024-65535, e.g. 2222): " SSH_PORT
if [[ -z "$SSH_PORT" ]] || ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1024 ]] || [[ "$SSH_PORT" -gt 65535 ]]; then
    echo "Specify a valid port (1024-65535, ports 1-1023 are reserved)."
    exit 1
fi

echo "Paste your public SSH key (single line, then Enter):"
read -r SSH_KEY
if [[ -z "$SSH_KEY" ]]; then
    echo "SSH key not provided."
    exit 1
fi

echo ""
echo "Will perform:"
echo "  - Create user: $NEW_USER"
echo "  - SSH port: $SSH_PORT"
echo "  - Disable root login, login only as $NEW_USER"
echo "  - Disable password authentication"
echo ""
read -p "Continue? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    echo "Cancelled."
    exit 0
fi

# 0. Update package list
echo "[0/5] Updating apt..."
apt-get update -qq

# 1. Create user
echo "[1/5] Creating user $NEW_USER..."
useradd -m -s /bin/bash "$NEW_USER"

# 2. Sudo privileges
echo "[2/5] Adding $NEW_USER to sudo..."
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/$NEW_USER"
chmod 440 "/etc/sudoers.d/$NEW_USER"

# 3. SSH key
echo "[3/5] Setting up authorized_keys..."
mkdir -p "/home/$NEW_USER/.ssh"
echo "$SSH_KEY" >> "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"

# 4. SSH config (drop-in with 00 prefix)
echo "[4/5] Configuring SSH..."
mkdir -p /etc/ssh/sshd_config.d
DROPIN="/etc/ssh/sshd_config.d/00-setup-server.conf"
cat > "$DROPIN" << EOF
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
EOF
chmod 644 "$DROPIN"

# Backup and modify main config if Include is absent
SSHD_CONF="/etc/ssh/sshd_config"
cp "$SSHD_CONF" "${SSHD_CONF}.bak"
sed -i "s/^#*Port .*/Port $SSH_PORT/" "$SSHD_CONF"
sed -i "s/^#*PermitRootLogin .*/PermitRootLogin no/" "$SSHD_CONF"
sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication no/" "$SSHD_CONF"
sed -i "s/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/" "$SSHD_CONF"

# 5. Restart SSH
echo "[5/5] Restarting sshd..."
# Disable socket activation
systemctl stop ssh.socket 2>/dev/null || true
systemctl stop sshd.socket 2>/dev/null || true
systemctl disable ssh.socket 2>/dev/null || true
systemctl disable sshd.socket 2>/dev/null || true
# Enable and start the service
systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true

echo ""
echo "=== Done ==="
echo ""
