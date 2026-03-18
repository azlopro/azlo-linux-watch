#!/bin/bash
set -e

SERVICE_USER="azlo-watch"
NOLOGIN=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)

# Create dedicated system user
if ! id "${SERVICE_USER}" &>/dev/null; then
  useradd \
    --system \
    --no-create-home \
    --shell "${NOLOGIN}" \
    --comment "azlo-linux-watch daemon" \
    "${SERVICE_USER}"
fi

# Add to utmp group so 'who' is readable
if getent group utmp &>/dev/null; then
  usermod -aG utmp "${SERVICE_USER}" 2>/dev/null || true
fi

# Ensure /opt directory exists
mkdir -p /opt/azlo-linux-watch
chown root:root /opt/azlo-linux-watch
chmod 755 /opt/azlo-linux-watch

# Fix env file permissions (nfpm installs it, but be safe)
if [ -f /etc/azlo-linux-watch/env ]; then
  chown root:root /etc/azlo-linux-watch/env
  chmod 600 /etc/azlo-linux-watch/env
fi

systemctl daemon-reload
systemctl enable azlo-linux-watch

# If webhook URL is not yet configured, print instructions instead of starting
if grep -q '^DISCORD_WEBHOOK_URL=$' /etc/azlo-linux-watch/env 2>/dev/null; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║        azlo-linux-watch — one more step!                    ║"
  echo "╠══════════════════════════════════════════════════════════════╣"
  echo "║  1. Edit:   sudo nano /etc/azlo-linux-watch/env             ║"
  echo "║             Set DISCORD_WEBHOOK_URL=<your Discord URL>      ║"
  echo "║  2. Start:  sudo systemctl start azlo-linux-watch           ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
else
  systemctl restart azlo-linux-watch 2>/dev/null || systemctl start azlo-linux-watch
fi
