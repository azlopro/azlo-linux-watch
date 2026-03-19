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

# Add to adm group so auth.log is readable
if getent group adm &>/dev/null; then
  usermod -aG adm "${SERVICE_USER}" 2>/dev/null || true
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

# Ensure pam-notify.sh is executable
if [ -f /opt/azlo-linux-watch/pam-notify.sh ]; then
  chmod 755 /opt/azlo-linux-watch/pam-notify.sh
fi

# Install PAM hook for sshd if not already present
if [ -d /etc/pam.d ] && [ -f /etc/pam.d/azlo-linux-watch ]; then
  # Hook into sshd PAM config if not already done
  if [ -f /etc/pam.d/sshd ] && ! grep -q 'azlo-linux-watch' /etc/pam.d/sshd 2>/dev/null; then
    echo '# azlo-linux-watch instant login detection' >> /etc/pam.d/sshd
    echo '@include azlo-linux-watch' >> /etc/pam.d/sshd
  fi
fi

# Register APT repository for automatic updates (Debian/Ubuntu only)
APT_SOURCE="/etc/apt/sources.list.d/azlo-linux-watch.list"
if command -v apt &>/dev/null && [ ! -f "${APT_SOURCE}" ]; then
  echo "deb [trusted=yes] https://azlopro.github.io/azlo-linux-watch/apt stable main" > "${APT_SOURCE}"
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
