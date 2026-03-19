#!/usr/bin/env bash
# install.sh — production installer for azlo-linux-watch
# Detects the system package manager and installs the appropriate package.
# Falls back to a raw binary install when no supported package manager is found.
# Must be run as root or via sudo.
set -euo pipefail

REPO="azlopro/azlo-linux-watch"
BIN_NAME="azlo-linux-watch"
SERVICE_USER="azlo-watch"
ENV_DIR="/etc/${BIN_NAME}"
ENV_FILE="${ENV_DIR}/env"

# ── helpers ────────────────────────────────────────────────────────────────────
info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || error "This script must be run as root. Try: sudo $0"
}

# ── detect architecture (Go-style) ────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    *)       error "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── detect package manager ────────────────────────────────────────────────────
detect_pkgmgr() {
  if   command -v pacman &>/dev/null; then echo "pacman"
  elif command -v apt    &>/dev/null; then echo "apt"
  elif command -v dnf    &>/dev/null; then echo "dnf"
  elif command -v yum    &>/dev/null; then echo "yum"
  elif command -v zypper &>/dev/null; then echo "zypper"
  else                                     echo "none"
  fi
}

# ── fetch latest release version tag ─────────────────────────────────────────
fetch_latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | cut -d '"' -f 4
}

# ── fetch a release asset URL by filename pattern (empty string if not found) ─
fetch_release_url() {
  local asset="$1"
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep "browser_download_url" \
    | grep "/${asset}\"" \
    | cut -d '"' -f 4
}

# ── same but exits on failure ─────────────────────────────────────────────────
require_release_url() {
  local asset="$1"
  local url
  url=$(fetch_release_url "${asset}")
  [ -n "$url" ] || error "Could not find release asset '${asset}'. Check https://github.com/${REPO}/releases"
  echo "$url"
}

# ── download + verify a single asset to /tmp ──────────────────────────────────
download_and_verify() {
  local asset="$1"
  info "Downloading ${asset}"
  curl -fsSL "$(require_release_url "${asset}")" -o "/tmp/${asset}"
  curl -fsSL "$(require_release_url "checksums.txt")" -o "/tmp/checksums.txt"
  info "Verifying checksum"
  pushd /tmp >/dev/null
  grep " ${asset}$" checksums.txt | sha256sum --check --status \
    || error "Checksum verification failed! Aborting."
  popd >/dev/null
  info "Checksum OK"
}

# ── prompt for webhook URL if not already configured ─────────────────────────
configure_webhook() {
  if [ -f "${ENV_FILE}" ] && grep -q "^DISCORD_WEBHOOK_URL=.\+" "${ENV_FILE}" 2>/dev/null; then
    info "Existing webhook config found at ${ENV_FILE} — skipping prompt"
    return
  fi
  echo ""
  read -r -p "Paste your Discord webhook URL: " WEBHOOK_URL
  [ -n "$WEBHOOK_URL" ] || error "Webhook URL cannot be empty"
  mkdir -p "${ENV_DIR}"
  printf 'DISCORD_WEBHOOK_URL=%s\n' "${WEBHOOK_URL}" > "${ENV_FILE}"
  chown root:root "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
  info "Webhook URL saved to ${ENV_FILE} (permissions: 600 root:root)"
}

# ── raw binary install (fallback) ─────────────────────────────────────────────
install_binary() {
  local arch="$1"
  local asset="${BIN_NAME}-${arch}"
  local install_dir="/opt/${BIN_NAME}"
  local install_path="${install_dir}/${BIN_NAME}"

  # Create system user
  if ! id "${SERVICE_USER}" &>/dev/null; then
    info "Creating system user '${SERVICE_USER}'"
    NOLOGIN=$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)
    useradd --system --no-create-home --shell "${NOLOGIN}" \
      --comment "azlo-linux-watch daemon" "${SERVICE_USER}"
  fi
  getent group utmp &>/dev/null && usermod -aG utmp "${SERVICE_USER}" 2>/dev/null || true
  getent group adm  &>/dev/null && usermod -aG adm  "${SERVICE_USER}" 2>/dev/null || true

  info "Creating ${install_dir}"
  mkdir -p "${install_dir}"
  chown root:root "${install_dir}"
  chmod 755 "${install_dir}"

  download_and_verify "${asset}"

  info "Installing binary to ${install_path}"
  mv "/tmp/${asset}" "${install_path}"
  chown root:root "${install_path}"
  chmod 755 "${install_path}"

  # Install service unit from the cloned repo
  local service_dest="/etc/systemd/system/${BIN_NAME}.service"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  info "Installing systemd service to ${service_dest}"
  cp "${SCRIPT_DIR}/${BIN_NAME}.service" "${service_dest}"
  chown root:root "${service_dest}"
  chmod 644 "${service_dest}"

  # Install PAM helper script
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  if [ -f "${SCRIPT_DIR}/pam-notify.sh" ]; then
    info "Installing PAM helper script"
    cp "${SCRIPT_DIR}/pam-notify.sh" /opt/${BIN_NAME}/pam-notify.sh
    chmod 755 /opt/${BIN_NAME}/pam-notify.sh
  fi

  # Install PAM config
  if [ -d /etc/pam.d ] && [ -f "${SCRIPT_DIR}/packaging/pam-azlo-watch" ]; then
    info "Installing PAM configuration"
    cp "${SCRIPT_DIR}/packaging/pam-azlo-watch" /etc/pam.d/azlo-linux-watch
    chmod 644 /etc/pam.d/azlo-linux-watch
    # Hook into sshd if not already done
    if [ -f /etc/pam.d/sshd ] && ! grep -q 'azlo-linux-watch' /etc/pam.d/sshd 2>/dev/null; then
      echo '# azlo-linux-watch instant login detection' >> /etc/pam.d/sshd
      echo '@include azlo-linux-watch' >> /etc/pam.d/sshd
      info "PAM hook added to sshd"
    fi
  fi
}

# ── package manager installs ──────────────────────────────────────────────────
install_deb() {
  local asset="${BIN_NAME}_${VERSION}_linux_${ARCH}.deb"
  download_and_verify "${asset}"
  info "Installing with apt/dpkg"
  DEBIAN_FRONTEND=noninteractive dpkg -i "/tmp/${asset}"
}

install_rpm() {
  local asset="${BIN_NAME}_${VERSION}_linux_${ARCH}.rpm"
  download_and_verify "${asset}"
  info "Installing with ${PKGMGR}"
  "${PKGMGR}" install -y "/tmp/${asset}"
}

install_pacman() {
  local asset="${BIN_NAME}_${VERSION}_linux_${ARCH}.pkg.tar.zst"
  download_and_verify "${asset}"
  info "Installing with pacman"
  pacman -U --noconfirm "/tmp/${asset}"
}

# ══════════════════════════════════════════════════════════════════════════════
require_root

ARCH=$(detect_arch)
PKGMGR=$(detect_pkgmgr)
VERSION=$(fetch_latest_version)

info "Installing azlo-linux-watch ${VERSION} for linux/${ARCH}"
info "Detected package manager: ${PKGMGR}"

case "${PKGMGR}" in
  apt)
    PKG_ASSET="${BIN_NAME}_${VERSION}_linux_${ARCH}.deb"
    if [ -n "$(fetch_release_url "${PKG_ASSET}")" ]; then
      install_deb
    else
      info "Package ${PKG_ASSET} not in release yet — falling back to raw binary"
      install_binary "${ARCH}"
    fi
    ;;
  dnf|yum|zypper)
    PKG_ASSET="${BIN_NAME}_${VERSION}_linux_${ARCH}.rpm"
    if [ -n "$(fetch_release_url "${PKG_ASSET}")" ]; then
      install_rpm
    else
      info "Package ${PKG_ASSET} not in release yet — falling back to raw binary"
      install_binary "${ARCH}"
    fi
    ;;
  pacman)
    PKG_ASSET="${BIN_NAME}_${VERSION}_linux_${ARCH}.pkg.tar.zst"
    if [ -n "$(fetch_release_url "${PKG_ASSET}")" ]; then
      install_pacman
    else
      info "Package ${PKG_ASSET} not in release yet — falling back to raw binary"
      install_binary "${ARCH}"
    fi
    ;;
  none)
    info "No supported package manager found — falling back to raw binary install"
    install_binary "${ARCH}"
    ;;
esac

# ── configure webhook (package postinstall may have created the template) ─────
configure_webhook

# ── ensure service is running ─────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "${BIN_NAME}"
if systemctl is-active --quiet "${BIN_NAME}"; then
  info "Restarting ${BIN_NAME}"
  systemctl restart "${BIN_NAME}"
else
  info "Starting ${BIN_NAME}"
  systemctl start "${BIN_NAME}"
fi

# ── done ──────────────────────────────────────────────────────────────────────
echo ""
info "Installation complete!"
echo ""
systemctl status "${BIN_NAME}" --no-pager
echo ""
info "View logs with: journalctl -u ${BIN_NAME} -f"
