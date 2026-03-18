#!/usr/bin/env bash
# install.sh — production installer for azlo-linux-watch
# Downloads the latest release binary and sets up a hardened systemd service.
# Must be run as root or via sudo.
set -euo pipefail

REPO="azlopro/azlo-linux-watch"
BIN_NAME="azlo-linux-watch"
INSTALL_DIR="/opt/${BIN_NAME}"
INSTALL_PATH="${INSTALL_DIR}/${BIN_NAME}"
SERVICE_NAME="${BIN_NAME}.service"
SERVICE_DEST="/etc/systemd/system/${SERVICE_NAME}"
SERVICE_USER="azlo-watch"
ENV_DIR="/etc/${BIN_NAME}"
ENV_FILE="${ENV_DIR}/env"

# ── helpers ────────────────────────────────────────────────────────────────────
info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root. Try: sudo $0"
  fi
}

# ── detect architecture ────────────────────────────────────────────────────────
detect_arch() {
  case "$(uname -m)" in
    x86_64)  echo "amd64" ;;
    aarch64) echo "arm64" ;;
    *)       error "Unsupported architecture: $(uname -m)" ;;
  esac
}

# ── fetch latest release asset URL ────────────────────────────────────────────
fetch_release_url() {
  local asset="$1"
  local url
  url=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep "browser_download_url" \
    | grep "${asset}\"" \
    | cut -d '"' -f 4)
  [ -n "$url" ] || error "Could not find release asset '${asset}'. Check https://github.com/${REPO}/releases"
  echo "$url"
}

# ══════════════════════════════════════════════════════════════════════════════
require_root

ARCH=$(detect_arch)
ASSET="${BIN_NAME}-${ARCH}"

info "Installing azlo-linux-watch for linux/${ARCH}"

# ── create system user ─────────────────────────────────────────────────────────
if ! id "${SERVICE_USER}" &>/dev/null; then
  info "Creating system user '${SERVICE_USER}'"
  useradd \
    --system \
    --no-create-home \
    --shell /usr/sbin/nologin \
    --comment "azlo-linux-watch daemon" \
    "${SERVICE_USER}"
else
  info "System user '${SERVICE_USER}' already exists"
fi

# ── create install directory ───────────────────────────────────────────────────
info "Creating ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
chown root:root "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}"

# ── download binary ────────────────────────────────────────────────────────────
info "Fetching latest release from github.com/${REPO}"
RELEASE_URL=$(fetch_release_url "${ASSET}")

CHECKSUM_URL=$(fetch_release_url "checksums.txt")

info "Downloading ${ASSET}"
curl -fsSL "${RELEASE_URL}" -o "/tmp/${ASSET}"
curl -fsSL "${CHECKSUM_URL}" -o "/tmp/checksums.txt"

info "Verifying checksum"
pushd /tmp >/dev/null
grep "${ASSET}" checksums.txt | sha256sum --check --status \
  || error "Checksum verification failed! Aborting."
popd >/dev/null
info "Checksum OK"

# ── install binary ─────────────────────────────────────────────────────────────
info "Installing binary to ${INSTALL_PATH}"
mv "/tmp/${ASSET}" "${INSTALL_PATH}"
chown root:root "${INSTALL_PATH}"
chmod 755 "${INSTALL_PATH}"

# ── write env file ────────────────────────────────────────────────────────────
if [ -f "${ENV_FILE}" ] && grep -q "DISCORD_WEBHOOK_URL=" "${ENV_FILE}"; then
  info "Existing webhook config found at ${ENV_FILE} — skipping prompt"
else
  echo ""
  read -r -p "Paste your Discord webhook URL: " WEBHOOK_URL
  [ -n "$WEBHOOK_URL" ] || error "Webhook URL cannot be empty"
  mkdir -p "${ENV_DIR}"
  printf 'DISCORD_WEBHOOK_URL=%s\n' "${WEBHOOK_URL}" > "${ENV_FILE}"
  chown root:root "${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
  info "Webhook URL saved to ${ENV_FILE} (permissions: 600 root:root)"
fi

# ── install service ────────────────────────────────────────────────────────────
info "Installing systemd service to ${SERVICE_DEST}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "${SCRIPT_DIR}/${SERVICE_NAME}" "${SERVICE_DEST}"
chown root:root "${SERVICE_DEST}"
chmod 644 "${SERVICE_DEST}"

systemctl daemon-reload
systemctl enable --now "${BIN_NAME}"

# ── done ───────────────────────────────────────────────────────────────────────
echo ""
info "Installation complete!"
echo ""
systemctl status "${BIN_NAME}" --no-pager
echo ""
info "View logs with: journalctl -u ${BIN_NAME} -f"
