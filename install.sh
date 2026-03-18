#!/usr/bin/env bash
# install.sh — download the latest azlo-linux-watch release and install as a systemd service
set -euo pipefail

REPO="azlopro/azlo-linux-watch"
BIN_NAME="azlo-linux-watch"
INSTALL_PATH="/usr/local/bin/${BIN_NAME}"
SERVICE_SRC="$(dirname "$0")/azlo-linux-watch.service"
SERVICE_DEST="/etc/systemd/system/${BIN_NAME}.service"

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH_SUFFIX="amd64" ;;
  aarch64) ARCH_SUFFIX="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

ASSET="${BIN_NAME}-${ARCH_SUFFIX}"

echo "Fetching latest release from github.com/${REPO}..."
RELEASE_URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep "browser_download_url" \
  | grep "${ASSET}" \
  | cut -d '"' -f 4)

if [ -z "$RELEASE_URL" ]; then
  echo "Could not find release asset '${ASSET}'. Check https://github.com/${REPO}/releases" >&2
  exit 1
fi

echo "Downloading ${ASSET} from ${RELEASE_URL}..."
curl -fsSL "$RELEASE_URL" -o "/tmp/${BIN_NAME}"
chmod +x "/tmp/${BIN_NAME}"

echo "Installing binary to ${INSTALL_PATH}..."
sudo mv "/tmp/${BIN_NAME}" "$INSTALL_PATH"

echo "Installing systemd service to ${SERVICE_DEST}..."
sudo cp "$SERVICE_SRC" "$SERVICE_DEST"
sudo systemctl daemon-reload
sudo systemctl enable --now "${BIN_NAME}"

echo ""
echo "Done! Service status:"
sudo systemctl status "${BIN_NAME}" --no-pager
