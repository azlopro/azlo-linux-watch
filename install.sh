#!/usr/bin/env bash
set -e

BIN=/usr/local/bin/azlo-linux-watch
SERVICE=/etc/systemd/system/azlo-linux-watch.service

echo "Building..."
go build -o azlo-linux-watch .

echo "Installing binary to $BIN"
sudo cp azlo-linux-watch "$BIN"
sudo chmod 755 "$BIN"

echo "Installing systemd service"
sudo cp azlo-linux-watch.service "$SERVICE"
sudo systemctl daemon-reload
sudo systemctl enable --now azlo-linux-watch

echo "Done. Status:"
sudo systemctl status azlo-linux-watch --no-pager
