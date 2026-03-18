# azlo-linux-watch

Monitors Linux logins and sends alerts to a Discord webhook.

Detects SSH and local sessions via `who -u`, polling every 5 seconds. Sends a Discord embed on login, logout, and daemon startup.

## Install (no Go required)

```bash
git clone https://github.com/azlopro/azlo-linux-watch.git
cd azlo-linux-watch
sudo ./install.sh
```

The script auto-detects your architecture (amd64 / arm64), downloads the latest release binary, and registers a systemd service.

## Check logs

```bash
journalctl -u azlo-linux-watch -f
```

## Release a new version

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions will cross-compile for linux/amd64 and linux/arm64 and publish the binaries as a GitHub Release automatically.

## Build locally (requires Go)

```bash
make build
```
