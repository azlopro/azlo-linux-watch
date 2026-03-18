# azlo-linux-watch

Monitors Linux user logins and logouts and sends real-time alerts to a Discord webhook.

Detects SSH and local sessions via `who -u`, polling every 5 seconds. Sends a Discord embed on login, logout, and daemon startup.

---

## Requirements

- Linux (amd64 or arm64)
- `curl`
- `systemd`
- Root / sudo access

---

## Production Install

### 1 — Clone the repository

```bash
git clone https://github.com/azlopro/azlo-linux-watch.git
cd azlo-linux-watch
```

### 2 — Run the installer

```bash
sudo ./install.sh
```

The installer will:

1. Create a dedicated system user `azlo-watch` (no shell, no home directory)
2. Create `/opt/azlo-linux-watch/` with correct ownership
3. Download the correct pre-built binary for your architecture from GitHub Releases
4. Verify the SHA-256 checksum before installing
5. Install the binary to `/opt/azlo-linux-watch/azlo-linux-watch`
6. **Prompt for your Discord webhook URL** and save it to `/etc/azlo-linux-watch/env` (`600 root:root`)
7. Install and enable the systemd service

### 3 — Verify it's running

```bash
sudo systemctl status azlo-linux-watch
```

Expected output:

```
● azlo-linux-watch.service - azlo Linux Login Monitor
     Loaded: loaded (/etc/systemd/system/azlo-linux-watch.service; enabled)
     Active: active (running)
```

### 4 — Check logs

```bash
journalctl -u azlo-linux-watch -f
```

---

## What gets installed

| Path | Description |
|------|-------------|
| `/opt/azlo-linux-watch/azlo-linux-watch` | Binary |
| `/etc/systemd/system/azlo-linux-watch.service` | Systemd service unit |
| `/etc/azlo-linux-watch/env` | Environment file containing the webhook URL |

### System user

A dedicated system user `azlo-watch` is created with:
- No login shell (`/usr/sbin/nologin`)
- No home directory
- Membership of the `utmp` group (required to read login sessions)

### Webhook configuration

The Discord webhook URL is stored in `/etc/azlo-linux-watch/env` with permissions `600 root:root`. It is injected into the process by systemd via `EnvironmentFile=` — the service user never has direct access to the file.

To update the webhook URL after install:

```bash
sudo nano /etc/azlo-linux-watch/env
# Edit the DISCORD_WEBHOOK_URL= line, save, then:
sudo systemctl restart azlo-linux-watch
```

---

## Service hardening

The systemd unit applies the following restrictions:

| Setting | Effect |
|---------|--------|
| `User=azlo-watch` | Runs as an unprivileged system user |
| `NoNewPrivileges=true` | Prevents privilege escalation |
| `PrivateTmp=true` | Isolated `/tmp` |
| `PrivateDevices=true` | No access to device nodes |
| `ProtectSystem=strict` | Filesystem is read-only (except `/proc`, `/sys`) |
| `ProtectHome=true` | No access to user home directories |
| `ProtectKernelTunables=true` | Cannot modify kernel parameters |
| `ProtectControlGroups=true` | Cannot modify cgroups |
| `CapabilityBoundingSet=` | Zero Linux capabilities |
| `RestrictAddressFamilies=AF_INET AF_INET6` | Only TCP/IP networking |
| `MemoryDenyWriteExecute=true` | No writable+executable memory |
| `RestrictNamespaces=true` | Cannot create namespaces |
| `LockPersonality=true` | Cannot change execution domain |
| `SystemCallFilter=@system-service` | Syscall allowlist only |

---

## Managing the service

```bash
# Stop the service
sudo systemctl stop azlo-linux-watch

# Start the service
sudo systemctl start azlo-linux-watch

# Restart the service
sudo systemctl restart azlo-linux-watch

# Disable autostart
sudo systemctl disable azlo-linux-watch

# View logs (live)
journalctl -u azlo-linux-watch -f

# View logs (last 100 lines)
journalctl -u azlo-linux-watch -n 100
```

---

## Uninstall

```bash
sudo systemctl disable --now azlo-linux-watch
sudo rm /etc/systemd/system/azlo-linux-watch.service
sudo rm -rf /opt/azlo-linux-watch
sudo rm -rf /etc/azlo-linux-watch
sudo userdel azlo-watch
sudo systemctl daemon-reload
```

---

## Releasing a new version

Tag a commit and GitHub Actions will cross-compile for `linux/amd64` and `linux/arm64` and publish the binaries automatically.

```bash
git tag v1.1.0
git push origin v1.1.0
```

## Building locally (requires Go)

```bash
make build          # native binary
make build-amd64    # cross-compile for amd64
make build-arm64    # cross-compile for arm64
make vet            # run go vet
make clean          # remove compiled binaries
```
