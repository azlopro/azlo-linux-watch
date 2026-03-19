# azlo-linux-watch

Real-time Linux security monitoring with Discord alerts.

Detects SSH logins/logouts, failed login attempts, brute force attacks, sudo commands, su attempts, SSH key fingerprints, and enriches alerts with IP geolocation data. Sends beautiful Discord embeds for every event.

---

## Features

| Feature | Source | What it catches |
|---------|--------|----------------|
| 🔐 **auth.log tailing** | `/var/log/auth.log` | Failed logins, brute force (≥5 in 60s), SSH key fingerprints, sudo commands, su attempts, invalid usernames |
| 🌍 **IP geolocation** | ip-api.com | Country, city, ISP for every remote IP (with LRU cache + rate limiting) |
| ⚡ **PAM hook** | `pam_exec` → Unix socket | Instant login/logout detection (zero polling lag) |
| 👁️ **who polling** | `who -u` | Login/logout detection via 5s polling (fallback) |
| 🔍 **eBPF tracing** | `sys_enter_execve` | Process spawn monitoring (kernel ≥ 5.x, coming soon) |

All features can be individually enabled/disabled via the `FEATURES` environment variable.

### Discord Alert Types

| Event | Emoji | Color |
|-------|-------|-------|
| User login | 🟢 | Green |
| User logout | 🔴 | Red |
| Failed login | ⚠️ | Orange |
| Invalid username | ❌ | Red |
| Brute force detected | 🚨 | Red |
| SSH key used | 🔑 | Blue |
| Sudo command | 🛡️ | Purple |
| Su attempt | 🔄 | Gold |
| Process spawn (eBPF) | 🔍 | Teal |
| Daemon started | 🔵 | Blue |

---

## Requirements

- Linux (amd64 or arm64)
- `curl`
- `systemd`
- `socat` (for PAM hook — optional)
- Root / sudo access

---

## Production Install

### Option A — Package manager (recommended)

The installer auto-detects your package manager and installs a native package (`.deb`, `.rpm`, or `.pkg.tar.zst`). This means you can update with your normal system tools.

```bash
git clone https://github.com/azlopro/azlo-linux-watch.git
cd azlo-linux-watch
sudo ./install.sh
```

The installer will:

1. Detect your package manager (`apt`, `dnf`, `yum`, `zypper`, or `pacman`)
2. Download the correct package and verify its SHA-256 checksum
3. Install via your package manager (registers it for `apt upgrade`, `pacman -Syu`, etc.)
4. **Prompt for your Discord webhook URL** and save it to `/etc/azlo-linux-watch/env` (`600 root:root`)
5. Create the `azlo-watch` system user with `utmp` + `adm` groups
6. Install the PAM hook for instant SSH login detection
7. Enable and start the systemd service

### Option B — Manual package install

Download and install the package for your distro directly from [GitHub Releases](https://github.com/azlopro/azlo-linux-watch/releases/latest):

**Debian / Ubuntu**
```bash
curl -LO https://github.com/azlopro/azlo-linux-watch/releases/latest/download/azlo-linux-watch_latest_linux_amd64.deb
sudo dpkg -i azlo-linux-watch_latest_linux_amd64.deb
sudo nano /etc/azlo-linux-watch/env     # set DISCORD_WEBHOOK_URL=
sudo systemctl start azlo-linux-watch
```

**RHEL / Fedora / openSUSE**
```bash
curl -LO https://github.com/azlopro/azlo-linux-watch/releases/latest/download/azlo-linux-watch_latest_linux_amd64.rpm
sudo dnf install ./azlo-linux-watch_latest_linux_amd64.rpm
sudo nano /etc/azlo-linux-watch/env     # set DISCORD_WEBHOOK_URL=
sudo systemctl start azlo-linux-watch
```

**Arch Linux / Manjaro (via pacman)**
```bash
curl -LO https://github.com/azlopro/azlo-linux-watch/releases/latest/download/azlo-linux-watch_latest_linux_amd64.pkg.tar.zst
sudo pacman -U azlo-linux-watch_latest_linux_amd64.pkg.tar.zst
sudo nano /etc/azlo-linux-watch/env     # set DISCORD_WEBHOOK_URL=
sudo systemctl start azlo-linux-watch
```

### Updating

Once installed via a package, update through your normal system tools:

```bash
# Debian / Ubuntu
sudo apt update && sudo apt upgrade azlo-linux-watch

# Arch (after re-running install.sh or downloading new .pkg.tar.zst)
sudo pacman -U azlo-linux-watch_<version>_linux_amd64.pkg.tar.zst

# Or just re-run the installer — it will detect and upgrade
sudo ./install.sh
```

### Verify it's running

```bash
sudo systemctl status azlo-linux-watch
```

Expected output:

```
● azlo-linux-watch.service - azlo Linux Security Monitor
     Loaded: loaded (/etc/systemd/system/azlo-linux-watch.service; enabled)
     Active: active (running)
```

### Check logs

```bash
journalctl -u azlo-linux-watch -f
```

---

## Configuration

All configuration is in `/etc/azlo-linux-watch/env`:

```bash
# Discord webhook URL (required)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Comma-separated list of enabled features
# Available: authlog, geoip, pam, who, ebpf
FEATURES=authlog,geoip,pam,who,ebpf

# Enable/disable IP geolocation enrichment
GEOIP_ENABLED=true
```

To edit:

```bash
sudo nano /etc/azlo-linux-watch/env
sudo systemctl restart azlo-linux-watch
```

---

## What gets installed

| Path | Description |
|------|-------------|
| `/opt/azlo-linux-watch/azlo-linux-watch` | Main binary |
| `/opt/azlo-linux-watch/pam-notify.sh` | PAM helper script |
| `/etc/systemd/system/azlo-linux-watch.service` | Systemd service unit |
| `/etc/azlo-linux-watch/env` | Environment / configuration file |
| `/etc/pam.d/azlo-linux-watch` | PAM configuration drop-in |
| `/run/azlo-linux-watch/pam.sock` | Unix socket for PAM events (runtime) |

### System user

A dedicated system user `azlo-watch` is created with:
- No login shell (`/usr/sbin/nologin`)
- No home directory
- Membership of the `utmp` group (required to read login sessions)
- Membership of the `adm` group (required to read auth.log)

### Webhook configuration

The Discord webhook URL is stored in `/etc/azlo-linux-watch/env` with permissions `600 root:root`. It is injected into the process by systemd via `EnvironmentFile=` — the service user never has direct access to the file.

---

## Service hardening

The systemd unit applies the following restrictions:

| Setting | Effect |
|---------|--------|
| `User=azlo-watch` | Runs as an unprivileged system user |
| `SupplementaryGroups=adm` | Read access to auth.log |
| `RuntimeDirectory=azlo-linux-watch` | Creates socket directory under `/run/` |
| `NoNewPrivileges=true` | Prevents privilege escalation |
| `PrivateTmp=true` | Isolated `/tmp` |
| `PrivateDevices=true` | No access to device nodes |
| `ProtectSystem=strict` | Filesystem is read-only |
| `ProtectHome=true` | No access to user home directories |
| `ProtectKernelTunables=true` | Cannot modify kernel parameters |
| `ProtectControlGroups=true` | Cannot modify cgroups |
| `CapabilityBoundingSet=CAP_BPF CAP_PERFMON` | Only BPF-related capabilities |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | TCP/IP + Unix sockets only |
| `MemoryDenyWriteExecute=true` | No writable+executable memory |
| `RestrictNamespaces=true` | Cannot create namespaces |
| `LockPersonality=true` | Cannot change execution domain |
| `SystemCallFilter=@system-service` | Syscall allowlist only |
| `ReadOnlyPaths=/var/log` | Allows reading log files |

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
sudo rm -f /etc/pam.d/azlo-linux-watch
# Remove PAM hook from sshd config
sudo sed -i '/azlo-linux-watch/d' /etc/pam.d/sshd
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
