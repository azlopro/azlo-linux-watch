#!/bin/bash
# pam-notify.sh — called by pam_exec on session open/close.
# Sends a JSON event to the azlo-linux-watch Unix socket.
#
# PAM environment variables available:
#   PAM_USER   — the user logging in/out
#   PAM_TTY    — the tty (e.g. pts/0, ssh)
#   PAM_RHOST  — the remote host (IP for SSH, empty for local)
#   PAM_TYPE   — open_session or close_session
#   PAM_SERVICE — sshd, login, su, etc.

SOCKET="/run/azlo-linux-watch/pam.sock"

# Bail silently if the socket doesn't exist (service not running)
[ -S "$SOCKET" ] || exit 0

# Build minimal JSON — no external deps, just printf
printf '{"user":"%s","tty":"%s","rhost":"%s","action":"%s","service":"%s"}\n' \
  "${PAM_USER:-}" \
  "${PAM_TTY:-}" \
  "${PAM_RHOST:-}" \
  "${PAM_TYPE:-}" \
  "${PAM_SERVICE:-}" \
  | socat - UNIX-CONNECT:"$SOCKET" 2>/dev/null

# Always exit 0 — never block login on notification failure
exit 0
