package main

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

const pamSocketDir = "/run/azlo-linux-watch"
const pamSocketPath = "/run/azlo-linux-watch/pam.sock"

// pamEvent is the JSON payload sent by the pam-notify.sh helper.
type pamEvent struct {
	User    string `json:"user"`
	TTY     string `json:"tty"`
	RHost   string `json:"rhost"`
	Action  string `json:"action"` // "open_session" or "close_session"
	Service string `json:"service"` // "sshd", "login", etc.
}

// startPAMListener listens on a Unix socket for PAM session events.
func startPAMListener(events chan<- SecurityEvent) {
	// Ensure the socket directory exists
	if err := os.MkdirAll(pamSocketDir, 0755); err != nil {
		log.Printf("[pam] cannot create socket dir %s: %v — skipping PAM listener", pamSocketDir, err)
		return
	}

	// Remove stale socket
	os.Remove(pamSocketPath)

	ln, err := net.Listen("unix", pamSocketPath)
	if err != nil {
		log.Printf("[pam] cannot listen on %s: %v — skipping PAM listener", pamSocketPath, err)
		return
	}

	// Make the socket world-writable so the PAM script (running as any user) can connect
	if err := os.Chmod(pamSocketPath, 0666); err != nil {
		log.Printf("[pam] cannot chmod socket: %v", err)
	}

	log.Printf("[pam] listening on %s", pamSocketPath)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[pam] accept error: %v", err)
			continue
		}
		go handlePAMConnection(conn, events)
	}
}

func handlePAMConnection(conn net.Conn, events chan<- SecurityEvent) {
	defer conn.Close()

	// Set a short deadline — PAM messages are tiny
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var pe pamEvent
		if err := json.Unmarshal(scanner.Bytes(), &pe); err != nil {
			log.Printf("[pam] invalid JSON: %v", err)
			continue
		}

		evType := EventLogin
		if pe.Action == "close_session" {
			evType = EventLogout
		}

		events <- SecurityEvent{
			Type:      evType,
			User:      pe.User,
			SourceIP:  pe.RHost,
			TTY:       pe.TTY,
			Timestamp: time.Now(),
			Source:    "pam",
			Details:   pe.Service,
		}
	}
}

// installPAMConfig writes the PAM configuration drop-in if not already present.
// This is called during initial setup / install — not at runtime.
func installPAMConfig() error {
	pamDir := "/etc/pam.d"
	if _, err := os.Stat(pamDir); os.IsNotExist(err) {
		return nil // no PAM on this system
	}

	// We hook into common-session (Debian) or system-auth (RHEL) via a drop-in
	// The safest approach is a standalone file that sshd/login include
	configPath := filepath.Join(pamDir, "azlo-linux-watch")
	if _, err := os.Stat(configPath); err == nil {
		return nil // already installed
	}

	content := "# azlo-linux-watch — notify on session open/close\nsession optional pam_exec.so /opt/azlo-linux-watch/pam-notify.sh\n"
	return os.WriteFile(configPath, []byte(content), 0644)
}
