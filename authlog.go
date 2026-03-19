package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─── auth.log regexes ───────────────────────────────────────────────────────

var (
	// Failed password for bob from 192.168.1.1 port 22 ssh2
	reFailedPassword = regexp.MustCompile(
		`Failed password for (\S+) from (\S+) port (\d+)`,
	)

	// Failed password for invalid user admin from 192.168.1.1 port 22 ssh2
	reFailedInvalidUser = regexp.MustCompile(
		`Failed password for invalid user (\S+) from (\S+) port (\d+)`,
	)

	// Invalid user admin from 192.168.1.1 port 22
	reInvalidUser = regexp.MustCompile(
		`Invalid user (\S+) from (\S+) port (\d+)`,
	)

	// Accepted publickey for bob from 192.168.1.1 port 22 ssh2: RSA SHA256:abc123def456
	reAcceptedKey = regexp.MustCompile(
		`Accepted publickey for (\S+) from (\S+) port (\d+) ssh2: (\S+ \S+)`,
	)

	// bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update
	reSudo = regexp.MustCompile(
		`(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)`,
	)

	// Successful su for root by bob
	reSuSuccess = regexp.MustCompile(
		`Successful su for (\S+) by (\S+)`,
	)

	// pam_unix(su:auth): authentication failure; ... user=bob
	reSuFailure = regexp.MustCompile(
		`pam_unix\(su(?::\w+)?\): authentication failure;.*\buser=(\S+)`,
	)

	// Accepted password for bob from 192.168.1.1 port 22 ssh2
	reAcceptedPassword = regexp.MustCompile(
		`Accepted password for (\S+) from (\S+) port (\d+)`,
	)

	// bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/su
	reSudoNotInSudoers = regexp.MustCompile(
		`(\S+) : user NOT in sudoers ; TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)`,
	)

	// bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/su
	reSudoWrongPassword = regexp.MustCompile(
		`(\S+) : (\d+) incorrect password attempt`,
	)

	// useradd[1234]: new user: name=bob, UID=1001, ...
	reUserAdd = regexp.MustCompile(
		`useradd\[\d+\]: new user: name=(\S+)`,
	)

	// userdel[1234]: delete user 'bob'
	reUserDel = regexp.MustCompile(
		`userdel\[\d+\]: delete user '(\S+)'`,
	)

	// usermod[1234]: change user 'bob' ...
	reUserMod = regexp.MustCompile(
		`usermod\[\d+\]: change user '(\S+)'`,
	)

	// passwd[1234]: pam_unix(passwd:chauthtok): password changed for bob
	rePasswdChange = regexp.MustCompile(
		`passwd\[\d+\]:.*password changed for (\S+)`,
	)

	// groupadd[1234]: new group: name=docker, GID=999
	reGroupAdd = regexp.MustCompile(
		`groupadd\[\d+\]: new group: name=(\S+)`,
	)
)

// ─── Brute-force detector ───────────────────────────────────────────────────

type bruteForceDetector struct {
	mu        sync.Mutex
	attempts  map[string][]time.Time // IP -> timestamps of failed logins
	threshold int
	window    time.Duration
	alerted   map[string]time.Time // IP -> last alert time (prevent spam)
}

func newBruteForceDetector() *bruteForceDetector {
	return &bruteForceDetector{
		attempts:  make(map[string][]time.Time),
		threshold: 5,
		window:    60 * time.Second,
		alerted:   make(map[string]time.Time),
	}
}

// record adds a failed attempt and returns true if the threshold is crossed.
func (b *bruteForceDetector) record(ip string, t time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := t.Add(-b.window)

	// Filter old entries
	recent := b.attempts[ip][:0]
	for _, ts := range b.attempts[ip] {
		if ts.After(cutoff) {
			recent = append(recent, ts)
		}
	}
	recent = append(recent, t)
	b.attempts[ip] = recent

	if len(recent) >= b.threshold {
		// Only alert once per window per IP
		if lastAlert, ok := b.alerted[ip]; ok && t.Sub(lastAlert) < b.window {
			return false
		}
		b.alerted[ip] = t
		return true
	}
	return false
}

// ─── auth.log paths ─────────────────────────────────────────────────────────

func findAuthLogPath() string {
	candidates := []string{
		"/var/log/auth.log",    // Debian / Ubuntu
		"/var/log/secure",      // RHEL / CentOS / Fedora
		"/var/log/messages",    // openSUSE fallback
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ─── Tail & parse ───────────────────────────────────────────────────────────

// watchAuthLog tails the auth log file and emits security events.
func watchAuthLog(events chan<- SecurityEvent) {
	path := findAuthLogPath()
	if path == "" {
		log.Printf("[authlog] no auth log found (tried auth.log, secure, messages) — skipping")
		return
	}

	log.Printf("[authlog] tailing %s", path)
	brute := newBruteForceDetector()
	ipTracker := NewIPTracker()

	for {
		if err := tailAuthLog(path, events, brute, ipTracker); err != nil {
			log.Printf("[authlog] error: %v — retrying in 5s", err)
			time.Sleep(5 * time.Second)
		}
	}
}

func tailAuthLog(path string, events chan<- SecurityEvent, brute *bruteForceDetector, ipTracker *IPTracker) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	// Seek to end — we only care about new entries
	if _, err := f.Seek(0, 2); err != nil {
		return fmt.Errorf("seek %s: %w", path, err)
	}

	scanner := bufio.NewScanner(f)
	var lastSize int64

	for {
		for scanner.Scan() {
			line := scanner.Text()
			parseAuthLogLine(line, events, brute, ipTracker)
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scan %s: %w", path, err)
		}

		// Check for log rotation (file truncated or replaced)
		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		currentSize := stat.Size()
		if currentSize < lastSize {
			// File was truncated or rotated — re-open
			log.Printf("[authlog] detected log rotation, re-opening %s", path)
			return nil // will be re-opened by the outer loop
		}
		lastSize = currentSize

		// Sleep briefly before checking for more lines
		time.Sleep(500 * time.Millisecond)

		// Re-create scanner to pick up new content after the sleep
		scanner = bufio.NewScanner(f)
	}
}

// parseAuthLogLine matches a single auth.log line against known patterns.
func parseAuthLogLine(line string, events chan<- SecurityEvent, brute *bruteForceDetector, ipTracker *IPTracker) {
	now := time.Now()

	// ── Failed password for invalid user ─────────────────────────────────
	if m := reFailedInvalidUser.FindStringSubmatch(line); m != nil {
		user, ip := m[1], m[2]

		events <- SecurityEvent{
			Type:      EventInvalidUser,
			User:      user,
			SourceIP:  ip,
			Details:   fmt.Sprintf("Failed login for invalid user `%s` from %s", user, ip),
			Timestamp: now,
			Source:    "authlog",
		}

		if brute.record(ip, now) {
			events <- SecurityEvent{
				Type:      EventBruteForce,
				SourceIP:  ip,
				Details:   fmt.Sprintf("≥%d failed attempts from %s in the last 60s", brute.threshold, ip),
				Timestamp: now,
				Source:    "authlog",
			}
		}
		return
	}

	// ── Failed password (valid user) ─────────────────────────────────────
	if m := reFailedPassword.FindStringSubmatch(line); m != nil {
		user, ip := m[1], m[2]

		events <- SecurityEvent{
			Type:      EventFailedLogin,
			User:      user,
			SourceIP:  ip,
			Details:   fmt.Sprintf("Failed password for `%s` from %s", user, ip),
			Timestamp: now,
			Source:    "authlog",
		}

		if brute.record(ip, now) {
			events <- SecurityEvent{
				Type:      EventBruteForce,
				SourceIP:  ip,
				Details:   fmt.Sprintf("≥%d failed attempts from %s in the last 60s", brute.threshold, ip),
				Timestamp: now,
				Source:    "authlog",
			}
		}
		return
	}

	// ── Invalid user (without failed password, e.g. key-only server) ────
	if m := reInvalidUser.FindStringSubmatch(line); m != nil {
		user, ip := m[1], m[2]

		events <- SecurityEvent{
			Type:      EventInvalidUser,
			User:      user,
			SourceIP:  ip,
			Details:   fmt.Sprintf("Invalid user `%s` from %s", user, ip),
			Timestamp: now,
			Source:    "authlog",
		}

		if brute.record(ip, now) {
			events <- SecurityEvent{
				Type:      EventBruteForce,
				SourceIP:  ip,
				Details:   fmt.Sprintf("≥%d failed attempts from %s in the last 60s", brute.threshold, ip),
				Timestamp: now,
				Source:    "authlog",
			}
		}
		return
	}

	// ── Accepted public key ──────────────────────────────────────────────
	if m := reAcceptedKey.FindStringSubmatch(line); m != nil {
		user, ip, fingerprint := m[1], m[2], m[4]

		events <- SecurityEvent{
			Type:      EventSSHKey,
			User:      user,
			SourceIP:  ip,
			Details:   fmt.Sprintf("Key: `%s`", fingerprint),
			Timestamp: now,
			Source:    "authlog",
		}

		// Check for new IP
		if ipTracker != nil && ip != "" {
			if isNew := ipTracker.Record(user, ip); isNew {
				events <- SecurityEvent{
					Type:      EventNewIP,
					User:      user,
					SourceIP:  ip,
					Details:   fmt.Sprintf("First login from `%s` for user `%s`", ip, user),
					Timestamp: now,
					Source:    "authlog",
				}
			}
		}
		return
	}

	// ── Accepted password ───────────────────────────────────────────────
	if m := reAcceptedPassword.FindStringSubmatch(line); m != nil {
		user, ip := m[1], m[2]

		events <- SecurityEvent{
			Type:      EventPasswordLogin,
			User:      user,
			SourceIP:  ip,
			Details:   fmt.Sprintf("Password login for `%s` from %s", user, ip),
			Timestamp: now,
			Source:    "authlog",
		}

		// Check for new IP
		if ipTracker != nil && ip != "" {
			if isNew := ipTracker.Record(user, ip); isNew {
				events <- SecurityEvent{
					Type:      EventNewIP,
					User:      user,
					SourceIP:  ip,
					Details:   fmt.Sprintf("First login from `%s` for user `%s`", ip, user),
					Timestamp: now,
					Source:    "authlog",
				}
			}
		}
		return
	}

	// ── sudo command ─────────────────────────────────────────────────────
	if m := reSudo.FindStringSubmatch(line); m != nil {
		user, tty, command := m[1], m[2], m[5]
		// Don't alert on the monitor itself
		if strings.Contains(command, "azlo-linux-watch") {
			return
		}

		events <- SecurityEvent{
			Type:      EventSudo,
			User:      user,
			TTY:       tty,
			Details:   fmt.Sprintf("```\n%s\n```", strings.TrimSpace(command)),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── su success ───────────────────────────────────────────────────────
	if m := reSuSuccess.FindStringSubmatch(line); m != nil {
		targetUser, byUser := m[1], m[2]

		events <- SecurityEvent{
			Type:      EventSuAttempt,
			User:      byUser,
			Details:   fmt.Sprintf("Successful `su` to `%s` by `%s`", targetUser, byUser),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── su failure ───────────────────────────────────────────────────────
	if m := reSuFailure.FindStringSubmatch(line); m != nil {
		user := m[1]

		events <- SecurityEvent{
			Type:      EventSuAttempt,
			User:      user,
			Details:   fmt.Sprintf("Failed `su` attempt by `%s`", user),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── sudo: user NOT in sudoers ────────────────────────────────────────
	if m := reSudoNotInSudoers.FindStringSubmatch(line); m != nil {
		user, tty, command := m[1], m[2], m[5]

		events <- SecurityEvent{
			Type:      EventSudoFailed,
			User:      user,
			TTY:       tty,
			Details:   fmt.Sprintf("User `%s` is NOT in sudoers\n```\n%s\n```", user, strings.TrimSpace(command)),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── sudo: incorrect password ─────────────────────────────────────────
	if m := reSudoWrongPassword.FindStringSubmatch(line); m != nil {
		user, attempts := m[1], m[2]

		events <- SecurityEvent{
			Type:      EventSudoFailed,
			User:      user,
			Details:   fmt.Sprintf("`%s` entered %s incorrect sudo password attempts", user, attempts),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── useradd ─────────────────────────────────────────────────────────
	if m := reUserAdd.FindStringSubmatch(line); m != nil {
		events <- SecurityEvent{
			Type:      EventUserChange,
			Details:   fmt.Sprintf("New user created: `%s`", m[1]),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── userdel ─────────────────────────────────────────────────────────
	if m := reUserDel.FindStringSubmatch(line); m != nil {
		events <- SecurityEvent{
			Type:      EventUserChange,
			Details:   fmt.Sprintf("User deleted: `%s`", m[1]),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── usermod ─────────────────────────────────────────────────────────
	if m := reUserMod.FindStringSubmatch(line); m != nil {
		events <- SecurityEvent{
			Type:      EventUserChange,
			Details:   fmt.Sprintf("User modified: `%s`", m[1]),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── passwd ──────────────────────────────────────────────────────────
	if m := rePasswdChange.FindStringSubmatch(line); m != nil {
		events <- SecurityEvent{
			Type:      EventUserChange,
			Details:   fmt.Sprintf("Password changed for user: `%s`", m[1]),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}

	// ── groupadd ────────────────────────────────────────────────────────
	if m := reGroupAdd.FindStringSubmatch(line); m != nil {
		events <- SecurityEvent{
			Type:      EventUserChange,
			Details:   fmt.Sprintf("New group created: `%s`", m[1]),
			Timestamp: now,
			Source:    "authlog",
		}
		return
	}
}
