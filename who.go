package main

import (
	"log"
	"os/exec"
	"strings"
	"time"
)

// WhoSession represents a parsed line from `who -u`.
type WhoSession struct {
	User      string
	TTY       string
	From      string
	PID       string
	LoginTime time.Time
}

func getWhoOutput() (string, error) {
	out, err := exec.Command("who", "-u").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parseWho parses `who -u` output into a map of tty -> WhoSession.
//
// `who -u` format:
//
//	user  tty  DATE  TIME  IDLE  PID  (FROM)
//	bob   pts/0  2026-03-18  22:08  00:05  1234  (192.168.1.1)
func parseWho(output string) map[string]WhoSession {
	sessions := make(map[string]WhoSession)
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		user := fields[0]
		tty := fields[1]
		pid := fields[5]

		loginTime, err := time.ParseInLocation("2006-01-02 15:04", fields[2]+" "+fields[3], time.Local)
		if err != nil {
			loginTime = time.Now()
		}

		from := ""
		if len(fields) >= 7 {
			from = strings.Trim(fields[6], "()")
		}

		sessions[tty] = WhoSession{
			User:      user,
			TTY:       tty,
			From:      from,
			PID:       pid,
			LoginTime: loginTime,
		}
	}
	return sessions
}

// pollWho runs the `who -u` poller every 5 seconds and emits login/logout events.
func pollWho(events chan<- SecurityEvent) {
	raw, err := getWhoOutput()
	if err != nil {
		log.Printf("[who] cannot run 'who': %v", err)
		return
	}
	known := parseWho(raw)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		raw, err := getWhoOutput()
		if err != nil {
			log.Printf("[who] error: %v", err)
			continue
		}
		current := parseWho(raw)

		// Detect new sessions (logins)
		for tty, sess := range current {
			if _, exists := known[tty]; !exists {
				events <- SecurityEvent{
					Type:      EventLogin,
					User:      sess.User,
					SourceIP:  sess.From,
					TTY:       tty,
					PID:       sess.PID,
					LoginTime: sess.LoginTime,
					Timestamp: time.Now(),
					Source:    "who",
				}
			}
		}

		// Detect ended sessions (logouts)
		for tty, sess := range known {
			if _, exists := current[tty]; !exists {
				events <- SecurityEvent{
					Type:      EventLogout,
					User:      sess.User,
					SourceIP:  sess.From,
					TTY:       tty,
					PID:       sess.PID,
					LoginTime: sess.LoginTime,
					Timestamp: time.Now(),
					Source:    "who",
				}
			}
		}

		known = current
	}
}
