package main

import (
	"testing"
	"time"
)

func TestParseWho(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantLen  int
		wantUser string
		wantFrom string
		wantTTY  string
	}{
		{
			name:     "remote SSH session",
			input:    "bob      pts/0        2026-03-18 22:08   00:05       1234 (192.168.1.1)",
			wantLen:  1,
			wantUser: "bob",
			wantFrom: "192.168.1.1",
			wantTTY:  "pts/0",
		},
		{
			name:     "local session",
			input:    "alice    tty1         2026-03-18 10:30   .          5678",
			wantLen:  1,
			wantUser: "alice",
			wantFrom: "",
			wantTTY:  "tty1",
		},
		{
			name:    "multiple sessions",
			input:   "bob      pts/0        2026-03-18 22:08   00:05       1234 (192.168.1.1)\nalice    tty1         2026-03-18 10:30   .          5678",
			wantLen: 2,
		},
		{
			name:    "empty input",
			input:   "",
			wantLen: 0,
		},
		{
			name:    "short lines ignored",
			input:   "foo bar",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := parseWho(tt.input)
			if len(sessions) != tt.wantLen {
				t.Errorf("parseWho() returned %d sessions, want %d", len(sessions), tt.wantLen)
			}
			if tt.wantTTY != "" {
				sess, ok := sessions[tt.wantTTY]
				if !ok {
					t.Fatalf("expected session on %s not found", tt.wantTTY)
				}
				if sess.User != tt.wantUser {
					t.Errorf("user = %q, want %q", sess.User, tt.wantUser)
				}
				if sess.From != tt.wantFrom {
					t.Errorf("from = %q, want %q", sess.From, tt.wantFrom)
				}
			}
		})
	}
}

func TestParseAuthLogLine(t *testing.T) {
	events := make(chan SecurityEvent, 10)
	brute := newBruteForceDetector()

	tests := []struct {
		name      string
		line      string
		wantType  EventType
		wantUser  string
		wantIP    string
		wantCount int // expected number of events
	}{
		{
			name:      "failed password valid user",
			line:      "Mar 18 22:10:01 server sshd[1234]: Failed password for bob from 203.0.113.1 port 22 ssh2",
			wantType:  EventFailedLogin,
			wantUser:  "bob",
			wantIP:    "203.0.113.1",
			wantCount: 1,
		},
		{
			name:      "failed password invalid user",
			line:      "Mar 18 22:10:02 server sshd[1234]: Failed password for invalid user admin from 198.51.100.1 port 22 ssh2",
			wantType:  EventInvalidUser,
			wantUser:  "admin",
			wantIP:    "198.51.100.1",
			wantCount: 1,
		},
		{
			name:      "invalid user without failed password",
			line:      "Mar 18 22:10:03 server sshd[1234]: Invalid user hacker from 198.51.100.2 port 42569",
			wantType:  EventInvalidUser,
			wantUser:  "hacker",
			wantIP:    "198.51.100.2",
			wantCount: 1,
		},
		{
			name:      "accepted publickey",
			line:      "Mar 18 22:10:04 server sshd[1234]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2: RSA SHA256:abc123def456",
			wantType:  EventSSHKey,
			wantUser:  "deploy",
			wantIP:    "10.0.0.1",
			wantCount: 1,
		},
		{
			name:      "sudo command",
			line:      "Mar 18 22:10:05 server sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update",
			wantType:  EventSudo,
			wantUser:  "bob",
			wantCount: 1,
		},
		{
			name:      "su success",
			line:      "Mar 18 22:10:06 server su: Successful su for root by bob",
			wantType:  EventSuAttempt,
			wantUser:  "bob",
			wantCount: 1,
		},
		{
			name:      "su failure",
			line:      "Mar 18 22:10:07 server su: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=pts/1 ruser=alice rhost= user=alice",
			wantType:  EventSuAttempt,
			wantUser:  "alice",
			wantCount: 1,
		},
		{
			name:      "unrelated line",
			line:      "Mar 18 22:10:08 server CRON[9999]: pam_unix(cron:session): session opened for user root",
			wantCount: 0,
		},
		{
			name:      "accepted password",
			line:      "Mar 18 22:10:09 server sshd[1234]: Accepted password for bob from 203.0.113.5 port 22 ssh2",
			wantType:  EventPasswordLogin,
			wantUser:  "bob",
			wantIP:    "203.0.113.5",
			wantCount: 1,
		},
		{
			name:      "sudo not in sudoers",
			line:      "Mar 18 22:10:10 server sudo: alice : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/su",
			wantType:  EventSudoFailed,
			wantUser:  "alice",
			wantCount: 1,
		},
		{
			name:      "sudo wrong password",
			line:      "Mar 18 22:10:11 server sudo: bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt",
			wantType:  EventSudoFailed,
			wantUser:  "bob",
			wantCount: 1,
		},
		{
			name:      "useradd",
			line:      "Mar 18 22:10:12 server useradd[5678]: new user: name=newguy, UID=1002, GID=1002",
			wantType:  EventUserChange,
			wantCount: 1,
		},
		{
			name:      "userdel",
			line:      "Mar 18 22:10:13 server userdel[5679]: delete user 'oldguy'",
			wantType:  EventUserChange,
			wantCount: 1,
		},
		{
			name:      "passwd change",
			line:      "Mar 18 22:10:14 server passwd[5680]: pam_unix(passwd:chauthtok): password changed for bob",
			wantType:  EventUserChange,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Drain the channel
			for len(events) > 0 {
				<-events
			}

			parseAuthLogLine(tt.line, events, brute, nil)

			if len(events) != tt.wantCount {
				t.Fatalf("got %d events, want %d", len(events), tt.wantCount)
			}

			if tt.wantCount > 0 {
				ev := <-events
				if ev.Type != tt.wantType {
					t.Errorf("type = %v, want %v", ev.Type, tt.wantType)
				}
				if tt.wantUser != "" && ev.User != tt.wantUser {
					t.Errorf("user = %q, want %q", ev.User, tt.wantUser)
				}
				if tt.wantIP != "" && ev.SourceIP != tt.wantIP {
					t.Errorf("ip = %q, want %q", ev.SourceIP, tt.wantIP)
				}
			}
		})
	}
}

func TestBruteForceDetector(t *testing.T) {
	brute := newBruteForceDetector()
	ip := "198.51.100.99"
	now := time.Now()

	// First 4 attempts should not trigger
	for i := 0; i < 4; i++ {
		if brute.record(ip, now.Add(time.Duration(i)*time.Second)) {
			t.Errorf("attempt %d triggered brute force prematurely", i+1)
		}
	}

	// 5th attempt should trigger
	if !brute.record(ip, now.Add(4*time.Second)) {
		t.Error("5th attempt should trigger brute force alert")
	}

	// 6th attempt should NOT re-trigger (already alerted within window)
	if brute.record(ip, now.Add(5*time.Second)) {
		t.Error("6th attempt should not re-trigger within same window")
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"203.0.113.1", false},
		{"1.1.1.1", false},
		{"", true},           // empty = treat as private
		{"not-an-ip", true},  // unparseable = treat as private
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := isPrivateIP(tt.ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}

func TestEventTypes(t *testing.T) {
	// Ensure all event types have string representations
	types := []EventType{
		EventLogin, EventLogout, EventFailedLogin, EventInvalidUser,
		EventBruteForce, EventSSHKey, EventSudo, EventSuAttempt,
		EventPasswordLogin, EventNewIP, EventSudoFailed, EventUserChange,
		EventProcessSpawn, EventDaemonStarted,
	}
	for _, et := range types {
		if et.String() == "unknown" {
			t.Errorf("event type %d has no string representation", et)
		}
		// Check they all have colors and titles
		if eventColor(et) == 0 {
			t.Errorf("event type %s has no color", et)
		}
		if eventTitle(et) == "" {
			t.Errorf("event type %s has no title", et)
		}
	}
}

func TestIPTracker(t *testing.T) {
	tracker := NewIPTracker()

	if !tracker.Record("bob", "1.2.3.4") {
		t.Error("first IP should be flagged as new")
	}
	if tracker.Record("bob", "1.2.3.4") {
		t.Error("same IP should not be flagged as new again")
	}
	if !tracker.Record("bob", "5.6.7.8") {
		t.Error("different IP should be flagged as new")
	}
	if !tracker.Record("alice", "1.2.3.4") {
		t.Error("same IP for different user should be flagged as new")
	}
	if tracker.Record("", "1.2.3.4") {
		t.Error("empty user should not be flagged")
	}
	if tracker.Record("bob", "") {
		t.Error("empty IP should not be flagged")
	}
}
