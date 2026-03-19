package main

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

const knownIPsPath = "/var/lib/azlo-linux-watch/known_ips.json"

// IPTracker tracks known IPs per user and flags new ones.
type IPTracker struct {
	mu      sync.Mutex
	known   map[string]map[string]bool // user -> set of IPs
	dirty   bool
}

// NewIPTracker creates a new IP tracker, loading persisted data if available.
func NewIPTracker() *IPTracker {
	t := &IPTracker{
		known: make(map[string]map[string]bool),
	}
	t.load()
	return t
}

// Record registers an IP for a user. Returns true if this IP is new for the user.
func (t *IPTracker) Record(user, ip string) bool {
	if user == "" || ip == "" {
		return false
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.known[user] == nil {
		t.known[user] = make(map[string]bool)
	}

	if t.known[user][ip] {
		return false // already known
	}

	t.known[user][ip] = true
	t.dirty = true

	// Persist in the background (best-effort)
	go t.save()

	log.Printf("[ip-tracker] new IP for user %s: %s", user, ip)
	return true
}

// load reads persisted known IPs from disk.
func (t *IPTracker) load() {
	data, err := os.ReadFile(knownIPsPath)
	if err != nil {
		// File doesn't exist yet — that's fine
		return
	}

	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("[ip-tracker] failed to parse %s: %v", knownIPsPath, err)
		return
	}

	for user, ips := range raw {
		t.known[user] = make(map[string]bool)
		for _, ip := range ips {
			t.known[user][ip] = true
		}
	}

	total := 0
	for _, ips := range t.known {
		total += len(ips)
	}
	log.Printf("[ip-tracker] loaded %d known IPs for %d users from %s", total, len(t.known), knownIPsPath)
}

// save persists known IPs to disk.
func (t *IPTracker) save() {
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	// Convert map[string]map[string]bool -> map[string][]string for JSON
	raw := make(map[string][]string)
	for user, ips := range t.known {
		for ip := range ips {
			raw[user] = append(raw[user], ip)
		}
	}
	t.dirty = false
	t.mu.Unlock()

	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		log.Printf("[ip-tracker] failed to marshal: %v", err)
		return
	}

	// Ensure directory exists
	if err := os.MkdirAll("/var/lib/azlo-linux-watch", 0755); err != nil {
		log.Printf("[ip-tracker] cannot create dir: %v", err)
		return
	}

	if err := os.WriteFile(knownIPsPath, data, 0644); err != nil {
		log.Printf("[ip-tracker] failed to write %s: %v", knownIPsPath, err)
	}
}
