package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// ─── Event types ────────────────────────────────────────────────────────────

type EventType int

const (
	EventLogin          EventType = iota // who / PAM login
	EventLogout                          // who / PAM logout
	EventFailedLogin                     // auth.log: failed password
	EventInvalidUser                     // auth.log: invalid username attempt
	EventBruteForce                      // auth.log: ≥ threshold failures in window
	EventSSHKey                          // auth.log: accepted publickey + fingerprint
	EventSudo                            // auth.log: sudo command executed
	EventSuAttempt                       // auth.log: su attempt
	EventProcessSpawn                    // eBPF: execve traced
	EventDaemonStarted                   // internal: service just started
)

func (e EventType) String() string {
	switch e {
	case EventLogin:
		return "login"
	case EventLogout:
		return "logout"
	case EventFailedLogin:
		return "failed_login"
	case EventInvalidUser:
		return "invalid_user"
	case EventBruteForce:
		return "brute_force"
	case EventSSHKey:
		return "ssh_key"
	case EventSudo:
		return "sudo"
	case EventSuAttempt:
		return "su_attempt"
	case EventProcessSpawn:
		return "process_spawn"
	case EventDaemonStarted:
		return "daemon_started"
	default:
		return "unknown"
	}
}

// ─── Security event ─────────────────────────────────────────────────────────

type SecurityEvent struct {
	Type      EventType
	User      string
	SourceIP  string
	TTY       string
	PID       string
	Details   string // free-form: command, fingerprint, etc.
	Timestamp time.Time
	Source    string // "authlog", "who", "pam", "ebpf"

	// Set by the who poller for logout duration calculation
	LoginTime time.Time

	// Populated by the geo enricher
	Geo *GeoResult
}

// ─── Discord embed structs ──────────────────────────────────────────────────

type DiscordEmbed struct {
	Title       string       `json:"title"`
	Description string       `json:"description,omitempty"`
	Color       int          `json:"color"`
	Fields      []EmbedField `json:"fields"`
	Footer      *EmbedFooter `json:"footer,omitempty"`
	Timestamp   string       `json:"timestamp"`
}

type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type EmbedFooter struct {
	Text string `json:"text"`
}

type DiscordPayload struct {
	Embeds []DiscordEmbed `json:"embeds"`
}

// ─── Event → Discord ────────────────────────────────────────────────────────

func eventEmoji(t EventType) string {
	switch t {
	case EventLogin:
		return "🟢"
	case EventLogout:
		return "🔴"
	case EventFailedLogin:
		return "⚠️"
	case EventInvalidUser:
		return "❌"
	case EventBruteForce:
		return "🚨"
	case EventSSHKey:
		return "🔑"
	case EventSudo:
		return "🛡️"
	case EventSuAttempt:
		return "🔄"
	case EventProcessSpawn:
		return "🔍"
	case EventDaemonStarted:
		return "🔵"
	default:
		return "❓"
	}
}

func eventColor(t EventType) int {
	switch t {
	case EventLogin:
		return 0x2ECC71 // green
	case EventLogout:
		return 0xE74C3C // red
	case EventFailedLogin:
		return 0xE67E22 // orange
	case EventInvalidUser:
		return 0xE74C3C // red
	case EventBruteForce:
		return 0xE74C3C // red
	case EventSSHKey:
		return 0x3498DB // blue
	case EventSudo:
		return 0x9B59B6 // purple
	case EventSuAttempt:
		return 0xF39C12 // gold
	case EventProcessSpawn:
		return 0x1ABC9C // teal
	case EventDaemonStarted:
		return 0x3498DB // blue
	default:
		return 0x95A5A6 // grey
	}
}

func eventTitle(t EventType) string {
	switch t {
	case EventLogin:
		return "User Login"
	case EventLogout:
		return "User Logout"
	case EventFailedLogin:
		return "Failed Login Attempt"
	case EventInvalidUser:
		return "Invalid Username Attempt"
	case EventBruteForce:
		return "Brute Force Detected"
	case EventSSHKey:
		return "SSH Key Authentication"
	case EventSudo:
		return "Sudo Command Executed"
	case EventSuAttempt:
		return "Su Attempt"
	case EventProcessSpawn:
		return "Process Spawned"
	case EventDaemonStarted:
		return "Login Monitor Started"
	default:
		return "Security Event"
	}
}

// buildEmbed creates a Discord embed for a SecurityEvent.
func buildEmbed(ev SecurityEvent) DiscordEmbed {
	hostname := getHostname()
	emoji := eventEmoji(ev.Type)
	title := fmt.Sprintf("%s %s", emoji, eventTitle(ev.Type))

	fields := []EmbedField{
		{Name: "Host", Value: hostname, Inline: true},
	}

	if ev.User != "" {
		fields = append(fields, EmbedField{Name: "User", Value: ev.User, Inline: true})
	}

	if ev.TTY != "" {
		sType := sessionType(ev.TTY, ev.SourceIP)
		fields = append(fields, EmbedField{Name: "Session", Value: sType, Inline: true})
		fields = append(fields, EmbedField{Name: "TTY", Value: ev.TTY, Inline: true})
	}

	if ev.PID != "" {
		fields = append(fields, EmbedField{Name: "PID", Value: ev.PID, Inline: true})
	}

	// Source IP + rDNS + Geo
	if ev.SourceIP != "" {
		fromDisplay := ev.SourceIP
		if rdns := reverseDNS(ev.SourceIP); rdns != "" {
			fromDisplay = fmt.Sprintf("%s\n(%s)", ev.SourceIP, rdns)
		}
		fields = append(fields, EmbedField{Name: "Source", Value: fromDisplay, Inline: true})

		if ev.Geo != nil {
			geoStr := fmt.Sprintf("🌍 %s, %s\n%s", ev.Geo.City, ev.Geo.Country, ev.Geo.ISP)
			fields = append(fields, EmbedField{Name: "Location", Value: geoStr, Inline: true})
		}
	}

	if ev.Details != "" {
		fields = append(fields, EmbedField{Name: "Details", Value: ev.Details, Inline: false})
	}

	if ev.Source != "" {
		fields = append(fields, EmbedField{Name: "Detected by", Value: ev.Source, Inline: true})
	}

	// Login-specific fields
	if ev.Type == EventLogin && !ev.LoginTime.IsZero() {
		fields = append(fields, EmbedField{
			Name: "Login time", Value: ev.LoginTime.Format("2006-01-02 15:04:05"), Inline: true,
		})
	}

	// Logout-specific: session duration
	if ev.Type == EventLogout && !ev.LoginTime.IsZero() {
		duration := ev.Timestamp.Sub(ev.LoginTime).Truncate(time.Second)
		fields = append(fields, EmbedField{
			Name: "Session duration", Value: duration.String(), Inline: true,
		})
	}

	return DiscordEmbed{
		Title:     title,
		Color:     eventColor(ev.Type),
		Fields:    fields,
		Footer:    &EmbedFooter{Text: "azlo-linux-watch " + version},
		Timestamp: ev.Timestamp.UTC().Format(time.RFC3339),
	}
}

// ─── Dispatcher ─────────────────────────────────────────────────────────────

// runDispatcher reads events from the channel, enriches with geo, sends to Discord.
func runDispatcher(events <-chan SecurityEvent, webhookURL string, geo *GeoLookup) {
	for ev := range events {
		// Enrich with geolocation
		if geo != nil && ev.SourceIP != "" && !isPrivateIP(ev.SourceIP) {
			if result, err := geo.Lookup(ev.SourceIP); err == nil {
				ev.Geo = result
			}
		}

		embed := buildEmbed(ev)
		payload := DiscordPayload{Embeds: []DiscordEmbed{embed}}
		body, err := json.Marshal(payload)
		if err != nil {
			log.Printf("failed to marshal payload: %v", err)
			continue
		}

		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("failed to send webhook: %v", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 {
			log.Printf("webhook returned status %d", resp.StatusCode)
		} else {
			log.Printf("[%s] sent %s alert (user=%s, source=%s, ip=%s)",
				getHostname(), ev.Type, ev.User, ev.Source, ev.SourceIP)
		}

		// Discord rate limit: if we get 429, back off
		if resp.StatusCode == 429 {
			log.Printf("discord rate limited, sleeping 2s")
			time.Sleep(2 * time.Second)
		}
	}
}
