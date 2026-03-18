package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

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

type LoginEvent struct {
	User      string
	TTY       string
	From      string // source IP, empty for local
	PID       string
	LoginTime time.Time
	Action    string // "login" or "logout"
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func getKernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func reverseDNS(ip string) string {
	if ip == "" {
		return ""
	}
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func getWhoOutput() (string, error) {
	out, err := exec.Command("who", "-u").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parseWho parses `who -u` output into a map of tty -> LoginEvent.
//
// `who -u` format:
//   user  tty  DATE  TIME  IDLE  PID  (FROM)
//   bob   pts/0  2026-03-18  22:08  00:05  1234  (192.168.1.1)
func parseWho(output string) map[string]LoginEvent {
	sessions := make(map[string]LoginEvent)
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		user := fields[0]
		tty := fields[1]
		pid := fields[5]

		// Parse login time from date + time columns
		loginTime, err := time.ParseInLocation("2006-01-02 15:04", fields[2]+" "+fields[3], time.Local)
		if err != nil {
			loginTime = time.Now()
		}

		// fields[6] is the source "(IP)" — only present for remote sessions
		from := ""
		if len(fields) >= 7 {
			from = strings.Trim(fields[6], "()")
		}

		sessions[tty] = LoginEvent{
			User:      user,
			TTY:       tty,
			From:      from,
			PID:       pid,
			LoginTime: loginTime,
			Action:    "login",
		}
	}
	return sessions
}

func sessionType(tty, from string) string {
	if from != "" {
		return "SSH"
	}
	if strings.HasPrefix(tty, "pts/") {
		return "Pseudo-terminal"
	}
	return "Local"
}

func sendDiscordAlert(webhookURL string, event LoginEvent) {
	hostname := getHostname()
	now := time.Now()

	color := 0x2ECC71 // green for login
	title := "🟢 User Login"
	if event.Action == "logout" {
		color = 0xE74C3C // red for logout
		title = "🔴 User Logout"
	}

	from := event.From
	fromDisplay := from
	if from == "" {
		fromDisplay = "local"
	} else {
		if rdns := reverseDNS(from); rdns != "" {
			fromDisplay = fmt.Sprintf("%s\n(%s)", from, rdns)
		}
	}

	fields := []EmbedField{
		{Name: "Host", Value: hostname, Inline: true},
		{Name: "User", Value: event.User, Inline: true},
		{Name: "Session", Value: sessionType(event.TTY, event.From), Inline: true},
		{Name: "TTY", Value: event.TTY, Inline: true},
		{Name: "PID", Value: event.PID, Inline: true},
		{Name: "Source", Value: fromDisplay, Inline: true},
		{Name: "Login time", Value: event.LoginTime.Format("2006-01-02 15:04:05"), Inline: true},
	}

	if event.Action == "logout" {
		duration := now.Sub(event.LoginTime).Truncate(time.Second)
		fields = append(fields, EmbedField{Name: "Session duration", Value: duration.String(), Inline: true})
	}

	embed := DiscordEmbed{
		Title:     title,
		Color:     color,
		Fields:    fields,
		Footer:    &EmbedFooter{Text: "azlo-linux-watch " + version},
		Timestamp: now.UTC().Format(time.RFC3339),
	}

	payload := DiscordPayload{Embeds: []DiscordEmbed{embed}}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("failed to marshal payload: %v", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("failed to send webhook: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("webhook returned status %d", resp.StatusCode)
	} else {
		log.Printf("[%s] sent %s alert for %s@%s (pid %s, from %s)", hostname, event.Action, event.User, event.TTY, event.PID, event.From)
	}
}

func main() {
	fmt.Printf("azlo-linux-watch %s started — monitoring logins\n", version)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable is not set")
	}

	hostname := getHostname()
	kernel := getKernelVersion()

	startEmbed := DiscordEmbed{
		Title: "🔵 Login Monitor Started",
		Color: 0x3498DB,
		Fields: []EmbedField{
			{Name: "Host", Value: hostname, Inline: true},
			{Name: "Kernel", Value: kernel, Inline: true},
			{Name: "Version", Value: version, Inline: true},
		},
		Footer:    &EmbedFooter{Text: "azlo-linux-watch " + version},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	startPayload := DiscordPayload{Embeds: []DiscordEmbed{startEmbed}}
	startBody, _ := json.Marshal(startPayload)
	http.Post(webhookURL, "application/json", bytes.NewReader(startBody)) //nolint

	raw, err := getWhoOutput()
	if err != nil {
		log.Fatalf("cannot run 'who': %v", err)
	}
	known := parseWho(raw)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		raw, err := getWhoOutput()
		if err != nil {
			log.Printf("who error: %v", err)
			continue
		}
		current := parseWho(raw)

		for tty, ev := range current {
			if _, exists := known[tty]; !exists {
				ev.Action = "login"
				sendDiscordAlert(webhookURL, ev)
			}
		}

		for tty, ev := range known {
			if _, exists := current[tty]; !exists {
				ev.Action = "logout"
				sendDiscordAlert(webhookURL, ev)
			}
		}

		known = current
	}
}
