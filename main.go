package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

type DiscordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []EmbedField   `json:"fields"`
	Footer      *EmbedFooter   `json:"footer,omitempty"`
	Timestamp   string         `json:"timestamp"`
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
	User    string
	TTY     string
	From    string
	Time    time.Time
	Action  string // "login" or "logout"
}

func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func getWhoOutput() (string, error) {
	out, err := exec.Command("who", "-u").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parseWho parses `who -u` output into a map of tty -> LoginEvent
func parseWho(output string) map[string]LoginEvent {
	sessions := make(map[string]LoginEvent)
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		user := fields[0]
		tty := fields[1]
		// fields[2] = date, fields[3] = time, fields[4] = idle or pid, fields[5] optionally = from
		from := ""
		if len(fields) >= 6 {
			from = strings.Trim(fields[5], "()")
		}
		sessions[tty] = LoginEvent{
			User:   user,
			TTY:    tty,
			From:   from,
			Time:   time.Now(),
			Action: "login",
		}
	}
	return sessions
}

func sendDiscordAlert(webhookURL string, event LoginEvent) {
	hostname := getHostname()

	color := 0x2ECC71 // green for login
	title := "User Login Detected"
	if event.Action == "logout" {
		color = 0xE74C3C // red for logout
		title = "User Logout Detected"
	}

	from := event.From
	if from == "" {
		from = "local"
	}

	embed := DiscordEmbed{
		Title: title,
		Color: color,
		Fields: []EmbedField{
			{Name: "Host", Value: hostname, Inline: true},
			{Name: "User", Value: event.User, Inline: true},
			{Name: "TTY", Value: event.TTY, Inline: true},
			{Name: "From", Value: from, Inline: true},
		},
		Footer:    &EmbedFooter{Text: "azlo-linux-watch " + version},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
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
		log.Printf("[%s] sent %s alert for user %s on %s", hostname, event.Action, event.User, event.TTY)
	}
}

func main() {
	fmt.Printf("azlo-linux-watch %s started — monitoring logins\n", version)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable is not set")
	}

	// Send startup notification
	hostname := getHostname()
	startEmbed := DiscordEmbed{
		Title:       "Login Monitor Started",
		Description: fmt.Sprintf("Now watching logins on **%s**", hostname),
		Color:       0x3498DB,
		Footer:      &EmbedFooter{Text: "azlo-linux-watch " + version},
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	startPayload := DiscordPayload{Embeds: []DiscordEmbed{startEmbed}}
	startBody, _ := json.Marshal(startPayload)
	http.Post(webhookURL, "application/json", bytes.NewReader(startBody)) //nolint

	// Initial snapshot
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

		// Detect new logins
		for tty, ev := range current {
			if _, exists := known[tty]; !exists {
				ev.Action = "login"
				sendDiscordAlert(webhookURL, ev)
			}
		}

		// Detect logouts
		for tty, ev := range known {
			if _, exists := current[tty]; !exists {
				ev.Action = "logout"
				sendDiscordAlert(webhookURL, ev)
			}
		}

		known = current
	}
}
