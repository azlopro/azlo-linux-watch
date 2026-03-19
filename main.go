package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

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

func sessionType(tty, from string) string {
	if from != "" {
		return "SSH"
	}
	if strings.HasPrefix(tty, "pts/") {
		return "Pseudo-terminal"
	}
	return "Local"
}

// featureEnabled checks whether a feature is in the FEATURES env var.
func featureEnabled(features []string, name string) bool {
	for _, f := range features {
		if strings.TrimSpace(f) == name {
			return true
		}
	}
	return false
}

func main() {
	fmt.Printf("azlo-linux-watch %s started\n", version)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		log.Fatal("DISCORD_WEBHOOK_URL environment variable is not set")
	}

	// Parse enabled features
	featuresStr := os.Getenv("FEATURES")
	if featuresStr == "" {
		featuresStr = "authlog,geoip,pam,who,ebpf"
	}
	features := strings.Split(featuresStr, ",")

	// Set up geolocation
	var geo *GeoLookup
	geoEnabled := os.Getenv("GEOIP_ENABLED")
	if geoEnabled == "" {
		geoEnabled = "true"
	}
	if featureEnabled(features, "geoip") && geoEnabled == "true" {
		geo = NewGeoLookup()
		log.Printf("[main] IP geolocation enabled (ip-api.com)")
	} else {
		log.Printf("[main] IP geolocation disabled")
	}

	// Event channel — buffered to avoid blocking producers
	events := make(chan SecurityEvent, 100)

	// Start the dispatcher
	go runDispatcher(events, webhookURL, geo)

	// Send startup notification
	hostname := getHostname()
	kernel := getKernelVersion()
	enabledList := strings.Join(features, ", ")

	events <- SecurityEvent{
		Type:      EventDaemonStarted,
		Timestamp: time.Now(),
		Source:    "main",
		Details:   fmt.Sprintf("Host: **%s**\nKernel: `%s`\nVersion: `%s`\nFeatures: %s", hostname, kernel, version, enabledList),
	}

	// Start feature goroutines
	if featureEnabled(features, "authlog") {
		go watchAuthLog(events)
		log.Printf("[main] auth.log watcher enabled")
	}

	if featureEnabled(features, "pam") {
		go startPAMListener(events)
		log.Printf("[main] PAM listener enabled")
	}

	if featureEnabled(features, "ebpf") {
		go startEBPFTracer(events)
		log.Printf("[main] eBPF tracer enabled")
	}

	if featureEnabled(features, "who") {
		go pollWho(events)
		log.Printf("[main] who poller enabled (5s interval)")
	}

	// Block forever — all work is done in goroutines
	select {}
}
