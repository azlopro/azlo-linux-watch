package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── GeoResult ──────────────────────────────────────────────────────────────

type GeoResult struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Query   string `json:"query"`
}

type geoAPIResponse struct {
	Status  string `json:"status"`
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	Query   string `json:"query"`
}

// ─── LRU cache ──────────────────────────────────────────────────────────────

type cacheEntry struct {
	result    *GeoResult
	timestamp time.Time
}

// GeoLookup provides IP geolocation with caching and rate limiting.
type GeoLookup struct {
	mu       sync.Mutex
	cache    map[string]cacheEntry
	maxSize  int
	cacheTTL time.Duration

	// Simple rate limiter: track request timestamps
	requests []time.Time
	rateMax  int           // max requests per window
	rateWin  time.Duration // window duration

	client *http.Client
}

// NewGeoLookup creates a new geolocation lookup service.
func NewGeoLookup() *GeoLookup {
	return &GeoLookup{
		cache:    make(map[string]cacheEntry),
		maxSize:  256,
		cacheTTL: 1 * time.Hour,
		requests: make([]time.Time, 0, 45),
		rateMax:  40, // stay under ip-api's 45/min limit
		rateWin:  1 * time.Minute,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Lookup returns geolocation data for the given IP.
func (g *GeoLookup) Lookup(ip string) (*GeoResult, error) {
	if isPrivateIP(ip) {
		return nil, fmt.Errorf("private IP: %s", ip)
	}

	g.mu.Lock()

	// Check cache
	if entry, ok := g.cache[ip]; ok {
		if time.Since(entry.timestamp) < g.cacheTTL {
			g.mu.Unlock()
			return entry.result, nil
		}
		delete(g.cache, ip)
	}

	// Rate limit check
	now := time.Now()
	cutoff := now.Add(-g.rateWin)
	valid := g.requests[:0]
	for _, t := range g.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	g.requests = valid

	if len(g.requests) >= g.rateMax {
		g.mu.Unlock()
		return nil, fmt.Errorf("rate limited (>%d req/min)", g.rateMax)
	}
	g.requests = append(g.requests, now)
	g.mu.Unlock()

	// Call the API
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,city,isp,query", ip)
	resp, err := g.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("geo API error: %w", err)
	}
	defer resp.Body.Close()

	var apiResp geoAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("geo API decode error: %w", err)
	}
	if apiResp.Status != "success" {
		return nil, fmt.Errorf("geo API returned status: %s", apiResp.Status)
	}

	result := &GeoResult{
		Country: apiResp.Country,
		City:    apiResp.City,
		ISP:     apiResp.ISP,
		Query:   apiResp.Query,
	}

	// Store in cache
	g.mu.Lock()
	if len(g.cache) >= g.maxSize {
		// Evict oldest entry
		var oldestKey string
		var oldestTime time.Time
		for k, v := range g.cache {
			if oldestKey == "" || v.timestamp.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.timestamp
			}
		}
		delete(g.cache, oldestKey)
	}
	g.cache[ip] = cacheEntry{result: result, timestamp: now}
	g.mu.Unlock()

	log.Printf("[geo] %s → %s, %s (%s)", ip, result.City, result.Country, result.ISP)
	return result, nil
}

// ─── Private IP detection ───────────────────────────────────────────────────

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fd00::/8",
		"fe80::/10",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, network)
	}
}

func isPrivateIP(ipStr string) bool {
	// Strip port if present
	host := ipStr
	if strings.Contains(ipStr, ":") && !strings.Contains(ipStr, "::") {
		// Could be IPv4:port
		if h, _, err := net.SplitHostPort(ipStr); err == nil {
			host = h
		}
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return true // treat unparseable IPs as private (don't look up)
	}

	for _, r := range privateRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}
