package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type TrackerEntry struct {
	URL          string  `json:"url"`
	Status       string  `json:"status"`
	Protocol     string  `json:"protocol"`
	PingMs       *int64  `json:"ping_ms,omitempty"`
	SupportsIPv4 *bool   `json:"supports_ipv4,omitempty"`
	SupportsIPv6 *bool   `json:"supports_ipv6,omitempty"`
}

type TrackerHistory struct {
	Checks             uint64
	AliveChecks        uint64
	FirstSeenTs        int64
	FirstAliveTs       int64
	LastSeenTs         int64
	LastAliveTs        int64
	StreakAliveStartTs int64
}

type ProtocolStats struct {
	HTTP     int     `json:"http"`
	HTTPS    int     `json:"https"`
	UDP      int     `json:"udp"`
	WSS      int     `json:"wss"`
	WebRTC   int     `json:"webrtc"`
	I2P      int     `json:"i2p"`
	DNS      int     `json:"dns"`
	HTTPPct  float64 `json:"http_pct"`
	HTTPSPct float64 `json:"https_pct"`
	UDPPct   float64 `json:"udp_pct"`
	WSSPct   float64 `json:"wss_pct"`
}

type JekyllData struct {
	Total        int            `json:"total"`
	AliveCount   int            `json:"alive_count"`
	DeadCount    int            `json:"dead_count"`
	InvalidCount int            `json:"invalid_count"`
	UptimePct    float64        `json:"uptime_pct"`
	Protocols    ProtocolStats  `json:"protocols"`
	Trackers     []TrackerEntry `json:"trackers"`
	AvgPingMs    float64        `json:"avg_ping_ms"`
	MinPingMs    int64          `json:"min_ping_ms"`
	MaxPingMs    int64          `json:"max_ping_ms"`
}

var trackerRe = regexp.MustCompile(`(?i)(https?|udp|wss?|dns)://[^\s,]+?/announce[^\s,]*`)

func parseTrackerLine(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") && strings.Contains(line, "](") && strings.HasSuffix(line, ")") {
		if _, after, ok := strings.Cut(line, "]("); ok {
			return strings.TrimSuffix(after, ")")
		}
	}
	return line
}

func collapsePathSlashes(path string) string {
	var out []rune
	prevSlash := false
	for _, ch := range path {
		if ch == '/' {
			if !prevSlash {
				out = append(out, ch)
			}
			prevSlash = true
		} else {
			out = append(out, ch)
			prevSlash = false
		}
	}
	if len(out) == 0 {
		return "/"
	}
	return string(out)
}

func normalizeTrackerURL(raw string) (string, error) {
	candidate := strings.Trim(raw, "\"'<>[](){};,.")
	u, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "udp" && scheme != "wss" && scheme != "ws" && scheme != "dns" {
		return "", fmt.Errorf("unsupported scheme")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no host")
	}
	if ip := net.ParseIP(host); ip == nil && !strings.Contains(host, ".") && !strings.HasSuffix(host, ".i2p") {
		return "", fmt.Errorf("invalid host")
	}
	normalizedPath := collapsePathSlashes(u.Path)
	if scheme == "dns" {
		return candidate, nil
	}
	if !(strings.HasSuffix(normalizedPath, "/announce") ||
		strings.Contains(normalizedPath, "/announce?") ||
		strings.HasSuffix(normalizedPath, "/announce.php") ||
		strings.HasSuffix(normalizedPath, "/announce.jsp") ||
		strings.HasSuffix(normalizedPath, "/announce.aspx")) {
		return "", fmt.Errorf("path must be related to /announce")
	}
	u.Path = normalizedPath
	u.Fragment = ""
	if (scheme == "http" && u.Port() == "80") || (scheme == "https" && u.Port() == "443") {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
	}
	return u.String(), nil
}

func loadAllTrackersFromInput(inputFile string) ([]string, error) {
	f, err := os.Open(inputFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	content, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(content), ",", "\n")
	trackers := []string{}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := scanner.Text()
		parsed := parseTrackerLine(line)
		if parsed == "" || strings.HasPrefix(parsed, "#") {
			continue
		}
		for _, match := range trackerRe.FindAllString(parsed, -1) {
			norm, err := normalizeTrackerURL(match)
			if err != nil {
				continue
			}
			if !seen[norm] {
				seen[norm] = true
				trackers = append(trackers, norm)
			}
		}
	}
	return trackers, scanner.Err()
}

func loadJSONResults(file string) ([]TrackerEntry, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var entries []TrackerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func getProtocol(entry TrackerEntry) string {
	if entry.Protocol != "" {
		return entry.Protocol
	}
	if strings.HasSuffix(entry.URL, ".i2p") {
		return "i2p"
	}
	parsed, _ := url.Parse(entry.URL)
	if parsed != nil {
		return strings.ToLower(parsed.Scheme)
	}
	return "unknown"
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, line := range lines {
		fmt.Fprintln(f, line)
	}
	return nil
}

func loadHistory(path string) (map[string]*TrackerHistory, error) {
	hist := map[string]*TrackerHistory{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hist, nil
		}
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			continue
		}
		var h TrackerHistory
		h.Checks, _ = strconv.ParseUint(parts[1], 10, 64)
		h.AliveChecks, _ = strconv.ParseUint(parts[2], 10, 64)
		h.FirstSeenTs, _ = strconv.ParseInt(parts[3], 10, 64)
		h.FirstAliveTs, _ = strconv.ParseInt(parts[4], 10, 64)
		h.LastSeenTs, _ = strconv.ParseInt(parts[5], 10, 64)
		h.LastAliveTs, _ = strconv.ParseInt(parts[6], 10, 64)
		if len(parts) >= 8 {
			h.StreakAliveStartTs, _ = strconv.ParseInt(parts[7], 10, 64)
		} else if h.LastSeenTs != 0 && h.LastSeenTs == h.LastAliveTs {
			h.StreakAliveStartTs = h.LastSeenTs
		}
		hist[parts[0]] = &h
	}
	return hist, scanner.Err()
}

func saveHistory(path string, hist map[string]*TrackerHistory) error {
	urls := make([]string, 0, len(hist))
	for u := range hist {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, u := range urls {
		h := hist[u]
		fmt.Fprintf(f, "%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			u, h.Checks, h.AliveChecks, h.FirstSeenTs, h.FirstAliveTs, h.LastSeenTs, h.LastAliveTs, h.StreakAliveStartTs)
	}
	return nil
}

func updateHistory(hist map[string]*TrackerHistory, results map[string]TrackerEntry, nowTs int64) {
	for url, entry := range results {
		histEntry, exists := hist[url]
		if !exists {
			histEntry = &TrackerHistory{}
			hist[url] = histEntry
		}
		lastWasAlive := histEntry.LastSeenTs != 0 && histEntry.LastSeenTs == histEntry.LastAliveTs
		histEntry.Checks++
		if histEntry.FirstSeenTs == 0 {
			histEntry.FirstSeenTs = nowTs
		}
		histEntry.LastSeenTs = nowTs
		if entry.Status == "ALIVE" {
			if !lastWasAlive || histEntry.StreakAliveStartTs == 0 {
				histEntry.StreakAliveStartTs = nowTs
			}
			histEntry.AliveChecks++
			if histEntry.FirstAliveTs == 0 {
				histEntry.FirstAliveTs = nowTs
			}
			histEntry.LastAliveTs = nowTs
		} else {
			histEntry.StreakAliveStartTs = 0
		}
	}
}

func main() {
	inputFile := flag.String("input", "merged_trackers.txt", "Original input file")
	flag.Parse()

	allTrackers, err := loadAllTrackersFromInput(*inputFile)
	if err != nil {
		log.Fatalf("Failed to load input: %v", err)
	}
	writeLines("trackers_all.txt", allTrackers)

	httpEntries, _ := loadJSONResults("trackers_http.json")
	udpWssEntries, _ := loadJSONResults("trackers_udp_wss.json")

	allEntries := make(map[string]TrackerEntry)
	for _, e := range httpEntries {
		allEntries[e.URL] = e
	}
	for _, e := range udpWssEntries {
		allEntries[e.URL] = e
	}

	var finalEntries []TrackerEntry
	var aliveList, aliveHTTP, aliveHTTPS, aliveUDP, aliveWSS, aliveI2P []string
	var aliveIPv4Only, aliveIPv6Only, aliveDualStack []string
	var totalAlive, totalDead, totalInvalid int
	var sumPing int64
	var countPing int64
	var minPing int64 = -1
	var maxPing int64

	for _, url := range allTrackers {
		entry, ok := allEntries[url]
		if !ok {
			entry = TrackerEntry{URL: url, Status: "INVALID", Protocol: getProtocolFromURL(url)}
		}
		finalEntries = append(finalEntries, entry)
		switch entry.Status {
		case "ALIVE":
			aliveList = append(aliveList, url)
			totalAlive++
			proto := getProtocol(entry)
			switch proto {
			case "http":
				aliveHTTP = append(aliveHTTP, url)
			case "https":
				aliveHTTPS = append(aliveHTTPS, url)
			case "udp":
				aliveUDP = append(aliveUDP, url)
			case "ws", "wss":
				aliveWSS = append(aliveWSS, url)
			case "i2p":
				aliveI2P = append(aliveI2P, url)
			}
			if entry.SupportsIPv4 != nil && entry.SupportsIPv6 != nil && *entry.SupportsIPv4 && *entry.SupportsIPv6 {
				aliveDualStack = append(aliveDualStack, url)
			} else if entry.SupportsIPv4 != nil && *entry.SupportsIPv4 && (entry.SupportsIPv6 == nil || !*entry.SupportsIPv6) {
				aliveIPv4Only = append(aliveIPv4Only, url)
			} else if entry.SupportsIPv6 != nil && *entry.SupportsIPv6 && (entry.SupportsIPv4 == nil || !*entry.SupportsIPv4) {
				aliveIPv6Only = append(aliveIPv6Only, url)
			}
			if entry.PingMs != nil {
				p := *entry.PingMs
				sumPing += p
				countPing++
				if minPing == -1 || p < minPing {
					minPing = p
				}
				if p > maxPing {
					maxPing = p
				}
			}
		case "DEAD":
			totalDead++
		default:
			totalInvalid++
		}
	}

	sort.Strings(aliveList)
	writeLines("trackers_best.txt", aliveList)
	writeLines("trackers_best_http.txt", sortUnique(aliveHTTP))
	writeLines("trackers_best_https.txt", sortUnique(aliveHTTPS))
	writeLines("trackers_best_udp.txt", sortUnique(aliveUDP))
	writeLines("trackers_best_ws.txt", sortUnique(aliveWSS))
	writeLines("trackers_best_i2p.txt", sortUnique(aliveI2P))
	writeLines("trackers_alive_ipv4only.txt", sortUnique(aliveIPv4Only))
	writeLines("trackers_alive_ipv6only.txt", sortUnique(aliveIPv6Only))
	writeLines("trackers_alive_dualstack.txt", sortUnique(aliveDualStack))

	protocols := ProtocolStats{}
	for _, u := range aliveList {
		proto := getProtocolFromURL(u)
		switch proto {
		case "http":
			protocols.HTTP++
		case "https":
			protocols.HTTPS++
		case "udp":
			protocols.UDP++
		case "ws", "wss":
			protocols.WSS++
		case "i2p":
			protocols.I2P++
		}
	}
	total := len(allTrackers)
	if total > 0 {
		protocols.HTTPPct = float64(protocols.HTTP) * 100 / float64(total)
		protocols.HTTPSPct = float64(protocols.HTTPS) * 100 / float64(total)
		protocols.UDPPct = float64(protocols.UDP) * 100 / float64(total)
		protocols.WSSPct = float64(protocols.WSS) * 100 / float64(total)
	}

	historyPath := "tracker_history.tsv"
	history, _ := loadHistory(historyPath)
	nowTs := time.Now().Unix()
	updateHistory(history, allEntries, nowTs)
	saveHistory(historyPath, history)

	aliveCount := totalAlive
	uptimePct := 0.0
	if total > 0 {
		uptimePct = float64(aliveCount) * 100 / float64(total)
	}
	avgPing := 0.0
	if countPing > 0 {
		avgPing = float64(sumPing) / float64(countPing)
	}
	if minPing == -1 {
		minPing = 0
	}

	jData := JekyllData{
		Total:        total,
		AliveCount:   aliveCount,
		DeadCount:    totalDead,
		InvalidCount: totalInvalid,
		UptimePct:    uptimePct,
		Protocols:    protocols,
		Trackers:     finalEntries,
		AvgPingMs:    avgPing,
		MinPingMs:    minPing,
		MaxPingMs:    maxPing,
	}
	jsonBytes, _ := json.MarshalIndent(jData, "", "  ")
	os.WriteFile("jekyll/_data/trackers.json", jsonBytes, 0644)
	fmt.Println("Merge complete")
}

func sortUnique(items []string) []string {
	if len(items) == 0 {
		return items
	}
	slices.Sort(items)
	return slices.Compact(items)
}

func getProtocolFromURL(raw string) string {
	if strings.HasSuffix(raw, ".i2p") {
		return "i2p"
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "unknown"
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "ws" || scheme == "wss" {
		return "ws"
	}
	return scheme
}