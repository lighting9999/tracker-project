package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Status string

const (
	StatusAlive   Status = "ALIVE"
	StatusDead    Status = "DEAD"
	StatusInvalid Status = "INVALID"
)

type LocaleMap map[string]string

var locales = map[string]LocaleMap{
	"en": {
		"title": "Tracker Status Dashboard",
		"stats_summary": "Stats Summary",
		"total_checked": "Total Checked",
		"online": "Available",
		"dead": "Unavailable",
		"invalid": "Invalid",
		"global_uptime": "Global Uptime",
		"protocols": "Protocols",
		"downloads": "Downloads",
		"all_trackers": "All trackers (incl. dead/invalid)",
		"all_alive": "All available",
		"http": "HTTP", "https": "HTTPS", "udp": "UDP", "wss": "WSS",
		"detailed_status": "Tracker Details",
		"status": "Status", "url": "URL", "uptime": "Uptime",
		"days": "Days", "page": "Page",
		"available": "Available", "unavailable": "Unavailable",
		"back_to_top": "Back to top",
	},
	"zh": {
		"title": "Tracker 状态仪表盘",
		"stats_summary": "统计摘要",
		"total_checked": "总检测数",
		"online": "可用", "dead": "不可用", "invalid": "无效",
		"global_uptime": "全局在线率",
		"protocols": "协议", "downloads": "下载",
		"all_trackers": "全部 tracker（含失效/无效）",
		"all_alive": "所有可用",
		"http": "HTTP", "https": "HTTPS", "udp": "UDP", "wss": "WSS",
		"detailed_status": "Tracker 详情",
		"status": "状态", "url": "URL", "uptime": "在线率",
		"days": "连续天数", "page": "页码",
		"available": "可用", "unavailable": "不可用",
		"back_to_top": "回到顶部",
	},
}

type TrackerEntry struct {
	URL      string  `json:"url"`
	Status   string  `json:"status"`
	Uptime   float64 `json:"uptime"`
	Days     int     `json:"days"`
	Protocol string  `json:"protocol"`
}

type ProtoCounts struct {
	HTTP  int `json:"http"`
	HTTPS int `json:"https"`
	UDP   int `json:"udp"`
	WSS   int `json:"wss"`
}

type JSONData struct {
	Locales     map[string]LocaleMap `json:"locales"`
	Total       int                  `json:"total"`
	AliveCount  int                  `json:"alive_count"`
	DeadCount   int                  `json:"dead_count"`
	InvalidCount int                 `json:"invalid_count"`
	UptimePct   float64              `json:"uptime_pct"`
	Protocols   ProtoCounts          `json:"protocols"`
	Trackers    []TrackerEntry       `json:"trackers"`
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

func getProtocol(u string) string {
	if proto, _, ok := strings.Cut(u, "://"); ok {
		return strings.ToLower(proto)
	}
	return "other"
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
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
		if v, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
			h.Checks = v
		}
		if v, err := strconv.ParseUint(parts[2], 10, 64); err == nil {
			h.AliveChecks = v
		}
		if v, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
			h.FirstSeenTs = v
		}
		if v, err := strconv.ParseInt(parts[4], 10, 64); err == nil {
			h.FirstAliveTs = v
		}
		if v, err := strconv.ParseInt(parts[5], 10, 64); err == nil {
			h.LastSeenTs = v
		}
		if v, err := strconv.ParseInt(parts[6], 10, 64); err == nil {
			h.LastAliveTs = v
		}
		if len(parts) >= 8 {
			if v, err := strconv.ParseInt(parts[7], 10, 64); err == nil {
				h.StreakAliveStartTs = v
			}
		} else if h.LastSeenTs != 0 && h.LastSeenTs == h.LastAliveTs {
			h.StreakAliveStartTs = h.LastSeenTs
		}
		hist[parts[0]] = &h
	}
	return hist, scanner.Err()
}

// safeSlug creates a safe filename from a URL
var slugRe = regexp.MustCompile(`[^\w\-\.]`)

func safeSlug(url string) string {
	return slugRe.ReplaceAllString(url, "_")
}

func main() {
	trackersAll := flag.String("trackers-all", "trackers_all.txt", "Path to trackers_all.txt")
	trackersBest := flag.String("trackers-best", "trackers_best.txt", "Path to trackers_best.txt")
	historyFile := flag.String("history", "tracker_history.tsv", "Path to tracker_history.tsv")
	outputDir := flag.String("output-dir", "hugo", "Output directory for Hugo files")
	flag.Parse()

	allURLs, err := readLines(*trackersAll)
	if err != nil {
		log.Fatalf("Failed to read %s: %v", *trackersAll, err)
	}
	bestURLs := make(map[string]bool)
	if bestLines, err := readLines(*trackersBest); err == nil {
		for _, u := range bestLines {
			bestURLs[u] = true
		}
	}

	statusMap := make(map[string]Status)
	for _, u := range allURLs {
		if bestURLs[u] {
			statusMap[u] = StatusAlive
		} else {
			statusMap[u] = StatusDead
		}
	}

	history, err := loadHistory(*historyFile)
	if err != nil {
		log.Fatalf("Failed to load history: %v", err)
	}
	nowTs := time.Now().Unix()

	// Prepare JSON data
	data := JSONData{
		Locales:     locales,
		Total:       len(allURLs),
		AliveCount:  0,
		DeadCount:   0,
		InvalidCount: 0,
		UptimePct:   0,
		Protocols:   ProtoCounts{},
		Trackers:    []TrackerEntry{},
	}

	for _, u := range allURLs {
		status := statusMap[u]
		switch status {
		case StatusAlive:
			data.AliveCount++
		case StatusDead:
			data.DeadCount++
		case StatusInvalid:
			data.InvalidCount++
		}

		h := history[u]
		if h == nil {
			h = &TrackerHistory{}
		}
		uptime := 0.0
		if h.Checks > 0 {
			uptime = float64(h.AliveChecks) * 100 / float64(h.Checks)
		}
		days := 0
		if status == StatusAlive && h.StreakAliveStartTs > 0 {
			days = int((nowTs - h.StreakAliveStartTs) / 86400) + 1
		}
		proto := getProtocol(u)
		if status == StatusAlive {
			switch proto {
			case "http":
				data.Protocols.HTTP++
			case "https":
				data.Protocols.HTTPS++
			case "udp":
				data.Protocols.UDP++
			case "wss":
				data.Protocols.WSS++
			}
		}
		data.Trackers = append(data.Trackers, TrackerEntry{
			URL:      u,
			Status:   string(status),
			Uptime:   uptime,
			Days:     days,
			Protocol: proto,
		})
	}
	if data.Total > 0 {
		data.UptimePct = float64(data.AliveCount) * 100 / float64(data.Total)
	}

	// Write JSON
	baseDir := *outputDir
	dataDir := filepath.Join(baseDir, "data")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data dir: %v", err)
	}
	jsonPath := filepath.Join(dataDir, "trackers.json")
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(jsonPath, jsonBytes, 0644); err != nil {
		log.Fatalf("Failed to write JSON: %v", err)
	}
	fmt.Printf("✅ JSON written to %s\n", jsonPath)

	// Write Hugo content files (required for pagination)
	contentDir := filepath.Join(baseDir, "content", "trackers")
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		log.Fatalf("Failed to create content dir: %v", err)
	}
	for _, entry := range data.Trackers {
		slug := safeSlug(entry.URL)
		md := fmt.Sprintf(`---
url: "%s"
status: "%s"
uptime: %.2f
days: %d
protocol: "%s"
---
%s
`, entry.URL, entry.Status, entry.Uptime, entry.Days, entry.Protocol, entry.URL)
		filename := fmt.Sprintf("%s.md", slug)
		filePath := filepath.Join(contentDir, filename)
		if err := os.WriteFile(filePath, []byte(md), 0644); err != nil {
			log.Fatalf("Failed to write %s: %v", filePath, err)
		}
	}
	fmt.Printf("✅ %d tracker markdown files written to %s\n", len(data.Trackers), contentDir)
}
