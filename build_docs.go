package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type LocaleMap map[string]string

var locales = map[string]LocaleMap{
	"en": {
		"title":            "Tracker Status Dashboard",
		"stats_summary":    "Stats Summary",
		"total_checked":    "Total Checked",
		"online":           "Available",
		"dead":             "Unavailable",
		"invalid":          "Invalid",
		"global_uptime":    "Global Uptime",
		"protocols":        "Protocols",
		"downloads":        "Downloads",
		"all_trackers":     "All trackers (incl. dead/invalid)",
		"all_alive":        "All available",
		"http":             "HTTP", "https": "HTTPS", "udp": "UDP", "wss": "WSS",
		"detailed_status":  "Tracker Details",
		"status":           "Status", "url": "URL", "uptime": "Uptime",
		"days":             "Days", "page": "Page",
		"available":        "Available", "unavailable": "Unavailable",
		"back_to_top":      "Back to top",
	},
	"zh": {
		"title":            "Tracker 状态仪表盘",
		"stats_summary":    "统计摘要",
		"total_checked":    "总检测数",
		"online":           "可用", "dead": "不可用", "invalid": "无效",
		"global_uptime":    "全局在线率",
		"protocols":        "协议", "downloads": "下载",
		"all_trackers":     "全部 tracker（含失效/无效）",
		"all_alive":        "所有可用",
		"http": "HTTP", "https": "HTTPS", "udp": "UDP", "wss": "WSS",
		"detailed_status":  "Tracker 详情",
		"status":           "状态", "url": "URL", "uptime": "在线率",
		"days":             "连续天数", "page": "页码",
		"available":        "可用", "unavailable": "不可用",
		"back_to_top":      "回到顶部",
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
	HTTP     int     `json:"http"`
	HTTPS    int     `json:"https"`
	UDP      int     `json:"udp"`
	WSS      int     `json:"wss"`
	HTTPPct  float64 `json:"http_pct"`
	HTTPSPct float64 `json:"https_pct"`
	UDPPct   float64 `json:"udp_pct"`
	WSSPct   float64 `json:"wss_pct"`
}

type JSONData struct {
	Locales      map[string]LocaleMap `json:"locales"`
	Total        int                  `json:"total"`
	AliveCount   int                  `json:"alive_count"`
	DeadCount    int                  `json:"dead_count"`
	InvalidCount int                  `json:"invalid_count"`
	UptimePct    float64              `json:"uptime_pct"`
	Protocols    ProtoCounts          `json:"protocols"`
	Trackers     []TrackerEntry       `json:"trackers"`
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

// partialStats holds intermediate counts from one goroutine
type partialStats struct {
	alive, dead, invalid int
	protoHTTP, protoHTTPS, protoUDP, protoWSS int
}

func main() {
	trackersAll := flag.String("trackers-all", "trackers_all.txt", "Path to trackers_all.txt")
	trackersBest := flag.String("trackers-best", "trackers_best.txt", "Path to trackers_best.txt")
	historyFile := flag.String("history", "tracker_history.tsv", "Path to tracker_history.tsv")
	outputFile := flag.String("output", "_data/trackers.json", "Output JSON file for Jekyll")
	workers := flag.Int("workers", runtime.NumCPU(), "Number of parallel goroutines")
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

	statusMap := make(map[string]string, len(allURLs))
	for _, u := range allURLs {
		if bestURLs[u] {
			statusMap[u] = "ALIVE"
		} else {
			statusMap[u] = "DEAD"
		}
	}

	history, err := loadHistory(*historyFile)
	if err != nil {
		log.Fatalf("Failed to load history: %v", err)
	}
	nowTs := time.Now().Unix()

	// ----- Multi‑threaded stats aggregation -----
	numWorkers := *workers
	if numWorkers < 1 {
		numWorkers = 1
	}
	chunkSize := len(allURLs) / numWorkers
	if chunkSize < 1 {
		chunkSize = 1
	}

	var wg sync.WaitGroup
	statsCh := make(chan partialStats, numWorkers)

	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == numWorkers-1 {
			end = len(allURLs)
		}
		wg.Add(1)
		go func(urls []string) {
			defer wg.Done()
			var ps partialStats
			for _, u := range urls {
				st := statusMap[u]
				switch st {
				case "ALIVE":
					ps.alive++
					switch getProtocol(u) {
					case "http":
						ps.protoHTTP++
					case "https":
						ps.protoHTTPS++
					case "udp":
						ps.protoUDP++
					case "wss":
						ps.protoWSS++
					}
				case "DEAD":
					ps.dead++
				default:
					ps.invalid++
				}
			}
			statsCh <- ps
		}(allURLs[start:end])
	}
	wg.Wait()
	close(statsCh)

	var totalAlive, totalDead, totalInvalid int
	var totalHTTP, totalHTTPS, totalUDP, totalWSS int
	for ps := range statsCh {
		totalAlive += ps.alive
		totalDead += ps.dead
		totalInvalid += ps.invalid
		totalHTTP += ps.protoHTTP
		totalHTTPS += ps.protoHTTPS
		totalUDP += ps.protoUDP
		totalWSS += ps.protoWSS
	}

	total := len(allURLs)
	uptimePct := 0.0
	if total > 0 {
		uptimePct = float64(totalAlive) * 100 / float64(total)
	}

	protocols := ProtoCounts{
		HTTP:  totalHTTP,
		HTTPS: totalHTTPS,
		UDP:   totalUDP,
		WSS:   totalWSS,
	}
	if total > 0 {
		protocols.HTTPPct  = float64(totalHTTP) * 100 / float64(total)
		protocols.HTTPSPct = float64(totalHTTPS) * 100 / float64(total)
		protocols.UDPPct   = float64(totalUDP) * 100 / float64(total)
		protocols.WSSPct   = float64(totalWSS) * 100 / float64(total)
	}

	// Build full tracker list for optional use (preserving original functionality)
	trackers := make([]TrackerEntry, 0, total)
	for _, u := range allURLs {
		st := statusMap[u]
		h := history[u]
		if h == nil {
			h = &TrackerHistory{}
		}
		uptime := 0.0
		if h.Checks > 0 {
			uptime = float64(h.AliveChecks) * 100 / float64(h.Checks)
		}
		days := 0
		if st == "ALIVE" && h.StreakAliveStartTs > 0 {
			days = int((nowTs - h.StreakAliveStartTs) / 86400) + 1
		}
		trackers = append(trackers, TrackerEntry{
			URL:      u,
			Status:   st,
			Uptime:   uptime,
			Days:     days,
			Protocol: getProtocol(u),
		})
	}

	data := JSONData{
		Locales:      locales,
		Total:        total,
		AliveCount:   totalAlive,
		DeadCount:    totalDead,
		InvalidCount: totalInvalid,
		UptimePct:    uptimePct,
		Protocols:    protocols,
		Trackers:     trackers,
	}

	outputDir := filepath.Dir(*outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(*outputFile, jsonBytes, 0644); err != nil {
		log.Fatalf("Failed to write JSON: %v", err)
	}
	fmt.Printf("✅ Jekyll data (multithreaded) written to %s\n", *outputFile)
}
