package tracker

import (
    "bufio"
    "fmt"
    "io"
    "net/url"
    "os"
    "path/filepath"
    "sort"
    "strconv"
    "strings"
    "time"
)

func LoadAllTrackersFromInput(inputFile string) ([]string, error) {
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
        parsed := ParseTrackerLine(line)
        if parsed == "" || strings.HasPrefix(parsed, "#") {
            continue
        }
        for _, match := range trackerRe.FindAllString(parsed, -1) {
            norm, err := NormalizeTrackerURL(match)
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

func GetProtocol(entry TrackerEntry) string {
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

func GetProtocolFromURL(raw string) string {
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

func LoadHistory(path string) (map[string]*TrackerHistory, error) {
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

func SaveHistory(path string, hist map[string]*TrackerHistory) error {
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

func UpdateHistory(hist map[string]*TrackerHistory, results map[string]TrackerEntry, nowTs int64) {
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

func MergeAndOutput(allTrackers []string, httpResults, udpWssResults []CheckResult, outputDir string) error {
    // 构建合并 map
    allEntries := make(map[string]TrackerEntry)
    for _, r := range httpResults {
        allEntries[r.URL] = TrackerEntry{
            URL:          r.URL,
            Status:       r.Status,
            Protocol:     GetProtocolFromURL(r.URL),
            PingMs:       r.PingMs,
            SupportsIPv4: r.SupportsIPv4,
            SupportsIPv6: r.SupportsIPv6,
        }
    }
    for _, r := range udpWssResults {
        allEntries[r.URL] = TrackerEntry{
            URL:          r.URL,
            Status:       r.Status,
            Protocol:     GetProtocolFromURL(r.URL),
            PingMs:       r.PingMs,
            SupportsIPv4: r.SupportsIPv4,
            SupportsIPv6: r.SupportsIPv6,
        }
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
            entry = TrackerEntry{URL: url, Status: "INVALID", Protocol: GetProtocolFromURL(url)}
        }
        finalEntries = append(finalEntries, entry)
        switch entry.Status {
        case "ALIVE":
            aliveList = append(aliveList, url)
            totalAlive++
            proto := GetProtocol(entry)
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
    // 写入 txt 文件到 outputDir
    txtFiles := map[string][]string{
        "trackers_best.txt":          aliveList,
        "trackers_best_http.txt":     SortUnique(aliveHTTP),
        "trackers_best_https.txt":    SortUnique(aliveHTTPS),
        "trackers_best_udp.txt":      SortUnique(aliveUDP),
        "trackers_best_ws.txt":       SortUnique(aliveWSS),
        "trackers_best_i2p.txt":      SortUnique(aliveI2P),
        "trackers_alive_ipv4only.txt": SortUnique(aliveIPv4Only),
        "trackers_alive_ipv6only.txt": SortUnique(aliveIPv6Only),
        "trackers_alive_dualstack.txt": SortUnique(aliveDualStack),
    }
    for name, lines := range txtFiles {
        if err := WriteLines(filepath.Join(outputDir, name), lines); err != nil {
            return err
        }
    }

    // 计算协议统计
    protocols := ProtocolStats{}
    for _, u := range aliveList {
        proto := GetProtocolFromURL(u)
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

    // 历史记录
    historyPath := filepath.Join(outputDir, "tracker_history.tsv")
    history, _ := LoadHistory(historyPath)
    nowTs := time.Now().Unix()
    UpdateHistory(history, allEntries, nowTs)
    SaveHistory(historyPath, history)

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

    data := FrontendData{
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

    jsonBytes, _ := json.MarshalIndent(data, "", "  ")
    if err := os.MkdirAll(outputDir, 0755); err != nil {
        return err
    }
    if err := os.WriteFile(filepath.Join(outputDir, "trackers.json"), jsonBytes, 0644); err != nil {
        return err
    }

    fmt.Printf("✅ 合并完成，数据已写入 %s\n", outputDir)
    return nil
}