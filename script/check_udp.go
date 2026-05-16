// check_udp.go
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const defaultTimeout = 5 * time.Second
const defaultWorkers = 1000
const defaultRetries = 1

const (
	StatusAlive   = "ALIVE"
	StatusDead    = "DEAD"
	StatusInvalid = "INVALID"
)

type CheckResult struct {
	URL          string  `json:"url"`
	Status       string  `json:"status"`
	PingMs       *int64  `json:"ping_ms,omitempty"`
	SupportsIPv4 *bool   `json:"supports_ipv4,omitempty"`
	SupportsIPv6 *bool   `json:"supports_ipv6,omitempty"`
}

type TrackerEntry struct {
	URL          string  `json:"url"`
	Status       string  `json:"status"`
	Protocol     string  `json:"protocol"`
	PingMs       *int64  `json:"ping_ms,omitempty"`
	SupportsIPv4 *bool   `json:"supports_ipv4,omitempty"`
	SupportsIPv6 *bool   `json:"supports_ipv6,omitempty"`
}

var (
	trackerRe      = regexp.MustCompile(`(?i)(https?|udp|wss?|dns)://[^\s,]+?/announce[^\s,]*`)
	peerIDPrefix   string
	infoHashes     []string
	hashIndex      uint32
	dnsCache       sync.Map
	dnsCacheTTL    = 10 * time.Minute
	peersCollector sync.Map
	rateLimiter    *rate.Limiter
	customDNS      string
	dnsTimeout     time.Duration
	hostsMap       map[string][]string
	hostsMapMu     sync.RWMutex
	hostsFilePath  string
)

type dnsCacheEntry struct {
	addrs []string
	ts    time.Time
}

func init() {
	peerIDPrefix = fmt.Sprintf("-RS0001-%s", randomNumeric(12))
	rateLimiter = rate.NewLimiter(rate.Limit(1000), 100)
}

func randomNumeric(n int) string {
	const digits = "0123456789"
	ret := make([]byte, n)
	for i := range ret {
		bi, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		ret[i] = digits[bi.Int64()]
	}
	return string(ret)
}

func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return int(n.Int64()) + min
}

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

func loadHostsFile() {
	hostsMapMu.Lock()
	defer hostsMapMu.Unlock()
	hostsMap = make(map[string][]string)
	path := hostsFilePath
	if path == "" {
		if runtime.GOOS == "windows" {
			path = `C:\Windows\System32\drivers\etc\hosts`
		} else {
			path = "/etc/hosts"
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		for _, host := range fields[1:] {
			hostsMap[strings.ToLower(host)] = append(hostsMap[strings.ToLower(host)], ip)
		}
	}
}

func lookupIPWithHosts(ctx context.Context, host string) ([]net.IP, error) {
	hostLower := strings.ToLower(host)
	hostsMapMu.RLock()
	ipsStr, ok := hostsMap[hostLower]
	hostsMapMu.RUnlock()
	if ok {
		ips := make([]net.IP, 0, len(ipsStr))
		for _, s := range ipsStr {
			if ip := net.ParseIP(s); ip != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}
	dialer := &net.Dialer{Timeout: dnsTimeout}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if customDNS != "" {
				if !strings.Contains(customDNS, ":") {
					address = customDNS + ":53"
				} else {
					address = customDNS
				}
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	addrs, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, addr := range addrs {
		ips[i] = addr.IP
	}
	return ips, nil
}

func resolveUDPAddrWithHosts(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if net.ParseIP(host) != nil {
		ips = []net.IP{net.ParseIP(host)}
	} else {
		if val, ok := dnsCache.Load(host); ok {
			entry := val.(*dnsCacheEntry)
			if time.Since(entry.ts) < dnsCacheTTL {
				ips = make([]net.IP, len(entry.addrs))
				for i, a := range entry.addrs {
					ips[i] = net.ParseIP(a)
				}
			}
		}
		if ips == nil {
			var err error
			ips, err = lookupIPWithHosts(ctx, host)
			if err != nil {
				return nil, err
			}
			addrs := make([]string, len(ips))
			for i, ip := range ips {
				addrs[i] = ip.String()
			}
			dnsCache.Store(host, &dnsCacheEntry{addrs: addrs, ts: time.Now()})
		}
	}
	for _, ip := range ips {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	return nil, fmt.Errorf("no IP for %s", host)
}

func bdecodeSimple(data []byte) bool {
	if len(data) == 0 || data[0] != 'd' {
		return false
	}
	for _, k := range []string{"interval", "peers", "failure reason"} {
		if strings.Contains(string(data), k) {
			return true
		}
	}
	return false
}

func extractCompactPeers(data []byte) []string {
	idx := strings.Index(string(data), "5:peers")
	if idx == -1 {
		return nil
	}
	rest := data[idx+7:]
	if len(rest) < 1 {
		return nil
	}
	var numStr string
	i := 0
	for i < len(rest) && rest[i] != ':' {
		if rest[i] >= '0' && rest[i] <= '9' {
			numStr += string(rest[i])
			i++
		} else {
			break
		}
	}
	if rest[i] != ':' {
		return nil
	}
	length, err := strconv.Atoi(numStr)
	if err != nil || length%6 != 0 || length == 0 {
		return nil
	}
	peerBytes := rest[i+1 : i+1+length]
	if len(peerBytes) < length {
		return nil
	}
	var peers []string
	for j := 0; j < length; j += 6 {
		ip := net.IPv4(peerBytes[j], peerBytes[j+1], peerBytes[j+2], peerBytes[j+3]).String()
		port := uint16(peerBytes[j+4])<<8 | uint16(peerBytes[j+5])
		peers = append(peers, net.JoinHostPort(ip, strconv.Itoa(int(port))))
	}
	return peers
}

func extractCompact6Peers(data []byte) []string {
	idx := strings.Index(string(data), "6:peers6")
	if idx == -1 {
		return nil
	}
	rest := data[idx+8:]
	if len(rest) < 1 {
		return nil
	}
	var numStr string
	i := 0
	for i < len(rest) && rest[i] != ':' {
		if rest[i] >= '0' && rest[i] <= '9' {
			numStr += string(rest[i])
			i++
		} else {
			break
		}
	}
	if rest[i] != ':' {
		return nil
	}
	length, err := strconv.Atoi(numStr)
	if err != nil || length%18 != 0 || length == 0 {
		return nil
	}
	peerBytes := rest[i+1 : i+1+length]
	if len(peerBytes) < length {
		return nil
	}
	var peers []string
	for j := 0; j < length; j += 18 {
		ip := net.IP(peerBytes[j : j+16]).String()
		port := uint16(peerBytes[j+16])<<8 | uint16(peerBytes[j+17])
		peers = append(peers, net.JoinHostPort(ip, strconv.Itoa(int(port))))
	}
	return peers
}

func responseHasIPv6Peers(data []byte) bool {
	idx := strings.Index(string(data), "6:peers6")
	if idx == -1 {
		return false
	}
	rest := data[idx+8:]
	if len(rest) < 1 {
		return false
	}
	var numStr string
	i := 0
	for i < len(rest) && rest[i] != ':' {
		if rest[i] >= '0' && rest[i] <= '9' {
			numStr += string(rest[i])
			i++
		} else {
			break
		}
	}
	if rest[i] != ':' {
		return false
	}
	length, err := strconv.Atoi(numStr)
	if err != nil || length%18 != 0 || length == 0 {
		return false
	}
	return true
}

func normalizeTrackerURL(raw string) (string, error) {
	candidate := strings.Trim(raw, "\"'<>[](){};,.")
	u, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "udp" {
		return "", fmt.Errorf("unsupported scheme")
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("no host")
	}
	if ip := net.ParseIP(host); ip == nil && !strings.Contains(host, ".") {
		return "", fmt.Errorf("invalid host")
	}
	normalizedPath := collapsePathSlashes(u.Path)
	if !(strings.HasSuffix(normalizedPath, "/announce") ||
		strings.Contains(normalizedPath, "/announce?") ||
		strings.HasSuffix(normalizedPath, "/announce.php") ||
		strings.HasSuffix(normalizedPath, "/announce.jsp") ||
		strings.HasSuffix(normalizedPath, "/announce.aspx")) {
		return "", fmt.Errorf("path must be related to /announce")
	}
	u.Path = normalizedPath
	u.Fragment = ""
	return u.String(), nil
}

func nextInfoHash() string {
	if len(infoHashes) == 0 {
		return ""
	}
	idx := atomic.AddUint32(&hashIndex, 1) - 1
	return infoHashes[idx%uint32(len(infoHashes))]
}

func infoHashBytes(hashStr string) []byte {
	if len(hashStr) != 40 {
		return nil
	}
	raw, err := hex.DecodeString(hashStr)
	if err != nil || len(raw) != 20 {
		return nil
	}
	return raw
}

func checkUDPWithFamily(ctx context.Context, tracker string, infoHash string, ipv6Only bool) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
	if err := rateLimiter.Wait(ctx); err != nil {
		return false, nil, false, err
	}
	u, err := url.Parse(tracker)
	if err != nil {
		return false, nil, false, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	addr, err := resolveUDPAddrWithHosts(ctx, "udp", net.JoinHostPort(host, port))
	if err != nil {
		return false, nil, false, err
	}
	if ipv6Only && addr.IP.To4() != nil {
		return false, nil, false, fmt.Errorf("ipv6 only but got ipv4")
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return false, nil, false, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(defaultTimeout))

	connectionID := uint64(0x41727101980)
	transConnect := uint32(randomInt(0, 0xFFFFFFFF))
	connReq := make([]byte, 16)
	binary.BigEndian.PutUint64(connReq[0:8], connectionID)
	binary.BigEndian.PutUint32(connReq[8:12], 0)
	binary.BigEndian.PutUint32(connReq[12:16], transConnect)

	start := time.Now()
	if _, err := conn.Write(connReq); err != nil {
		return false, nil, false, err
	}
	connResp := make([]byte, 16)
	n, err := conn.Read(connResp)
	if err != nil || n < 16 || binary.BigEndian.Uint32(connResp[0:4]) != 0 || binary.BigEndian.Uint32(connResp[4:8]) != transConnect {
		return false, nil, false, fmt.Errorf("connect failed")
	}
	newConnectionID := binary.BigEndian.Uint64(connResp[8:16])

	ih := infoHashBytes(infoHash)
	if ih == nil {
		ih = make([]byte, 20)
		if _, err := rand.Read(ih); err != nil {
			return false, nil, false, err
		}
	}

	transAnnounce := uint32(randomInt(0, 0xFFFFFFFF))
	annReq := make([]byte, 98)
	binary.BigEndian.PutUint64(annReq[0:8], newConnectionID)
	binary.BigEndian.PutUint32(annReq[8:12], 1)
	binary.BigEndian.PutUint32(annReq[12:16], transAnnounce)
	copy(annReq[16:36], ih)
	copy(annReq[36:56], []byte(peerIDPrefix))
	binary.BigEndian.PutUint64(annReq[56:64], 0)
	binary.BigEndian.PutUint64(annReq[64:72], 0)
	binary.BigEndian.PutUint64(annReq[72:80], 0)
	binary.BigEndian.PutUint32(annReq[80:84], 2)
	binary.BigEndian.PutUint32(annReq[84:88], 0)
	binary.BigEndian.PutUint32(annReq[88:92], 0)
	binary.BigEndian.PutUint32(annReq[92:96], ^uint32(0))
	binary.BigEndian.PutUint16(annReq[96:98], 6881)

	if _, err := conn.Write(annReq); err != nil {
		return false, nil, false, err
	}
	annResp := make([]byte, 2048)
	n, err = conn.Read(annResp)
	if err != nil || n < 20 {
		return false, nil, false, err
	}
	elapsed := int64(time.Since(start).Milliseconds())
	action := binary.BigEndian.Uint32(annResp[0:4])
	if (action == 1 && binary.BigEndian.Uint32(annResp[4:8]) == transAnnounce) || action == 3 {
		has6 := responseHasIPv6Peers(annResp[:n])
		if has6 {
			if peers6 := extractCompact6Peers(annResp[:n]); len(peers6) > 0 {
				for _, p := range peers6 {
					peersCollector.Store(p, struct{}{})
				}
			}
		}
		if peers := extractCompactPeers(annResp[:n]); len(peers) > 0 {
			for _, p := range peers {
				peersCollector.Store(p, struct{}{})
			}
		}
		return true, &elapsed, has6, nil
	}
	return false, &elapsed, false, nil
}

func checkUDP(ctx context.Context, tracker string, infoHash string) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
	alive4, ping4, has6inResp4, err4 := checkUDPWithFamily(ctx, tracker, infoHash, false)
	has4 := alive4
	var bestPing *int64
	if has4 {
		bestPing = ping4
	}
	has6 := false
	if has4 && has6inResp4 {
		has6 = true
	}
	if !has6 {
		alive6, ping6, _, err6 := checkUDPWithFamily(ctx, tracker, infoHash, true)
		if alive6 {
			has6 = true
			if bestPing == nil || (ping6 != nil && (bestPing == nil || *ping6 < *bestPing)) {
				bestPing = ping6
			}
		}
		_ = err6
	}
	if has4 && has6 {
		true4, true6 := true, true
		return StatusAlive, bestPing, &true4, &true6
	}
	if has4 {
		true4 := true
		return StatusAlive, bestPing, &true4, nil
	}
	if has6 {
		true6 := true
		return StatusAlive, bestPing, nil, &true6
	}
	return StatusDead, nil, nil, nil
}

func validateTracker(ctx context.Context, tracker string, maxAttempts int) CheckResult {
	var last CheckResult
	for attempt := 0; attempt < maxAttempts; attempt++ {
		u, err := url.Parse(tracker)
		if err != nil {
			last = CheckResult{URL: tracker, Status: StatusInvalid}
			break
		}
		scheme := strings.ToLower(u.Scheme)
		infoHash := nextInfoHash()
		var status string
		var ping *int64
		var supportsIPv4, supportsIPv6 *bool
		switch scheme {
		case "udp":
			status, ping, supportsIPv4, supportsIPv6 = checkUDP(ctx, tracker, infoHash)
		default:
			status = StatusInvalid
		}
		last = CheckResult{URL: tracker, Status: status, PingMs: ping, SupportsIPv4: supportsIPv4, SupportsIPv6: supportsIPv6}
		if status != StatusDead {
			break
		}
		if attempt < maxAttempts-1 {
			time.Sleep(time.Duration(500+randomInt(0, 1001)) * time.Millisecond)
		}
	}
	return last
}

func loadTrackers(filepath string) ([]string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading %s: %v", filepath, err)
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

func filterByProtocol(trackers []string, protocol string) []string {
	var filtered []string
	for _, t := range trackers {
		u, err := url.Parse(t)
		if err != nil {
			continue
		}
		if strings.ToLower(u.Scheme) == protocol {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

func sortUnique(items []string) []string {
	if len(items) == 0 {
		return items
	}
	slices.Sort(items)
	return slices.Compact(items)
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

func main() {
	input := flag.String("input", "merged_trackers.txt", "Input file")
	workers := flag.Int("workers", defaultWorkers, "Concurrent workers")
	retries := flag.Int("retries", defaultRetries, "Retries")
	dnsFlag := flag.String("dns", "", "Custom DNS server (e.g., 8.8.8.8:53)")
	dnsTimeoutFlag := flag.Duration("dns-timeout", 5*time.Second, "DNS lookup timeout")
	hostsFileFlag := flag.String("hosts-file", "", "Custom hosts file path")
	rateLimitFlag := flag.Int("rate-limit", 1000, "Max requests per second")
	flag.Parse()

	customDNS = *dnsFlag
	dnsTimeout = *dnsTimeoutFlag
	hostsFilePath = *hostsFileFlag
	rateLimiter = rate.NewLimiter(rate.Limit(*rateLimitFlag), *rateLimitFlag)
	loadHostsFile()

	allTrackers, err := loadTrackers(*input)
	if err != nil {
		log.Fatalf("Failed to load trackers: %v", err)
	}
	udpTrackers := filterByProtocol(allTrackers, "udp")
	if len(udpTrackers) == 0 {
		log.Fatal("No UDP trackers found.")
	}

	total := len(udpTrackers)
	sem := make(chan struct{}, *workers)
	results := make(chan CheckResult, total)
	var wg sync.WaitGroup
	var completed int32

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	maxAttempts := *retries + 1

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			done := atomic.LoadInt32(&completed)
			fmt.Printf("[UDP] [%d/%d] processed\n", done, total)
			if done >= int32(total) {
				return
			}
		}
	}()

	for _, t := range udpTrackers {
		wg.Add(1)
		go func(tracker string) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Panic in tracker %s: %v", tracker, r)
					results <- CheckResult{URL: tracker, Status: StatusInvalid}
					atomic.AddInt32(&completed, 1)
				}
				<-sem
				wg.Done()
			}()
			sem <- struct{}{}
			res := validateTracker(ctx, tracker, maxAttempts)
			results <- res
			atomic.AddInt32(&completed, 1)
		}(t)
	}

	wg.Wait()
	close(results)

	var allResults []CheckResult
	for res := range results {
		allResults = append(allResults, res)
	}

	var aliveList, aliveIPv4Only, aliveIPv6Only, aliveDualStack []string
	var entries []TrackerEntry
	for _, r := range allResults {
		entry := TrackerEntry{
			URL:          r.URL,
			Status:       r.Status,
			Protocol:     "udp",
			PingMs:       r.PingMs,
			SupportsIPv4: r.SupportsIPv4,
			SupportsIPv6: r.SupportsIPv6,
		}
		entries = append(entries, entry)
		if r.Status == StatusAlive {
			aliveList = append(aliveList, r.URL)
			if r.SupportsIPv4 != nil && r.SupportsIPv6 != nil && *r.SupportsIPv4 && *r.SupportsIPv6 {
				aliveDualStack = append(aliveDualStack, r.URL)
			} else if r.SupportsIPv4 != nil && *r.SupportsIPv4 && (r.SupportsIPv6 == nil || !*r.SupportsIPv6) {
				aliveIPv4Only = append(aliveIPv4Only, r.URL)
			} else if r.SupportsIPv6 != nil && *r.SupportsIPv6 && (r.SupportsIPv4 == nil || !*r.SupportsIPv4) {
				aliveIPv6Only = append(aliveIPv6Only, r.URL)
			}
		}
	}

	outputDir := filepath.Dir(".")
	writeLines(filepath.Join(outputDir, "trackers_best_udp.txt"), sortUnique(aliveList))
	writeLines(filepath.Join(outputDir, "trackers_best_udp_ipv4only.txt"), sortUnique(aliveIPv4Only))
	writeLines(filepath.Join(outputDir, "trackers_best_udp_ipv6only.txt"), sortUnique(aliveIPv6Only))
	writeLines(filepath.Join(outputDir, "trackers_best_udp_dualstack.txt"), sortUnique(aliveDualStack))

	jsonData, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(filepath.Join(outputDir, "trackers_udp.json"), jsonData, 0644)
	fmt.Println("UDP check complete")
}