package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

const defaultTimeout = 5 * time.Second
const defaultWorkers = 500
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
	globalClient   *http.Client
	insecureSkip   bool
	proxyAddrs     []string
	proxyPool      []proxy.Dialer
	proxyMu        sync.Mutex
	proxyIdx       uint32
	peersCollector sync.Map
	rateLimiter    *rate.Limiter
)

type dnsCacheEntry struct {
	addrs []string
	ts    time.Time
}

type contextDialer struct {
	d    proxy.Dialer
	ipv4 bool
	ipv6 bool
}

func init() {
	peerIDPrefix = fmt.Sprintf("-RS0001-%s", randomNumeric(12))
	rateLimiter = rate.NewLimiter(rate.Limit(100), 1)
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

func cachedDialContext(ctx context.Context, network, addr string, ipv4Only, ipv6Only bool) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	if net.ParseIP(host) != nil {
		dialer := net.Dialer{}
		if ipv4Only && net.ParseIP(host).To4() == nil {
			return nil, fmt.Errorf("not an IPv4 address")
		}
		if ipv6Only && net.ParseIP(host).To4() != nil {
			return nil, fmt.Errorf("not an IPv6 address")
		}
		return dialer.DialContext(ctx, network, addr)
	}
	var ips []net.IP
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
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var err error
		done := make(chan struct{})
		go func() {
			ips, err = net.LookupIP(host)
			close(done)
		}()
		select {
		case <-lookupCtx.Done():
			return nil, lookupCtx.Err()
		case <-done:
			if err != nil {
				dnsCache.Store(host, &dnsCacheEntry{addrs: []string{}, ts: time.Now()})
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, network, addr)
			}
			addrs := make([]string, len(ips))
			for i, ip := range ips {
				addrs[i] = ip.String()
			}
			dnsCache.Store(host, &dnsCacheEntry{addrs: addrs, ts: time.Now()})
		}
	}
	var targetIP net.IP
	for _, ip := range ips {
		if ipv4Only && ip.To4() != nil {
			targetIP = ip
			break
		}
		if ipv6Only && ip.To4() == nil {
			targetIP = ip
			break
		}
		if !ipv4Only && !ipv6Only {
			targetIP = ip
			break
		}
	}
	if targetIP == nil {
		return nil, fmt.Errorf("no suitable IP address for %s", host)
	}
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(targetIP.String(), port))
}

func getNextProxy() proxy.Dialer {
	if len(proxyPool) == 0 {
		return nil
	}
	proxyMu.Lock()
	defer proxyMu.Unlock()
	idx := atomic.AddUint32(&proxyIdx, 1) - 1
	return proxyPool[idx%uint32(len(proxyPool))]
}

func normalizeTrackerURL(raw string) (string, error) {
	candidate := strings.Trim(raw, "\"'<>[](){};,.")
	u, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "ws" && scheme != "wss" {
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
	if (scheme == "ws" && u.Port() == "80") || (scheme == "wss" && u.Port() == "443") {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
	}
	return u.String(), nil
}

func checkWSSWithFamily(ctx context.Context, tracker string, ipv4Only, ipv6Only bool) (bool, *int64, error) {
	if err := rateLimiter.Wait(ctx); err != nil {
		return false, nil, err
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultTimeout,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cachedDialContext(ctx, network, addr, ipv4Only, ipv6Only)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkip},
	}
	start := time.Now()
	conn, _, err := dialer.DialContext(ctx, tracker, nil)
	if err != nil {
		return false, nil, err
	}
	defer conn.Close()
	elapsed := int64(time.Since(start).Milliseconds())
	return true, &elapsed, nil
}

func checkWSS(ctx context.Context, tracker string) (string, *int64, *bool, *bool) {
	alive4, ping4, err4 := checkWSSWithFamily(ctx, tracker, true, false)
	has4 := alive4
	var bestPing *int64
	if has4 {
		bestPing = ping4
	}
	alive6, ping6, _ := checkWSSWithFamily(ctx, tracker, false, true)
	has6 := alive6
	if has6 && (bestPing == nil || (ping6 != nil && (bestPing == nil || *ping6 < *bestPing))) {
		bestPing = ping6
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
	if err4 != nil && !alive4 {
		return StatusDead, nil, nil, nil
	}
	return StatusInvalid, nil, nil, nil
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
		infoHash := ""
		var status string
		var ping *int64
		var supportsIPv4, supportsIPv6 *bool
		switch scheme {
		case "ws", "wss":
			status, ping, supportsIPv4, supportsIPv6 = checkWSS(ctx, tracker)
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

func filterByProtocol(trackers []string, protocols []string) []string {
	var filtered []string
	for _, t := range trackers {
		u, err := url.Parse(t)
		if err != nil {
			continue
		}
		if slices.Contains(protocols, strings.ToLower(u.Scheme)) {
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
	insecure := flag.Bool("insecure", false, "Skip TLS")
	proxyFlag := flag.String("proxy", "", "SOCKS5 proxy")
	flag.Parse()

	insecureSkip = *insecure
	if *proxyFlag != "" {
		rawDialer, err := proxy.SOCKS5("tcp", *proxyFlag, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
		}
		proxyPool = append(proxyPool, &contextDialer{d: rawDialer})
	}

	allTrackers, err := loadTrackers(*input)
	if err != nil {
		log.Fatalf("Failed to load trackers: %v", err)
	}
	wsTrackers := filterByProtocol(allTrackers, []string{"ws", "wss"})
	if len(wsTrackers) == 0 {
		log.Fatal("No WS/WSS trackers found.")
	}

	total := len(wsTrackers)
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
			fmt.Printf("[WSS] [%d/%d] processed\n", done, total)
			if done >= int32(total) {
				return
			}
		}
	}()

	for _, t := range wsTrackers {
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

	var aliveList []string
	var entries []TrackerEntry
	for _, r := range allResults {
		u, _ := url.Parse(r.URL)
		protocol := strings.ToLower(u.Scheme)
		entry := TrackerEntry{
			URL:          r.URL,
			Status:       r.Status,
			Protocol:     protocol,
			PingMs:       r.PingMs,
			SupportsIPv4: r.SupportsIPv4,
			SupportsIPv6: r.SupportsIPv6,
		}
		entries = append(entries, entry)
		if r.Status == StatusAlive {
			aliveList = append(aliveList, r.URL)
		}
	}

	outputDir := filepath.Dir(".")
	writeLines(filepath.Join(outputDir, "trackers_best_ws.txt"), sortUnique(aliveList))
	jsonData, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(filepath.Join(outputDir, "trackers_wss.json"), jsonData, 0644)
	fmt.Println("WSS/WS check complete")
}