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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
)

const (
	defaultTimeout = 10 * time.Second
	defaultWorkers = 50
	defaultRetries = 1
)

const (
	StatusAlive   = "ALIVE"
	StatusDead    = "DEAD"
	StatusInvalid = "INVALID"
)

type CheckResult struct {
	URL    string `json:"url"`
	Status string `json:"status"`
	PingMs *int64 `json:"ping_ms,omitempty"`
}

type TrackerHistory struct {
	Checks             uint64 `json:"checks"`
	AliveChecks        uint64 `json:"alive_checks"`
	FirstSeenTs        int64  `json:"first_seen_ts"`
	FirstAliveTs       int64  `json:"first_alive_ts"`
	LastSeenTs         int64  `json:"last_seen_ts"`
	LastAliveTs        int64  `json:"last_alive_ts"`
	StreakAliveStartTs int64  `json:"streak_alive_start_ts"`
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

type TrackerEntry struct {
	URL      string  `json:"url"`
	Status   string  `json:"status"`
	Uptime   float64 `json:"uptime"`
	Days     int     `json:"days"`
	Protocol string  `json:"protocol"`
	PingMs   *int64  `json:"ping_ms,omitempty"`
}

var (
	trackerRe    = regexp.MustCompile(`(?i)(https?|udp|wss?|dns)://[^\s,]+?/announce[^\s,]*`)
	peerIDPrefix string
	infoHashes   []string
	hashIndex    uint32
	userAgents   = []string{
		"qBittorrent/4.6.0",
		"Transmission/3.00",
		"uTorrent/2210(25302)",
		"BitTorrent/7.10.5",
		"Deluge/2.0.3",
		"aria2/1.36.0",
		"libtorrent/1.2.18.0",
	}

	dnsCache     = map[string]*dnsCacheEntry{}
	dnsCacheMu   sync.Mutex
	dnsCacheTTL  = 10 * time.Minute
	globalClient *http.Client

	compact0Fallback bool
	insecureSkip     bool
	proxyAddr        string
	peersCollector   = map[string]struct{}{}
	peersMu          sync.Mutex
)

type dnsCacheEntry struct {
	addrs []string
	ts    time.Time
}

func init() {
	peerIDPrefix = fmt.Sprintf("-RS0001-%s", randomNumeric(12))
}

func randomNumeric(n int) string {
	const digits = "0123456789"
	ret := make([]byte, n)
	for i := range ret {
		bi, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			bi = big.NewInt(0)
		}
		ret[i] = digits[bi.Int64()]
	}
	return string(ret)
}

func parseTrackerLine(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") && strings.Contains(line, "](") && strings.HasSuffix(line, ")") {
		_, after, found := strings.Cut(line, "](")
		if found {
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

func cachedDial(network, addr string) (net.Conn, error) {
	host, port, _ := net.SplitHostPort(addr)
	if ip := net.ParseIP(host); ip != nil {
		return net.Dial(network, addr)
	}
	dnsCacheMu.Lock()
	entry, ok := dnsCache[host]
	dnsCacheMu.Unlock()
	if ok && time.Since(entry.ts) < dnsCacheTTL {
		if len(entry.addrs) == 0 {
			return net.Dial(network, addr)
		}
		return net.Dial(network, net.JoinHostPort(entry.addrs[0], port))
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		dnsCacheMu.Lock()
		dnsCache[host] = &dnsCacheEntry{addrs: []string{}, ts: time.Now()}
		dnsCacheMu.Unlock()
		return net.Dial(network, addr)
	}
	var addrs []string
	for _, ip := range ips {
		addrs = append(addrs, ip.String())
	}
	dnsCacheMu.Lock()
	dnsCache[host] = &dnsCacheEntry{addrs: addrs, ts: time.Now()}
	dnsCacheMu.Unlock()
	return net.Dial(network, net.JoinHostPort(addrs[0], port))
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

func isHTML(data []byte) bool {
	limit := len(data)
	if limit > 200 {
		limit = 200
	}
	head := strings.ToLower(string(data[:limit]))
	return strings.Contains(head, "<html") || strings.Contains(head, "<!doctype") ||
		strings.Contains(head, "<body") || strings.Contains(head, "<head")
}

func isParkedDomain(content []byte) bool {
	lower := strings.ToLower(string(content))
	indicators := []string{
		"domain for sale", "domain is for sale", "buy this domain",
		"domain expired", "domain has expired", "this domain is expired",
		"register this domain", "domain available", "parked domain",
		"domain parking", "coming soon", "under construction",
		"page not found", "404 not found", "namecheap",
		"godaddy parked", "sedo domain parking", "domain portfolio",
		"premium domain", "afternic", "escrow.com", "dan.com/buy-domain",
		"undeveloped", "this webpage was generated by the domain owner",
		"hugedomains.com", "bodis.com", "sedoparking",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
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

func randomUA() string {
	return userAgents[randomInt(0, len(userAgents))]
}

func checkHTTP(ctx context.Context, tracker string, infoHash string) (string, *int64) {
	return checkHTTPWithCompact(ctx, tracker, infoHash, true)
}

func checkHTTPWithCompact(ctx context.Context, tracker string, infoHash string, compact bool) (string, *int64) {
	base, err := url.Parse(tracker)
	if err != nil {
		return StatusInvalid, nil
	}
	params := base.Query()
	if raw := infoHashBytes(infoHash); raw != nil {
		params.Set("info_hash", url.QueryEscape(string(raw)))
	} else {
		params.Set("info_hash", "00000000000000000000")
	}
	params.Set("peer_id", peerIDPrefix)
	params.Set("port", "6881")
	params.Set("uploaded", "0")
	params.Set("downloaded", "0")
	params.Set("left", "0")
	if compact {
		params.Set("compact", "1")
	} else {
		params.Set("compact", "0")
	}
	params.Set("event", "started")
	base.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", base.String(), nil)
	if err != nil {
		return StatusDead, nil
	}
	req.Header.Set("User-Agent", randomUA())
	start := time.Now()
	resp, err := globalClient.Do(req)
	if err != nil {
		return StatusDead, nil
	}
	defer resp.Body.Close()
	elapsed := int64(time.Since(start).Milliseconds())
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return StatusDead, &elapsed
	}

	if isHTML(body) || isParkedDomain(body) {
		return StatusInvalid, &elapsed
	}
	if bdecodeSimple(body) {
		if peers := extractCompactPeers(body); len(peers) > 0 {
			peersMu.Lock()
			for _, p := range peers {
				peersCollector[p] = struct{}{}
			}
			peersMu.Unlock()
		}
		return StatusAlive, &elapsed
	}
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden) && bdecodeSimple(body) {
		if peers := extractCompactPeers(body); len(peers) > 0 {
			peersMu.Lock()
			for _, p := range peers {
				peersCollector[p] = struct{}{}
			}
			peersMu.Unlock()
		}
		return StatusAlive, &elapsed
	}
	if resp.StatusCode == http.StatusOK && len(body) > 50000 {
		return StatusInvalid, &elapsed
	}
	return StatusDead, &elapsed
}

func checkUDP(ctx context.Context, tracker string, infoHash string) (string, *int64) {
	u, err := url.Parse(tracker)
	if err != nil {
		return StatusInvalid, nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return StatusInvalid, nil
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return StatusDead, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(defaultTimeout))

	connectionID := uint64(0x41727101980)
	transConnect := uint32(randomInt(0, 0xFFFFFFFF))
	connReq := make([]byte, 16)
	bigEndianPutUint64(connReq[0:8], connectionID)
	bigEndianPutUint32(connReq[8:12], 0)
	bigEndianPutUint32(connReq[12:16], transConnect)

	start := time.Now()
	if _, err := conn.Write(connReq); err != nil {
		return StatusDead, nil
	}
	connResp := make([]byte, 16)
	n, err := conn.Read(connResp)
	if err != nil || n < 16 || bigEndianUint32(connResp[0:4]) != 0 || bigEndianUint32(connResp[4:8]) != transConnect {
		return StatusDead, nil
	}
	newConnectionID := bigEndianUint64(connResp[8:16])

	infoHashBytes := infoHashBytes(infoHash)
	if infoHashBytes == nil {
		infoHashBytes = make([]byte, 20)
		if _, err := rand.Read(infoHashBytes); err != nil {
			return StatusDead, nil
		}
	}

	transAnnounce := uint32(randomInt(0, 0xFFFFFFFF))
	annReq := make([]byte, 98)
	bigEndianPutUint64(annReq[0:8], newConnectionID)
	bigEndianPutUint32(annReq[8:12], 1)
	bigEndianPutUint32(annReq[12:16], transAnnounce)
	copy(annReq[16:36], infoHashBytes)
	copy(annReq[36:56], []byte(peerIDPrefix))
	bigEndianPutUint64(annReq[56:64], 0)
	bigEndianPutUint64(annReq[64:72], 0)
	bigEndianPutUint64(annReq[72:80], 0)
	bigEndianPutUint32(annReq[80:84], 2)
	bigEndianPutUint32(annReq[84:88], 0)
	bigEndianPutUint32(annReq[88:92], 0)
	bigEndianPutInt32(annReq[92:96], -1)
	bigEndianPutUint16(annReq[96:98], 6881)

	if _, err := conn.Write(annReq); err != nil {
		return StatusDead, nil
	}
	annResp := make([]byte, 2048)
	n2, err := conn.Read(annResp)
	if err != nil || n2 < 20 {
		return StatusDead, nil
	}
	elapsed := int64(time.Since(start).Milliseconds())
	action := bigEndianUint32(annResp[0:4])
	if action == 1 && bigEndianUint32(annResp[4:8]) == transAnnounce {
		return StatusAlive, &elapsed
	}
	if action == 3 {
		return StatusAlive, &elapsed
	}
	return StatusDead, &elapsed
}

func checkWSS(ctx context.Context, tracker string) (string, *int64) {
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultTimeout,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if proxyAddr != "" {
				dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
				if err == nil {
					return dialer.Dial(network, addr)
				}
			}
			return cachedDial(network, addr)
		},
	}
	start := time.Now()
	conn, _, err := dialer.DialContext(ctx, tracker, nil)
	if err != nil {
		return StatusDead, nil
	}
	defer conn.Close()
	elapsed := int64(time.Since(start).Milliseconds())
	return StatusAlive, &elapsed
}

func checkDNS(ctx context.Context, tracker string) (string, *int64) {
	u, err := url.Parse(tracker)
	if err != nil {
		return StatusInvalid, nil
	}
	domain := u.Hostname()
	if domain == "" {
		domain = strings.TrimPrefix(tracker, "dns://")
	}
	start := time.Now()
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return StatusDead, nil
	}
	elapsed := int64(time.Since(start).Milliseconds())
	for _, txt := range txts {
		if strings.Contains(strings.ToLower(txt), "bittorrent") || strings.Contains(txt, "peer") {
			return StatusAlive, &elapsed
		}
	}
	return StatusDead, &elapsed
}

func validateTracker(ctx context.Context, tracker string) CheckResult {
	u, err := url.Parse(tracker)
	if err != nil {
		return CheckResult{URL: tracker, Status: StatusInvalid}
	}
	scheme := strings.ToLower(u.Scheme)
	infoHash := nextInfoHash()
	var status string
	var ping *int64
	switch scheme {
	case "http", "https":
		status, ping = checkHTTP(ctx, tracker, infoHash)
		if status != StatusAlive && compact0Fallback {
			status, ping = checkHTTPWithCompact(ctx, tracker, infoHash, false)
		}
	case "udp":
		status, ping = checkUDP(ctx, tracker, infoHash)
	case "wss", "ws":
		status, ping = checkWSS(ctx, tracker)
	case "dns":
		status, ping = checkDNS(ctx, tracker)
	default:
		status = StatusInvalid
	}
	return CheckResult{URL: tracker, Status: status, PingMs: ping}
}

func validateTrackerWithRetry(ctx context.Context, tracker string, maxAttempts int) CheckResult {
	var last CheckResult
	for attempt := 0; attempt < maxAttempts; attempt++ {
		last = validateTracker(ctx, tracker)
		if last.Status != StatusDead {
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

func filterBlacklist(trackers []string, blFile string) []string {
	if _, err := os.Stat(blFile); os.IsNotExist(err) {
		return trackers
	}
	f, err := os.Open(blFile)
	if err != nil {
		return trackers
	}
	defer f.Close()
	patterns := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	if len(patterns) == 0 {
		return trackers
	}
	filtered := make([]string, 0, len(trackers))
	for _, t := range trackers {
		exclude := false
		for _, p := range patterns {
			if strings.Contains(t, p) {
				exclude = true
				break
			}
		}
		if !exclude {
			filtered = append(filtered, t)
		}
	}
	return filtered
}

func sortUnique(items []string) []string {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	unique := make([]string, 0, len(m))
	for item := range m {
		unique = append(unique, item)
	}
	sort.Strings(unique)
	return unique
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

func updateHistory(hist map[string]*TrackerHistory, results []CheckResult, nowTs int64) {
	for _, r := range results {
		entry, exists := hist[r.URL]
		if !exists {
			entry = &TrackerHistory{}
			hist[r.URL] = entry
		}
		lastWasAlive := entry.LastSeenTs != 0 && entry.LastSeenTs == entry.LastAliveTs
		entry.Checks++
		if entry.FirstSeenTs == 0 {
			entry.FirstSeenTs = nowTs
		}
		entry.LastSeenTs = nowTs

		if r.Status == StatusAlive {
			if !lastWasAlive || entry.StreakAliveStartTs == 0 {
				entry.StreakAliveStartTs = nowTs
			}
			entry.AliveChecks++
			if entry.FirstAliveTs == 0 {
				entry.FirstAliveTs = nowTs
			}
			entry.LastAliveTs = nowTs
		} else {
			entry.StreakAliveStartTs = 0
		}
	}
}

func getProtocol(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return "other"
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "wss" || scheme == "ws" {
		if strings.Contains(u, "webrtc") {
			return "webrtc"
		}
	}
	if strings.HasSuffix(parsed.Hostname(), ".i2p") {
		return "i2p"
	}
	if scheme == "dns" {
		return "dns"
	}
	return scheme
}

func bigEndianPutUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}

func bigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func bigEndianPutInt32(b []byte, v int32) {
	bigEndianPutUint32(b, uint32(v))
}

func bigEndianPutUint16(b []byte, v uint16) {
	b[0] = byte(v >> 8)
	b[1] = byte(v)
}

func bigEndianUint64(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 |
		uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
}

func bigEndianUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func randomInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return int(n.Int64()) + min
}

func main() {
	input := flag.String("input", "merged_trackers.txt", "Input file with raw tracker URLs")
	output := flag.String("output", "trackers_best.txt", "File to write best (alive) trackers")
	workers := flag.Int("workers", defaultWorkers, "Number of concurrent workers")
	jsonOutput := flag.String("json-output", "jekyll/_data/trackers.json", "Path to output Jekyll JSON data")
	infoHashesFlag := flag.String("info-hashes", "", "Comma-separated 40-char hex info_hash values (20 bytes each)")
	retries := flag.Int("retries", defaultRetries, "Max additional retries for DEAD trackers (total attempts = 1 + retries)")
	compact0 := flag.Bool("compact0-fallback", false, "Retry with compact=0 if compact=1 fails")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	proxyFlag := flag.String("proxy", "", "SOCKS5 proxy address (e.g. socks5://127.0.0.1:9050)")
	flag.Parse()

	compact0Fallback = *compact0
	insecureSkip = *insecure
	proxyAddr = *proxyFlag

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkip},
		MaxIdleConns:    200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout: 30 * time.Second,
		DisableKeepAlives: false,
	}
	if proxyAddr != "" {
		dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	} else {
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return cachedDial(network, addr)
		}
	}
	globalClient = &http.Client{
		Transport: tr,
		Timeout:   defaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	inputFile := *input
	outputFile := *output
	concurrency := *workers
	if concurrency < 1 {
		concurrency = defaultWorkers
	}

	if *infoHashesFlag != "" {
		parts := strings.Split(*infoHashesFlag, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if len(p) != 40 {
				log.Fatalf("invalid info_hash length: %q", p)
			}
			infoHashes = append(infoHashes, p)
		}
	}

	trackers, err := loadTrackers(inputFile)
	if err != nil {
		log.Fatalf("Failed to load trackers: %v", err)
	}
	trackers = filterBlacklist(trackers, "blackstr.txt")
	allTrackers := sortUnique(trackers)
	if len(allTrackers) == 0 {
		log.Fatal("No valid trackers found.")
	}

	outputDir := filepath.Dir(outputFile)
	if err := writeLines(filepath.Join(outputDir, "trackers_all.txt"), allTrackers); err != nil {
		log.Fatalf("Error writing trackers_all.txt: %v", err)
	}

	total := len(allTrackers)
	jobs := make(chan string, total)
	resultsCh := make(chan []CheckResult, concurrency)
	progressCh := make(chan int, concurrency*2)

	var wg sync.WaitGroup
	ctx := context.Background()
	maxAttempts := *retries + 1

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]CheckResult, 0, total/concurrency+1)
			for tracker := range jobs {
				res := validateTrackerWithRetry(ctx, tracker, maxAttempts)
				local = append(local, res)
				select {
				case progressCh <- 1:
				default:
				}
			}
			resultsCh <- local
		}()
	}

	var progressDone sync.WaitGroup
	progressDone.Add(1)
	var completed int32
	go func() {
		defer progressDone.Done()
		for range progressCh {
			done := atomic.AddInt32(&completed, 1)
			fmt.Printf("[%d/%d] processed\n", done, total)
		}
	}()

	startTime := time.Now()
	for _, t := range allTrackers {
		jobs <- t
	}
	close(jobs)

	wg.Wait()
	close(resultsCh)
	close(progressCh)
	progressDone.Wait()

	var results []CheckResult
	for r := range resultsCh {
		results = append(results, r...)
	}

	var aliveList []string
	var deadCount, invalidCount int
	var sumPing int64
	var countPing int64
	var minPing int64 = -1
	var maxPing int64
	for _, r := range results {
		switch r.Status {
		case StatusAlive:
			aliveList = append(aliveList, r.URL)
			if r.PingMs != nil {
				p := *r.PingMs
				sumPing += p
				countPing++
				if minPing == -1 || p < minPing {
					minPing = p
				}
				if p > maxPing {
					maxPing = p
				}
			}
		case StatusDead:
			deadCount++
		case StatusInvalid:
			invalidCount++
		}
	}
	aliveList = sortUnique(aliveList)

	if err := writeLines(outputFile, aliveList); err != nil {
		log.Fatalf("Error writing %s: %v", outputFile, err)
	}
	for _, proto := range []string{"http", "https", "udp", "ws", "wss"} {
		var urls []string
		for _, u := range aliveList {
			if getProtocol(u) == proto {
				urls = append(urls, u)
			}
		}
		writeLines(filepath.Join(outputDir, "trackers_best_"+proto+".txt"), sortUnique(urls))
	}

	peersList := make([]string, 0, len(peersCollector))
	for p := range peersCollector {
		peersList = append(peersList, p)
	}
	sort.Strings(peersList)
	if len(peersList) > 0 {
		writeLines(filepath.Join(outputDir, "trackers_peers.txt"), peersList)
	}

	historyPath := filepath.Join(outputDir, "tracker_history.tsv")
	history, err := loadHistory(historyPath)
	if err != nil {
		log.Fatalf("Failed to load history: %v", err)
	}
	nowTs := time.Now().Unix()
	updateHistory(history, results, nowTs)
	if err := saveHistory(historyPath, history); err != nil {
		log.Fatalf("Failed to save history: %v", err)
	}

	aliveCount := len(aliveList)
	uptimePct := 0.0
	if total > 0 {
		uptimePct = float64(aliveCount) * 100 / float64(total)
	}

	protocols := ProtocolStats{}
	for _, u := range aliveList {
		switch getProtocol(u) {
		case "http":
			protocols.HTTP++
		case "https":
			protocols.HTTPS++
		case "udp":
			protocols.UDP++
		case "wss", "ws":
			protocols.WSS++
		case "webrtc":
			protocols.WebRTC++
		case "i2p":
			protocols.I2P++
		case "dns":
			protocols.DNS++
		}
	}
	if total > 0 {
		protocols.HTTPPct = float64(protocols.HTTP) * 100 / float64(total)
		protocols.HTTPSPct = float64(protocols.HTTPS) * 100 / float64(total)
		protocols.UDPPct = float64(protocols.UDP) * 100 / float64(total)
		protocols.WSSPct = float64(protocols.WSS) * 100 / float64(total)
	}

	trackerEntries := make([]TrackerEntry, 0, total)
	for _, r := range results {
		hist := history[r.URL]
		if hist == nil {
			hist = &TrackerHistory{}
		}
		uptime := 0.0
		if hist.Checks > 0 {
			uptime = float64(hist.AliveChecks) * 100 / float64(hist.Checks)
		}
		days := 0
		if r.Status == StatusAlive && hist.StreakAliveStartTs > 0 {
			days = int((nowTs - hist.StreakAliveStartTs) / 86400) + 1
		}
		trackerEntries = append(trackerEntries, TrackerEntry{
			URL:      r.URL,
			Status:   r.Status,
			Uptime:   uptime,
			Days:     days,
			Protocol: getProtocol(r.URL),
			PingMs:   r.PingMs,
		})
	}

	var avgPing float64
	if countPing > 0 {
		avgPing = float64(sumPing) / float64(countPing)
	}
	if minPing == -1 {
		minPing = 0
	}

	jData := JekyllData{
		Total:        total,
		AliveCount:   aliveCount,
		DeadCount:    deadCount,
		InvalidCount: invalidCount,
		UptimePct:    uptimePct,
		Protocols:    protocols,
		Trackers:     trackerEntries,
		AvgPingMs:    avgPing,
		MinPingMs:    minPing,
		MaxPingMs:    maxPing,
	}

	if err := os.MkdirAll(filepath.Dir(*jsonOutput), 0755); err != nil {
		log.Fatalf("Failed to create JSON output directory: %v", err)
	}
	jsonBytes, err := json.MarshalIndent(jData, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}
	if err := os.WriteFile(*jsonOutput, jsonBytes, 0644); err != nil {
		log.Fatalf("Failed to write JSON: %v", err)
	}
	fmt.Printf("✅ Jekyll data written to %s\n", *jsonOutput)

	elapsed := time.Since(startTime).Round(time.Millisecond)
	fmt.Printf("Checked %d trackers in %s. Alive: %d, Dead: %d, Invalid: %d\n",
		len(results), elapsed, aliveCount, deadCount, invalidCount)
}