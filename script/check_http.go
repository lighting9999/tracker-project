package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	jsoniter "github.com/json-iterator/go"
	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultTimeout = 5 * time.Second
const defaultWorkers = 1000
const defaultRetries = 1
const maxPeersCollector = 10000

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

type dnsCacheEntry struct {
	addrs []string
	ts    time.Time
	isErr bool
}

var (
	trackerRe         = regexp.MustCompile(`(?i)(https?|udp|wss?|dns)://[^\s,]+?/announce[^\s,]*`)
	peerIDPrefix      string
	infoHashes        []string
	hashIndex         uint32
	userAgents        = []string{"qBittorrent/4.6.0", "Transmission/3.00", "uTorrent/2210(25302)", "BitTorrent/7.10.5", "Deluge/2.0.3", "aria2/1.36.0", "libtorrent/1.2.18.0"}
	dnsCache          *lru.Cache[string, *dnsCacheEntry]
	dnsCacheTTL       = 10 * time.Minute
	dnsNegativeTTL    = 30 * time.Second
	compact0Fallback  bool
	insecureSkip      bool
	proxyPool         []proxy.Dialer
	proxyMu           sync.Mutex
	proxyIdx          uint32
	peersCollector    sync.Map
	peersCollectorCnt int32
	rateLimiter       *rate.Limiter
	useSAM            bool
	samHost           string
	customDNS         string
	dnsTimeout        time.Duration
	hostsMap          map[string][]string
	hostsMapMu        sync.RWMutex
	hostsFilePath     string
	samConnCache      sync.Map
	samGroup          singleflight.Group
	colorReset        = "\033[0m"
	colorRed          = "\033[31m"
	colorGreen        = "\033[32m"
	colorYellow       = "\033[33m"
	colorBlue         = "\033[34m"
	colorCyan         = "\033[36m"
	json              = jsoniter.ConfigCompatibleWithStandardLibrary
	logCh             = make(chan string, 10000)
	logWg             sync.WaitGroup
	bufferPool        = sync.Pool{New: func() interface{} { return make([]byte, 0, 4096) }}
	httpClientCache   sync.Map
	preWarmOnce       sync.Once
	dnsSingleflight   singleflight.Group
)

type samPooledConn struct {
	net.Conn
	host string
	once sync.Once
}

func (c *samPooledConn) Close() error {
	var err error
	c.once.Do(func() {
		samConnCache.Delete(c.host)
		err = c.Conn.Close()
	})
	return err
}

func init() {
	peerIDPrefix = fmt.Sprintf("-RS0001-%s", randomNumeric(12))
	rateLimiter = rate.NewLimiter(rate.Limit(2000), 200)
	var err error
	dnsCache, err = lru.New[string, *dnsCacheEntry](5000)
	if err != nil {
		panic(err)
	}
	logWg.Add(1)
	go func() {
		defer logWg.Done()
		for msg := range logCh {
			fmt.Print(msg)
		}
	}()
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

func randomUA() string { return userAgents[randomInt(0, len(userAgents))] }

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
	if i >= len(rest) || rest[i] != ':' {
		return nil
	}
	length, err := strconv.Atoi(numStr)
	if err != nil || length%6 != 0 || length == 0 {
		return nil
	}
	if i+1+length > len(rest) {
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
	if i >= len(rest) || rest[i] != ':' {
		return nil
	}
	length, err := strconv.Atoi(numStr)
	if err != nil || length%18 != 0 || length == 0 {
		return nil
	}
	if i+1+length > len(rest) {
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
	if i >= len(rest) || rest[i] != ':' {
		return false
	}
	length, err := strconv.Atoi(numStr)
	if err != nil || length%18 != 0 || length == 0 {
		return false
	}
	return i+1+length <= len(rest)
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
	if entry, ok := dnsCache.Get(host); ok {
		if entry.isErr {
			if time.Since(entry.ts) < dnsNegativeTTL {
				return nil, fmt.Errorf("cached DNS error for %s", host)
			}
			dnsCache.Remove(host)
		} else if time.Since(entry.ts) < dnsCacheTTL {
			ips = make([]net.IP, len(entry.addrs))
			for i, a := range entry.addrs {
				ips[i] = net.ParseIP(a)
			}
		}
	}
	if ips == nil {
		v, err, _ := dnsSingleflight.Do(host, func() (interface{}, error) {
			lookupCtx, cancel := context.WithTimeout(ctx, dnsTimeout)
			defer cancel()
			ipsLocal, err := lookupIPWithHosts(lookupCtx, host)
			if err != nil {
				dnsCache.Add(host, &dnsCacheEntry{addrs: []string{}, ts: time.Now(), isErr: true})
				return nil, err
			}
			addrs := make([]string, len(ipsLocal))
			for i, ip := range ipsLocal {
				addrs[i] = ip.String()
			}
			dnsCache.Add(host, &dnsCacheEntry{addrs: addrs, ts: time.Now(), isErr: false})
			logCh <- fmt.Sprintf("%s[DNS] %s -> %s%s\n", colorCyan, host, strings.Join(addrs, ","), colorReset)
			return ipsLocal, nil
		})
		if err != nil {
			return nil, err
		}
		ips = v.([]net.IP)
	}
	var targetIP net.IP
	for _, ip := range ips {
		if ipv4Only && ip.To4() != nil {
			targetIP = ip
			break
		}
		if ipv6Only && ip.To4() == nil && ip.To16() != nil {
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

func samHello(conn net.Conn) error {
	_, err := fmt.Fprintf(conn, "HELLO VERSION MIN=3.0 MAX=3.0\n")
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "HELLO REPLY") {
		return fmt.Errorf("bad hello reply: %s", line)
	}
	return nil
}

func samCreateSession(conn net.Conn, sessionID string) error {
	cmd := fmt.Sprintf("SESSION CREATE STYLE=STREAM ID=%s DESTINATION=TRANSIENT\n", sessionID)
	_, err := conn.Write([]byte(cmd))
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "RESULT=OK") {
		return fmt.Errorf("session create failed: %s", line)
	}
	return nil
}

func samStreamConnect(conn net.Conn, sessionID, dest, port string) error {
	cmd := fmt.Sprintf("STREAM CONNECT ID=%s DESTINATION=%s PORT=%s\n", sessionID, dest, port)
	_, err := conn.Write([]byte(cmd))
	if err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, "RESULT=OK") {
		return fmt.Errorf("stream connect failed: %s", line)
	}
	return nil
}

func dialSAMRaw(ctx context.Context, dest, port string) (net.Conn, error) {
	samConn, err := net.DialTimeout("tcp", samHost, defaultTimeout)
	if err != nil {
		return nil, fmt.Errorf("connect to SAM bridge: %w", err)
	}
	if err := samHello(samConn); err != nil {
		samConn.Close()
		return nil, fmt.Errorf("sam hello: %w", err)
	}
	sessionID := fmt.Sprintf("tracker-%d", randomInt(0, 1<<31))
	if err := samCreateSession(samConn, sessionID); err != nil {
		samConn.Close()
		return nil, fmt.Errorf("sam session: %w", err)
	}
	if err := samStreamConnect(samConn, sessionID, dest, port); err != nil {
		samConn.Close()
		return nil, fmt.Errorf("sam connect: %w", err)
	}
	return &samStreamConn{Conn: samConn, reader: bufio.NewReader(samConn)}, nil
}

type samStreamConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *samStreamConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func getSAMConnection(ctx context.Context, hostWithPort string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostWithPort)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(host, ".i2p") {
		return nil, fmt.Errorf("not an i2p host")
	}
	key := host
	if cached, ok := samConnCache.Load(key); ok {
		conn := cached.(*samPooledConn)
		if conn.Conn != nil {
			return conn, nil
		}
	}
	v, err, _ := samGroup.Do(key, func() (interface{}, error) {
		if cached, ok := samConnCache.Load(key); ok {
			conn := cached.(*samPooledConn)
			if conn.Conn != nil {
				return conn, nil
			}
		}
		rawConn, err := dialSAMRaw(ctx, host, port)
		if err != nil {
			return nil, err
		}
		pooled := &samPooledConn{Conn: rawConn, host: key}
		samConnCache.Store(key, pooled)
		return pooled, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(net.Conn), nil
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

func warmTransport() {
	preWarmOnce.Do(func() {
		tr := &http.Transport{
			MaxIdleConns:        2000,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     90 * time.Second,
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if strings.HasSuffix(host, ".i2p") {
				if useSAM {
					return getSAMConnection(ctx, addr)
				}
				if p := getNextProxy(); p != nil {
					return p.Dial(network, addr)
				}
			}
			return cachedDialContext(ctx, network, addr, false, false)
		}
		client := &http.Client{Transport: tr, Timeout: defaultTimeout}
		for _, urlStr := range []string{"https://1.1.1.1", "https://8.8.8.8"} {
			req, _ := http.NewRequest("HEAD", urlStr, nil)
			resp, err := client.Do(req)
			if err == nil && resp != nil {
				resp.Body.Close()
			}
		}
		tr.CloseIdleConnections()
	})
}

func getHTTPClient(ipv4Only, ipv6Only bool) *http.Client {
	warmTransport()
	key := fmt.Sprintf("v4:%v_v6:%v", ipv4Only, ipv6Only)
	if cached, ok := httpClientCache.Load(key); ok {
		return cached.(*http.Client)
	}
	tr := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: insecureSkip},
		MaxIdleConns:          2000,
		MaxIdleConnsPerHost:   200,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if strings.HasSuffix(host, ".i2p") {
			if useSAM {
				return getSAMConnection(ctx, addr)
			}
			if p := getNextProxy(); p != nil {
				return p.Dial(network, addr)
			}
		}
		return cachedDialContext(ctx, network, addr, ipv4Only, ipv6Only)
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   defaultTimeout,
		Jar:       nil,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpClientCache.Store(key, client)
	return client
}

func normalizeTrackerURL(raw string) (string, error) {
	candidate := strings.Trim(raw, "\"'<>[](){};,.")
	u, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if !slices.Contains([]string{"http", "https", "udp", "wss", "ws", "dns"}, scheme) {
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

func storePeer(peer string) {
	if atomic.LoadInt32(&peersCollectorCnt) >= maxPeersCollector {
		return
	}
	_, loaded := peersCollector.LoadOrStore(peer, struct{}{})
	if !loaded {
		atomic.AddInt32(&peersCollectorCnt, 1)
	}
}

func checkHTTPAttempt(ctx context.Context, tracker string, infoHash string, compact bool, ipv4Only, ipv6Only bool, hostPort string) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
	base, err := url.Parse(tracker)
	if err != nil {
		return false, nil, false, err
	}
	if hostPort != "" {
		base.Host = hostPort
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
		return false, nil, false, err
	}
	req.Header.Set("User-Agent", randomUA())

	client := getHTTPClient(ipv4Only, ipv6Only)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, false, err
	}
	defer resp.Body.Close()
	elapsed := int64(time.Since(start).Milliseconds())
	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter != "" {
			if sec, err := strconv.Atoi(retryAfter); err == nil && sec > 0 {
				select {
				case <-time.After(time.Duration(sec) * time.Second):
				case <-ctx.Done():
				}
				return false, &elapsed, false, fmt.Errorf("rate limited")
			}
		}
		return false, &elapsed, false, fmt.Errorf("rate limited")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return false, &elapsed, false, err
	}
	if isHTML(body) || isParkedDomain(body) {
		return false, &elapsed, false, fmt.Errorf("html or parked")
	}
	if bdecodeSimple(body) {
		if peers := extractCompactPeers(body); len(peers) > 0 {
			for _, p := range peers {
				storePeer(p)
			}
		}
		has6 := responseHasIPv6Peers(body)
		if has6 {
			if peers6 := extractCompact6Peers(body); len(peers6) > 0 {
				for _, p := range peers6 {
					storePeer(p)
				}
			}
		}
		return true, &elapsed, has6, nil
	}
	if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden) && bdecodeSimple(body) {
		if peers := extractCompactPeers(body); len(peers) > 0 {
			for _, p := range peers {
				storePeer(p)
			}
		}
		has6 := responseHasIPv6Peers(body)
		if has6 {
			if peers6 := extractCompact6Peers(body); len(peers6) > 0 {
				for _, p := range peers6 {
					storePeer(p)
				}
			}
		}
		return true, &elapsed, has6, nil
	}
	if resp.StatusCode == http.StatusOK && len(body) > 50000 {
		return false, &elapsed, false, fmt.Errorf("too large")
	}
	return false, &elapsed, false, fmt.Errorf("invalid response")
}

func checkHTTPWithFamily(ctx context.Context, tracker string, infoHash string, compact bool, ipv4Only, ipv6Only bool) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
	if err := rateLimiter.Wait(ctx); err != nil {
		return false, nil, false, err
	}
	u, _ := url.Parse(tracker)
	originalPort := u.Port()
	scheme := u.Scheme
	host := u.Hostname()
	isI2P := strings.HasSuffix(host, ".i2p")
	var fallbackPorts []string
	if originalPort != "" {
		fallbackPorts = append(fallbackPorts, originalPort)
	}
	if scheme == "http" {
		fallbackPorts = append(fallbackPorts, "80")
	} else if scheme == "https" {
		fallbackPorts = append(fallbackPorts, "443")
	}
	if isI2P {
		fallbackPorts = append(fallbackPorts, "80", "443")
	}
	fallbackPorts = append(fallbackPorts, "")
	seen := make(map[string]bool)
	for _, port := range fallbackPorts {
		if port == "" {
			port = ""
		}
		hostPort := host
		if port != "" {
			hostPort = net.JoinHostPort(host, port)
		} else {
			hostPort = host
		}
		if seen[hostPort] {
			continue
		}
		seen[hostPort] = true
		alive, ping, has6, _ := checkHTTPAttempt(ctx, tracker, infoHash, compact, ipv4Only, ipv6Only, hostPort)
		if alive {
			return true, ping, has6, nil
		}
	}
	return false, nil, false, fmt.Errorf("all ports failed")
}

func checkHTTP(ctx context.Context, tracker string, infoHash string, useCompact0 bool) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
	compact := !useCompact0
	alive4, ping4, has6inResp4, err4 := checkHTTPWithFamily(ctx, tracker, infoHash, compact, true, false)
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
		alive6, ping6, _, err6 := checkHTTPWithFamily(ctx, tracker, infoHash, compact, false, true)
		if alive6 {
			has6 = true
			if bestPing == nil || (ping6 != nil && *ping6 < *bestPing) {
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
	if err4 == nil || (err4 != nil && !alive4) {
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
		infoHash := nextInfoHash()
		var status string
		var ping *int64
		var supportsIPv4, supportsIPv6 *bool
		switch scheme {
		case "http", "https":
			status, ping, supportsIPv4, supportsIPv6 = checkHTTP(ctx, tracker, infoHash, false)
			if status != StatusAlive && compact0Fallback {
				altStatus, altPing, alt4, alt6 := checkHTTP(ctx, tracker, infoHash, true)
				if altStatus == StatusAlive {
					status, ping, supportsIPv4, supportsIPv6 = altStatus, altPing, alt4, alt6
				}
			}
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
		scheme := strings.ToLower(u.Scheme)
		if strings.HasSuffix(u.Hostname(), ".i2p") && slices.Contains(protocols, "i2p") {
			filtered = append(filtered, t)
		} else if slices.Contains(protocols, scheme) {
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

func colorize(status string) string {
	switch status {
	case StatusAlive:
		return colorGreen + status + colorReset
	case StatusDead:
		return colorRed + status + colorReset
	case StatusInvalid:
		return colorYellow + status + colorReset
	default:
		return status
	}
}

func main() {
	input := flag.String("input", "merged_trackers.txt", "Input file")
	workers := flag.Int("workers", defaultWorkers, "Concurrent workers")
	retries := flag.Int("retries", defaultRetries, "Retries")
	compact0 := flag.Bool("compact0-fallback", false, "Fallback to compact=0")
	insecure := flag.Bool("insecure", false, "Skip TLS")
	proxyFlag := flag.String("proxy", "", "SOCKS5 proxy")
	samFlag := flag.Bool("sam", false, "Enable I2P SAM bridge (port 7656)")
	samHostFlag := flag.String("sam-host", "127.0.0.1:7656", "SAM bridge address")
	dnsFlag := flag.String("dns", "1.1.1.1:53", "Custom DNS server")
	dnsTimeoutFlag := flag.Duration("dns-timeout", 5*time.Second, "DNS lookup timeout")
	hostsFileFlag := flag.String("hosts-file", "", "Custom hosts file path")
	rateLimitFlag := flag.Int("rate-limit", 2000, "Max requests per second")
	shards := flag.Int("shards", 4, "Number of shards for parallel scanning")
	flag.Parse()

	if *shards < 1 {
		*shards = 1
	}
	compact0Fallback = *compact0
	insecureSkip = *insecure
	useSAM = *samFlag
	samHost = *samHostFlag
	customDNS = *dnsFlag
	dnsTimeout = *dnsTimeoutFlag
	hostsFilePath = *hostsFileFlag
	rateLimiter = rate.NewLimiter(rate.Limit(*rateLimitFlag), *rateLimitFlag)

	if *proxyFlag != "" {
		rawDialer, err := proxy.SOCKS5("tcp", *proxyFlag, nil, proxy.Direct)
		if err != nil {
			log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
		}
		proxyPool = append(proxyPool, rawDialer)
	}
	loadHostsFile()

	allTrackers, err := loadTrackers(*input)
	if err != nil {
		log.Fatalf("Failed to load trackers: %v", err)
	}
	httpTrackers := filterByProtocol(allTrackers, []string{"http", "https", "i2p"})
	if len(httpTrackers) == 0 {
		log.Fatal("No HTTP/HTTPS/I2P trackers found.")
	}

	total := len(httpTrackers)
	shardSize := (total + *shards - 1) / *shards
	actualShards := (total + shardSize - 1) / shardSize
	shardResults := make([]chan CheckResult, actualShards)
	for i := 0; i < actualShards; i++ {
		shardResults[i] = make(chan CheckResult, shardSize)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	maxAttempts := *retries + 1
	startTime := time.Now()
	var completed int32

	for sh := 0; sh < actualShards; sh++ {
		start := sh * shardSize
		end := start + shardSize
		if end > total {
			end = total
		}
		if start >= total {
			break
		}
		wg.Add(1)
		go func(shardIdx int, trackers []string) {
			defer wg.Done()
			sem := make(chan struct{}, *workers)
			var shardWg sync.WaitGroup
			for _, t := range trackers {
				shardWg.Add(1)
				go func(tracker string) {
					defer func() {
						if r := recover(); r != nil {
							logCh <- fmt.Sprintf("%sPanic in tracker %s: %v%s\n", colorRed, tracker, r, colorReset)
							shardResults[shardIdx] <- CheckResult{URL: tracker, Status: StatusInvalid}
						}
						<-sem
						shardWg.Done()
					}()
					sem <- struct{}{}
					res := validateTracker(ctx, tracker, maxAttempts)
					done := atomic.AddInt32(&completed, 1)
					coloredStatus := colorize(res.Status)
					pingStr := "N/A"
					if res.PingMs != nil {
						pingStr = fmt.Sprintf("%dms", *res.PingMs)
					}
					logCh <- fmt.Sprintf("%s[%d/%d]%s %s %s %s\n",
						colorBlue, done, total, colorReset, tracker, coloredStatus, pingStr)
					shardResults[shardIdx] <- res
				}(t)
			}
			shardWg.Wait()
			close(shardResults[shardIdx])
		}(sh, httpTrackers[start:end])
	}
	wg.Wait()
	elapsed := time.Since(startTime)

	var allResults []CheckResult
	for _, ch := range shardResults {
		for res := range ch {
			allResults = append(allResults, res)
		}
	}

	var httpList, httpsList, i2pList []string
	var ipv4OnlyList, ipv6OnlyList, dualStackList []string
	var entries []TrackerEntry
	for _, r := range allResults {
		u, _ := url.Parse(r.URL)
		scheme := strings.ToLower(u.Scheme)
		host := u.Hostname()
		protocol := scheme
		if strings.HasSuffix(host, ".i2p") {
			protocol = "i2p"
		}
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
			if protocol == "http" {
				httpList = append(httpList, r.URL)
			} else if protocol == "https" {
				httpsList = append(httpsList, r.URL)
			} else if protocol == "i2p" {
				i2pList = append(i2pList, r.URL)
			}
			if r.SupportsIPv4 != nil && r.SupportsIPv6 != nil && *r.SupportsIPv4 && *r.SupportsIPv6 {
				dualStackList = append(dualStackList, r.URL)
			} else if r.SupportsIPv4 != nil && *r.SupportsIPv4 && (r.SupportsIPv6 == nil || !*r.SupportsIPv6) {
				ipv4OnlyList = append(ipv4OnlyList, r.URL)
			} else if r.SupportsIPv6 != nil && *r.SupportsIPv6 && (r.SupportsIPv4 == nil || !*r.SupportsIPv4) {
				ipv6OnlyList = append(ipv6OnlyList, r.URL)
			}
		}
	}

	outputDir := filepath.Dir(".")
	writeLines(filepath.Join(outputDir, "trackers_best_http.txt"), sortUnique(httpList))
	writeLines(filepath.Join(outputDir, "trackers_best_https.txt"), sortUnique(httpsList))
	writeLines(filepath.Join(outputDir, "trackers_best_i2p.txt"), sortUnique(i2pList))
	writeLines(filepath.Join(outputDir, "trackers_alive_ipv4only.txt"), sortUnique(ipv4OnlyList))
	writeLines(filepath.Join(outputDir, "trackers_alive_ipv6only.txt"), sortUnique(ipv6OnlyList))
	writeLines(filepath.Join(outputDir, "trackers_alive_dualstack.txt"), sortUnique(dualStackList))

	jsonData, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(filepath.Join(outputDir, "trackers_http.json"), jsonData, 0644)

	fmt.Printf("%s✓ HTTP/HTTPS/I2P check finished in %s%s\n", colorGreen, elapsed, colorReset)
	fmt.Printf("%s  Total trackers: %d%s\n", colorBlue, total, colorReset)
	aliveCount := len(httpList) + len(httpsList) + len(i2pList)
	fmt.Printf("%s  Alive: %d%s\n", colorGreen, aliveCount, colorReset)
	fmt.Printf("%s  Dead: %d%s\n", colorRed, total-aliveCount, colorReset)
	close(logCh)
	logWg.Wait()
}