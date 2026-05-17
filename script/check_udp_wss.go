package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
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

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	jsoniter "github.com/json-iterator/go"
	lru "github.com/hashicorp/golang-lru/v2"
)

const defaultTimeout = 10 * time.Second
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
	trackerRe         = regexp.MustCompile(`(?i)(udp|wss?|https?)://[^\s,]+?/announce[^\s,]*`)
	peerIDPrefix      string
	infoHashes        []string
	hashIndex         uint32
	dnsCache          *lru.Cache[string, *dnsCacheEntry]
	dnsCacheTTL       = 10 * time.Minute
	dnsNegativeTTL    = 30 * time.Second
	peersCollector    sync.Map
	peersCollectorCnt int32
	rateLimiter       *rate.Limiter
	customDNS         string
	dnsTimeout        time.Duration
	hostsMap          map[string][]string
	hostsMapMu        sync.RWMutex
	hostsFilePath     string
	insecureSkip      bool
	proxyPool         []proxy.Dialer
	proxyMu           sync.Mutex
	proxyIdx          uint32
	colorReset        = "\033[0m"
	colorRed          = "\033[31m"
	colorGreen        = "\033[32m"
	colorYellow       = "\033[33m"
	colorBlue         = "\033[34m"
	colorMagenta      = "\033[35m"
	colorCyan         = "\033[36m"
	json              = jsoniter.ConfigCompatibleWithStandardLibrary
	logCh             = make(chan string, 10000)
	logWg             sync.WaitGroup
	bufferPool        = sync.Pool{New: func() interface{} { return make([]byte, 0, 4096) }}
	preWarmOnce       sync.Once
	dnsSingleflight   singleflight.Group
)

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
				ipsLocal, err := lookupIPWithHosts(ctx, host)
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
	}
	for _, ip := range ips {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}
	return nil, fmt.Errorf("no IP for %s", host)
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
			return cachedDialContext(ctx, network, addr, false, false)
		}
		client := &http.Client{Transport: tr, Timeout: defaultTimeout}
		req, _ := http.NewRequest("HEAD", "https://1.1.1.1", nil)
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			resp.Body.Close()
		}
		tr.CloseIdleConnections()
	})
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

func storePeer(peer string) {
	if atomic.LoadInt32(&peersCollectorCnt) >= maxPeersCollector {
		return
	}
	_, loaded := peersCollector.LoadOrStore(peer, struct{}{})
	if !loaded {
		atomic.AddInt32(&peersCollectorCnt, 1)
	}
}

func normalizeTrackerURL(raw string) (string, error) {
	candidate := strings.Trim(raw, "\"'<>[](){};,.")
	u, err := url.Parse(candidate)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "udp" && scheme != "ws" && scheme != "wss" {
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
	if !(strings.HasSuffix(normalizedPath, "/announce") ||
		strings.Contains(normalizedPath, "/announce?") ||
		strings.HasSuffix(normalizedPath, "/announce.php") ||
		strings.HasSuffix(normalizedPath, "/announce.jsp") ||
		strings.HasSuffix(normalizedPath, "/announce.aspx")) {
		return "", fmt.Errorf("path must be related to /announce")
	}
	u.Path = normalizedPath
	u.Fragment = ""
	if (scheme == "udp" && u.Port() == "80") ||
		(scheme == "ws" && u.Port() == "80") ||
		(scheme == "wss" && u.Port() == "443") {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
	}
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

func checkUDPAttempt(ctx context.Context, tracker string, infoHash string, ipv6Only bool, targetPort string) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
	u, err := url.Parse(tracker)
	if err != nil {
		return false, nil, false, err
	}
	host := u.Hostname()
	var port string
	if targetPort != "" {
		port = targetPort
	} else if u.Port() != "" {
		port = u.Port()
	} else {
		port = "6969"
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
	if err != nil || n < 16 {
		return false, nil, false, fmt.Errorf("connect failed")
	}
	if binary.BigEndian.Uint32(connResp[0:4]) != 0 || binary.BigEndian.Uint32(connResp[4:8]) != transConnect {
		return false, nil, false, fmt.Errorf("connect transaction mismatch")
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
					storePeer(p)
				}
			}
		}
		if peers := extractCompactPeers(annResp[:n]); len(peers) > 0 {
			for _, p := range peers {
				storePeer(p)
			}
		}
		return true, &elapsed, has6, nil
	}
	return false, &elapsed, false, nil
}

func checkUDPWithFamily(ctx context.Context, tracker string, infoHash string, ipv6Only bool) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
	if err := rateLimiter.Wait(ctx); err != nil {
		return false, nil, false, err
	}
	u, _ := url.Parse(tracker)
	originalPort := u.Port()
	fallbackPorts := []string{originalPort, "6969", "1337"}
	if originalPort != "" && originalPort != "6969" && originalPort != "1337" {
		fallbackPorts = append(fallbackPorts, originalPort)
	}
	seen := make(map[string]bool)
	for _, port := range fallbackPorts {
		if port == "" {
			continue
		}
		if seen[port] {
			continue
		}
		seen[port] = true
		alive, ping, has6, _ := checkUDPAttempt(ctx, tracker, infoHash, ipv6Only, port)
		if alive {
			return true, ping, has6, nil
		}
	}
	return false, nil, false, fmt.Errorf("all UDP ports failed")
}

func checkUDP(ctx context.Context, tracker string, infoHash string) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
	alive4, ping4, has6inResp4, _ := checkUDPWithFamily(ctx, tracker, infoHash, false)
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
		alive6, ping6, _, _ := checkUDPWithFamily(ctx, tracker, infoHash, true)
		if alive6 {
			has6 = true
			if bestPing == nil || (ping6 != nil && *ping6 < *bestPing) {
				bestPing = ping6
			}
		}
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

func checkWSSWithFamily(ctx context.Context, tracker string, ipv4Only, ipv6Only bool) (bool, *int64, error) {
	if err := rateLimiter.Wait(ctx); err != nil {
		return false, nil, err
	}
	warmTransport()
	header := http.Header{}
	header.Set("User-Agent", "qBittorrent/4.6.0")
	dialer := websocket.Dialer{
		HandshakeTimeout: defaultTimeout,
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if strings.HasSuffix(host, ".i2p") {
				if p := getNextProxy(); p != nil {
					return p.Dial(network, addr)
				}
			}
			return cachedDialContext(ctx, network, addr, ipv4Only, ipv6Only)
		},
		Proxy:            http.ProxyFromEnvironment,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: insecureSkip},
		Jar:              nil,
		Subprotocols:     []string{"binary"},
		EnableCompression: true,
	}
	start := time.Now()
	conn, _, err := dialer.DialContext(ctx, tracker, header)
	if err != nil {
		return false, nil, err
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(defaultTimeout))
	conn.SetWriteDeadline(time.Now().Add(defaultTimeout))
	elapsed := int64(time.Since(start).Milliseconds())
	return true, &elapsed, nil
}

func checkWSS(ctx context.Context, tracker string) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
	alive4, ping4, _ := checkWSSWithFamily(ctx, tracker, true, false)
	has4 := alive4
	var bestPing *int64
	if has4 {
		bestPing = ping4
	}
	alive6, ping6, _ := checkWSSWithFamily(ctx, tracker, false, true)
	has6 := alive6
	if has6 && (bestPing == nil || (ping6 != nil && *ping6 < *bestPing)) {
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

func filterByProtocols(trackers []string, protocols []string) []string {
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

func protocolColor(proto string) string {
	switch proto {
	case "udp":
		return colorCyan + proto + colorReset
	case "ws", "wss":
		return colorMagenta + proto + colorReset
	default:
		return proto
	}
}

func main() {
	input := flag.String("input", "merged_trackers.txt", "Input file")
	workers := flag.Int("workers", defaultWorkers, "Concurrent workers")
	retries := flag.Int("retries", defaultRetries, "Retries")
	insecure := flag.Bool("insecure", false, "Skip TLS")
	proxyFlag := flag.String("proxy", "", "SOCKS5 proxy")
	dnsFlag := flag.String("dns", "1.1.1.1:53", "Custom DNS server")
	dnsTimeoutFlag := flag.Duration("dns-timeout", 5*time.Second, "DNS lookup timeout")
	hostsFileFlag := flag.String("hosts-file", "", "Custom hosts file path")
	rateLimitFlag := flag.Int("rate-limit", 2000, "Max requests per second")
	shards := flag.Int("shards", 4, "Number of shards for parallel scanning")
	flag.Parse()

	if *shards < 1 {
		*shards = 1
	}
	insecureSkip = *insecure
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
	udpWssTrackers := filterByProtocols(allTrackers, []string{"udp", "ws", "wss"})
	if len(udpWssTrackers) == 0 {
		log.Fatal("No UDP/WS/WSS trackers found.")
	}

	total := len(udpWssTrackers)
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
					u, _ := url.Parse(tracker)
					proto := strings.ToLower(u.Scheme)
					coloredProto := protocolColor(proto)
					coloredStatus := colorize(res.Status)
					pingStr := "N/A"
					if res.PingMs != nil {
						pingStr = fmt.Sprintf("%dms", *res.PingMs)
					}
					logCh <- fmt.Sprintf("%s[%d/%d]%s %s %s %s %s\n",
						colorBlue, done, total, colorReset, coloredProto, tracker, coloredStatus, pingStr)
					shardResults[shardIdx] <- res
				}(t)
			}
			shardWg.Wait()
			close(shardResults[shardIdx])
		}(sh, udpWssTrackers[start:end])
	}
	wg.Wait()
	elapsed := time.Since(startTime)

	var allResults []CheckResult
	for _, ch := range shardResults {
		for res := range ch {
			allResults = append(allResults, res)
		}
	}

	var aliveList, aliveUDP, aliveWS, aliveIPv4Only, aliveIPv6Only, aliveDualStack []string
	var entries []TrackerEntry
	var sumPing int64
	var countPing int64

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
			if protocol == "udp" {
				aliveUDP = append(aliveUDP, r.URL)
			} else if protocol == "ws" || protocol == "wss" {
				aliveWS = append(aliveWS, r.URL)
			}
			if r.SupportsIPv4 != nil && r.SupportsIPv6 != nil && *r.SupportsIPv4 && *r.SupportsIPv6 {
				aliveDualStack = append(aliveDualStack, r.URL)
			} else if r.SupportsIPv4 != nil && *r.SupportsIPv4 && (r.SupportsIPv6 == nil || !*r.SupportsIPv6) {
				aliveIPv4Only = append(aliveIPv4Only, r.URL)
			} else if r.SupportsIPv6 != nil && *r.SupportsIPv6 && (r.SupportsIPv4 == nil || !*r.SupportsIPv4) {
				aliveIPv6Only = append(aliveIPv6Only, r.URL)
			}
			if r.PingMs != nil {
				sumPing += *r.PingMs
				countPing++
			}
		}
	}

	avgPing := 0.0
	if countPing > 0 {
		avgPing = float64(sumPing) / float64(countPing)
	}

	outputDir := filepath.Dir(".")
	writeLines(filepath.Join(outputDir, "trackers_best_udp_wss.txt"), sortUnique(aliveList))
	writeLines(filepath.Join(outputDir, "trackers_best_udp.txt"), sortUnique(aliveUDP))
	writeLines(filepath.Join(outputDir, "trackers_best_ws.txt"), sortUnique(aliveWS))
	writeLines(filepath.Join(outputDir, "trackers_alive_ipv4only.txt"), sortUnique(aliveIPv4Only))
	writeLines(filepath.Join(outputDir, "trackers_alive_ipv6only.txt"), sortUnique(aliveIPv6Only))
	writeLines(filepath.Join(outputDir, "trackers_alive_dualstack.txt"), sortUnique(aliveDualStack))

	jsonData, _ := json.MarshalIndent(entries, "", "  ")
	os.WriteFile(filepath.Join(outputDir, "trackers_udp_wss.json"), jsonData, 0644)

	fmt.Printf("%s✓ UDP+WSS check finished in %s%s\n", colorGreen, elapsed, colorReset)
	fmt.Printf("%s  Total trackers: %d%s\n", colorBlue, total, colorReset)
	fmt.Printf("%s  Alive: %d%s\n", colorGreen, len(aliveList), colorReset)
	fmt.Printf("%s  Dead: %d%s\n", colorRed, total-len(aliveList), colorReset)
	fmt.Printf("%s  Avg response time: %.2f ms%s\n", colorYellow, avgPing, colorReset)
	close(logCh)
	logWg.Wait()
}