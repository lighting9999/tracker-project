package tracker

import (
    "context"
    "crypto/tls"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "sync"
    "time"
)

// ---------- HTTP 客户端缓存 ----------
var httpClientCache sync.Map
var preWarmOnce sync.Once

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
                if UseSAM {
                    return getSAMConnection(ctx, addr)
                }
                if p := GetNextProxy(); p != nil {
                    return p.Dial(network, addr)
                }
            }
            return CachedDialContext(ctx, network, addr, false, false)
        }
        client := &http.Client{Transport: tr, Timeout: DefaultTimeout}
        // 预热
        req, _ := http.NewRequest("HEAD", "https://1.1.1.1", nil)
        resp, err := client.Do(req)
        if err == nil && resp != nil {
            resp.Body.Close()
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
        TLSClientConfig:       &tls.Config{InsecureSkipVerify: InsecureSkip},
        MaxIdleConns:          2000,
        MaxIdleConnsPerHost:   200,
        IdleConnTimeout:       90 * time.Second,
        DisableKeepAlives:     false,
        ForceAttemptHTTP2:     true,
    }
    tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
        host, _, _ := net.SplitHostPort(addr)
        if strings.HasSuffix(host, ".i2p") {
            if UseSAM {
                return getSAMConnection(ctx, addr)
            }
            if p := GetNextProxy(); p != nil {
                return p.Dial(network, addr)
            }
        }
        return CachedDialContext(ctx, network, addr, ipv4Only, ipv6Only)
    }
    client := &http.Client{
        Transport: tr,
        Timeout:   DefaultTimeout,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    httpClientCache.Store(key, client)
    return client
}

// ---------- SAM 连接 (I2P) ----------
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

var samConnCache sync.Map
var samGroup singleflight.Group

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
    samConn, err := net.DialTimeout("tcp", SAMHost, DefaultTimeout)
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

// ---------- HTTP 检查核心 ----------
func CheckHTTPAttempt(ctx context.Context, tracker string, infoHash string, compact bool, ipv4Only, ipv6Only bool, hostPort string) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
    base, err := url.Parse(tracker)
    if err != nil {
        return false, nil, false, err
    }
    if hostPort != "" {
        base.Host = hostPort
    }
    params := base.Query()
    if raw := InfoHashBytes(infoHash); raw != nil {
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

func CheckHTTPWithFamily(ctx context.Context, tracker string, infoHash string, compact bool, ipv4Only, ipv6Only bool) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
    if err := RateLimiter.Wait(ctx); err != nil {
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
        alive, ping, has6, _ := CheckHTTPAttempt(ctx, tracker, infoHash, compact, ipv4Only, ipv6Only, hostPort)
        if alive {
            return true, ping, has6, nil
        }
    }
    return false, nil, false, fmt.Errorf("all ports failed")
}

func CheckHTTP(ctx context.Context, tracker string, infoHash string, useCompact0 bool) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
    compact := !useCompact0
    alive4, ping4, has6inResp4, err4 := CheckHTTPWithFamily(ctx, tracker, infoHash, compact, true, false)
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
        alive6, ping6, _, err6 := CheckHTTPWithFamily(ctx, tracker, infoHash, compact, false, true)
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

// ---------- 辅助函数（从原 check_http.go 复制） ----------
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

var peersCollector sync.Map
var peersCollectorCnt int32

func storePeer(peer string) {
    if atomic.LoadInt32(&peersCollectorCnt) >= MaxPeersCollector {
        return
    }
    _, loaded := peersCollector.LoadOrStore(peer, struct{}{})
    if !loaded {
        atomic.AddInt32(&peersCollectorCnt, 1)
    }
}