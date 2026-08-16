package tracker

import (
    "bufio"
    "context"
    "crypto/rand"
    "fmt"
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

    "golang.org/x/sync/singleflight"
    "golang.org/x/time/rate"
    lru "github.com/hashicorp/golang-lru/v2"
    jsoniter "github.com/json-iterator/go"
)

// ---------- 常量 ----------
const (
    StatusAlive   = "ALIVE"
    StatusDead    = "DEAD"
    StatusInvalid = "INVALID"

    DefaultTimeout   = 10 * time.Second
    DefaultWorkers   = 1000
    DefaultRetries   = 1
    MaxPeersCollector = 10000
)

var (
    trackerRe = regexp.MustCompile(`(?i)(https?|udp|wss?|dns)://[^\s,]+?/announce[^\s,]*`)

    // DNS 缓存
    dnsCache        *lru.Cache[string, *dnsCacheEntry]
    dnsCacheTTL     = 10 * time.Minute
    dnsNegativeTTL  = 30 * time.Second
    dnsSingleflight singleflight.Group

    // 全局配置
    Compact0Fallback bool
    InsecureSkip     bool
    CustomDNS        string
    DNSTimeout       time.Duration
    RateLimiter      *rate.Limiter
    HostsFilePath    string
    UseSAM           bool
    SAMHost          string

    // 代理
    ProxyPool []proxy.Dialer
    proxyMu   sync.Mutex
    proxyIdx  uint32

    // 日志
    LogCh   = make(chan string, 10000)
    LogWg   sync.WaitGroup
    colorReset  = "\033[0m"
    colorRed    = "\033[31m"
    colorGreen  = "\033[32m"
    colorYellow = "\033[33m"
    colorBlue   = "\033[34m"
    colorCyan   = "\033[36m"
    colorMagenta= "\033[35m"

    json = jsoniter.ConfigCompatibleWithStandardLibrary

    // 其他
    peerIDPrefix string
    infoHashes   []string
    hashIndex    uint32
    userAgents   = []string{"qBittorrent/4.6.0", "Transmission/3.00", "uTorrent/2210(25302)", "BitTorrent/7.10.5", "Deluge/2.0.3", "aria2/1.36.0", "libtorrent/1.2.18.0"}

    hostsMap   map[string][]string
    hostsMapMu sync.RWMutex
)

// ---------- 内部类型 ----------
type dnsCacheEntry struct {
    addrs []string
    ts    time.Time
    isErr bool
}

func init() {
    peerIDPrefix = fmt.Sprintf("-RS0001-%s", randomNumeric(12))
    RateLimiter = rate.NewLimiter(rate.Limit(2000), 200)
    var err error
    dnsCache, err = lru.New[string, *dnsCacheEntry](5000)
    if err != nil {
        panic(err)
    }
    LogWg.Add(1)
    go func() {
        defer LogWg.Done()
        for msg := range LogCh {
            fmt.Print(msg)
        }
    }()
}

// ---------- 随机工具 ----------
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

// ---------- 文本处理 ----------
func ParseTrackerLine(line string) string {
    line = strings.TrimSpace(line)
    if strings.HasPrefix(line, "[") && strings.Contains(line, "](") && strings.HasSuffix(line, ")") {
        if _, after, ok := strings.Cut(line, "]("); ok {
            return strings.TrimSuffix(after, ")")
        }
    }
    return line
}

func CollapsePathSlashes(path string) string {
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

func NormalizeTrackerURL(raw string) (string, error) {
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
    normalizedPath := CollapsePathSlashes(u.Path)
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

// ---------- Hosts 文件 ----------
func LoadHostsFile() {
    hostsMapMu.Lock()
    defer hostsMapMu.Unlock()
    hostsMap = make(map[string][]string)
    path := HostsFilePath
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

// ---------- DNS 解析 ----------
func LookupIPWithHosts(ctx context.Context, host string) ([]net.IP, error) {
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
    dialer := &net.Dialer{Timeout: DNSTimeout}
    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            if CustomDNS != "" {
                if !strings.Contains(CustomDNS, ":") {
                    address = CustomDNS + ":53"
                } else {
                    address = CustomDNS
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

// CachedDialContext 支持 IPv4/IPv6 优先和 DNS 缓存
func CachedDialContext(ctx context.Context, network, addr string, ipv4Only, ipv6Only bool) (net.Conn, error) {
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
            lookupCtx, cancel := context.WithTimeout(ctx, DNSTimeout)
            defer cancel()
            ipsLocal, err := LookupIPWithHosts(lookupCtx, host)
            if err != nil {
                dnsCache.Add(host, &dnsCacheEntry{addrs: []string{}, ts: time.Now(), isErr: true})
                return nil, err
            }
            addrs := make([]string, len(ipsLocal))
            for i, ip := range ipsLocal {
                addrs[i] = ip.String()
            }
            dnsCache.Add(host, &dnsCacheEntry{addrs: addrs, ts: time.Now(), isErr: false})
            LogCh <- fmt.Sprintf("%s[DNS] %s -> %s%s\n", colorCyan, host, strings.Join(addrs, ","), colorReset)
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

// ResolveUDPAddrWithHosts 专门用于 UDP 解析
func ResolveUDPAddrWithHosts(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
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
                ipsLocal, err := LookupIPWithHosts(ctx, host)
                if err != nil {
                    dnsCache.Add(host, &dnsCacheEntry{addrs: []string{}, ts: time.Now(), isErr: true})
                    return nil, err
                }
                addrs := make([]string, len(ipsLocal))
                for i, ip := range ipsLocal {
                    addrs[i] = ip.String()
                }
                dnsCache.Add(host, &dnsCacheEntry{addrs: addrs, ts: time.Now(), isErr: false})
                LogCh <- fmt.Sprintf("%s[DNS] %s -> %s%s\n", colorCyan, host, strings.Join(addrs, ","), colorReset)
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

// ---------- 代理 ----------
func GetNextProxy() proxy.Dialer {
    if len(ProxyPool) == 0 {
        return nil
    }
    proxyMu.Lock()
    defer proxyMu.Unlock()
    idx := atomic.AddUint32(&proxyIdx, 1) - 1
    return ProxyPool[idx%uint32(len(ProxyPool))]
}

// ---------- 杂项 ----------
func NextInfoHash() string {
    if len(infoHashes) == 0 {
        return ""
    }
    idx := atomic.AddUint32(&hashIndex, 1) - 1
    return infoHashes[idx%uint32(len(infoHashes))]
}

func InfoHashBytes(hashStr string) []byte {
    if len(hashStr) != 40 {
        return nil
    }
    raw, err := hex.DecodeString(hashStr)
    if err != nil || len(raw) != 20 {
        return nil
    }
    return raw
}

func SortUnique(items []string) []string {
    if len(items) == 0 {
        return items
    }
    slices.Sort(items)
    return slices.Compact(items)
}

func WriteLines(path string, lines []string) error {
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

func ColorizeStatus(status string) string {
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