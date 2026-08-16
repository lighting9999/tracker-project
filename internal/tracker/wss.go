package tracker

import (
    "context"
    "crypto/tls"
    "net/http"
    "net/url"
    "strings"
    "time"

    "github.com/gorilla/websocket"
)

func CheckWSSWithFamily(ctx context.Context, tracker string, ipv4Only, ipv6Only bool) (bool, *int64, error) {
    if err := RateLimiter.Wait(ctx); err != nil {
        return false, nil, err
    }
    warmTransport()
    header := http.Header{}
    header.Set("User-Agent", "qBittorrent/4.6.0")
    dialer := websocket.Dialer{
        HandshakeTimeout: DefaultTimeout,
        NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, _, _ := net.SplitHostPort(addr)
            if strings.HasSuffix(host, ".i2p") {
                if p := GetNextProxy(); p != nil {
                    return p.Dial(network, addr)
                }
            }
            return CachedDialContext(ctx, network, addr, ipv4Only, ipv6Only)
        },
        Proxy:            http.ProxyFromEnvironment,
        TLSClientConfig:  &tls.Config{InsecureSkipVerify: InsecureSkip},
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
    conn.SetReadDeadline(time.Now().Add(DefaultTimeout))
    conn.SetWriteDeadline(time.Now().Add(DefaultTimeout))
    elapsed := int64(time.Since(start).Milliseconds())
    return true, &elapsed, nil
}

func CheckWSS(ctx context.Context, tracker string) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
    alive4, ping4, _ := CheckWSSWithFamily(ctx, tracker, true, false)
    has4 := alive4
    var bestPing *int64
    if has4 {
        bestPing = ping4
    }
    alive6, ping6, _ := CheckWSSWithFamily(ctx, tracker, false, true)
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