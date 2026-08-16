package tracker

import (
    "context"
    "crypto/rand"
    "encoding/binary"
    "fmt"
    "net"
    "net/url"
    "time"
)

func CheckUDPAttempt(ctx context.Context, tracker string, infoHash string, ipv6Only bool, targetPort string) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
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
    addr, err := ResolveUDPAddrWithHosts(ctx, "udp", net.JoinHostPort(host, port))
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
    conn.SetDeadline(time.Now().Add(DefaultTimeout))

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

    ih := InfoHashBytes(infoHash)
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

func CheckUDPWithFamily(ctx context.Context, tracker string, infoHash string, ipv6Only bool) (alive bool, ping *int64, hasIPv6Peers bool, err error) {
    if err := RateLimiter.Wait(ctx); err != nil {
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
        alive, ping, has6, _ := CheckUDPAttempt(ctx, tracker, infoHash, ipv6Only, port)
        if alive {
            return true, ping, has6, nil
        }
    }
    return false, nil, false, fmt.Errorf("all UDP ports failed")
}

func CheckUDP(ctx context.Context, tracker string, infoHash string) (status string, ping *int64, supportsIPv4, supportsIPv6 *bool) {
    alive4, ping4, has6inResp4, _ := CheckUDPWithFamily(ctx, tracker, infoHash, false)
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
        alive6, ping6, _, _ := CheckUDPWithFamily(ctx, tracker, infoHash, true)
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