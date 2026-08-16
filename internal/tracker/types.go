package tracker

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

// FrontendData 是最终提供给前端的完整数据结构
type FrontendData struct {
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

// TrackerHistory 用于历史记录（保留原有功能）
type TrackerHistory struct {
    Checks             uint64
    AliveChecks        uint64
    FirstSeenTs        int64
    FirstAliveTs       int64
    LastSeenTs         int64
    LastAliveTs        int64
    StreakAliveStartTs int64
}