package main

import (
    "context"
    "flag"
    "fmt"
    "log"
    "sync"
    "sync/atomic"
    "time"

    "golang.org/x/net/proxy"
    "golang.org/x/time/rate"
    "tracker-project/internal/tracker"
)

func main() {
    // 命令行参数
    input := flag.String("input", "merged_trackers.txt", "输入 tracker 列表文件")
    workers := flag.Int("workers", tracker.DefaultWorkers, "并发工作数")
    retries := flag.Int("retries", tracker.DefaultRetries, "重试次数")
    compact0 := flag.Bool("compact0-fallback", false, "启用 compact=0 备选")
    insecure := flag.Bool("insecure", false, "跳过 TLS 验证")
    proxyFlag := flag.String("proxy", "", "SOCKS5 代理地址")
    samFlag := flag.Bool("sam", false, "启用 I2P SAM 桥")
    samHostFlag := flag.String("sam-host", "127.0.0.1:7656", "SAM 桥地址")
    dnsFlag := flag.String("dns", "1.1.1.1:53", "自定义 DNS 服务器")
    dnsTimeoutFlag := flag.Duration("dns-timeout", 5*time.Second, "DNS 超时")
    hostsFileFlag := flag.String("hosts-file", "", "自定义 hosts 文件路径")
    rateLimitFlag := flag.Int("rate-limit", 2000, "每秒请求上限")
    outputDir := flag.String("output", "public", "输出目录")
    flag.Parse()

    // 初始化全局配置
    tracker.Compact0Fallback = *compact0
    tracker.InsecureSkip = *insecure
    tracker.CustomDNS = *dnsFlag
    tracker.DNSTimeout = *dnsTimeoutFlag
    tracker.HostsFilePath = *hostsFileFlag
    tracker.UseSAM = *samFlag
    tracker.SAMHost = *samHostFlag
    tracker.RateLimiter = rate.NewLimiter(rate.Limit(float64(*rateLimitFlag)), *rateLimitFlag)

    if *proxyFlag != "" {
        rawDialer, err := proxy.SOCKS5("tcp", *proxyFlag, nil, proxy.Direct)
        if err != nil {
            log.Fatalf("创建 SOCKS5 代理失败: %v", err)
        }
        tracker.ProxyPool = append(tracker.ProxyPool, rawDialer)
    }
    tracker.LoadHostsFile()

    // 加载所有 tracker
    allTrackers, err := tracker.LoadAllTrackersFromInput(*input)
    if err != nil {
        log.Fatalf("加载输入文件失败: %v", err)
    }
    if len(allTrackers) == 0 {
        log.Fatal("未找到任何 tracker")
    }

    // 分离 HTTP/HTTPS/I2P 和 UDP/WSS
    var httpTrackers, udpWssTrackers []string
    for _, t := range allTrackers {
        proto := tracker.GetProtocolFromURL(t)
        if proto == "http" || proto == "https" || proto == "i2p" {
            httpTrackers = append(httpTrackers, t)
        } else if proto == "udp" || proto == "ws" || proto == "wss" {
            udpWssTrackers = append(udpWssTrackers, t)
        }
        // 忽略其他协议（如 dns）
    }

    fmt.Printf("总共 %d 个 tracker，其中 HTTP/HTTPS/I2P: %d，UDP/WSS: %d\n",
        len(allTrackers), len(httpTrackers), len(udpWssTrackers))

    // 并发检查
    ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
    defer cancel()

    var wg sync.WaitGroup
    var httpResults, udpResults []tracker.CheckResult
    var httpMu, udpMu sync.Mutex

    // 检查 HTTP/HTTPS/I2P
    if len(httpTrackers) > 0 {
        wg.Add(1)
        go func() {
            defer wg.Done()
            res := runChecks(ctx, httpTrackers, *workers, *retries)
            httpMu.Lock()
            httpResults = res
            httpMu.Unlock()
        }()
    }

    // 检查 UDP/WSS
    if len(udpWssTrackers) > 0 {
        wg.Add(1)
        go func() {
            defer wg.Done()
            res := runChecks(ctx, udpWssTrackers, *workers, *retries)
            udpMu.Lock()
            udpResults = res
            udpMu.Unlock()
        }()
    }

    wg.Wait()

    // 合并并输出
    if err := tracker.MergeAndOutput(allTrackers, httpResults, udpResults, *outputDir); err != nil {
        log.Fatalf("合并输出失败: %v", err)
    }

    close(tracker.LogCh)
    tracker.LogWg.Wait()
    fmt.Println("所有任务完成")
}

// runChecks 使用 worker pool 并发检查 tracker 列表
func runChecks(ctx context.Context, trackers []string, workers, retries int) []tracker.CheckResult {
    total := len(trackers)
    if total == 0 {
        return nil
    }

    // 结果通道，缓冲全部容量避免阻塞
    results := make(chan tracker.CheckResult, total)
    taskCh := make(chan string, total)

    // 启动固定数量的 worker
    var wg sync.WaitGroup
    for i := 0; i < workers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for url := range taskCh {
                // 检查 context 是否取消
                select {
                case <-ctx.Done():
                    return
                default:
                }
                res := tracker.ValidateTracker(ctx, url, retries+1)
                results <- res
            }
        }()
    }

    // 分发任务
    for _, url := range trackers {
        select {
        case taskCh <- url:
        case <-ctx.Done():
            break
        }
    }
    close(taskCh)

    // 等待所有 worker 完成
    wg.Wait()
    close(results)

    // 收集结果
    out := make([]tracker.CheckResult, 0, total)
    for r := range results {
        out = append(out, r)
    }
    return out
}