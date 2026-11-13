using System.Globalization;
using System.Net;
using System.Text;
using System.Threading.RateLimiting;

namespace TrackerChecker;

public static class Program
{
    private const string Reset = "\u001b[0m";
    private const string Green = "\u001b[32m";
    private const string Yellow = "\u001b[33m";
    private const string Red = "\u001b[31m";
    private const string Cyan = "\u001b[36m";
    private const string Magenta = "\u001b[35m";

    public static async Task<int> Main(string[] args)
    {
        CliOptions opt;
        try
        {
            opt = CliOptions.Parse(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{Red}[BOOT]{Reset} 命令行参数解析失败: {ex.Message}");
            return 2;
        }

        Console.WriteLine($"{Magenta}=== TrackerChecker (.NET 10) ==={Reset}");
        Console.WriteLine($"{Cyan}[BOOT]{Reset} input={opt.Input} workers={opt.Workers} retries={opt.Retries} output={opt.Output}");
        Console.WriteLine($"{Cyan}[BOOT]{Reset} dns={(opt.UseDoH ? "DoH" : "CustomDns")} proxy={(opt.Proxy ?? "-")} sam={opt.Sam} dns-timeout={opt.DnsTimeout}");

        TrackerChecker.Compact0Fallback = opt.Compact0Fallback;
        TrackerChecker.InsecureSkip = opt.Insecure;
        TrackerChecker.DnsTimeout = opt.DnsTimeout;
        TrackerChecker.HostsFilePath = opt.HostsFile;
        TrackerChecker.UseSam = opt.Sam;
        TrackerChecker.SamHost = opt.SamHost;

        TrackerChecker.CustomDns = opt.CustomDns;
        TrackerChecker.UseDoH = opt.UseDoH;
        TrackerChecker.DoHServers = opt.DoHServers;

        TrackerChecker.RateLimiter = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = opt.RateLimit,
            TokensPerPeriod = opt.RateLimit,
            ReplenishmentPeriod = TimeSpan.FromSeconds(1),
            QueueLimit = int.MaxValue,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true,
        });

        if (!string.IsNullOrWhiteSpace(opt.Proxy))
        {
            try
            {
                TrackerChecker.Socks5Proxy = ParseSocks5(opt.Proxy);
                Console.WriteLine($"{Cyan}[BOOT]{Reset} SOCKS5 代理: {TrackerChecker.Socks5Proxy.Host}:{TrackerChecker.Socks5Proxy.Port}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"{Red}[BOOT]{Reset} SOCKS5 地址无效: {ex.Message}");
                return 2;
            }
        }

        TrackerChecker.LoadHostsFile();

        List<string> allTrackers;
        try
        {
            allTrackers = await TrackerChecker.LoadAllTrackersFromInputAsync(opt.Input);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"{Red}[INPUT]{Reset} 加载输入文件失败: {ex.Message}");
            return 1;
        }

        if (allTrackers.Count == 0)
        {
            Console.WriteLine($"{Red}[INPUT]{Reset} 未找到任何 tracker");
            return 1;
        }

        var httpTrackers = new List<string>();
        var udpWssTrackers = new List<string>();
        foreach (var t in allTrackers)
        {
            var proto = TrackerChecker.GetProtocolFromUrl(t);
            if (proto is "http" or "https" or "i2p") httpTrackers.Add(t);
            else if (proto is "udp" or "ws" or "wss") udpWssTrackers.Add(t);
        }

        Console.WriteLine($"{Cyan}[INPUT]{Reset} 共 {allTrackers.Count} 个 tracker，其中 HTTP/HTTPS/I2P: {httpTrackers.Count}，UDP/WSS: {udpWssTrackers.Count}");

        Console.WriteLine($"{Magenta}[DNS]{Reset} 开始预解析 DNS...");
        await Task.WhenAll(
            TrackerChecker.PreResolveDnsAsync(httpTrackers),
            TrackerChecker.PreResolveDnsAsync(udpWssTrackers));
        Console.WriteLine($"{Magenta}[DNS]{Reset} 预解析完成，开始检查...");

        using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(12));
        var ct = cts.Token;

        List<TrackerChecker.CheckResult> httpResults;
        List<TrackerChecker.CheckResult> udpResults;

        try
        {
            var httpTask = httpTrackers.Count > 0
                ? TrackerChecker.RunChecksAsync(httpTrackers, opt.Workers, opt.Retries, ct)
                : Task.FromResult(new List<TrackerChecker.CheckResult>());

            var udpTask = udpWssTrackers.Count > 0
                ? TrackerChecker.RunChecksAsync(udpWssTrackers, opt.Workers, opt.Retries, ct)
                : Task.FromResult(new List<TrackerChecker.CheckResult>());

            await Task.WhenAll(httpTask, udpTask);
            httpResults = await httpTask;
            udpResults = await udpTask;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine($"{Yellow}[WARN]{Reset} 检查超时或被取消，使用已完成的结果继续输出...");
            httpResults = new List<TrackerChecker.CheckResult>();
            udpResults = new List<TrackerChecker.CheckResult>();
        }

        await TrackerChecker.MergeAndOutputAsync(allTrackers, httpResults, udpResults, opt.Output);
        await TrackerChecker.FlushLogAsync();

        var alive = httpResults.Concat(udpResults).Count(r => r.Status == "ALIVE");
        var dead = httpResults.Concat(udpResults).Count(r => r.Status == "DEAD");
        var invalid = httpResults.Concat(udpResults).Count(r => r.Status == "INVALID");
        Console.WriteLine($"{Green}[DONE]{Reset} ALIVE={alive} DEAD={dead} INVALID={invalid} (total={allTrackers.Count})");
        return 0;
    }

    /// <summary>
    /// 解析 SOCKS5 地址。兼容以下写法：
    ///   - "host:port"
    ///   - "user:pass@host:port"
    ///   - "socks5://host:port"
    ///   - "socks5h://host:port"
    ///   - "socks5://user:pass@host:port"
    ///   - "[::1]:1080" 或 "socks5://[::1]:1080"
    /// </summary>
    private static TrackerChecker.Socks5Options ParseSocks5(string value)
    {
        var raw = value.Trim();

        // 去掉 socks5:// / socks5h:// / socks4:// / socks4a:// / http:// 等前缀
        var schemeEnd = raw.IndexOf("://", StringComparison.Ordinal);
        if (schemeEnd > 0)
            raw = raw[(schemeEnd + 3)..];

        // 剥离 user:pass@ 前缀
        string? username = null, password = null;
        var at = raw.LastIndexOf('@');
        if (at >= 0)
        {
            var cred = raw[..at];
            var colon = cred.IndexOf(':');
            if (colon >= 0)
            {
                username = cred[..colon];
                password = cred[(colon + 1)..];
            }
            else
            {
                username = cred;
            }
            raw = raw[(at + 1)..];
        }

        // 拆分 host 和 port，支持 IPv6 字面量 [::1]:1080
        string host;
        int port;
        if (raw.StartsWith('['))
        {
            var close = raw.IndexOf(']');
            if (close < 0)
                throw new ArgumentException($"缺少 ']'，输入: {value}");
            host = raw[1..close];
            var rest = raw[(close + 1)..];
            if (!rest.StartsWith(':') || !int.TryParse(rest[1..], NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
                throw new ArgumentException($"缺少端口，输入: {value}");
        }
        else
        {
            var colon = raw.LastIndexOf(':');
            if (colon < 0)
                throw new ArgumentException($"缺少 ':port'，输入: {value}");
            host = raw[..colon];
            if (!int.TryParse(raw[(colon + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out port))
                throw new ArgumentException($"端口不是数字，输入: {value}");
        }

        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException($"host 为空，输入: {value}");
        if (port <= 0 || port > 65535)
            throw new ArgumentException($"端口越界 ({port})，输入: {value}");

        return new TrackerChecker.Socks5Options
        {
            Host = host,
            Port = port,
            Username = username,
            Password = password,
        };
    }
}

public sealed class CliOptions
{
    public string Input = "merged_trackers.txt";
    public int Workers = TrackerChecker.DefaultWorkers;
    public int Retries = TrackerChecker.DefaultRetries;
    public bool Compact0Fallback;
    public bool Insecure;
    public string? Proxy;
    public bool Sam;
    public string SamHost = "127.0.0.1:7656";
    public string? HostsFile;
    public int RateLimit = 2000;
    public string Output = "public";
    public TimeSpan DnsTimeout = TimeSpan.FromSeconds(5);

    public string CustomDns = "1.1.1.1,8.8.8.8,9.9.9.9";
    public bool UseDoH;
    public List<string> DoHServers = new() { "https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query" };

    public static CliOptions Parse(string[] args)
    {
        var o = new CliOptions();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "-input" when i + 1 < args.Length: o.Input = args[++i]; break;
                case "-workers" when i + 1 < args.Length: o.Workers = ParseInt(args[++i], "-workers"); break;
                case "-retries" when i + 1 < args.Length: o.Retries = ParseInt(args[++i], "-retries"); break;
                case "-compact0-fallback": o.Compact0Fallback = true; break;
                case "-insecure": o.Insecure = true; break;
                case "-proxy" when i + 1 < args.Length: o.Proxy = args[++i]; break;
                case "-sam": o.Sam = true; break;
                case "-sam-host" when i + 1 < args.Length: o.SamHost = args[++i]; break;
                case "-hosts-file" when i + 1 < args.Length: o.HostsFile = args[++i]; break;
                case "-rate-limit" when i + 1 < args.Length: o.RateLimit = ParseInt(args[++i], "-rate-limit"); break;
                case "-output" when i + 1 < args.Length: o.Output = args[++i]; break;

                // 关键修复：兼容 "5"、"5s"、"500ms"、"1m"、"1h"、"1m30s"、"1.5s"
                case "-dns-timeout" when i + 1 < args.Length:
                    o.DnsTimeout = ParseDuration(args[++i], "-dns-timeout");
                    break;

                case "-dns" when i + 1 < args.Length: o.CustomDns = args[++i]; break;
                case "-doh": o.UseDoH = true; break;
                case "-doh-servers" when i + 1 < args.Length:
                    o.DoHServers = args[++i]
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                    break;
                default:
                    // 未知参数：给出警告但不中断，方便后续扩展
                    if (args[i].StartsWith('-'))
                        Console.Error.WriteLine($"警告: 未知参数 {args[i]}");
                    break;
            }
        }
        return o;
    }

    private static int ParseInt(string raw, string flag)
    {
        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v))
            throw new ArgumentException($"{flag} 需要一个整数，收到: {raw}");
        return v;
    }

    /// <summary>
    /// 解析 Go 风格 duration。支持组合单位（如 "1h30m"）和小数（如 "1.5s"）。
    /// 纯数字视为秒。
    /// </summary>
    private static TimeSpan ParseDuration(string raw, string flag)
    {
        raw = raw.Trim();
        if (raw.Length == 0)
            throw new ArgumentException($"{flag} 不能为空");

        // 纯数字 → 秒（如 "5"、"1.5"）
        if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var plainSecs))
        {
            if (plainSecs < 0) throw new ArgumentException($"{flag} 不能为负数: {raw}");
            return TimeSpan.FromSeconds(plainSecs);
        }

        double totalSeconds = 0;
        int i = 0;
        bool parsedAny = false;

        while (i < raw.Length)
        {
            // 读数字部分（含小数点）
            int numStart = i;
            while (i < raw.Length && (char.IsDigit(raw[i]) || raw[i] == '.')) i++;
            if (i == numStart)
                throw new ArgumentException($"{flag} 非法 duration（缺少数字）: {raw}");

            var numPart = raw[numStart..i];
            if (!double.TryParse(numPart, NumberStyles.Float, CultureInfo.InvariantCulture, out var n))
                throw new ArgumentException($"{flag} 非法 duration 数值: {numPart}");

            // 读单位部分（连续非数字字符）
            int unitStart = i;
            while (i < raw.Length && !char.IsDigit(raw[i]) && raw[i] != '.') i++;
            var unit = raw[unitStart..i].ToLowerInvariant();

            totalSeconds += unit switch
            {
                "ns" => n / 1_000_000_000d,
                "us" or "µs" or "μs" => n / 1_000_000d,
                "ms" => n / 1_000d,
                "s" => n,
                "m" => n * 60d,
                "h" => n * 3600d,
                "" => throw new ArgumentException($"{flag} 缺少单位: {raw}"),
                _ => throw new ArgumentException($"{flag} 未知单位 '{unit}': {raw}"),
            };
            parsedAny = true;
        }

        if (!parsedAny)
            throw new ArgumentException($"{flag} 非法 duration: {raw}");
        if (totalSeconds < 0)
            throw new ArgumentException($"{flag} 不能为负数: {raw}");

        return TimeSpan.FromSeconds(totalSeconds);
    }
}