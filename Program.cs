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
        var opt = CliOptions.Parse(args);

        Console.WriteLine($"{Magenta}=== TrackerChecker (.NET 10) ==={Reset}");
        Console.WriteLine($"{Cyan}[BOOT]{Reset} input={opt.Input} workers={opt.Workers} retries={opt.Retries} output={opt.Output}");
        Console.WriteLine($"{Cyan}[BOOT]{Reset} dns={(opt.UseDoH ? "DoH" : "CustomDns")} proxy={(opt.Proxy ?? "-")} sam={opt.Sam}");

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
            TrackerChecker.Socks5Proxy = ParseSocks5(opt.Proxy);

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

    private static TrackerChecker.Socks5Options ParseSocks5(string value)
    {
        var at = value.LastIndexOf('@');
        var hostPort = at >= 0 ? value[(at + 1)..] : value;
        var parts = hostPort.Split(':');
        if (parts.Length < 2) throw new ArgumentException($"非法 SOCKS5 地址: {value}");
        var opt = new TrackerChecker.Socks5Options { Host = parts[0], Port = int.Parse(parts[1]) };
        if (at >= 0)
        {
            var cred = value[..at].Split(':');
            if (cred.Length >= 2) { opt.Username = cred[0]; opt.Password = cred[1]; }
        }
        return opt;
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
                case "-workers" when i + 1 < args.Length: o.Workers = int.Parse(args[++i]); break;
                case "-retries" when i + 1 < args.Length: o.Retries = int.Parse(args[++i]); break;
                case "-compact0-fallback": o.Compact0Fallback = true; break;
                case "-insecure": o.Insecure = true; break;
                case "-proxy" when i + 1 < args.Length: o.Proxy = args[++i]; break;
                case "-sam": o.Sam = true; break;
                case "-sam-host" when i + 1 < args.Length: o.SamHost = args[++i]; break;
                case "-hosts-file" when i + 1 < args.Length: o.HostsFile = args[++i]; break;
                case "-rate-limit" when i + 1 < args.Length: o.RateLimit = int.Parse(args[++i]); break;
                case "-output" when i + 1 < args.Length: o.Output = args[++i]; break;
                case "-dns-timeout" when i + 1 < args.Length: o.DnsTimeout = TimeSpan.FromSeconds(double.Parse(args[++i])); break;
                case "-dns" when i + 1 < args.Length: o.CustomDns = args[++i]; break;
                case "-doh": o.UseDoH = true; break;
                case "-doh-servers" when i + 1 < args.Length:
                    o.DoHServers = args[++i]
                        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList();
                    break;
            }
        }
        return o;
    }
}