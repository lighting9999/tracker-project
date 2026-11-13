using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using System.Threading.RateLimiting;
using System.Web;

namespace TrackerChecker;

public static class TrackerChecker
{
    public const string StatusAlive = "ALIVE";
    public const string StatusDead = "DEAD";
    public const string StatusInvalid = "INVALID";
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);
    public const int DefaultWorkers = 1000;
    public const int DefaultRetries = 1;
    public const int MaxPeersCollector = 10000;

    // ---------- ANSI 颜色 ----------
    private const string Reset = "\u001b[0m";
    private const string Red = "\u001b[31m";
    private const string Green = "\u001b[32m";
    private const string Yellow = "\u001b[33m";
    private const string Blue = "\u001b[34m";
    private const string Magenta = "\u001b[35m";
    private const string Cyan = "\u001b[36m";
    private const string Gray = "\u001b[90m";

    // ---------- 全局状态 ----------
    private static readonly Regex TrackerRe = new(
        @"(?i)(https?|udp|wss?|dns)://[^\s,]+?/announce[^\s,]*",
        RegexOptions.Compiled);

    private static readonly ConcurrentDictionary<string, DnsCacheEntry> DnsCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly TimeSpan DnsCacheTtl = TimeSpan.FromMinutes(100);
    private static readonly TimeSpan DnsNegativeTtl = TimeSpan.FromSeconds(2);
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> DnsSingleflight = new(StringComparer.OrdinalIgnoreCase);

    public static bool Compact0Fallback { get; set; }
    public static bool InsecureSkip { get; set; }
    public static string? CustomDns { get; set; } = "1.1.1.1,8.8.8.8,9.9.9.9";
    public static bool UseDoH { get; set; }
    public static List<string> DoHServers { get; set; } = new()
    {
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
    };
    public static TimeSpan DnsTimeout { get; set; } = TimeSpan.FromSeconds(5);
    public static RateLimiter? RateLimiter { get; set; }
    public static string? HostsFilePath { get; set; }
    public static bool UseSam { get; set; }
    public static string SamHost { get; set; } = "127.0.0.1:7656";
    public static Socks5Options? Socks5Proxy { get; set; }

    private static readonly ConcurrentDictionary<string, List<string>> HostsMap = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string PeerIdPrefix = "-RS0001-" + RandomNumeric(12);
    private static readonly string[] UserAgents =
    {
        "qBittorrent/4.6.0", "Transmission/3.00", "uTorrent/2210(25302)",
        "BitTorrent/7.10.5", "Deluge/2.0.3", "aria2/1.36.0", "libtorrent/1.2.18.0"
    };

    private static readonly ConcurrentDictionary<string, HttpClient> HttpClientCache = new();
    private static readonly object HttpWarmLock = new();
    private static bool _httpWarmed;

    private static readonly HttpClient DohHttpClient;

    private static readonly ConcurrentDictionary<string, SamPooledConn> SamConnCache = new();
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> SamGroups = new();

    private static readonly ConcurrentDictionary<string, byte> PeersCollector = new();
    private static int _peersCollectorCnt;

    // 日志 channel
    private static readonly Channel<string> LogCh = Channel.CreateBounded<string>(
        new BoundedChannelOptions(100_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });
    private static Task? _logTask;
    private static readonly object LogLock = new();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    // ---------- 静态构造：初始化 DoH HTTP 客户端 ----------
    static TrackerChecker()
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = TimeSpan.FromSeconds(5),
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            EnableMultipleHttp2Connections = true,
        };
        handler.SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, _, _, _) => InsecureSkip,
        };
        handler.ConnectCallback = async (context, ct) =>
        {
            var host = context.DnsEndPoint.Host;
            var port = context.DnsEndPoint.Port;

            IPAddress ip;
            if (IPAddress.TryParse(host, out var parsed))
            {
                ip = parsed;
            }
            else
            {
                IPAddress[] addrs;
                try
                {
                    addrs = await ResolveAsync(host, ct);
                }
                catch (Exception ex)
                {
                    throw new IOException($"cannot resolve DoH host {host}: {ex.Message}", ex);
                }
                ip = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                     ?? addrs.FirstOrDefault()
                     ?? throw new IOException($"cannot resolve DoH host {host}");
            }

            var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(new IPEndPoint(ip, port)).WaitAsync(ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };

        DohHttpClient = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(10),
            DefaultRequestVersion = HttpVersion.Version20,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher,
        };
    }

    // ==================================================================
    //  类型
    // ==================================================================
    public sealed record CheckResult(
        string Url, string Status, long? PingMs, bool? SupportsIPv4, bool? SupportsIPv6);

    public sealed record TrackerEntry(
        string Url, string Status, string Protocol, long? PingMs, bool? SupportsIPv4, bool? SupportsIPv6);

    public sealed class ProtocolStats
    {
        public int Http { get; set; }
        public int Https { get; set; }
        public int Udp { get; set; }
        public int Wss { get; set; }
        public int WebRtc { get; set; }
        public int I2P { get; set; }
        public int Dns { get; set; }
        public double HttpPct { get; set; }
        public double HttpsPct { get; set; }
        public double UdpPct { get; set; }
        public double WssPct { get; set; }
    }

    public sealed class FrontendData
    {
        public int Total { get; set; }
        public int AliveCount { get; set; }
        public int DeadCount { get; set; }
        public int InvalidCount { get; set; }
        public double UptimePct { get; set; }
        public ProtocolStats Protocols { get; set; } = new();
        public List<TrackerEntry> Trackers { get; set; } = new();
        public double AvgPingMs { get; set; }
        public long MinPingMs { get; set; }
        public long MaxPingMs { get; set; }
    }

    public sealed class TrackerHistory
    {
        public ulong Checks;
        public ulong AliveChecks;
        public long FirstSeenTs;
        public long FirstAliveTs;
        public long LastSeenTs;
        public long LastAliveTs;
        public long StreakAliveStartTs;
    }

    private sealed record DnsCacheEntry(string[] Addrs, DateTime Ts, bool IsErr);

    public sealed class Socks5Options
    {
        public string Host = "";
        public int Port;
        public string? Username;
        public string? Password;
    }

    private sealed class SamPooledConn : IDisposable
    {
        public required TcpClient Client;
        public required NetworkStream Stream;
        public required BufferedStream Reader;
        public required string Host;
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                SamConnCache.TryRemove(Host, out _);
                try { Stream.Dispose(); } catch { }
                try { Client.Dispose(); } catch { }
            }
        }
    }

    // ==================================================================
    //  DNS 统一入口（核心修复）
    // ==================================================================
    /// <summary>
    /// 统一的 host 解析辅助方法。
    /// 使用兼容性最好的单参数 GetHostAddressesAsync(host) + WaitAsync(ct) 附加取消，
    /// 避免依赖 (string, CancellationToken) 重载（该重载在部分裁剪运行时上不存在，
    /// 会导致 CS1503 cannot convert from 'string' to 'System.Net.IPAddress'）。
    /// </summary>
    public static async Task<IPAddress[]> ResolveAsync(string host, CancellationToken ct = default)
    {
        try
        {
            return await Dns.GetHostAddressesAsync(host).WaitAsync(ct);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (
            // 极少数运行时连单参数异步重载都被裁剪 → 兜底到同步版本
            ex is MissingMethodException or NotSupportedException or NotImplementedException)
        {
            return await Task.Run(() => Dns.GetHostAddresses(host), ct);
        }
    }

    // ==================================================================
    //  彩色日志
    // ==================================================================
    private static void EnsureLogTask()
    {
        if (_logTask is not null) return;
        lock (LogLock)
        {
            if (_logTask is not null) return;
            _logTask = Task.Run(async () =>
            {
                await foreach (var line in LogCh.Reader.ReadAllAsync())
                    Console.Write(line);
            });
        }
    }

    private static void Emit(string raw) => LogCh.Writer.TryWrite(raw + "\n");

    private static void LogTag(string color, string tag, string msg)
        => Emit($"{color}[{tag}]{Reset} {msg}");

    private static void LogBoot(string m) => LogTag(Magenta, "BOOT", m);
    private static void LogInput(string m) => LogTag(Cyan, "INPUT", m);
    private static void LogDns(string m) => LogTag(Blue, "DNS", m);
    private static void LogDnsOk(string m) => LogTag(Green, "DNS", m);
    private static void LogDoh(string m) => LogTag(Magenta, "DOH", m);
    private static void LogUdpDns(string m) => LogTag(Blue, "UDP-DNS", m);
    private static void LogCache(string m) => LogTag(Gray, "CACHE", m);
    private static void LogHttp(string m) => LogTag(Cyan, "HTTP", m);
    private static void LogUdp(string m) => LogTag(Yellow, "UDP", m);
    private static void LogWss(string m) => LogTag(Green, "WSS", m);
    private static void LogSam(string m) => LogTag(Magenta, "SAM", m);
    private static void LogSocks(string m) => LogTag(Gray, "SOCKS5", m);
    private static void LogWarn(string m) => LogTag(Yellow, "WARN", m);
    private static void LogErr(string m) => LogTag(Red, "ERR", m);
    private static void LogMerge(string m) => LogTag(Green, "MERGE", m);

    private static void LogResult(string url, string status, long? ping, bool? v4, bool? v6)
    {
        var color = status switch
        {
            StatusAlive => Green,
            StatusDead => Red,
            _ => Yellow,
        };
        var pingText = ping is not null ? $" {ping}ms" : "";
        var vText = (v4, v6) switch
        {
            (true, true) => " v4+v6",
            (true, _) => " v4",
            (_, true) => " v6",
            _ => "",
        };
        Emit($"{color}[{status,-7}]{Reset} {url}{pingText}{vText}");
    }

    public static async Task FlushLogAsync()
    {
        EnsureLogTask();
        LogCh.Writer.TryComplete();
        if (_logTask is not null) await _logTask;
    }

    // ==================================================================
    //  基础工具
    // ==================================================================
    private static string RandomNumeric(int n)
    {
        const string digits = "0123456789";
        var chars = new char[n];
        for (int i = 0; i < n; i++)
            chars[i] = digits[Random.Shared.Next(digits.Length)];
        return new string(chars);
    }

    private static int RandomInt(int min, int max) => Random.Shared.Next(min, max);
    private static string RandomUa() => UserAgents[RandomInt(0, UserAgents.Length)];

    public static string ParseTrackerLine(string line)
    {
        line = line.Trim();
        if (line.StartsWith('[') && line.Contains("](") && line.EndsWith(')'))
        {
            var idx = line.IndexOf("](", StringComparison.Ordinal);
            return line[(idx + 2)..^1];
        }
        return line;
    }

    private static string CollapsePathSlashes(string path)
    {
        var sb = new StringBuilder(path.Length);
        bool prevSlash = false;
        foreach (var ch in path)
        {
            if (ch == '/')
            {
                if (!prevSlash) sb.Append(ch);
                prevSlash = true;
            }
            else
            {
                sb.Append(ch);
                prevSlash = false;
            }
        }
        return sb.Length == 0 ? "/" : sb.ToString();
    }

    public static (string? Normalized, string? Error) NormalizeTrackerUrl(string raw)
    {
        var candidate = raw.Trim('"', '\'', '<', '>', '[', ']', '(', ')', '{', '}', ';', ',', '.');
        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var u))
            return (null, "invalid url");

        var scheme = u.Scheme.ToLowerInvariant();
        if (scheme is not ("http" or "https" or "udp" or "wss" or "ws" or "dns"))
            return (null, "unsupported scheme");

        var host = u.Host;
        if (string.IsNullOrEmpty(host)) return (null, "no host");
        if (scheme == "dns") return (candidate, null);

        var normalizedPath = CollapsePathSlashes(u.AbsolutePath);
        if (!(normalizedPath.EndsWith("/announce", StringComparison.OrdinalIgnoreCase) ||
              normalizedPath.Contains("/announce?", StringComparison.OrdinalIgnoreCase) ||
              normalizedPath.EndsWith("/announce.php", StringComparison.OrdinalIgnoreCase) ||
              normalizedPath.EndsWith("/announce.jsp", StringComparison.OrdinalIgnoreCase) ||
              normalizedPath.EndsWith("/announce.aspx", StringComparison.OrdinalIgnoreCase)))
            return (null, "path must be related to /announce");

        var builder = new UriBuilder(u) { Path = normalizedPath, Fragment = "" };
        if ((scheme == "http" && u.Port == 80) || (scheme == "https" && u.Port == 443))
            builder.Port = -1;

        return (builder.Uri.AbsoluteUri, null);
    }

    private static byte[]? InfoHashBytes(string? hashStr)
    {
        if (string.IsNullOrEmpty(hashStr) || hashStr.Length != 40) return null;
        try { return Convert.FromHexString(hashStr); }
        catch { return null; }
    }

    private static string NextInfoHash() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(20)).ToLowerInvariant();

    // ==================================================================
    //  hosts / DNS
    // ==================================================================
    public static void LoadHostsFile()
    {
        HostsMap.Clear();
        var path = HostsFilePath;
        if (string.IsNullOrEmpty(path))
        {
            path = OperatingSystem.IsWindows()
                ? @"C:\Windows\System32\drivers\etc\hosts"
                : "/etc/hosts";
        }

        int count = 0;
        try
        {
            foreach (var rawLine in File.ReadLines(path))
            {
                var line = rawLine;
                var hashIdx = line.IndexOf('#');
                if (hashIdx >= 0) line = line[..hashIdx];
                line = line.Trim();
                if (line.Length == 0) continue;

                var fields = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length < 2) continue;

                var ip = fields[0];
                for (int i = 1; i < fields.Length; i++)
                {
                    var host = fields[i].ToLowerInvariant();
                    HostsMap.AddOrUpdate(host,
                        _ => new List<string> { ip },
                        (_, list) => { lock (list) list.Add(ip); return list; });
                    count++;
                }
            }
            LogBoot($"hosts 文件已加载: {path}（{count} 条记录）");
        }
        catch (Exception ex)
        {
            LogWarn($"hosts 文件读取失败: {path} ({ex.Message})");
        }
    }

    public static bool GetDns(string host, out string[] addrs)
    {
        if (DnsCache.TryGetValue(host, out var entry) && !entry.IsErr)
        {
            addrs = entry.Addrs;
            return true;
        }
        addrs = Array.Empty<string>();
        return false;
    }

    /// <summary>
    /// 统一 host 解析：hosts → DoH → CustomDns(UDP) → 系统 DNS
    /// </summary>
    public static async Task<IPAddress[]> LookupIpWithHostsAsync(string host, CancellationToken ct)
    {
        // 1. hosts 文件
        if (HostsMap.TryGetValue(host, out var ipStrings))
        {
            var ips = ipStrings
                .Select(s => IPAddress.TryParse(s, out var ip) ? ip : null)
                .Where(ip => ip is not null)
                .Cast<IPAddress>()
                .ToArray();
            if (ips.Length > 0)
            {
                LogDnsOk($"{host} -> {string.Join(",", ips.Select(i => i.ToString()))} (hosts)");
                return ips;
            }
        }

        // 2. DoH
        if (UseDoH && DoHServers.Count > 0)
        {
            var (ips, success) = await DohLookupAsync(host, ct);
            if (success)
            {
                LogDnsOk($"{host} -> {(ips.Length == 0 ? "NXDOMAIN" : string.Join(",", ips.Select(i => i.ToString())))} (DoH)");
                return ips;
            }
            LogDoh($"DoH 全部服务器失败，回退: {host}");
        }

        // 3. CustomDns (UDP)
        if (!string.IsNullOrWhiteSpace(CustomDns))
        {
            var servers = CustomDns.Split(',',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var srv in servers)
            {
                try
                {
                    var ips = await UdpDnsLookupAsync(srv, host, ct);
                    if (ips.Length > 0)
                    {
                        LogDnsOk($"{host} -> {string.Join(",", ips.Select(i => i.ToString()))} (UDP-DNS {srv})");
                        return ips;
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    LogUdpDns($"{srv} 查询 {host} 失败: {ex.Message}");
                }
            }
        }

        // 4. 系统 DNS（统一走 ResolveAsync）
        try
        {
            var result = await ResolveAsync(host, ct);
            if (result.Length > 0)
                LogDnsOk($"{host} -> {string.Join(",", result.Select(i => i.ToString()))} (system)");
            return result;
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }

    // ---------- DoH ----------
    private static async Task<(IPAddress[] Ips, bool Success)> DohLookupAsync(string host, CancellationToken ct)
    {
        var servers = DoHServers;
        if (servers.Count == 0) return (Array.Empty<IPAddress>(), false);

        var start = Random.Shared.Next(servers.Count);
        for (int i = 0; i < servers.Count; i++)
        {
            var server = servers[(start + i) % servers.Count];
            try
            {
                LogDoh($"查询 {host} via {server}");
                var ips = await DohQueryAsync(server, host, ct);
                return (ips, true);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                LogDoh($"✗ {server} 查询 {host} 失败: {ex.Message}");
            }
        }
        return (Array.Empty<IPAddress>(), false);
    }

    private static async Task<IPAddress[]> DohQueryAsync(string server, string host, CancellationToken ct)
    {
        var id = (ushort)Random.Shared.Next(0, 1 << 16);
        var qa = BuildDnsQuery(host, 1, id);
        var qa6 = BuildDnsQuery(host, 28, id);

        var taskA = SendDohQueryAsync(server, qa, id, ct);
        var taskAaaa = SendDohQueryAsync(server, qa6, id, ct);

        var results = new List<IPAddress>();
        Exception? lastErr = null;

        try { results.AddRange(await taskA); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { lastErr = ex; }

        try { results.AddRange(await taskAaaa); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { lastErr ??= ex; }

        if (results.Count == 0 && lastErr is not null) throw lastErr;
        return results.ToArray();
    }

    private static async Task<List<IPAddress>> SendDohQueryAsync(
        string server, byte[] query, ushort expectedId, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, server)
        {
            Content = new ByteArrayContent(query),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };
        req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/dns-message");
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/dns-message"));

        using var resp = await DohHttpClient.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var bytes = await resp.Content.ReadAsByteArrayAsync(ct);
        return ParseDnsResponse(bytes, expectedId);
    }

    // ---------- UDP DNS ----------
    private static async Task<IPAddress[]> UdpDnsLookupAsync(string server, string host, CancellationToken ct)
    {
        var (hostPart, port) = SplitHostPort(server, 53);
        IPAddress dnsIp;
        if (IPAddress.TryParse(hostPart, out var parsed))
        {
            dnsIp = parsed;
        }
        else
        {
            IPAddress[] addrs;
            try
            {
                addrs = await ResolveAsync(hostPart, ct);
            }
            catch (Exception ex)
            {
                throw new IOException($"cannot resolve DNS server {hostPart}: {ex.Message}", ex);
            }
            dnsIp = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                    ?? addrs.FirstOrDefault()
                    ?? throw new IOException($"cannot resolve DNS server {hostPart}");
        }

        using var udp = new UdpClient(dnsIp.AddressFamily);
        udp.Connect(dnsIp, port);

        var id = (ushort)Random.Shared.Next(0, 1 << 16);
        var ips = new List<IPAddress>();

        // A
        try
        {
            var qa = BuildDnsQuery(host, 1, id);
            await udp.SendAsync(qa, ct);
            using var recvCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            recvCts.CancelAfter(DnsTimeout);
            var r = await udp.ReceiveAsync(recvCts.Token);
            ips.AddRange(ParseDnsResponse(r.Buffer, id));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }

        // AAAA
        try
        {
            var qa6 = BuildDnsQuery(host, 28, id);
            await udp.SendAsync(qa6, ct);
            using var recvCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            recvCts.CancelAfter(DnsTimeout);
            var r = await udp.ReceiveAsync(recvCts.Token);
            ips.AddRange(ParseDnsResponse(r.Buffer, id));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { }

        return ips.ToArray();
    }

    private static (string Host, int Port) SplitHostPort(string s, int defaultPort)
    {
        var idx = s.LastIndexOf(':');
        if (idx > 0 && !s.Contains(']'))
        {
            if (int.TryParse(s[(idx + 1)..], out var p) && p > 0 && p <= 65535)
                return (s[..idx], p);
        }
        return (s, defaultPort);
    }

    // ---------- DNS wire format ----------
    private static byte[] BuildDnsQuery(string hostname, ushort qtype, ushort id)
    {
        using var ms = new MemoryStream(64);
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header, id);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..], 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(header[4..], 1);
        BinaryPrimitives.WriteUInt16BigEndian(header[6..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[8..], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], 0);
        ms.Write(header);

        foreach (var label in hostname.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            if (bytes.Length is 0 or > 63)
                throw new ArgumentException($"invalid DNS label in {hostname}");
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes);
        }
        ms.WriteByte(0);

        Span<byte> qtail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(qtail, qtype);
        BinaryPrimitives.WriteUInt16BigEndian(qtail[2..], 1);
        ms.Write(qtail);

        return ms.ToArray();
    }

    private static List<IPAddress> ParseDnsResponse(ReadOnlySpan<byte> response, ushort expectedId)
    {
        var ips = new List<IPAddress>();
        if (response.Length < 12) return ips;

        var id = BinaryPrimitives.ReadUInt16BigEndian(response);
        if (id != expectedId) return ips;

        var flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
        if ((flags & 0x000F) != 0) return ips;

        var qdcount = BinaryPrimitives.ReadUInt16BigEndian(response[4..]);
        var ancount = BinaryPrimitives.ReadUInt16BigEndian(response[6..]);

        int pos = 12;
        for (int i = 0; i < qdcount; i++)
        {
            pos = SkipDnsName(response, pos);
            if (pos < 0 || pos + 4 > response.Length) return ips;
            pos += 4;
        }

        for (int i = 0; i < ancount; i++)
        {
            pos = SkipDnsName(response, pos);
            if (pos < 0 || pos + 10 > response.Length) break;

            var type = BinaryPrimitives.ReadUInt16BigEndian(response[pos..]);
            var rdlen = BinaryPrimitives.ReadUInt16BigEndian(response[(pos + 8)..]);
            pos += 10;

            if (pos + rdlen > response.Length) break;

            if (type == 1 && rdlen == 4)
                ips.Add(new IPAddress(response.Slice(pos, 4)));
            else if (type == 28 && rdlen == 16)
                ips.Add(new IPAddress(response.Slice(pos, 16)));

            pos += rdlen;
        }
        return ips;
    }

    private static int SkipDnsName(ReadOnlySpan<byte> data, int pos)
    {
        while (pos < data.Length)
        {
            var len = data[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 2 > data.Length) return -1;
                return pos + 2;
            }
            pos += 1 + len;
        }
        return -1;
    }

    // ---------- DNS 缓存 + 单飞 ----------
    private static async Task<IPAddress[]> CachedLookupAsync(string host, CancellationToken ct)
    {
        if (DnsCache.TryGetValue(host, out var cached))
        {
            if (cached.IsErr)
            {
                if (DateTime.UtcNow - cached.Ts < DnsNegativeTtl)
                    throw new InvalidOperationException($"cached DNS error for {host}");
                DnsCache.TryRemove(host, out _);
            }
            else if (DateTime.UtcNow - cached.Ts < DnsCacheTtl)
            {
                LogCache($"hit {host} -> {string.Join(",", cached.Addrs)}");
                return cached.Addrs.Select(IPAddress.Parse).ToArray();
            }
        }

        var gate = DnsSingleflight.GetOrAdd(host, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            if (DnsCache.TryGetValue(host, out cached) && !cached.IsErr &&
                DateTime.UtcNow - cached.Ts < DnsCacheTtl)
            {
                LogCache($"hit (singleflight) {host} -> {string.Join(",", cached.Addrs)}");
                return cached.Addrs.Select(IPAddress.Parse).ToArray();
            }

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            linked.CancelAfter(DnsTimeout);
            var ips = await LookupIpWithHostsAsync(host, linked.Token);
            if (ips.Length == 0)
            {
                DnsCache[host] = new DnsCacheEntry(Array.Empty<string>(), DateTime.UtcNow, true);
                throw new InvalidOperationException($"DNS lookup failed for {host}");
            }

            var addrs = ips.Select(ip => ip.ToString()).ToArray();
            DnsCache[host] = new DnsCacheEntry(addrs, DateTime.UtcNow, false);
            return ips;
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<Stream> ConnectWithDnsAsync(
        string host, int port, bool ipv4Only, bool ipv6Only, CancellationToken ct)
    {
        var ips = await CachedLookupAsync(host, ct);
        var target = ips.FirstOrDefault(ip =>
            ipv4Only ? ip.AddressFamily == AddressFamily.InterNetwork :
            ipv6Only ? ip.AddressFamily == AddressFamily.InterNetworkV6 :
            true);

        if (target is null)
            throw new InvalidOperationException($"no suitable IP address for {host}");

        LogDns($"连接 {target}:{port} (from {host})");
        var socket = new Socket(target.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(target, port)).WaitAsync(ct);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    // ==================================================================
    //  HTTP 客户端
    // ==================================================================
    private static void WarmTransport()
    {
        lock (HttpWarmLock)
        {
            if (_httpWarmed) return;
            _httpWarmed = true;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                using var handler = CreateHandler(false, false);
                using var client = new HttpClient(handler) { Timeout = DefaultTimeout };
                using var req = new HttpRequestMessage(HttpMethod.Head, "https://1.1.1.1");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var resp = await client.SendAsync(req, cts.Token);
                LogHttp("预热完成");
            }
            catch (Exception ex) { LogWarn($"HTTP 预热失败: {ex.Message}"); }
        });
    }

    private static SocketsHttpHandler CreateHandler(bool ipv4Only, bool ipv6Only)
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = DefaultTimeout,
            AutomaticDecompression = DecompressionMethods.All,
            MaxConnectionsPerServer = 200,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };

        handler.SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, _, _, _) => InsecureSkip,
        };

        handler.ConnectCallback = async (context, ct) =>
        {
            var host = context.DnsEndPoint.Host;
            var port = context.DnsEndPoint.Port;

            if (host.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase))
            {
                if (UseSam) return await GetSamConnectionAsync(host, port, ct);
                if (Socks5Proxy is not null) return await Socks5ConnectAsync(Socks5Proxy, host, port, ct);
            }

            if (Socks5Proxy is not null)
                return await Socks5ConnectAsync(Socks5Proxy, host, port, ct);

            return await ConnectWithDnsAsync(host, port, ipv4Only, ipv6Only, ct);
        };

        return handler;
    }

    private static HttpClient GetHttpClient(bool ipv4Only, bool ipv6Only)
    {
        WarmTransport();
        var key = $"v4:{ipv4Only}_v6:{ipv6Only}";
        return HttpClientCache.GetOrAdd(key, _ =>
        {
            var handler = CreateHandler(ipv4Only, ipv6Only);
            return new HttpClient(handler, disposeHandler: true) { Timeout = DefaultTimeout };
        });
    }

    // ==================================================================
    //  SOCKS5
    // ==================================================================
    private static async Task<Stream> Socks5ConnectAsync(
        Socks5Options proxy, string destHost, int destPort, CancellationToken ct)
    {
        LogSocks($"连接 {proxy.Host}:{proxy.Port} → {destHost}:{destPort}");
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new DnsEndPoint(proxy.Host, proxy.Port)).WaitAsync(ct);
            var stream = new NetworkStream(socket, ownsSocket: true);

            byte[] hello = string.IsNullOrEmpty(proxy.Username)
                ? new byte[] { 0x05, 0x01, 0x00 }
                : new byte[] { 0x05, 0x02, 0x00, 0x02 };
            await stream.WriteAsync(hello, ct);
            var reply = new byte[2];
            await stream.ReadExactlyAsync(reply, ct);
            if (reply[0] != 0x05) throw new IOException("invalid SOCKS version");

            if (reply[1] == 0x02)
            {
                if (string.IsNullOrEmpty(proxy.Username))
                    throw new IOException("SOCKS requires auth but no credentials");
                var user = Encoding.UTF8.GetBytes(proxy.Username);
                var pass = Encoding.UTF8.GetBytes(proxy.Password ?? "");
                var auth = new byte[3 + user.Length + pass.Length];
                auth[0] = 0x01;
                auth[1] = (byte)user.Length;
                user.CopyTo(auth.AsSpan(2));
                auth[2 + user.Length] = (byte)pass.Length;
                pass.CopyTo(auth.AsSpan(3 + user.Length));
                await stream.WriteAsync(auth, ct);
                var authReply = new byte[2];
                await stream.ReadExactlyAsync(authReply, ct);
                if (authReply[1] != 0x00) throw new IOException("SOCKS auth failed");
            }
            else if (reply[1] != 0x00) throw new IOException($"SOCKS auth method not supported: {reply[1]}");

            var hostBytes = Encoding.UTF8.GetBytes(destHost);
            var req = new byte[4 + 1 + hostBytes.Length + 2];
            req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
            req[4] = (byte)hostBytes.Length;
            hostBytes.CopyTo(req.AsSpan(5));
            BinaryPrimitives.WriteUInt16BigEndian(req.AsSpan(5 + hostBytes.Length), (ushort)destPort);
            await stream.WriteAsync(req, ct);

            var resp = new byte[4];
            await stream.ReadExactlyAsync(resp, ct);
            if (resp[0] != 0x05 || resp[1] != 0x00) throw new IOException($"SOCKS connect failed: {resp[1]}");

            int addrLen = resp[3] switch
            {
                0x01 => 4,
                0x04 => 16,
                0x03 => await ReadByteAsync(stream, ct),
                _ => 0,
            };
            if (addrLen == 0) throw new IOException("invalid SOCKS atyp");
            var bind = new byte[addrLen + 2];
            await stream.ReadExactlyAsync(bind, ct);

            LogSocks($"✓ {destHost}:{destPort} 已建立");
            return stream;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task<int> ReadByteAsync(Stream stream, CancellationToken ct)
    {
        var b = new byte[1];
        await stream.ReadExactlyAsync(b, ct);
        return b[0];
    }

    // ==================================================================
    //  SAM (I2P)
    // ==================================================================
    private static async Task<Stream> GetSamConnectionAsync(string host, int port, CancellationToken ct)
    {
        if (SamConnCache.TryGetValue(host, out var cached))
        {
            LogSam($"复用 {host}");
            return cached.Stream;
        }

        var gate = SamGroups.GetOrAdd(host, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(ct);
        try
        {
            if (SamConnCache.TryGetValue(host, out cached))
            {
                LogSam($"复用(单飞) {host}");
                return cached.Stream;
            }

            LogSam($"新建 {host}:{port} via {SamHost}");
            var client = new TcpClient { NoDelay = true };
            await client.ConnectAsync(SamHost).WaitAsync(ct);
            var raw = client.GetStream();
            var reader = new BufferedStream(raw);

            await SamHelloAsync(reader, raw, ct);
            var sessionId = $"tracker-{RandomInt(0, 1 << 30)}";
            await SamCreateSessionAsync(reader, raw, sessionId, ct);
            await SamStreamConnectAsync(reader, raw, sessionId, host, port, ct);

            var pooled = new SamPooledConn
            {
                Client = client, Stream = raw, Reader = reader, Host = host,
            };
            SamConnCache[host] = pooled;
            LogSam($"✓ {host}:{port} 已建立");
            return raw;
        }
        finally { gate.Release(); }
    }

    private static async Task<string> ReadSamLineAsync(BufferedStream reader, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new byte[1];
        while (true)
        {
            await reader.ReadExactlyAsync(buf, ct);
            if (buf[0] == (byte)'\n') break;
            if (buf[0] != (byte)'\r') sb.Append((char)buf[0]);
        }
        return sb.ToString();
    }

    private static async Task SamHelloAsync(BufferedStream reader, Stream raw, CancellationToken ct)
    {
        await raw.WriteAsync(Encoding.ASCII.GetBytes("HELLO VERSION MIN=3.0 MAX=3.0\n"), ct);
        await raw.FlushAsync(ct);
        var line = await ReadSamLineAsync(reader, ct);
        if (!line.StartsWith("HELLO REPLY", StringComparison.Ordinal))
            throw new IOException($"bad SAM hello reply: {line}");
    }

    private static async Task SamCreateSessionAsync(
        BufferedStream reader, Stream raw, string sessionId, CancellationToken ct)
    {
        var cmd = $"SESSION CREATE STYLE=STREAM ID={sessionId} DESTINATION=TRANSIENT\n";
        await raw.WriteAsync(Encoding.ASCII.GetBytes(cmd), ct);
        await raw.FlushAsync(ct);
        var line = await ReadSamLineAsync(reader, ct);
        if (!line.Contains("RESULT=OK", StringComparison.Ordinal))
            throw new IOException($"SAM session create failed: {line}");
    }

    private static async Task SamStreamConnectAsync(
        BufferedStream reader, Stream raw, string sessionId, string dest, int port, CancellationToken ct)
    {
        var cmd = $"STREAM CONNECT ID={sessionId} DESTINATION={dest} PORT={port}\n";
        await raw.WriteAsync(Encoding.ASCII.GetBytes(cmd), ct);
        await raw.FlushAsync(ct);
        var line = await ReadSamLineAsync(reader, ct);
        if (!line.Contains("RESULT=OK", StringComparison.Ordinal))
            throw new IOException($"SAM stream connect failed: {line}");
    }

    // ==================================================================
    //  HTTP 检查
    // ==================================================================
    private static async Task<(bool Alive, long? Ping, bool HasIpv6Peers, string? Error)> CheckHttpAttemptAsync(
        string trackerUrl, string infoHash, bool compact, bool ipv4Only, bool ipv6Only, string? hostPort,
        CancellationToken ct)
    {
        if (!Uri.TryCreate(trackerUrl, UriKind.Absolute, out var baseUri))
            return (false, null, false, "invalid url");

        var builder = new UriBuilder(baseUri);
        if (!string.IsNullOrEmpty(hostPort))
        {
            var parts = hostPort.Split(':');
            if (parts.Length == 2) { builder.Host = parts[0]; builder.Port = int.Parse(parts[1]); }
            else builder.Host = hostPort;
        }

        var query = HttpUtility.ParseQueryString(baseUri.Query);
        var raw = InfoHashBytes(infoHash);
        query["info_hash"] = raw is null ? "00000000000000000000" : Encoding.Latin1.GetString(raw);
        query["peer_id"] = PeerIdPrefix;
        query["port"] = "6881";
        query["uploaded"] = "0";
        query["downloaded"] = "0";
        query["left"] = "0";
        query["compact"] = compact ? "1" : "0";
        query["event"] = "started";
        builder.Query = query.ToString();

        var family = ipv4Only ? "v4" : ipv6Only ? "v6" : "any";
        LogHttp($"{family} GET {builder.Uri}");

        using var req = new HttpRequestMessage(HttpMethod.Get, builder.Uri);
        req.Headers.UserAgent.ParseAdd(RandomUa());

        var client = GetHttpClient(ipv4Only, ipv6Only);
        var sw = Stopwatch.StartNew();
        HttpResponseMessage resp;
        try
        {
            resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        }
        catch (Exception ex)
        {
            LogHttp($"✗ {family} {trackerUrl}: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        using (resp)
        {
            sw.Stop();
            var ping = sw.ElapsedMilliseconds;

            if (resp.StatusCode == HttpStatusCode.TooManyRequests)
            {
                LogHttp($"429 {trackerUrl}");
                if (resp.Headers.RetryAfter?.Delta is { } delta && delta > TimeSpan.Zero)
                {
                    try { await Task.Delay(delta, ct); } catch (OperationCanceledException) { }
                }
                return (false, ping, false, "rate limited");
            }

            byte[] body;
            try
            {
                await using var stream = await resp.Content.ReadAsStreamAsync(ct);
                using var ms = new MemoryStream();
                var buf = new byte[81920];
                int total = 0, n;
                while ((n = await stream.ReadAsync(buf, ct)) > 0)
                {
                    total += n;
                    if (total > 100 * 1024) break;
                    ms.Write(buf, 0, n);
                }
                body = ms.ToArray();
            }
            catch (Exception ex)
            {
                LogHttp($"✗ {family} {trackerUrl} read: {ex.Message}");
                return (false, ping, false, ex.Message);
            }

            if (IsHtml(body) || IsParkedDomain(body))
            {
                LogHttp($"✗ {family} {trackerUrl}: html/parked");
                return (false, ping, false, "html or parked");
            }

            if (BdecodeSimple(body))
            {
                foreach (var p in ExtractCompactPeers(body)) StorePeer(p);
                var has6 = ResponseHasIpv6Peers(body);
                if (has6) foreach (var p in ExtractCompact6Peers(body)) StorePeer(p);
                LogHttp($"✓ {family} {trackerUrl} {ping}ms{(has6 ? " +v6peers" : "")}");
                return (true, ping, has6, null);
            }

            if (resp.StatusCode == HttpStatusCode.OK && body.Length > 50000)
            {
                LogHttp($"✗ {family} {trackerUrl}: body too large ({body.Length})");
                return (false, ping, false, "too large");
            }

            LogHttp($"✗ {family} {trackerUrl}: invalid response (status={resp.StatusCode}, len={body.Length})");
            return (false, ping, false, "invalid response");
        }
    }

    private static async Task<(bool Alive, long? Ping, bool HasIpv6Peers, string? Error)> CheckHttpWithFamilyAsync(
        string trackerUrl, string infoHash, bool compact, bool ipv4Only, bool ipv6Only, CancellationToken ct)
    {
        if (RateLimiter is not null)
        {
            using var lease = await RateLimiter.AcquireAsync(1, ct);
            if (!lease.IsAcquired) return (false, null, false, "rate limited");
        }

        var u = new Uri(trackerUrl);
        var scheme = u.Scheme.ToLowerInvariant();
        var host = u.Host;
        var originalPort = u.IsDefaultPort ? null : u.Port.ToString();
        var isI2P = host.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase);

        var ports = new List<string?>();
        if (!string.IsNullOrEmpty(originalPort)) ports.Add(originalPort);
        if (scheme == "http") ports.Add("80");
        else if (scheme == "https") ports.Add("443");
        if (isI2P) { ports.Add("80"); ports.Add("443"); }
        ports.Add(null);

        var seen = new HashSet<string>();
        foreach (var port in ports)
        {
            string? hostPort;
            if (port is not null) hostPort = $"{host}:{port}";
            else if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
                hostPort = $"[{host}]";
            else hostPort = host;

            if (!seen.Add(hostPort ?? host)) continue;
            var (alive, ping, has6, _) = await CheckHttpAttemptAsync(
                trackerUrl, infoHash, compact, ipv4Only, ipv6Only, hostPort, ct);
            if (alive) return (true, ping, has6, null);
        }

        return (false, null, false, "all ports failed");
    }

    public static async Task<(string Status, long? Ping, bool? V4, bool? V6)> CheckHttpAsync(
        string trackerUrl, string infoHash, bool useCompact0, CancellationToken ct)
    {
        var compact = !useCompact0;
        var (alive4, ping4, has6InResp4, _) = await CheckHttpWithFamilyAsync(
            trackerUrl, infoHash, compact, true, false, ct);
        var has4 = alive4;
        long? bestPing = has4 ? ping4 : null;
        var has6 = has4 && has6InResp4;

        if (!has6)
        {
            var (alive6, ping6, _, _) = await CheckHttpWithFamilyAsync(
                trackerUrl, infoHash, compact, false, true, ct);
            if (alive6)
            {
                has6 = true;
                if (bestPing is null || ping6 < bestPing) bestPing = ping6;
            }
        }

        return (has4, has6) switch
        {
            (true, true) => (StatusAlive, bestPing, true, true),
            (true, false) => (StatusAlive, bestPing, true, null),
            (false, true) => (StatusAlive, bestPing, null, true),
            _ => (StatusDead, null, null, null),
        };
    }

    // ==================================================================
    //  HTTP 响应辅助
    // ==================================================================
    private static bool IsHtml(ReadOnlySpan<byte> data)
    {
        var limit = Math.Min(data.Length, 200);
        var head = Encoding.UTF8.GetString(data[..limit]).ToLowerInvariant();
        return head.Contains("<html") || head.Contains("<!doctype") ||
               head.Contains("<body") || head.Contains("<head");
    }

    private static bool IsParkedDomain(ReadOnlySpan<byte> content)
    {
        var lower = Encoding.UTF8.GetString(content).ToLowerInvariant();
        string[] indicators =
        {
            "domain for sale", "domain is for sale", "buy this domain",
            "domain expired", "domain has expired", "this domain is expired",
            "register this domain", "domain available", "parked domain",
            "domain parking", "coming soon", "under construction",
            "page not found", "404 not found", "namecheap",
            "godaddy parked", "sedo domain parking", "domain portfolio",
            "premium domain", "afternic", "escrow.com", "dan.com/buy-domain",
            "undeveloped", "this webpage was generated by the domain owner",
            "hugedomains.com", "bodis.com", "sedoparking",
        };
        return indicators.Any(ind => lower.Contains(ind));
    }

    private static bool BdecodeSimple(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0 || data[0] != (byte)'d') return false;
        var s = Encoding.Latin1.GetString(data);
        return s.Contains("interval") || s.Contains("peers") || s.Contains("failure reason");
    }

    private static List<string> ExtractCompactPeers(ReadOnlySpan<byte> data)
    {
        var result = new List<string>();
        var idx = data.IndexOf("5:peers"u8);
        if (idx < 0) return result;
        var rest = data[(idx + 7)..];
        if (!TryReadBencodeLength(rest, out var length, out var consumed)) return result;
        if (length % 6 != 0 || length == 0 || consumed + length > rest.Length) return result;

        var peerBytes = rest.Slice(consumed, length);
        for (int j = 0; j < length; j += 6)
        {
            var ip = $"{peerBytes[j]}.{peerBytes[j + 1]}.{peerBytes[j + 2]}.{peerBytes[j + 3]}";
            var port = BinaryPrimitives.ReadUInt16BigEndian(peerBytes[(j + 4)..]);
            result.Add($"{ip}:{port}");
        }
        return result;
    }

    private static List<string> ExtractCompact6Peers(ReadOnlySpan<byte> data)
    {
        var result = new List<string>();
        var idx = data.IndexOf("6:peers6"u8);
        if (idx < 0) return result;
        var rest = data[(idx + 8)..];
        if (!TryReadBencodeLength(rest, out var length, out var consumed)) return result;
        if (length % 18 != 0 || length == 0 || consumed + length > rest.Length) return result;

        var peerBytes = rest.Slice(consumed, length);
        for (int j = 0; j < length; j += 18)
        {
            var ip = new IPAddress(peerBytes.Slice(j, 16));
            var port = BinaryPrimitives.ReadUInt16BigEndian(peerBytes[(j + 16)..]);
            result.Add($"[{ip}]:{port}");
        }
        return result;
    }

    private static bool ResponseHasIpv6Peers(ReadOnlySpan<byte> data)
    {
        var idx = data.IndexOf("6:peers6"u8);
        if (idx < 0) return false;
        var rest = data[(idx + 8)..];
        if (!TryReadBencodeLength(rest, out var length, out var consumed)) return false;
        return length % 18 == 0 && length > 0 && consumed + length <= rest.Length;
    }

    private static bool TryReadBencodeLength(ReadOnlySpan<byte> span, out int length, out int consumed)
    {
        length = 0; consumed = 0;
        var colon = span.IndexOf((byte)':');
        if (colon <= 0) return false;
        if (!int.TryParse(Encoding.ASCII.GetString(span[..colon]), out length)) return false;
        consumed = colon + 1;
        return true;
    }

    private static void StorePeer(string peer)
    {
        if (Volatile.Read(ref _peersCollectorCnt) >= MaxPeersCollector) return;
        if (PeersCollector.TryAdd(peer, 0))
            Interlocked.Increment(ref _peersCollectorCnt);
    }

    // ==================================================================
    //  UDP 检查
    // ==================================================================
    private static async Task<(bool Alive, long? Ping, bool HasIpv6Peers, string? Error)> CheckUdpAttemptAsync(
        string trackerUrl, string infoHash, bool ipv6Only, string targetPort, CancellationToken ct)
    {
        var u = new Uri(trackerUrl);
        var host = u.Host;
        var port = !string.IsNullOrEmpty(targetPort) ? targetPort :
            u.IsDefaultPort ? "6969" : u.Port.ToString();

        IPAddress[] ips;
        try
        {
            if (IPAddress.TryParse(host, out var literal))
                ips = new[] { literal };
            else
                ips = await CachedLookupAsync(host, ct);
        }
        catch (Exception ex)
        {
            LogUdp($"✗ {trackerUrl} DNS: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        var addr = ips.FirstOrDefault(ip =>
            ipv6Only ? ip.AddressFamily == AddressFamily.InterNetworkV6 :
            ip.AddressFamily == AddressFamily.InterNetwork);
        if (addr is null)
        {
            LogUdp($"✗ {trackerUrl} 无合适 IP（{string.Join(",", ips.Select(i => i.ToString()))}）");
            return (false, null, false, "no suitable IP");
        }

        using var udp = new UdpClient(addr.AddressFamily);
        try { udp.Connect(addr, int.Parse(port)); }
        catch (Exception ex)
        {
            LogUdp($"✗ {trackerUrl} connect: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        LogUdp($"{(ipv6Only ? "v6" : "v4")} {trackerUrl} -> {addr}:{port}");
        var start = Stopwatch.StartNew();

        const ulong protocolId = 0x41727101980;
        var transConnect = (uint)Random.Shared.NextInt64(0, uint.MaxValue);
        var connReq = new byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(connReq, protocolId);
        BinaryPrimitives.WriteUInt32BigEndian(connReq.AsSpan(8), 0);
        BinaryPrimitives.WriteUInt32BigEndian(connReq.AsSpan(12), transConnect);

        try { await udp.SendAsync(connReq, ct); }
        catch (Exception ex)
        {
            LogUdp($"✗ {trackerUrl} send connect: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        UdpReceiveResult connResp;
        try
        {
            using var recvCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            recvCts.CancelAfter(DefaultTimeout);
            connResp = await udp.ReceiveAsync(recvCts.Token);
        }
        catch (Exception ex)
        {
            LogUdp($"✗ {trackerUrl} connect timeout: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        if (connResp.Buffer.Length < 16)
        {
            LogUdp($"✗ {trackerUrl} connect response too short");
            return (false, null, false, "connect response too short");
        }
        var connSpan = connResp.Buffer.AsSpan();
        var action = BinaryPrimitives.ReadUInt32BigEndian(connSpan);
        var trans = BinaryPrimitives.ReadUInt32BigEndian(connSpan[4..]);
        if (action != 0 || trans != transConnect)
        {
            LogUdp($"✗ {trackerUrl} connect action mismatch");
            return (false, null, false, "connect transaction mismatch");
        }
        var connectionId = BinaryPrimitives.ReadUInt64BigEndian(connSpan[8..]);

        var ih = InfoHashBytes(infoHash) ?? RandomNumberGenerator.GetBytes(20);
        var transAnnounce = (uint)Random.Shared.NextInt64(0, uint.MaxValue);
        var annReq = new byte[98];
        BinaryPrimitives.WriteUInt64BigEndian(annReq, connectionId);
        BinaryPrimitives.WriteUInt32BigEndian(annReq.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt32BigEndian(annReq.AsSpan(12), transAnnounce);
        ih.CopyTo(annReq, 16);
        Encoding.ASCII.GetBytes(PeerIdPrefix).CopyTo(annReq, 36);
        BinaryPrimitives.WriteUInt32BigEndian(annReq.AsSpan(80), 2);
        BinaryPrimitives.WriteUInt32BigEndian(annReq.AsSpan(84), 0);
        BinaryPrimitives.WriteUInt32BigEndian(annReq.AsSpan(88), 0);
        BinaryPrimitives.WriteUInt32BigEndian(annReq.AsSpan(92), uint.MaxValue);
        BinaryPrimitives.WriteUInt16BigEndian(annReq.AsSpan(96), 6881);

        try { await udp.SendAsync(annReq, ct); }
        catch (Exception ex)
        {
            LogUdp($"✗ {trackerUrl} send announce: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        UdpReceiveResult annResp;
        try
        {
            using var recvCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            recvCts.CancelAfter(DefaultTimeout);
            annResp = await udp.ReceiveAsync(recvCts.Token);
        }
        catch (Exception ex)
        {
            LogUdp($"✗ {trackerUrl} announce timeout: {ex.Message}");
            return (false, null, false, ex.Message);
        }

        start.Stop();
        var ping = start.ElapsedMilliseconds;

        var respSpan = annResp.Buffer.AsSpan();
        if (respSpan.Length < 20)
        {
            LogUdp($"✗ {trackerUrl} announce response too short");
            return (false, ping, false, "announce response too short");
        }
        var act = BinaryPrimitives.ReadUInt32BigEndian(respSpan);
        var tr = BinaryPrimitives.ReadUInt32BigEndian(respSpan[4..]);
        if (!((act == 1 && tr == transAnnounce) || act == 3))
        {
            LogUdp($"✗ {trackerUrl} announce action invalid (act={act}, tr={tr})");
            return (false, ping, false, "invalid announce action");
        }

        var has6 = ResponseHasIpv6Peers(respSpan);
        if (has6) foreach (var p in ExtractCompact6Peers(respSpan)) StorePeer(p);
        foreach (var p in ExtractCompactPeers(respSpan)) StorePeer(p);

        LogUdp($"✓ {trackerUrl} {ping}ms{(has6 ? " +v6peers" : "")}");
        return (true, ping, has6, null);
    }

    private static async Task<(bool Alive, long? Ping, bool HasIpv6Peers, string? Error)> CheckUdpWithFamilyAsync(
        string trackerUrl, string infoHash, bool ipv6Only, CancellationToken ct)
    {
        if (RateLimiter is not null)
        {
            using var lease = await RateLimiter.AcquireAsync(1, ct);
            if (!lease.IsAcquired) return (false, null, false, "rate limited");
        }

        var u = new Uri(trackerUrl);
        var originalPort = u.IsDefaultPort ? null : u.Port.ToString();
        var ports = new List<string?>();
        if (!string.IsNullOrEmpty(originalPort)) ports.Add(originalPort);
        ports.Add("6969");
        ports.Add("1337");
        if (!string.IsNullOrEmpty(originalPort) && originalPort != "6969" && originalPort != "1337")
            ports.Add(originalPort);

        var seen = new HashSet<string>();
        foreach (var port in ports)
        {
            if (port is null || !seen.Add(port)) continue;
            var (alive, ping, has6, _) = await CheckUdpAttemptAsync(trackerUrl, infoHash, ipv6Only, port, ct);
            if (alive) return (true, ping, has6, null);
        }
        return (false, null, false, "all UDP ports failed");
    }

    public static async Task<(string Status, long? Ping, bool? V4, bool? V6)> CheckUdpAsync(
        string trackerUrl, string infoHash, CancellationToken ct)
    {
        var (alive4, ping4, has6InResp4, _) = await CheckUdpWithFamilyAsync(trackerUrl, infoHash, false, ct);
        var has4 = alive4;
        long? bestPing = has4 ? ping4 : null;
        var has6 = has4 && has6InResp4;

        if (!has6)
        {
            var (alive6, ping6, _, _) = await CheckUdpWithFamilyAsync(trackerUrl, infoHash, true, ct);
            if (alive6)
            {
                has6 = true;
                if (bestPing is null || ping6 < bestPing) bestPing = ping6;
            }
        }

        return (has4, has6) switch
        {
            (true, true) => (StatusAlive, bestPing, true, true),
            (true, false) => (StatusAlive, bestPing, true, null),
            (false, true) => (StatusAlive, bestPing, null, true),
            _ => (StatusDead, null, null, null),
        };
    }

    // ==================================================================
    //  WSS 检查
    // ==================================================================
    private static async Task<(bool Alive, long? Ping, string? Error)> CheckWssWithFamilyAsync(
        string trackerUrl, bool ipv4Only, bool ipv6Only, CancellationToken ct)
    {
        if (RateLimiter is not null)
        {
            using var lease = await RateLimiter.AcquireAsync(1, ct);
            if (!lease.IsAcquired) return (false, null, "rate limited");
        }

        var family = ipv4Only ? "v4" : ipv6Only ? "v6" : "any";
        var uri = new Uri(trackerUrl);
        using var ws = new ClientWebSocket();
        ws.Options.SetRequestHeader("User-Agent", "qBittorrent/4.6.0");
        ws.Options.AddSubProtocol("binary");
        if (InsecureSkip)
            ws.Options.RemoteCertificateValidationCallback = (_, _, _, _) => true;

        HttpMessageInvoker? invoker = null;
        if (Socks5Proxy is not null || (uri.Host.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase) && UseSam))
        {
            var handler = CreateHandler(ipv4Only, ipv6Only);
            invoker = new HttpMessageInvoker(handler, disposeHandler: true);
        }

        LogWss($"{family} {trackerUrl}");
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(DefaultTimeout);
            if (invoker is not null) await ws.ConnectAsync(uri, invoker, cts.Token);
            else await ws.ConnectAsync(uri, cts.Token);
            sw.Stop();
            LogWss($"✓ {family} {trackerUrl} {sw.ElapsedMilliseconds}ms");
            return (true, sw.ElapsedMilliseconds, null);
        }
        catch (Exception ex)
        {
            LogWss($"✗ {family} {trackerUrl}: {ex.Message}");
            return (false, null, ex.Message);
        }
        finally { invoker?.Dispose(); }
    }

    public static async Task<(string Status, long? Ping, bool? V4, bool? V6)> CheckWssAsync(
        string trackerUrl, CancellationToken ct)
    {
        var (alive4, ping4, _) = await CheckWssWithFamilyAsync(trackerUrl, true, false, ct);
        var has4 = alive4;
        long? bestPing = has4 ? ping4 : null;

        var (alive6, ping6, _) = await CheckWssWithFamilyAsync(trackerUrl, false, true, ct);
        var has6 = alive6;
        if (has6 && (bestPing is null || ping6 < bestPing)) bestPing = ping6;

        return (has4, has6) switch
        {
            (true, true) => (StatusAlive, bestPing, true, true),
            (true, false) => (StatusAlive, bestPing, true, null),
            (false, true) => (StatusAlive, bestPing, null, true),
            _ => (StatusDead, null, null, null),
        };
    }

    // ==================================================================
    //  统一入口
    // ==================================================================
    public static async Task<CheckResult> ValidateTrackerAsync(string trackerUrl, int maxAttempts, CancellationToken ct)
    {
        CheckResult last = new(trackerUrl, StatusInvalid, null, null, null);
        for (int attempt = 0; attempt < maxAttempts; attempt++)
        {
            if (!Uri.TryCreate(trackerUrl, UriKind.Absolute, out var u))
            {
                LogResult(trackerUrl, StatusInvalid, null, null, null);
                return new CheckResult(trackerUrl, StatusInvalid, null, null, null);
            }

            var scheme = u.Scheme.ToLowerInvariant();
            var infoHash = NextInfoHash();
            string status;
            long? ping = null;
            bool? v4 = null, v6 = null;

            try
            {
                switch (scheme)
                {
                    case "http" or "https":
                        (status, ping, v4, v6) = await CheckHttpAsync(trackerUrl, infoHash, Compact0Fallback, ct);
                        break;
                    case "udp":
                        (status, ping, v4, v6) = await CheckUdpAsync(trackerUrl, infoHash, ct);
                        break;
                    case "ws" or "wss":
                        (status, ping, v4, v6) = await CheckWssAsync(trackerUrl, ct);
                        break;
                    default:
                        status = StatusInvalid;
                        break;
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                LogErr($"{trackerUrl}: {ex.Message}");
                status = StatusDead;
            }

            last = new CheckResult(trackerUrl, status, ping, v4, v6);
            if (status != StatusDead)
            {
                LogResult(trackerUrl, status, ping, v4, v6);
                return last;
            }

            if (attempt < maxAttempts - 1)
            {
                LogWarn($"重试 {attempt + 1}/{maxAttempts - 1}: {trackerUrl}");
                try { await Task.Delay(500 + RandomInt(0, 1001), ct); }
                catch (OperationCanceledException)
                {
                    LogResult(trackerUrl, last.Status, last.PingMs, last.SupportsIPv4, last.SupportsIPv6);
                    return last;
                }
            }
        }

        LogResult(trackerUrl, last.Status, last.PingMs, last.SupportsIPv4, last.SupportsIPv6);
        return last;
    }

    // ==================================================================
    //  tracker 列表加载
    // ==================================================================
    public static async Task<List<string>> LoadAllTrackersFromInputAsync(string inputFile)
    {
        var text = await File.ReadAllTextAsync(inputFile);
        text = text.Replace(',', '\n');

        var result = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        using var reader = new StringReader(text);
        int lineNo = 0;
        while (await reader.ReadLineAsync() is { } line)
        {
            lineNo++;
            var parsed = ParseTrackerLine(line);
            if (string.IsNullOrWhiteSpace(parsed) || parsed.StartsWith('#')) continue;

            foreach (Match m in TrackerRe.Matches(parsed))
            {
                var (norm, err) = NormalizeTrackerUrl(m.Value);
                if (norm is not null && seen.Add(norm))
                    result.Add(norm);
                else if (err is not null)
                    LogWarn($"line {lineNo}: {m.Value} → {err}");
            }
        }
        LogInput($"读取完成: {inputFile}（{result.Count} 个唯一 tracker，共 {lineNo} 行）");
        return result;
    }

    public static string GetProtocolFromUrl(string raw)
    {
        if (raw.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase)) return "i2p";
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u)) return "unknown";
        var scheme = u.Scheme.ToLowerInvariant();
        return scheme is "ws" or "wss" ? "ws" : scheme;
    }

    // ==================================================================
    //  并发调度
    // ==================================================================
    public static async Task PreResolveDnsAsync(List<string> trackers)
    {
        if (trackers.Count == 0) return;

        LogDns($"预解析 {trackers.Count} 个 host");

        using var sem = new SemaphoreSlim(200);
        var tasks = new List<Task>(trackers.Count);

        foreach (var rawUrl in trackers)
        {
            await sem.WaitAsync();
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    if (!Uri.TryCreate(rawUrl, UriKind.Absolute, out var u)) return;
                    var host = u.Host;
                    if (string.IsNullOrEmpty(host)) return;
                    if (host.EndsWith(".i2p", StringComparison.OrdinalIgnoreCase))
                    {
                        LogDns($"{host} 是 i2p，跳过预解析");
                        return;
                    }
                    if (GetDns(host, out _)) return;

                    // 预解析给更宽裕的超时（30s），避免批量解析大量 host 时批量失败
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                    try { await CachedLookupAsync(host, cts.Token); }
                    catch (Exception ex) { LogWarn($"预解析 {host} 失败: {ex.Message}"); }
                }
                finally { sem.Release(); }
            }));
        }
        await Task.WhenAll(tasks);
        LogDns($"预解析完成（{trackers.Count} 个 host）");
    }

    public static async Task<List<CheckResult>> RunChecksAsync(
        List<string> trackers, int workers, int retries, CancellationToken ct)
    {
        if (trackers.Count == 0) return new List<CheckResult>();

        LogBoot($"启动检查池: {trackers.Count} tracker, {workers} worker");

        var resultChannel = Channel.CreateUnbounded<CheckResult>(
            new UnboundedChannelOptions { SingleReader = true });
        var taskChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(workers * 2)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleWriter = true,
        });

        var workerTasks = new Task[workers];
        for (int i = 0; i < workers; i++)
        {
            workerTasks[i] = Task.Run(async () =>
            {
                await foreach (var url in taskChannel.Reader.ReadAllAsync(ct))
                {
                    if (ct.IsCancellationRequested) break;
                    var res = await ValidateTrackerAsync(url, retries + 1, ct);
                    await resultChannel.Writer.WriteAsync(res, ct);
                }
            }, ct);
        }

        _ = Task.Run(async () =>
        {
            try
            {
                foreach (var url in trackers)
                    await taskChannel.Writer.WriteAsync(url, ct);
            }
            catch (OperationCanceledException) { }
            finally { taskChannel.Writer.TryComplete(); }
        }, ct);

        try { await Task.WhenAll(workerTasks); }
        catch (OperationCanceledException) { }
        finally { resultChannel.Writer.TryComplete(); }

        var results = new List<CheckResult>();
        await foreach (var r in resultChannel.Reader.ReadAllAsync(CancellationToken.None))
            results.Add(r);
        return results;
    }

    // ==================================================================
    //  历史记录
    // ==================================================================
    private static async Task<Dictionary<string, TrackerHistory>> LoadHistoryAsync(string path)
    {
        var hist = new Dictionary<string, TrackerHistory>(StringComparer.OrdinalIgnoreCase);
        if (!File.Exists(path)) return hist;

        foreach (var line in await File.ReadAllLinesAsync(path))
        {
            var parts = line.Split('\t');
            if (parts.Length < 7) continue;

            var h = new TrackerHistory();
            ulong.TryParse(parts[1], out h.Checks);
            ulong.TryParse(parts[2], out h.AliveChecks);
            long.TryParse(parts[3], out h.FirstSeenTs);
            long.TryParse(parts[4], out h.FirstAliveTs);
            long.TryParse(parts[5], out h.LastSeenTs);
            long.TryParse(parts[6], out h.LastAliveTs);
            if (parts.Length >= 8) long.TryParse(parts[7], out h.StreakAliveStartTs);
            else if (h.LastSeenTs != 0 && h.LastSeenTs == h.LastAliveTs) h.StreakAliveStartTs = h.LastSeenTs;

            hist[parts[0]] = h;
        }
        return hist;
    }

    private static async Task SaveHistoryAsync(string path, Dictionary<string, TrackerHistory> hist)
    {
        await using var writer = new StreamWriter(path);
        foreach (var kv in hist.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            var h = kv.Value;
            await writer.WriteLineAsync($"{kv.Key}\t{h.Checks}\t{h.AliveChecks}\t{h.FirstSeenTs}\t{h.FirstAliveTs}\t{h.LastSeenTs}\t{h.LastAliveTs}\t{h.StreakAliveStartTs}");
        }
    }

    private static void UpdateHistory(
        Dictionary<string, TrackerHistory> hist, Dictionary<string, TrackerEntry> results, long nowTs)
    {
        foreach (var (url, entry) in results)
        {
            if (!hist.TryGetValue(url, out var h))
            {
                h = new TrackerHistory();
                hist[url] = h;
            }

            var lastWasAlive = h.LastSeenTs != 0 && h.LastSeenTs == h.LastAliveTs;
            h.Checks++;
            if (h.FirstSeenTs == 0) h.FirstSeenTs = nowTs;
            h.LastSeenTs = nowTs;

            if (entry.Status == StatusAlive)
            {
                if (!lastWasAlive || h.StreakAliveStartTs == 0) h.StreakAliveStartTs = nowTs;
                h.AliveChecks++;
                if (h.FirstAliveTs == 0) h.FirstAliveTs = nowTs;
                h.LastAliveTs = nowTs;
            }
            else h.StreakAliveStartTs = 0;
        }
    }

    // ==================================================================
    //  合并输出
    // ==================================================================
    public static async Task MergeAndOutputAsync(
        List<string> allTrackers,
        List<CheckResult> httpResults,
        List<CheckResult> udpWssResults,
        string outputDir)
    {
        LogMerge($"合并 {httpResults.Count} HTTP 结果 + {udpWssResults.Count} UDP/WSS 结果 → {allTrackers.Count} tracker");

        var allEntries = new Dictionary<string, TrackerEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in httpResults.Concat(udpWssResults))
        {
            allEntries[r.Url] = new TrackerEntry(
                r.Url, r.Status, GetProtocolFromUrl(r.Url), r.PingMs, r.SupportsIPv4, r.SupportsIPv6);
        }

        var finalEntries = new List<TrackerEntry>(allTrackers.Count);
        var aliveList = new List<string>();
        var aliveHttp = new List<string>();
        var aliveHttps = new List<string>();
        var aliveUdp = new List<string>();
        var aliveWss = new List<string>();
        var aliveI2P = new List<string>();
        var aliveV4Only = new List<string>();
        var aliveV6Only = new List<string>();
        var aliveDual = new List<string>();

        int totalAlive = 0, totalDead = 0, totalInvalid = 0;
        long sumPing = 0, countPing = 0;
        long minPing = -1, maxPing = 0;

        foreach (var url in allTrackers)
        {
            if (!allEntries.TryGetValue(url, out var entry))
                entry = new TrackerEntry(url, StatusInvalid, GetProtocolFromUrl(url), null, null, null);

            finalEntries.Add(entry);

            switch (entry.Status)
            {
                case StatusAlive:
                    aliveList.Add(url);
                    totalAlive++;

                    switch (entry.Protocol)
                    {
                        case "http": aliveHttp.Add(url); break;
                        case "https": aliveHttps.Add(url); break;
                        case "udp": aliveUdp.Add(url); break;
                        case "ws" or "wss": aliveWss.Add(url); break;
                        case "i2p": aliveI2P.Add(url); break;
                    }

                    if (entry.SupportsIPv4 == true && entry.SupportsIPv6 == true) aliveDual.Add(url);
                    else if (entry.SupportsIPv4 == true) aliveV4Only.Add(url);
                    else if (entry.SupportsIPv6 == true) aliveV6Only.Add(url);

                    if (entry.PingMs is { } p)
                    {
                        sumPing += p;
                        countPing++;
                        if (minPing == -1) minPing = p;
                        else minPing = Math.Min(minPing, p);
                        maxPing = Math.Max(maxPing, p);
                    }
                    break;

                case StatusDead: totalDead++; break;
                default: totalInvalid++; break;
            }
        }

        aliveList.Sort(StringComparer.Ordinal);
        Directory.CreateDirectory(outputDir);

        var txtFiles = new Dictionary<string, List<string>>
        {
            ["trackers_best.txt"] = aliveList,
            ["trackers_best_http.txt"] = SortUnique(aliveHttp),
            ["trackers_best_https.txt"] = SortUnique(aliveHttps),
            ["trackers_best_udp.txt"] = SortUnique(aliveUdp),
            ["trackers_best_ws.txt"] = SortUnique(aliveWss),
            ["trackers_best_i2p.txt"] = SortUnique(aliveI2P),
            ["trackers_alive_ipv4only.txt"] = SortUnique(aliveV4Only),
            ["trackers_alive_ipv6only.txt"] = SortUnique(aliveV6Only),
            ["trackers_alive_dualstack.txt"] = SortUnique(aliveDual),
        };

        foreach (var (name, lines) in txtFiles)
        {
            await File.WriteAllLinesAsync(Path.Combine(outputDir, name), lines);
            LogMerge($"写入 {name} ({lines.Count} 条)");
        }

        var protocols = new ProtocolStats();
        foreach (var u in aliveList)
        {
            switch (GetProtocolFromUrl(u))
            {
                case "http": protocols.Http++; break;
                case "https": protocols.Https++; break;
                case "udp": protocols.Udp++; break;
                case "ws" or "wss": protocols.Wss++; break;
                case "i2p": protocols.I2P++; break;
            }
        }

        var total = allTrackers.Count;
        if (total > 0)
        {
            protocols.HttpPct = protocols.Http * 100.0 / total;
            protocols.HttpsPct = protocols.Https * 100.0 / total;
            protocols.UdpPct = protocols.Udp * 100.0 / total;
            protocols.WssPct = protocols.Wss * 100.0 / total;
        }

        var historyPath = Path.Combine(outputDir, "tracker_history.tsv");
        var history = await LoadHistoryAsync(historyPath);
        var nowTs = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        UpdateHistory(history, allEntries, nowTs);
        await SaveHistoryAsync(historyPath, history);
        LogMerge($"历史记录已更新（{history.Count} 条）");

        var avgPing = countPing > 0 ? (double)sumPing / countPing : 0;
        if (minPing == -1) minPing = 0;

        var data = new FrontendData
        {
            Total = total,
            AliveCount = totalAlive,
            DeadCount = totalDead,
            InvalidCount = totalInvalid,
            UptimePct = total > 0 ? totalAlive * 100.0 / total : 0,
            Protocols = protocols,
            Trackers = finalEntries,
            AvgPingMs = avgPing,
            MinPingMs = minPing,
            MaxPingMs = maxPing,
        };

        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(data, JsonOpts);
        await File.WriteAllBytesAsync(Path.Combine(outputDir, "trackers.json"), jsonBytes);
        LogMerge($"写入 trackers.json ({jsonBytes.Length} 字节)");

        LogMerge($"{Green}ALIVE {totalAlive}{Reset} / {Red}DEAD {totalDead}{Reset} / {Yellow}INVALID {totalInvalid}{Reset} (total {total})");
        LogMerge($"协议分布: HTTP={protocols.Http} HTTPS={protocols.Https} UDP={protocols.Udp} WSS={protocols.Wss} I2P={protocols.I2P}");
        if (countPing > 0)
            LogMerge($"延迟: avg={avgPing:F1}ms min={minPing}ms max={maxPing}ms ({countPing} 个样本)");
        LogMerge($"✅ 合并完成，数据已写入 {outputDir}");
    }

    private static List<string> SortUnique(List<string> items)
    {
        if (items.Count == 0) return items;
        items.Sort(StringComparer.Ordinal);
        var result = new List<string>(items.Count) { items[0] };
        for (int i = 1; i < items.Count; i++)
            if (!string.Equals(items[i], items[i - 1], StringComparison.Ordinal))
                result.Add(items[i]);
        return result;
    }
}