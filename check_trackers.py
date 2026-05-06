#!/usr/bin/env python3
import argparse, asyncio, random, re, socket, sys, time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, ParseResult, urlunparse
import aiohttp

TIMEOUT = 10
DEFAULT_WORKERS = 50

class Status:
    ALIVE = "ALIVE"
    DEAD = "DEAD"
    INVALID = "INVALID"

@dataclass
class CheckResult:
    url: str
    status: str
    ping_ms: Optional[int] = None

@dataclass
class TrackerHistory:
    checks: int = 0
    alive_checks: int = 0
    first_seen_ts: int = 0
    first_alive_ts: int = 0
    last_seen_ts: int = 0
    last_alive_ts: int = 0
    streak_alive_start_ts: int = 0

TRACKER_RE = re.compile(r"(?i)(https?|udp|wss)://[^\s,]*?/announce")

def parse_tracker_line(line: str) -> str:
    line = line.strip()
    if line.startswith("[") and "](" in line and line.endswith(")"):
        _, _, right = line.partition("](")
        return right[:-1]
    return line

def collapse_path_slashes(path: str) -> str:
    out = []; prev = False
    for ch in path:
        if ch == "/":
            if not prev: out.append(ch)
            prev = True
        else: out.append(ch); prev = False
    s = "".join(out)
    return s if s else "/"

def normalize_tracker_url(raw: str) -> Optional[str]:
    candidate = raw.strip().strip("\"'<>[](){};,.")
    try: parsed = urlparse(candidate)
    except: return None
    scheme = parsed.scheme.lower()
    if scheme not in ("http","https","udp","wss"): return None
    host = parsed.hostname
    if not host: return None
    try: socket.inet_aton(host); is_ip = True
    except OSError: is_ip = False
    if not is_ip and "." not in host: return None
    path = collapse_path_slashes(parsed.path)
    if not path.endswith("/announce"): return None
    new = ParseResult(scheme=scheme, netloc=parsed.netloc, path=path, params="", query="", fragment="")
    if (scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443):
        new = new._replace(netloc=host)
    return urlunparse(new)

def bdecode_simple(data: bytes) -> bool:
    return data.startswith(b"d") and any(k in data for k in (b"interval",b"peers",b"failure reason"))

def is_parked(content: bytes) -> bool:
    text = content.decode("utf-8", errors="replace").lower()
    triggers = ["domain for sale","domain is for sale","buy this domain","domain expired",
                "parked domain","domain parking","page not found","404 not found",
                "namecheap","godaddy parked","sedo domain parking"]
    if any(t in text for t in triggers): return True
    head = content[:500].decode("utf-8", errors="replace").lower()
    return "<html" in head or "<!doctype html" in head

def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set(); out = []
    for i in items:
        if i not in seen: seen.add(i); out.append(i)
    return out

def sort_unique(items: List[str]) -> List[str]:
    return sorted(set(items))

def get_protocol(url: str) -> str:
    try: return urlparse(url).scheme
    except: return "other"

def write_lines(path: Path, lines: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

_http_peer_static = "".join(str(random.randint(0,9)) for _ in range(12))

async def check_http(session: aiohttp.ClientSession, url: str, timeout: int) -> Tuple[str, Optional[int]]:
    params = {"info_hash":"00000000000000000000","peer_id":f"-RS0001-{_http_peer_static}",
              "port":"6881","uploaded":"0","downloaded":"0","left":"0","compact":"1","event":"started"}
    try:
        start = time.time()
        async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=timeout),
                                allow_redirects=False) as resp:
            body = await resp.read()
            elapsed = int((time.time()-start)*1000)
            if is_parked(body): return Status.INVALID, elapsed
            if bdecode_simple(body): return Status.ALIVE, elapsed
            if resp.status == 200:
                head = body[:200].decode("utf-8", errors="replace").lower()
                if any(t in head for t in ("<html","<body","<head")): return Status.INVALID, elapsed
                if len(body) > 50000: return Status.INVALID, elapsed
                return Status.DEAD, elapsed
            if resp.status in (400,403) and bdecode_simple(body): return Status.ALIVE, elapsed
            return Status.DEAD, elapsed
    except Exception:
        return Status.DEAD, None

class UDPClientProtocol:
    def __init__(self, on_response): self.transport = None; self.on_response = on_response
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr): self.on_response(data)
    def error_received(self, exc): self.on_response(None)
    def connection_lost(self, exc): pass

async def check_udp(url: str, timeout: int) -> Tuple[str, Optional[int]]:
    try:
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port or 80
    except: return Status.INVALID, None
    if not host: return Status.INVALID, None
    conn_id = 0x41727101980
    trans_id = random.randint(0,0xFFFFFFFF)
    packet = conn_id.to_bytes(8,"big") + (0).to_bytes(4,"big") + trans_id.to_bytes(4,"big")
    loop = asyncio.get_event_loop()
    resp_future = loop.create_future()
    def on_response(data):
        if not resp_future.done(): resp_future.set_result(data)
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPClientProtocol(on_response),
            remote_addr=(host, port), family=socket.AF_INET)
        start = time.time()
        transport.sendto(packet)
        data = await asyncio.wait_for(resp_future, timeout=timeout)
        elapsed = int((time.time()-start)*1000)
        return (Status.ALIVE, elapsed) if data and len(data)>=8 else (Status.DEAD, None)
    except Exception:
        return Status.DEAD, None
    finally:
        try: transport.close()
        except: pass

async def check_wss(url: str, timeout: int) -> Tuple[str, Optional[int]]:
    try:
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port or 443
    except: return Status.INVALID, None
    if not host: return Status.INVALID, None
    try:
        start = time.time()
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(url, timeout=aiohttp.ClientTimeout(total=timeout)):
                elapsed = int((time.time()-start)*1000)
                return Status.ALIVE, elapsed
    except Exception:
        return Status.DEAD, None

async def validate_tracker(session: aiohttp.ClientSession, url: str, timeout: int) -> CheckResult:
    try: parsed = urlparse(url)
    except: return CheckResult(url, Status.INVALID)
    scheme = parsed.scheme.lower()
    if scheme in ("http","https"): status, ping = await check_http(session, url, timeout)
    elif scheme == "udp": status, ping = await check_udp(url, timeout)
    elif scheme == "wss": status, ping = await check_wss(url, timeout)
    else: status, ping = Status.INVALID, None
    return CheckResult(url, status, ping)

def load_trackers(filepath: str) -> List[str]:
    text = Path(filepath).read_text(encoding="utf-8")
    text = text.replace(",","\n")
    trackers = []
    for line in text.splitlines():
        parsed = parse_tracker_line(line)
        if not parsed or parsed.startswith("#"): continue
        for m in TRACKER_RE.finditer(parsed):
            norm = normalize_tracker_url(m.group())
            if norm: trackers.append(norm)
    return dedupe_keep_order(trackers)

def filter_blacklist(trackers: List[str], bl_file: str = "blackstr.txt") -> List[str]:
    if not Path(bl_file).is_file(): return trackers
    patterns = [l.strip() for l in Path(bl_file).read_text().splitlines() if l.strip() and not l.startswith("#")]
    return [t for t in trackers if not any(p in t for p in patterns)]

def load_history(path: Path) -> Dict[str, TrackerHistory]:
    hist = {}
    if not path.is_file(): return hist
    for line in path.read_text().splitlines():
        parts = line.strip().split("\t")
        if len(parts) not in (7,8): continue
        try:
            url = parts[0]; vals = list(map(int, parts[1:]))
            streak = vals[6] if len(vals)==7 and vals[4]!=0 and vals[4]==vals[5] else vals[7] if len(vals)==8 else 0
            hist[url] = TrackerHistory(checks=vals[0], alive_checks=vals[1], first_seen_ts=vals[2],
                                       first_alive_ts=vals[3], last_seen_ts=vals[4], last_alive_ts=vals[5],
                                       streak_alive_start_ts=streak)
        except: continue
    return hist

def save_history(path: Path, hist: Dict[str, TrackerHistory]) -> None:
    lines = []
    for url in sorted(hist):
        h = hist[url]
        lines.append(f"{url}\t{h.checks}\t{h.alive_checks}\t{h.first_seen_ts}\t{h.first_alive_ts}\t{h.last_seen_ts}\t{h.last_alive_ts}\t{h.streak_alive_start_ts}")
    path.write_text("\n".join(lines)+"\n", encoding="utf-8")

def update_history(hist: Dict[str, TrackerHistory], results: List[CheckResult], now_ts: int) -> None:
    for r in results:
        entry = hist.setdefault(r.url, TrackerHistory())
        was_alive_last = entry.last_seen_ts != 0 and entry.last_seen_ts == entry.last_alive_ts
        entry.checks += 1
        if entry.first_seen_ts == 0: entry.first_seen_ts = now_ts
        entry.last_seen_ts = now_ts
        if r.status == Status.ALIVE:
            if not was_alive_last or entry.streak_alive_start_ts == 0: entry.streak_alive_start_ts = now_ts
            entry.alive_checks += 1
            if entry.first_alive_ts == 0: entry.first_alive_ts = now_ts
            entry.last_alive_ts = now_ts
        else: entry.streak_alive_start_ts = 0

async def async_main(args):
    output_dir = Path(args.output).resolve().parent
    trackers = load_trackers(args.input)
    trackers = filter_blacklist(trackers)
    all_trackers = sort_unique(trackers)
    if not all_trackers: sys.exit(1)
    write_lines(output_dir / "trackers_all.txt", all_trackers)
    conn = aiohttp.TCPConnector(limit=args.workers)
    timeout_obj = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout_obj) as session:
        sem = asyncio.Semaphore(args.workers)
        async def bounded_check(url):
            async with sem: return await validate_tracker(session, url, TIMEOUT)
        results = await asyncio.gather(*[bounded_check(url) for url in all_trackers], return_exceptions=True)
    final = [r for r in results if not isinstance(r, Exception)]
    alive = [r for r in final if r.status == Status.ALIVE]
    best_urls = sort_unique([r.url for r in alive])
    write_lines(output_dir / "trackers_best.txt", best_urls)
    for proto in ("http","https","udp","wss"):
        urls = [u for u in best_urls if get_protocol(u) == proto]
        write_lines(output_dir / f"trackers_best_{proto}.txt", sort_unique(urls))
    hist_path = output_dir / "tracker_history.tsv"
    hist = load_history(hist_path)
    now_ts = int(time.time())
    update_history(hist, final, now_ts)
    save_history(hist_path, hist)
    print(f"Checked {len(final)} trackers. Alive: {len(alive)}, Dead: {sum(1 for r in final if r.status==Status.DEAD)}, Invalid: {sum(1 for r in final if r.status==Status.INVALID)}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    args = parser.parse_args()
    asyncio.run(async_main(args))

if __name__ == "__main__":
    main()