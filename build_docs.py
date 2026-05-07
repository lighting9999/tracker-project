#!/usr/bin/env python3
import argparse, time, json
from collections import defaultdict
from pathlib import Path
from typing import List, Dict
from dataclasses import dataclass

PAGE_SIZE = 100
LOCALE = {
    "en": {
        "title": "Tracker Status Dashboard",
        "stats_summary": "Stats Summary",
        "total_checked": "Total Checked",
        "online": "Available",
        "dead": "Unavailable",
        "invalid": "Invalid",
        "global_uptime": "Global Uptime",
        "protocols": "Protocols",
        "downloads": "Downloads",
        "all_trackers": "All trackers (incl. dead/invalid)",
        "all_alive": "All available",
        "http": "HTTP", "https": "HTTPS", "udp": "UDP", "wss": "WSS",
        "detailed_status": "Tracker Details",
        "status": "Status", "url": "URL", "uptime": "Uptime",
        "days": "Days", "page": "Page",
        "available": "Available", "unavailable": "Unavailable",
        "back_to_top": "Back to top"
    },
    "zh": {
        "title": "Tracker 状态仪表盘",
        "stats_summary": "统计摘要",
        "total_checked": "总检测数",
        "online": "可用", "dead": "不可用", "invalid": "无效",
        "global_uptime": "全局在线率",
        "protocols": "协议", "downloads": "下载",
        "all_trackers": "全部 tracker（含失效/无效）",
        "all_alive": "所有可用",
        "http": "HTTP", "https": "HTTPS", "udp": "UDP", "wss": "WSS",
        "detailed_status": "Tracker 详情",
        "status": "状态", "url": "URL", "uptime": "在线率",
        "days": "连续天数", "page": "页码",
        "available": "可用", "unavailable": "不可用",
        "back_to_top": "回到顶部"
    }
}

class Status:
    ALIVE = "ALIVE"
    DEAD = "DEAD"
    INVALID = "INVALID"

@dataclass
class TrackerHistory:
    checks: int = 0
    alive_checks: int = 0
    first_seen_ts: int = 0
    first_alive_ts: int = 0
    last_seen_ts: int = 0
    last_alive_ts: int = 0
    streak_alive_start_ts: int = 0

def get_protocol(url: str) -> str:
    from urllib.parse import urlparse
    try: return urlparse(url).scheme
    except: return "other"

def read_lines(path: Path) -> List[str]:
    if not path.is_file(): return []
    return [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def load_history(path: Path) -> Dict[str, TrackerHistory]:
    hist = {}
    if not path.is_file(): return hist
    for line in path.read_text().splitlines():
        parts = line.strip().split("\t")
        if len(parts) not in (7,8): continue
        try:
            url = parts[0]; vals = list(map(int, parts[1:]))
            streak = vals[6] if len(vals)==7 and vals[4]!=0 and vals[4]==vals[5] else vals[7] if len(vals)==8 else 0
            hist[url] = TrackerHistory(checks=vals[0], alive_checks=vals[1],
                                       first_seen_ts=vals[2], first_alive_ts=vals[3],
                                       last_seen_ts=vals[4], last_alive_ts=vals[5],
                                       streak_alive_start_ts=streak)
        except: continue
    return hist

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trackers-all", default="trackers_all.txt")
    parser.add_argument("--trackers-best", default="trackers_best.txt")
    parser.add_argument("--history", default="tracker_history.tsv")
    parser.add_argument("--output-dir", default="hugo/data")
    args = parser.parse_args()

    all_urls = read_lines(Path(args.trackers_all))
    best_urls = set(read_lines(Path(args.trackers_best)))
    status_map = {}
    for u in all_urls:
        if u in best_urls: status_map[u] = Status.ALIVE
        else: status_map[u] = Status.DEAD

    history = load_history(Path(args.history))
    now_ts = int(time.time())

    data = {
        "locales": LOCALE,
        "total": len(all_urls),
        "alive_count": sum(1 for u in all_urls if status_map[u] == Status.ALIVE),
        "dead_count": sum(1 for u in all_urls if status_map[u] == Status.DEAD),
        "invalid_count": sum(1 for u in all_urls if status_map[u] == Status.INVALID),
        "uptime_pct": round((sum(1 for u in all_urls if status_map[u] == Status.ALIVE) * 100 / len(all_urls)), 2) if all_urls else 0,
        "protocols": {
            "http": sum(1 for u in all_urls if status_map[u] == Status.ALIVE and get_protocol(u) == "http"),
            "https": sum(1 for u in all_urls if status_map[u] == Status.ALIVE and get_protocol(u) == "https"),
            "udp": sum(1 for u in all_urls if status_map[u] == Status.ALIVE and get_protocol(u) == "udp"),
            "wss": sum(1 for u in all_urls if status_map[u] == Status.ALIVE and get_protocol(u) == "wss"),
        },
        "trackers": []
    }

    for url in all_urls:
        status = status_map[url]
        hist = history.get(url, TrackerHistory())
        uptime_val = (hist.alive_checks * 100 / hist.checks) if hist.checks else 0.0
        days = 0
        if status == Status.ALIVE and hist.streak_alive_start_ts:
            days = (now_ts - hist.streak_alive_start_ts) // 86400 + 1
        data["trackers"].append({
            "url": url,
            "status": status,
            "uptime": round(uptime_val, 2),
            "days": days,
            "protocol": get_protocol(url)
        })

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "trackers.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"✅ Data written to {output_dir / 'trackers.json'}")

if __name__ == "__main__":
    main()