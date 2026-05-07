```python
#!/usr/bin/env python3
import argparse, time
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
        "http": "HTTP",
        "https": "HTTPS",
        "udp": "UDP",
        "wss": "WSS",
        "detailed_status": "Tracker Details",
        "status": "Status",
        "url": "URL",
        "uptime": "Uptime",
        "days": "Days",
        "page": "Page",
        "available": "Available",
        "unavailable": "Unavailable"
    },
    "zh": {
        "title": "Tracker 状态仪表盘",
        "stats_summary": "统计摘要",
        "total_checked": "总检测数",
        "online": "可用",
        "dead": "不可用",
        "invalid": "无效",
        "global_uptime": "全局限存活率",
        "protocols": "协议",
        "downloads": "下载",
        "all_trackers": "全部 tracker（含失效/无效）",
        "all_alive": "所有可用",
        "http": "HTTP",
        "https": "HTTPS",
        "udp": "UDP",
        "wss": "WSS",
        "detailed_status": "Tracker 详情",
        "status": "状态",
        "url": "URL",
        "uptime": "在线率",
        "days": "连续在线天数",
        "page": "页码",
        "available": "可用",
        "unavailable": "不可用"
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
    try:
        return urlparse(url).scheme
    except:
        return "other"

def read_lines(path: Path) -> List[str]:
    if not path.is_file():
        return []
    return [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def load_history(path: Path) -> Dict[str, TrackerHistory]:
    hist = {}
    if not path.is_file():
        return hist
    for line in path.read_text().splitlines():
        parts = line.strip().split("\t")
        if len(parts) not in (7, 8):
            continue
        try:
            url = parts[0]
            vals = list(map(int, parts[1:]))
            streak = vals[6] if len(vals) == 7 and vals[4] != 0 and vals[4] == vals[5] else vals[7] if len(vals) == 8 else 0
            hist[url] = TrackerHistory(
                checks=vals[0],
                alive_checks=vals[1],
                first_seen_ts=vals[2],
                first_alive_ts=vals[3],
                last_seen_ts=vals[4],
                last_alive_ts=vals[5],
                streak_alive_start_ts=streak
            )
        except:
            continue
    return hist

def generate_rst_source(results: List[str], status_map: Dict[str, str],
                        history: Dict[str, TrackerHistory], lang: str,
                        page_size: int, output_dir: Path) -> None:
    locale = LOCALE.get(lang, LOCALE["en"])
    lang_dir = output_dir / lang
    lang_dir.mkdir(parents=True, exist_ok=True)

    now_ts = int(time.time())
    total = len(results)
    alive_count = sum(1 for u in results if status_map.get(u) == Status.ALIVE)
    dead_count = sum(1 for u in results if status_map.get(u) == Status.DEAD)
    invalid_count = total - alive_count - dead_count
    uptime_pct = (alive_count * 100 / total) if total else 0.0

    alive_by_proto = defaultdict(int)
    for u in results:
        if status_map.get(u) == Status.ALIVE:
            p = get_protocol(u)
            if p in ("http", "https", "udp", "wss"):
                alive_by_proto[p] += 1

    pages = [results[i:i+page_size] for i in range(0, total, page_size)]
    total_pages = len(pages)

    def page_header(page_num):
        hdr = f"{locale['title']} ({locale['page']} {page_num}/{total_pages})\n"
        hdr += "=" * len(hdr.strip()) + "\n\n"
        hdr += f"{locale['stats_summary']}\n------------------\n\n"
        hdr += f"- {locale['total_checked']}: {total}\n"
        hdr += f"- {locale['online']}: {alive_count}\n"
        hdr += f"- {locale['dead']}: {dead_count}\n"
        hdr += f"- {locale['invalid']}: {invalid_count}\n"
        hdr += f"- {locale['global_uptime']}: {uptime_pct:.2f}%\n\n"
        hdr += f"{locale['protocols']}\n------------\n\n"
        hdr += f"- {locale['http']}: {alive_by_proto['http']}\n"
        hdr += f"- {locale['https']}: {alive_by_proto['https']}\n"
        hdr += f"- {locale['udp']}: {alive_by_proto['udp']}\n"
        hdr += f"- {locale['wss']}: {alive_by_proto['wss']}\n\n"
        hdr += f"{locale['downloads']}\n------------\n\n"
        hdr += f"- `{locale['all_trackers']} <../trackers_all.txt>`_\n"
        hdr += f"- `{locale['all_alive']} <../trackers_best.txt>`_\n"
        hdr += f"- `{locale['http']} <../trackers_best_http.txt>`_ · "
        hdr += f"`{locale['https']} <../trackers_best_https.txt>`_ · "
        hdr += f"`{locale['udp']} <../trackers_best_udp.txt>`_ · "
        hdr += f"`{locale['wss']} <../trackers_best_wss.txt>`_\n\n"
        hdr += f"{locale['detailed_status']}\n{'='*len(locale['detailed_status'])}\n\n"
        return hdr

    for pnum, page in enumerate(pages, 1):
        rst = page_header(pnum)
        rst += ".. grid:: 1 2 3\n   :gutter: 2\n\n"
        for url in page:
            status = status_map.get(url, Status.DEAD)
            hist = history.get(url, TrackerHistory())
            uptime_val = (hist.alive_checks * 100 / hist.checks) if hist.checks else 0.0
            days = 0
            if status == Status.ALIVE and hist.streak_alive_start_ts:
                days = (now_ts - hist.streak_alive_start_ts) // 86400 + 1
            if status == Status.ALIVE:
                card_class = "bg-success text-white"
                status_text = locale["available"]
            elif status == Status.INVALID:
                card_class = "bg-warning text-dark"
                status_text = locale["invalid"]
            else:
                card_class = "bg-danger text-white"
                status_text = locale["unavailable"]
            rst += f"   .. card:: {status_text}\n"
            rst += f"      :class-title: {card_class}\n\n"
            rst += f"      **URL:** `{url} <{url}>`_\n"
            rst += f"      **{locale['uptime']}:** {uptime_val:.2f}%\n"
            rst += f"      **{locale['days']}:** {days}\n\n"
        # pagination links
        if total_pages > 1:
            rst += f"\n{locale['page']}: "
            links = []
            for p in range(1, total_pages+1):
                if p == pnum:
                    links.append(str(p))
                else:
                    links.append(f"`{p} <page_{p}.rst>`_")
            rst += " | ".join(links)
        rst += "\n\n.. raw:: html\n\n   <a href=\"#top\">🔝 Back to top</a>\n"
        (lang_dir / f"page_{pnum}.rst").write_text(rst, encoding="utf-8")

    # language index
    lang_index = f"{locale['title']}\n{'='*len(locale['title'])}\n\n"
    lang_index += f"Go to `{locale['title']} {locale['page']} 1 <page_1.rst>`_\n"
    (lang_dir / "index.rst").write_text(lang_index, encoding="utf-8")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trackers-all", default="trackers_all.txt")
    parser.add_argument("--trackers-best", default="trackers_best.txt")
    parser.add_argument("--history", default="tracker_history.tsv")
    parser.add_argument("--output-dir", default="source")
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE)
    parser.add_argument("--lang", choices=["en","zh"], nargs="+", default=["en","zh"])
    args = parser.parse_args()

    all_urls = read_lines(Path(args.trackers_all))
    best_urls = set(read_lines(Path(args.trackers_best)))
    status_map = {}
    for u in all_urls:
        if u in best_urls:
            status_map[u] = Status.ALIVE
        else:
            status_map[u] = Status.DEAD

    history = load_history(Path(args.history))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for lang in args.lang:
        generate_rst_source(all_urls, status_map, history, lang, args.page_size, output_dir)

    # root index.rst
    root_index = "Tracker Status Dashboard\n======================\n\n"
    root_index += "- `English <en/index.rst>`_\n"
    root_index += "- `中文 <zh/index.rst>`_\n"
    (output_dir / "index.rst").write_text(root_index, encoding="utf-8")

if __name__ == "__main__":
    main()
```