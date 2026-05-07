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

def build_html_page(locale: dict, results: List[str], status_map: Dict[str, str],
                    history: Dict[str, TrackerHistory], now_ts: int,
                    page_num: int, total_pages: int, lang: str) -> str:
    alive_count = sum(1 for u in results if status_map.get(u) == Status.ALIVE)
    dead_count = sum(1 for u in results if status_map.get(u) == Status.DEAD)
    invalid_count = len(results) - alive_count - dead_count
    uptime_pct = (alive_count * 100 / len(results)) if results else 0
    proto_counts = defaultdict(int)
    for u in results:
        if status_map.get(u) == Status.ALIVE:
            p = get_protocol(u)
            if p in ("http","https","udp","wss"): proto_counts[p] += 1

    cards = ""
    for url in results:
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
        cards += f'''<div class="card {card_class}">
  <div class="card-header">{status_text}</div>
  <div class="card-body">
    <p><strong>{locale["url"]}:</strong> <a href="{url}" target="_blank" style="color: inherit;">{url}</a></p>
    <p><strong>{locale["uptime"]}:</strong> {uptime_val:.2f}%</p>
    <p><strong>{locale["days"]}:</strong> {days}</p>
  </div>
</div>'''

    pagination = ""
    if total_pages > 1:
        links = []
        for p in range(1, total_pages+1):
            if p == page_num: links.append(f'<span class="current">{p}</span>')
            else:
                if p == 1: href = "index.html"
                else: href = f"page_{p}.html"
                links.append(f'<a href="{href}">{p}</a>')
        pagination = f'<div class="pagination">{locale["page"]}: {" | ".join(links)}</div>'

    back_top = f'<a href="#top" class="back-to-top">🔝 {locale["back_to_top"]}</a>'

    return f'''<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{locale["title"]} ({locale["page"]} {page_num}/{total_pages})</title>
<style>
  :root {{
    --bg: #ffffff; --text: #212529; --link: #0d6efd;
    --card-success: #198754; --card-danger: #dc3545; --card-warning: #ffc107;
    --border: #dee2e6;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #212529; --text: #f8f9fa; --link: #6ea8fe;
      --border: #495057;
    }}
  }}
  body {{ font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 1rem; }}
  a {{ color: var(--link); text-decoration: none; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  h1 {{ margin-bottom: 1rem; }}
  .stats {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }}
  .stat-card {{ background: var(--border); padding: 0.5rem 1rem; border-radius: 8px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 1rem; }}
  .card {{ border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  .card-header {{ padding: 0.5rem 1rem; font-weight: bold; }}
  .card-body {{ padding: 0.5rem 1rem; }}
  .bg-success {{ background-color: var(--card-success); }}
  .bg-danger {{ background-color: var(--card-danger); }}
  .bg-warning {{ background-color: var(--card-warning); color: #212529 !important; }}
  .pagination {{ margin: 1.5rem 0; text-align: center; }}
  .pagination a, .pagination span {{ margin: 0 0.3rem; }}
  .current {{ font-weight: bold; }}
  .back-to-top {{ display: block; text-align: center; margin-top: 2rem; }}
  .lang-switch {{ display: flex; justify-content: flex-end; gap: 0.5rem; margin-bottom: 1rem; }}
</style>
</head>
<body id="top">
<div class="container">
  <div class="lang-switch">
    <span>{locale["page"]}: <a href="../en/index.html">English</a> | <a href="../zh/index.html">中文</a></span>
  </div>
  <h1>{locale["title"]} ({locale["page"]} {page_num}/{total_pages})</h1>
  <div class="stats">
    <div class="stat-card"><strong>{locale["total_checked"]}:</strong> {len(results)}</div>
    <div class="stat-card"><strong>{locale["online"]}:</strong> {alive_count}</div>
    <div class="stat-card"><strong>{locale["dead"]}:</strong> {dead_count}</div>
    <div class="stat-card"><strong>{locale["invalid"]}:</strong> {invalid_count}</div>
    <div class="stat-card"><strong>{locale["global_uptime"]}:</strong> {uptime_pct:.2f}%</div>
  </div>
  <div class="stats">
    <div class="stat-card"><strong>{locale["protocols"]}:</strong> HTTP: {proto_counts["http"]} | HTTPS: {proto_counts["https"]} | UDP: {proto_counts["udp"]} | WSS: {proto_counts["wss"]}</div>
  </div>
  <div class="stats">
    <div class="stat-card">
      <strong>{locale["downloads"]}:</strong>
      <a href="../trackers_all.txt">{locale["all_trackers"]}</a> ·
      <a href="../trackers_best.txt">{locale["all_alive"]}</a> ·
      <a href="../trackers_best_http.txt">{locale["http"]}</a> ·
      <a href="../trackers_best_https.txt">{locale["https"]}</a> ·
      <a href="../trackers_best_udp.txt">{locale["udp"]}</a> ·
      <a href="../trackers_best_wss.txt">{locale["wss"]}</a>
    </div>
  </div>
  <h2>{locale["detailed_status"]}</h2>
  <div class="grid">
    {cards}
  </div>
  {pagination}
  {back_top}
</div>
</body>
</html>'''

def generate_site(all_urls: List[str], status_map: Dict[str, str],
                  history: Dict[str, TrackerHistory], lang: str,
                  page_size: int, output_dir: Path):
    locale = LOCALE.get(lang, LOCALE["en"])
    lang_dir = output_dir / lang
    lang_dir.mkdir(parents=True, exist_ok=True)
    now_ts = int(time.time())
    pages = [all_urls[i:i+page_size] for i in range(0, len(all_urls), page_size)]
    total_pages = len(pages)

    for idx, page in enumerate(pages, 1):
        html = build_html_page(locale, page, status_map, history, now_ts, idx, total_pages, lang)
        fname = "index.html" if idx == 1 else f"page_{idx}.html"
        (lang_dir / fname).write_text(html, encoding="utf-8")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trackers-all", default="trackers_all.txt")
    parser.add_argument("--trackers-best", default="trackers_best.txt")
    parser.add_argument("--history", default="tracker_history.tsv")
    parser.add_argument("--output-dir", default="public")
    parser.add_argument("--page-size", type=int, default=PAGE_SIZE)
    parser.add_argument("--lang", choices=["en","zh"], nargs="+", default=["en","zh"])
    args = parser.parse_args()

    all_urls = read_lines(Path(args.trackers_all))
    best_urls = set(read_lines(Path(args.trackers_best)))
    status_map = {}
    for u in all_urls:
        if u in best_urls: status_map[u] = Status.ALIVE
        else: status_map[u] = Status.DEAD

    history = load_history(Path(args.history))
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for lang in args.lang:
        generate_site(all_urls, status_map, history, lang, args.page_size, output_dir)

    # 根目录 index.html ：自动语言跳转
    redirect_html = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tracker Status</title>
<script>
  (function() {
    var lang = (navigator.language || navigator.userLanguage).substr(0,2);
    if (lang === 'zh') {
      window.location.href = 'zh/index.html';
    } else {
      window.location.href = 'en/index.html';
    }
  })();
</script>
</head>
<body>
  <noscript>
    <p>Please choose your language / 请选择语言：</p>
    <ul>
      <li><a href="en/index.html">English</a></li>
      <li><a href="zh/index.html">中文</a></li>
    </ul>
  </noscript>
</body>
</html>"""
    (output_dir / "index.html").write_text(redirect_html, encoding="utf-8")

    # 复制 tracker 文件到 public/ 根目录
    for f in ["trackers_all.txt", "trackers_best.txt", "trackers_best_http.txt",
              "trackers_best_https.txt", "trackers_best_udp.txt", "trackers_best_wss.txt"]:
        src = Path(f)
        if src.is_file():
            import shutil
            shutil.copy2(src, output_dir / f)

if __name__ == "__main__":
    main()