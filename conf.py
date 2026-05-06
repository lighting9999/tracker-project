# conf.py
project = 'Tracker Status Dashboard'
copyright = '2026, Auto Generated'
author = 'TrackerBot'
language = 'en'

extensions = [
    'sphinx_design',          # 可选，增强 UI 组件（可移除，不影响基本功能）
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# 使用内置 Alabaster 主题（简洁轻量）
html_theme = 'alabaster'

# 若你想使用默认的 Classic 主题，可替换为：
# html_theme = 'classic'

html_static_path = ['static']

# 将 tracker 下载文件复制到站点根目录，保持直接下载
html_extra_path = [
    'trackers_all.txt',
    'trackers_best.txt',
    'trackers_best_http.txt',
    'trackers_best_https.txt',
    'trackers_best_udp.txt',
    'trackers_best_wss.txt',
]

# Alabaster 主题简单配置
html_theme_options = {
    'description': 'BitTorrent Tracker Live Status',
    'github_user': 'lighting9999',
    'github_repo': 'tracker-project',
    'fixed_sidebar': True,
    'page_width': '1080px',
    'sidebar_width': '220px',
}

# 多语言支持（保留，虽然当前 RST 已分目录，但可配合 sphinx-intl）
locale_dirs = ['locale/']
gettext_compact = False