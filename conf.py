# conf.py
project = 'Tracker Status Dashboard'
copyright = '2026, Auto Generated'
author = 'TrackerBot'
language = 'en'

extensions = [
    'sphinx_rtd_dark_mode',   # 自动暗色模式
    'sphinx_design',          # 提供 grid/card 指令
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'

html_static_path = []

# 将 tracker 下载文件复制到站点根目录，供直接下载
html_extra_path = [
    'trackers_all.txt',
    'trackers_best.txt',
    'trackers_best_http.txt',
    'trackers_best_https.txt',
    'trackers_best_udp.txt',
    'trackers_best_wss.txt',
]

html_theme_options = {
    'navigation_depth': 3,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
    'display_version': False,
}

# 多语言支持（当前 RST 已分目录，无需额外插件）
locale_dirs = ['locale/']
gettext_compact = False