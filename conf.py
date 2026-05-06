# conf.py
project = 'Tracker Status Dashboard'
copyright = '2026, Auto Generated'
author = 'TrackerBot'
language = 'en'

extensions = [
    'sphinx_rtd_dark_mode',    # 可选：自动暗色模式（需 pip 安装）
    'sphinx_design',           # 可选：更好的 UI 组件
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'

html_static_path = ['static']

# 复制 tracker 文件到站点根目录
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
    'logo_only': False,
    'display_version': False,
}

# 多语言支持
locale_dirs = ['locale/']
gettext_compact = False
