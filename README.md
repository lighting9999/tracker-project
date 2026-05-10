# Trackerlist

> Daily updated public BitTorrent tracker collection with automatic validation, self-hosted mirror pages, and multi-client support.

<p align="center">
  <a href="https://github.com/lighting9999/tracker-project/actions/workflows/main.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/lighting9999/tracker-project/main.yml?style=for-the-badge&label=tracker-check" />
  </a>
  <a href="https://github.com/lighting9999/tracker-project/stargazers">
    <img src="https://img.shields.io/github/stars/lighting9999/tracker-project?style=for-the-badge" />
  </a>
  <a href="https://github.com/lighting9999/tracker-project/network/members">
    <img src="https://img.shields.io/github/forks/lighting9999/tracker-project?style=for-the-badge" />
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/github/license/lighting9999/tracker-project?style=for-the-badge" />
  </a>
</p>

---

# What is a Tracker?

BitTorrent downloads rely on peers sharing files with each other.

The more peers you can discover, the better your download performance usually becomes.

Peer discovery mainly comes from three systems:

| System | Description |
|---|---|
| Peer Exchange (PEX) | Shares peer information between connected users |
| DHT | Distributed peer discovery without centralized servers |
| Tracker | Centralized service that helps clients discover peers |

These systems complement each other.

Using DHT + PEX + high-quality trackers together generally produces the best results.

---

# Features

- Daily updated tracker lists
- Automatic tracker validation pipeline
- Multiple tracker categories
- HTTPS / HTTP / UDP tracker support
- Ready-to-use URLs for torrent clients
- GitHub Actions automated deployment
- Static mirror website included
- Lightweight and easy to use

---

# Available Lists

| File | Description |
|---|---|
| `trackers_all.txt` | Full tracker collection |
| `trackers_best.txt` | Best performing trackers |
| `trackers_best_http.txt` | Best HTTP/HTTPS trackers |
| `trackers_best_ip.txt` | Best IP-based trackers |
| `trackers_all_udp.txt` | All UDP trackers |
| `tracker_history.tsv` | Historical tracker records |

---

# Supported Clients

## qBittorrent

1. Open `Tools → Options → BitTorrent`
2. Enable:
   - Automatically add trackers from URLs
3. Paste tracker subscription URL or tracker list
4. Click `Apply`

---

## qBittorrent Enhanced Edition

Enhanced Edition adds:

- Tracker subscription support
- Advanced filtering
- Additional peer management features

Recommended for automatic tracker updates.

---

## BitComet

1. Open:

```text
Tools → Options → Task → BT Download → Tracker
```

2. Enable tracker update options
3. Paste tracker URLs
4. Click `Update Now`

---

## Motrix

1. Open:

```text
Settings → Advanced → Tracker Servers
```

2. Select tracker source
3. Save and apply

---

# Automatic Update System

This repository uses GitHub Actions to:

- Fetch tracker sources
- Validate availability
- Remove dead trackers
- Generate optimized lists
- Deploy updated pages automatically

Workflow file:

```text
.github/workflows/main.yml
```

---

# Website

Static Jekyll pages are included for:

- English pages
- Chinese pages
- Public tracker mirrors

Directory:

```text
/jekyll
```

---

# Repository Structure

```text
tracker-project/
├── trackers_all.txt
├── trackers_best.txt
├── trackers_best_http.txt
├── trackers_best_ip.txt
├── tracker_history.tsv
├── build.go
├── download_sources.txt
├── .github/workflows/
└── jekyll/
```

---

# Technical Notes

The project focuses on:

- Lightweight maintenance
- Automated validation
- Public accessibility
- Multi-client compatibility
- Reliable tracker synchronization

The validation pipeline helps reduce:

- Dead trackers
- Duplicate entries
- Unreachable hosts
- Outdated sources

---

# Why This Project?

Many public tracker lists:

- Become outdated quickly
- Contain dead trackers
- Lack automated validation
- Are difficult to maintain

Trackerlist focuses on:

- Continuous updates
- Clean usable lists
- Automation
- Simplicity

---

# Contributing

Contributions are welcome.

You can help by:

- Reporting invalid trackers
- Submitting tracker sources
- Improving validation logic
- Enhancing documentation

---

# License

MIT License

---

# GitHub Repository

https://github.com/lighting9999/tracker-project
