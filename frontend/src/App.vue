<script setup>
import { ref, computed, onMounted, watch } from 'vue'

// 数据
const allTrackers = ref([])
const meta = ref({})
const loading = ref(true)

// 筛选与排序
const search = ref('')
const statusFilter = ref('all')
const protocolFilter = ref('all')
const ipv6Filter = ref('all')
const pageSize = ref(20)
const currentPage = ref(1)
const sortColumn = ref('url')
const sortOrder = ref('asc')

// 计算过滤后数据
const filteredData = computed(() => {
  let data = allTrackers.value
  if (search.value) {
    const s = search.value.toLowerCase()
    data = data.filter(t => t.url.toLowerCase().includes(s))
  }
  if (statusFilter.value !== 'all') {
    data = data.filter(t => t.status === statusFilter.value)
  }
  if (protocolFilter.value !== 'all') {
    if (protocolFilter.value === 'wss') {
      data = data.filter(t => t.protocol === 'wss' || t.protocol === 'ws')
    } else {
      data = data.filter(t => t.protocol === protocolFilter.value)
    }
  }
  if (ipv6Filter.value === 'yes') {
    data = data.filter(t => t.supports_ipv6)
  } else if (ipv6Filter.value === 'no') {
    data = data.filter(t => !t.supports_ipv6)
  }
  return data
})

// 排序
const sortedData = computed(() => {
  const data = [...filteredData.value]
  const col = sortColumn.value
  const order = sortOrder.value
  data.sort((a, b) => {
    let va = a[col], vb = b[col]
    if (col === 'ping_ms') {
      va = va === null ? Infinity : va
      vb = vb === null ? Infinity : vb
    }
    if (col === 'supports_ipv6') {
      va = va ? 1 : 0
      vb = vb ? 1 : 0
    }
    if (va < vb) return order === 'asc' ? -1 : 1
    if (va > vb) return order === 'asc' ? 1 : -1
    return 0
  })
  return data
})

// 分页
const paginatedData = computed(() => {
  if (pageSize.value === 'all') return sortedData.value
  const start = (currentPage.value - 1) * pageSize.value
  const end = start + pageSize.value
  return sortedData.value.slice(start, end)
})
const totalPages = computed(() => {
  if (pageSize.value === 'all') return 1
  return Math.ceil(sortedData.value.length / pageSize.value)
})

// 统计
const stats = computed(() => {
  const total = allTrackers.value.length
  const alive = allTrackers.value.filter(t => t.status === 'ALIVE').length
  const dead = allTrackers.value.filter(t => t.status === 'DEAD').length
  const invalid = allTrackers.value.filter(t => t.status === 'INVALID').length
  const ipv6Alive = allTrackers.value.filter(t => t.status === 'ALIVE' && t.supports_ipv6).length
  const ipv6Pct = alive > 0 ? (ipv6Alive / alive * 100) : 0
  const protocols = { http:0, https:0, udp:0, wss:0 }
  allTrackers.value.forEach(t => {
    if (t.protocol === 'http') protocols.http++
    else if (t.protocol === 'https') protocols.https++
    else if (t.protocol === 'udp') protocols.udp++
    else if (t.protocol === 'wss' || t.protocol === 'ws') protocols.wss++
  })
  const pTotal = allTrackers.value.length
  return {
    total, alive, dead, invalid,
    ipv6Alive, ipv6Pct,
    protocols,
    httpPct: pTotal > 0 ? (protocols.http / pTotal * 100) : 0,
    httpsPct: pTotal > 0 ? (protocols.https / pTotal * 100) : 0,
    udpPct: pTotal > 0 ? (protocols.udp / pTotal * 100) : 0,
    wssPct: pTotal > 0 ? (protocols.wss / pTotal * 100) : 0,
    uptimePct: meta.value.uptime_pct || 0
  }
})

// 暗色主题
const theme = ref(localStorage.getItem('theme') || 
  (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
watch(theme, (val) => {
  document.documentElement.setAttribute('data-bs-theme', val)
  localStorage.setItem('theme', val)
})
onMounted(() => {
  document.documentElement.setAttribute('data-bs-theme', theme.value)
})

// 数据加载
const fetchData = async () => {
  try {
    const res = await fetch('/trackers.json')
    const json = await res.json()
    // 兼容两种结构：直接是数组 或 包含 meta 和 trackers
    if (json.meta) {
      meta.value = json.meta
      allTrackers.value = json.trackers
    } else if (Array.isArray(json)) {
      allTrackers.value = json
    } else {
      // 尝试直接从对象中提取 trackers
      allTrackers.value = json.trackers || []
      meta.value = json
    }
  } catch (e) {
    console.error('加载数据失败', e)
  } finally {
    loading.value = false
  }
}

// 表格操作
const toggleSort = (col) => {
  if (sortColumn.value === col) {
    sortOrder.value = sortOrder.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortColumn.value = col
    sortOrder.value = 'asc'
  }
}
const goToPage = (page) => {
  if (page >= 1 && page <= totalPages.value) {
    currentPage.value = page
  }
}
const copyUrl = async (url) => {
  try {
    await navigator.clipboard.writeText(url)
    // 简单反馈，可用 alert 或自定义提示
  } catch (e) {}
}

// 重置分页当筛选变化
watch([search, statusFilter, protocolFilter, ipv6Filter], () => {
  currentPage.value = 1
})

// 加载数据
onMounted(fetchData)
</script>

<template>
  <div v-if="!loading">
    <!-- 导航栏 -->
    <nav class="navbar navbar-expand-lg sticky-top bg-body-tertiary border-bottom shadow-sm glass-nav">
      <div class="container">
        <a class="navbar-brand fw-bold text-white" href="/">Tracker List</a>
        <div class="d-flex align-items-center gap-2 ms-auto">
          <a href="/en/" class="text-decoration-none small text-muted">EN</a>
          <a href="/zh/" class="text-decoration-none small text-white fw-semibold">中文</a>
          <button id="themeToggle" class="btn btn-sm btn-outline-light" @click="theme = theme === 'dark' ? 'light' : 'dark'">🌓</button>
        </div>
      </div>
    </nav>

    <!-- Hero -->
    <section class="hero-section">
      <div class="container text-center">
        <h1 class="hero-title">Tracker 列表</h1>
        <div class="uptime-ring-container">
          <svg class="uptime-ring" viewBox="0 0 120 120">
            <circle class="ring-bg" cx="60" cy="60" r="52" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="8"/>
            <circle class="ring-fill" cx="60" cy="60" r="52" fill="none" stroke="url(#gradient)" stroke-width="8" stroke-linecap="round"
                    :stroke-dasharray="326.7256"
                    :stroke-dashoffset="326.7256 - (stats.uptimePct / 100) * 326.7256"
                    transform="rotate(-90 60 60)"/>
            <defs>
              <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stop-color="#22c55e"/>
                <stop offset="100%" stop-color="#60a5fa"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="uptime-value">{{ stats.uptimePct.toFixed(2) }}<span class="uptime-percent">%</span></div>
          <div class="uptime-label">全局可用率</div>
        </div>
      </div>
    </section>

    <!-- 统计卡片 -->
    <div class="container py-4">
      <div class="section-header">
        <h2 class="section-title">摘要</h2>
      </div>
      <div class="stats-grid">
        <div class="stat-card fade-up"><div class="stat-label">检查总数</div><div class="stat-value">{{ stats.total }}</div></div>
        <div class="stat-card fade-up"><div class="stat-label">在线</div><div class="stat-value ok">{{ stats.alive }}</div></div>
        <div class="stat-card fade-up"><div class="stat-label">失效</div><div class="stat-value bad">{{ stats.dead }}</div></div>
        <div class="stat-card fade-up"><div class="stat-label">无效</div><div class="stat-value warn">{{ stats.invalid }}</div></div>
      </div>

      <!-- IPv6 -->
      <div class="row g-3 mb-4">
        <div class="col-md-4">
          <div class="stat-card text-center">
            <div class="stat-label">IPv6 就绪</div>
            <div class="stat-value">{{ stats.ipv6Alive }}</div>
            <div class="small text-muted mt-2">{{ stats.ipv6Pct.toFixed(1) }}% of alive</div>
          </div>
        </div>
        <div class="col-md-8">
          <div class="stat-card">
            <div class="stat-label">IPv6 / IPv4 分布</div>
            <div class="progress mt-2" style="height: 30px;">
              <div class="progress-bar bg-success" role="progressbar" :style="{ width: stats.ipv6Pct + '%' }">
                IPv6 {{ stats.ipv6Pct.toFixed(1) }}%
              </div>
              <div class="progress-bar bg-secondary" role="progressbar" :style="{ width: (100 - stats.ipv6Pct) + '%' }">
                IPv4 {{ (100 - stats.ipv6Pct).toFixed(1) }}%
              </div>
            </div>
            <div class="d-flex justify-content-between mt-2 small">
              <span>✓ IPv6: {{ stats.ipv6Alive }}</span>
              <span>✗ IPv4 only: {{ stats.alive - stats.ipv6Alive }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- 协议 -->
      <div class="section-header mt-5">
        <h2 class="section-title">协议</h2>
      </div>
      <div class="proto-grid">
        <div class="proto-card fade-up"><div class="proto-name http-color">HTTP</div><div class="proto-count">{{ stats.protocols.http }}</div><div class="proto-pct">{{ stats.httpPct.toFixed(1) }}%</div></div>
        <div class="proto-card fade-up"><div class="proto-name https-color">HTTPS</div><div class="proto-count">{{ stats.protocols.https }}</div><div class="proto-pct">{{ stats.httpsPct.toFixed(1) }}%</div></div>
        <div class="proto-card fade-up"><div class="proto-name udp-color">UDP</div><div class="proto-count">{{ stats.protocols.udp }}</div><div class="proto-pct">{{ stats.udpPct.toFixed(1) }}%</div></div>
        <div class="proto-card fade-up"><div class="proto-name wss-color">WSS</div><div class="proto-count">{{ stats.protocols.wss }}</div><div class="proto-pct">{{ stats.wssPct.toFixed(1) }}%</div></div>
      </div>

      <!-- 下载区 -->
      <div class="section-header mt-5">
        <h2 class="section-title">下载</h2>
      </div>
      <div class="downloads-section">
        <div class="downloads-explanation">点击文件名下载对应列表，或复制链接。</div>
        <div class="accordion" id="downloadAccordion">
          <!-- 简单示例，可以动态生成 -->
          <div class="accordion-item">
            <h2 class="accordion-header">
              <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseAll">
                📦 全部列表
              </button>
            </h2>
            <div id="collapseAll" class="accordion-collapse collapse show" data-bs-parent="#downloadAccordion">
              <div class="accordion-body d-flex flex-wrap align-items-center gap-3">
                <a href="/trackers_all.txt" class="btn btn-sm btn-outline-primary">trackers_all.txt</a>
                <button class="btn btn-sm btn-light copy-link-btn" @click="copyUrl('https://yourdomain/trackers_all.txt')">📋 复制链接</button>
              </div>
            </div>
          </div>
          <!-- 更多文件可仿此添加 -->
        </div>
      </div>

      <!-- 表格 -->
      <div class="section-header mt-5">
        <h2 class="section-title">Tracker 详情</h2>
        <button class="btn btn-sm btn-link" type="button" data-bs-toggle="collapse" data-bs-target="#trackerTableCollapse" aria-expanded="false">
          显示/隐藏
        </button>
      </div>
      <div class="collapse fade-up show" id="trackerTableCollapse">
        <div class="card shadow-sm">
          <div class="card-body">
            <!-- 工具栏 -->
            <div class="row g-3 mb-3 align-items-end">
              <div class="col-md-3">
                <div class="toolbar-label">搜索</div>
                <input type="text" class="form-control form-control-sm" placeholder="URL 包含..." v-model="search">
              </div>
              <div class="col-md-2">
                <div class="toolbar-label">状态</div>
                <select class="form-select form-select-sm" v-model="statusFilter">
                  <option value="all">全部</option>
                  <option value="ALIVE">在线</option>
                  <option value="DEAD">失效</option>
                  <option value="INVALID">无效</option>
                </select>
              </div>
              <div class="col-md-2">
                <div class="toolbar-label">协议</div>
                <select class="form-select form-select-sm" v-model="protocolFilter">
                  <option value="all">全部</option>
                  <option value="http">HTTP</option>
                  <option value="https">HTTPS</option>
                  <option value="udp">UDP</option>
                  <option value="wss">WSS/WS</option>
                </select>
              </div>
              <div class="col-md-2">
                <div class="toolbar-label">IPv6</div>
                <select class="form-select form-select-sm" v-model="ipv6Filter">
                  <option value="all">全部</option>
                  <option value="yes">支持</option>
                  <option value="no">不支持</option>
                </select>
              </div>
              <div class="col-md-3">
                <div class="toolbar-label">每页显示</div>
                <select class="form-select form-select-sm w-auto d-inline-block" v-model="pageSize">
                  <option :value="20">20</option>
                  <option :value="50">50</option>
                  <option :value="100">100</option>
                  <option value="all">全部</option>
                </select>
              </div>
            </div>

            <div class="table-responsive">
              <table class="table table-hover table-sm" id="trackerTable">
                <thead class="table-light">
                  <tr>
                    <th style="width:50px;">#</th>
                    <th class="sortable" @click="toggleSort('url')">URL <span class="sort-icon">{{ sortColumn === 'url' ? (sortOrder === 'asc' ? '▲' : '▼') : '' }}</span></th>
                    <th class="sortable" @click="toggleSort('status')">状态 <span class="sort-icon">{{ sortColumn === 'status' ? (sortOrder === 'asc' ? '▲' : '▼') : '' }}</span></th>
                    <th class="sortable" @click="toggleSort('protocol')">协议 <span class="sort-icon">{{ sortColumn === 'protocol' ? (sortOrder === 'asc' ? '▲' : '▼') : '' }}</span></th>
                    <th class="sortable" @click="toggleSort('ping_ms')">Ping (ms) <span class="sort-icon">{{ sortColumn === 'ping_ms' ? (sortOrder === 'asc' ? '▲' : '▼') : '' }}</span></th>
                    <th class="sortable" @click="toggleSort('supports_ipv6')">IPv6 <span class="sort-icon">{{ sortColumn === 'supports_ipv6' ? (sortOrder === 'asc' ? '▲' : '▼') : '' }}</span></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(tracker, idx) in paginatedData" :key="idx">
                    <td>{{ (pageSize === 'all' ? idx : (currentPage-1)*pageSize + idx) + 1 }}</td>
                    <td class="copy-cell" @click="copyUrl(tracker.url)" style="cursor:pointer;" title="点击复制URL">{{ tracker.url }}</td>
                    <td><span class="badge" :class="{'bg-success': tracker.status === 'ALIVE', 'bg-danger': tracker.status === 'DEAD', 'bg-secondary': tracker.status === 'INVALID'}">{{ tracker.status }}</span></td>
                    <td>{{ tracker.protocol.toUpperCase() }}</td>
                    <td>{{ tracker.ping_ms ? tracker.ping_ms : '—' }}</td>
                    <td><span class="badge" :class="tracker.supports_ipv6 ? 'badge-ipv6' : 'badge-ipv4'">{{ tracker.supports_ipv6 ? '✓ IPv6' : 'IPv4' }}</span></td>
                  </tr>
                </tbody>
              </table>
            </div>

            <!-- 分页 -->
            <div class="d-flex justify-content-between align-items-center mt-3">
              <div class="small text-muted">显示 {{ paginatedData.length }} / {{ sortedData.length }} 条</div>
              <nav>
                <ul class="pagination pagination-sm mb-0">
                  <li class="page-item" :class="{ disabled: currentPage === 1 }"><a class="page-link" href="#" @click.prevent="goToPage(currentPage-1)">«</a></li>
                  <li class="page-item" v-for="p in totalPages" :key="p" :class="{ active: p === currentPage }">
                    <a class="page-link" href="#" @click.prevent="goToPage(p)">{{ p }}</a>
                  </li>
                  <li class="page-item" :class="{ disabled: currentPage === totalPages }"><a class="page-link" href="#" @click.prevent="goToPage(currentPage+1)">»</a></li>
                </ul>
              </nav>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- 回到顶部 -->
    <button id="backToTop" class="back-to-top" @click="window.scrollTo({top:0, behavior:'smooth'})">⬆️</button>

    <footer class="container text-center text-muted small py-4">
      {{ new Date().toISOString().slice(0,16).replace('T',' ') }} UTC
    </footer>
  </div>
  <div v-else class="d-flex justify-content-center align-items-center vh-100">加载中...</div>
</template>

<style>
/* 直接复制原有 dashboard.html 中的样式，此处仅保留关键样式，详见原文件 */
/* 由于篇幅，此处省略完整样式，但可以快速导入 Bootstrap */
@import 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css';

/* 以下为自定义样式（简化版，完整版见之前的 dashboard.html 的 <style> 内容） */
.glass-nav { background: rgba(15,23,42,0.8)!important; backdrop-filter: blur(12px); border-bottom: 1px solid rgba(255,255,255,0.1)!important; }
.hero-section { padding: 80px 0 60px; text-align: center; }
.hero-title { font-size: 2.5rem; font-weight: 800; color: white; margin-bottom: 40px; }
.uptime-ring-container { position: relative; display: inline-block; width: 180px; height: 180px; }
.uptime-ring { width: 100%; height: 100%; }
.uptime-value { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 2.4rem; font-weight: 800; color: white; }
.uptime-percent { font-size: 1.4rem; font-weight: 600; opacity: 0.8; }
.uptime-label { position: absolute; bottom: 15px; left: 50%; transform: translateX(-50%); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; color: rgba(255,255,255,0.6); }
.section-header { margin-bottom: 24px; }
.section-title { font-size: 1.4rem; font-weight: 700; color: white; border-left: 4px solid #22c55e; padding-left: 16px; }
.stat-card, .proto-card, .accordion-item { background: rgba(255,255,255,0.06); backdrop-filter: blur(14px); border: 1px solid rgba(255,255,255,0.12); border-radius: 18px; padding: 24px 20px; }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(160px,1fr)); gap: 20px; }
.stat-label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.5px; color: rgba(226,232,240,0.7); }
.stat-value { font-size: 2.5rem; font-weight: 800; }
.ok { color: #22c55e; }
.bad { color: #ef4444; }
.warn { color: #f59e0b; }
.proto-grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(140px,1fr)); gap: 20px; }
.proto-name { font-size: 1.1rem; font-weight: 700; }
.proto-count { font-size: 2.2rem; font-weight: 800; }
.http-color { color: #60a5fa; }
.https-color { color: #34d399; }
.udp-color { color: #fbbf24; }
.wss-color { color: #a78bfa; }
.fade-up { animation: fadeUp 0.6s ease-out forwards; }
@keyframes fadeUp { to { opacity: 1; transform: translateY(0); } }
.back-to-top { position: fixed; bottom: 30px; right: 30px; width: 48px; height: 48px; border-radius: 50%; background-color: #22c55e; color: #000; border: none; cursor: pointer; }
.badge-ipv6 { background-color: #22c55e; color: #000; }
.badge-ipv4 { background-color: #6c757d; }
.toolbar-label { font-size: 0.75rem; color: #94a3b8; }
.copy-cell { cursor: pointer; }
.pagination .page-link { background: rgba(255,255,255,0.1); border-color: rgba(255,255,255,0.2); color: #e2e8f0; }
.pagination .active .page-link { background: #22c55e; border-color: #22c55e; color: #000; }
</style>