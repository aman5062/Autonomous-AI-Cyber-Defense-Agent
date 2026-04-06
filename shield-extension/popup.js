// ── AI Cyber Defense Shield — Popup (Standalone) ─────────────────────────────

const RISK = {
  SAFE:     { icon:'✅', cls:'safe',     label:'Safe',        bg:'bg-safe' },
  LOW:      { icon:'🟡', cls:'low',      label:'Low Risk',    bg:'bg-low' },
  MEDIUM:   { icon:'⚠️', cls:'medium',   label:'Medium Risk', bg:'bg-medium' },
  HIGH:     { icon:'🟠', cls:'high',     label:'High Risk',   bg:'bg-high' },
  CRITICAL: { icon:'🔴', cls:'critical', label:'CRITICAL',    bg:'bg-critical' },
  UNKNOWN:  { icon:'❓', cls:'unknown',  label:'Unknown',     bg:'' },
}

const RISK_PILL_STYLE = {
  SAFE:     'background:#14532d;color:#86efac',
  LOW:      'background:#365214;color:#bef264',
  MEDIUM:   'background:#713500;color:#fde68a',
  HIGH:     'background:#7c2d12;color:#fdba74',
  CRITICAL: 'background:#7f1d1d;color:#fca5a5',
  UNKNOWN:  'background:#374151;color:#9ca3af',
}

let currentDomain = ''

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.url) return
  try { currentDomain = new URL(tab.url).hostname } catch { return }

  // Tabs
  document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'))
      document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'))
      t.classList.add('active')
      document.getElementById(`tab-${t.dataset.tab}`).classList.add('active')
      if (t.dataset.tab === 'history') renderHistory()
      if (t.dataset.tab === 'blocked') renderBlocked()
      if (t.dataset.tab === 'stats') renderStats()
    })
  })

  // Scan current page
  const scanTimeout = setTimeout(() => {
    document.getElementById('risk-banner').innerHTML = `<div class="empty">🛡️ Scan not available on this page</div>`
    document.getElementById('issues-list').innerHTML = `<div class="empty">Browser system pages cannot be scanned for security.</div>`
  }, 1500)

  chrome.runtime.sendMessage({ type: 'SCAN_CURRENT' }, r => {
    clearTimeout(scanTimeout)
    if (r?.result) renderResult(r.result)
  })

  // Rescan button
  document.getElementById('btn-rescan').onclick = () => {
    document.getElementById('risk-banner').innerHTML = `<div class="scanning"><div class="spinner"></div><div>Scanning...</div></div>`
    document.getElementById('issues-list').innerHTML = `<div class="empty">Scanning...</div>`
    const t = setTimeout(() => {
      document.getElementById('risk-banner').innerHTML = `<div class="empty">Scan failed</div>`
    }, 2000)
    chrome.runtime.sendMessage({ type: 'SCAN_CURRENT' }, r => {
      clearTimeout(t)
      if (r?.result) renderResult(r.result)
    })
  }

  // Clear history
  document.getElementById('btn-clear').onclick = () => {
    showModal('Clear History?', 'This will permanently delete all scan history and statistics.', () => {
      chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' }, () => {
        renderHistory(); renderStats()
      })
    })
  }

  // Dashboard button
  document.getElementById('btn-dashboard').onclick = () => {
    chrome.tabs.create({ url: 'dashboard.html' })
  }
}

function showModal(title, msg, onConfirm) {
  const overlay = document.getElementById('cs-modal-overlay')
  const t = document.getElementById('cs-modal-title')
  const m = document.getElementById('cs-modal-msg')
  const btnCancel = document.getElementById('btn-modal-cancel')
  const btnConfirm = document.getElementById('btn-modal-confirm')

  t.textContent = title
  m.textContent = msg
  overlay.style.display = 'flex'

  btnCancel.onclick = () => overlay.style.display = 'none'
  btnConfirm.onclick = () => {
    overlay.style.display = 'none'
    onConfirm()
  }
}


function renderResult(result) {
  const cfg = RISK[result.riskLevel] || RISK.UNKNOWN

  // HTTPS badge
  document.getElementById('https-badge').innerHTML = result.isHTTPS
    ? `<span class="https-badge https-ok">🔒 HTTPS</span>`
    : `<span class="https-badge https-bad">⚠️ HTTP</span>`

  // Risk banner
  const banner = document.getElementById('risk-banner')
  banner.className = `risk-banner ${cfg.bg}`
  banner.innerHTML = `
    <div class="risk-icon">${cfg.icon}</div>
    <div>
      <div class="risk-label">Risk Level</div>
      <div class="risk-value ${cfg.cls}">${cfg.label}</div>
      <div class="risk-domain">${result.domain || currentDomain}</div>
      <span class="https-badge ${result.isHTTPS ? 'https-ok' : 'https-bad'}">${result.isHTTPS ? '🔒 HTTPS' : '⚠️ HTTP'}</span>
    </div>
    <div class="risk-score">
      <div class="risk-score-num ${cfg.cls}">${result.score ?? '—'}</div>
      <div class="risk-score-label">/ 100</div>
    </div>
  `

  // Issues
  const list = document.getElementById('issues-list')
  if (!result.issues?.length) {
    list.innerHTML = `<div class="empty">✅ No security issues detected on this page</div>`
  } else {
    list.innerHTML = result.issues.map(i => `
      <div class="issue iss-${i.severity.toLowerCase()}">
        <span class="sev sev-${i.severity.toLowerCase()}">${i.severity}</span>
        <div style="flex:1;margin-left:6px">
          <div class="issue-desc">${i.desc}</div>
          <div class="issue-rec">→ ${i.rec}</div>
        </div>
      </div>`).join('')
  }

  // Block/unblock button
  const actions = document.getElementById('actions')
  document.getElementById('btn-block-toggle')?.remove()

  if (result.riskLevel !== 'SAFE' && result.riskLevel !== 'UNKNOWN') {
    const isBlocked = result.issues?.some(i => i.type === 'BLOCKED')
    const btn = document.createElement('button')
    btn.id = 'btn-block-toggle'
    if (isBlocked) {
      btn.className = 'btn btn-unblock'
      btn.innerHTML = '🔓 Unblock This Site'
      btn.onclick = () => unblock(result.domain || currentDomain)
    } else {
      btn.className = 'btn btn-block'
      btn.innerHTML = '🚫 Block This Site'
      btn.onclick = () => block(result.domain || currentDomain, result.riskLevel)
    }
    actions.insertBefore(btn, actions.firstChild)
  }
}

function block(domain, severity) {
  chrome.runtime.sendMessage(
    { type: 'BLOCK_SITE', domain, reason: `Manually blocked (${severity} risk)`, severity },
    () => {
      renderBlocked()
      const btn = document.getElementById('btn-block-toggle')
      if (btn) { btn.className = 'btn btn-unblock'; btn.innerHTML = '🔓 Unblock This Site'; btn.onclick = () => unblock(domain) }
    }
  )
}

function unblock(domain) {
  chrome.runtime.sendMessage({ type: 'UNBLOCK_SITE', domain }, () => {
    renderBlocked()
    const btn = document.getElementById('btn-block-toggle')
    if (btn) { btn.className = 'btn btn-block'; btn.innerHTML = '🚫 Block This Site'; btn.onclick = () => block(domain, 'HIGH') }
  })
}

function renderBlocked() {
  chrome.runtime.sendMessage({ type: 'GET_BLOCKED' }, resp => {
    const el = document.getElementById('blocked-list')
    const list = resp?.blocked || []
    if (!list.length) { el.innerHTML = `<div class="empty">No sites blocked yet</div>`; return }
    el.innerHTML = list.map(s => `
      <div class="blocked-item">
        <div>
          <div class="blocked-domain">${s.domain}</div>
          <div class="blocked-meta">${s.reason || 'Blocked'} · ${fmt(s.blockedAt)}</div>
        </div>
        <button class="unblock-btn" data-domain="${s.domain}">Unblock</button>
      </div>`).join('')
    el.querySelectorAll('.unblock-btn').forEach(b => b.onclick = () => { unblock(b.dataset.domain); renderBlocked() })
  })
}

function renderHistory() {
  chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, resp => {
    const el = document.getElementById('history-list')
    const list = resp?.history || []
    if (!list.length) { el.innerHTML = `<div class="empty">No scan history yet</div>`; return }
    el.innerHTML = list.slice(0, 50).map(h => {
      const cfg = RISK[h.riskLevel] || RISK.UNKNOWN
      return `
        <div class="history-item">
          <div class="history-domain">${h.domain}</div>
          <div class="history-meta">
            <span class="risk-pill" style="${RISK_PILL_STYLE[h.riskLevel] || ''}">${h.riskLevel}</span>
            <span>${h.score ?? '?'}/100</span>
            <span>${h.issues?.length || 0} issue${h.issues?.length !== 1 ? 's' : ''}</span>
            <span>${fmt(h.scannedAt)}</span>
          </div>
        </div>`
    }).join('')
  })
}

function renderStats() {
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, resp => {
    const el = document.getElementById('stats-content')
    const s = resp?.stats || {}
    const byRisk = s.byRisk || {}
    el.innerHTML = `
      <div class="section-title">Lifetime Statistics</div>
      ${[
        ['Total Scans', s.totalScans || 0],
        ['Threats Found', s.totalThreats || 0],
        ['Sites Blocked', s.totalBlocked || 0],
        ['Critical Sites', byRisk.CRITICAL || 0],
        ['High Risk Sites', byRisk.HIGH || 0],
        ['Safe Sites', byRisk.SAFE || 0],
      ].map(([l, v]) => `
        <div class="stat-row">
          <span style="color:#8b949e">${l}</span>
          <span class="stat-val">${v}</span>
        </div>`).join('')}
    `
  })
}

function fmt(iso) {
  if (!iso) return ''
  try {
    const d = new Date(iso)
    const now = new Date()
    const diff = now - d
    if (diff < 60000) return 'just now'
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
    return d.toLocaleDateString()
  } catch { return '' }
}

init()