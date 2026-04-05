// ── AI Cyber Defense Shield — Popup Script ────────────────────────────────────
const DASHBOARD = 'http://localhost:3000/extension'

const RISK_CONFIG = {
  SAFE:     { icon: '✅', color: 'safe',     label: 'Safe',     bg: 'bg-safe' },
  LOW:      { icon: '🟡', color: 'low',      label: 'Low Risk', bg: 'bg-low' },
  MEDIUM:   { icon: '⚠️', color: 'medium',   label: 'Medium Risk', bg: 'bg-medium' },
  HIGH:     { icon: '🟠', color: 'high',     label: 'High Risk',bg: 'bg-high' },
  CRITICAL: { icon: '🔴', color: 'critical', label: 'CRITICAL', bg: 'bg-critical' },
  UNKNOWN:  { icon: '❓', color: 'unknown',  label: 'Unknown',  bg: '' },
}

let currentDomain = ''
let currentResult = null

// ── Init ──────────────────────────────────────────────────────────────────────
async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab?.url) return

  try {
    currentDomain = new URL(tab.url).hostname
  } catch { return }

  // Trigger scan
  chrome.runtime.sendMessage({ type: 'SCAN_CURRENT' }, (resp) => {
    if (resp?.result) renderResult(resp.result)
  })

  // Load blocked list
  renderBlockedList()

  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'))
      document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'))
      tab.classList.add('active')
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active')
    })
  })

  // Buttons
  document.getElementById('btn-rescan').addEventListener('click', () => {
    document.getElementById('risk-banner').innerHTML = `<div class="scanning"><div class="spinner"></div><div>Scanning...</div></div>`
    document.getElementById('issues-container').innerHTML = `<div class="empty">Scanning...</div>`
    chrome.runtime.sendMessage({ type: 'SCAN_CURRENT' }, (resp) => {
      if (resp?.result) renderResult(resp.result)
    })
  })

  document.getElementById('btn-dashboard').addEventListener('click', () => {
    chrome.tabs.create({ url: DASHBOARD })
  })
}

// ── Render scan result ────────────────────────────────────────────────────────
function renderResult(result) {
  currentResult = result
  const cfg = RISK_CONFIG[result.riskLevel] || RISK_CONFIG.UNKNOWN

  // HTTPS badge
  const httpsBadge = document.getElementById('https-badge')
  httpsBadge.innerHTML = result.isHTTPS
    ? `<span class="https-badge https-ok">🔒 HTTPS</span>`
    : `<span class="https-badge https-bad">⚠️ HTTP</span>`

  // Risk banner
  const banner = document.getElementById('risk-banner')
  banner.className = `risk-banner ${cfg.bg}`
  banner.innerHTML = `
    <div class="risk-icon">${cfg.icon}</div>
    <div>
      <div class="risk-label">Risk Level</div>
      <div class="risk-value ${cfg.color}">${cfg.label}</div>
      <div class="risk-domain">${result.domain || currentDomain}</div>
    </div>
    <div class="risk-score">
      <div class="risk-score-num ${cfg.color}">${result.score ?? '—'}</div>
      <div class="risk-score-label">/ 100</div>
    </div>
  `

  // Issues
  const container = document.getElementById('issues-container')
  if (!result.issues || result.issues.length === 0) {
    container.innerHTML = `<div class="empty">✅ No security issues detected</div>`
  } else {
    container.innerHTML = result.issues.map(issue => `
      <div class="issue ${RISK_CONFIG[issue.severity]?.bg || ''}">
        <span class="issue-sev sev-${issue.severity.toLowerCase()}">${issue.severity}</span>
        <div class="issue-text" style="margin-left:8px;">
          <div class="issue-desc">${issue.description}</div>
          <div class="issue-rec">→ ${issue.recommendation}</div>
        </div>
      </div>
    `).join('')
  }

  // Block/unblock button
  const actions = document.getElementById('actions')
  const isBlocked = result.issues?.some(i => i.type === 'BLOCKED')

  // Remove old block btn if exists
  const oldBtn = document.getElementById('btn-block-toggle')
  if (oldBtn) oldBtn.remove()

  if (result.riskLevel !== 'SAFE' && result.riskLevel !== 'UNKNOWN') {
    const btn = document.createElement('button')
    btn.id = 'btn-block-toggle'
    if (isBlocked) {
      btn.className = 'btn btn-unblock'
      btn.innerHTML = '🔓 Unblock This Site'
      btn.addEventListener('click', () => unblockSite(result.domain || currentDomain))
    } else {
      btn.className = 'btn btn-block'
      btn.innerHTML = '🚫 Block This Site'
      btn.addEventListener('click', () => blockSite(result.domain || currentDomain, result.riskLevel))
    }
    actions.insertBefore(btn, actions.firstChild)
  }
}

// ── Block / Unblock ───────────────────────────────────────────────────────────
function blockSite(domain, severity) {
  chrome.runtime.sendMessage(
    { type: 'BLOCK_SITE', domain, reason: `Manually blocked (${severity} risk)`, severity },
    () => {
      renderBlockedList()
      // Update button
      const btn = document.getElementById('btn-block-toggle')
      if (btn) {
        btn.className = 'btn btn-unblock'
        btn.innerHTML = '🔓 Unblock This Site'
        btn.onclick = () => unblockSite(domain)
      }
    }
  )
}

function unblockSite(domain) {
  chrome.runtime.sendMessage({ type: 'UNBLOCK_SITE', domain }, () => {
    renderBlockedList()
    const btn = document.getElementById('btn-block-toggle')
    if (btn) {
      btn.className = 'btn btn-block'
      btn.innerHTML = '🚫 Block This Site'
      btn.onclick = () => blockSite(domain, 'HIGH')
    }
  })
}

// ── Blocked list ──────────────────────────────────────────────────────────────
function renderBlockedList() {
  chrome.runtime.sendMessage({ type: 'GET_BLOCKED' }, (resp) => {
    const container = document.getElementById('blocked-container')
    const list = resp?.blocked || []

    if (list.length === 0) {
      container.innerHTML = `<div class="empty">No sites blocked yet</div>`
      return
    }

    container.innerHTML = list.map(site => `
      <div class="blocked-item">
        <div>
          <div class="blocked-domain">${site.domain}</div>
          <div class="blocked-reason">${site.reason || 'Blocked'} · ${formatDate(site.blockedAt)}</div>
        </div>
        <button class="unblock-btn" data-domain="${site.domain}">Unblock</button>
      </div>
    `).join('')

    container.querySelectorAll('.unblock-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        unblockSite(btn.dataset.domain)
      })
    })
  })
}

function formatDate(iso) {
  if (!iso) return ''
  try { return new Date(iso).toLocaleDateString() } catch { return '' }
}

init()
