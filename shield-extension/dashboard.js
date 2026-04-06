// ── AI Cyber Defense Shield — Dashboard Logic ─────────────────────────────────

const Views = {
  overview: document.getElementById('view-overview'),
  history: document.getElementById('view-history'),
  blocked: document.getElementById('view-blocked'),
  settings: document.getElementById('view-settings'),
}

const NavItems = document.querySelectorAll('.nav-item')

// Initialize
async function init() {
  await loadStats()
  await renderRecentActivity()
  setupNav()
  setupActions()
}

// Nav Navigation
function setupNav() {
  NavItems.forEach(item => {
    item.addEventListener('click', () => {
      const viewId = item.dataset.view
      if (!Views[viewId]) return

      // Update Nav
      NavItems.forEach(x => x.classList.remove('active'))
      item.classList.add('active')

      // Update View
      Object.keys(Views).forEach(k => Views[k].classList.add('hidden'))
      Views[viewId].classList.remove('hidden')

      // Update Title
      document.getElementById('view-title').textContent = item.textContent.trim()

      // Render View Data
      if (viewId === 'history') renderFullHistory()
      if (viewId === 'blocked') renderBlockedList()
      if (viewId === 'overview') {
        loadStats()
        renderRecentActivity()
      }
    })
  })
}

function setupActions() {
  document.getElementById('btn-refresh').onclick = () => init()
  document.getElementById('btn-wipe').onclick = () => {
    showModal('Wipe All Data?', 'Are you sure you want to PERMANENTLY delete all scan logs and history?', () => {
      chrome.runtime.sendMessage({ type: 'CLEAR_HISTORY' }, () => window.location.reload())
    })
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


// Data Fetching
async function loadStats() {
  chrome.runtime.sendMessage({ type: 'GET_STATS' }, resp => {
    const s = resp?.stats || { totalScans: 0, totalBlocked: 0, byRisk: {} }
    document.getElementById('stat-scans').textContent = s.totalScans.toLocaleString()
    document.getElementById('stat-blocked').textContent = s.totalBlocked.toLocaleString()

    // Avg score (approx from history)
    chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, histResp => {
      const h = histResp?.history || []
      const avg = h.length ? Math.round(h.reduce((acc, curr) => acc + (curr.score || 100), 0) / h.length) : 100
      const el = document.getElementById('stat-score')
      el.textContent = `${avg}%`
      el.style.color = avg >= 80 ? '#3fb950' : avg >= 50 ? '#d29922' : '#f85149'
    })
  })
}

async function renderRecentActivity() {
  chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, resp => {
    const list = resp?.history || []
    const tbody = document.getElementById('recent-table').querySelector('tbody')
    tbody.innerHTML = list.slice(0, 10).map(h => `
      <tr>
        <td style="font-weight: 500;">${h.domain}</td>
        <td><span class="risk-pill pill-${h.riskLevel}">${h.riskLevel}</span></td>
        <td>${h.score}/100</td>
        <td style="color: grey;">${h.issues?.length || 0} threats detected</td>
        <td style="font-size: 12px; color: var(--text-dim);">${fmtDate(h.scannedAt || h.checkedAt)}</td>
      </tr>
    `).join('')
  })
}

async function renderFullHistory() {
  chrome.runtime.sendMessage({ type: 'GET_HISTORY' }, resp => {
    const list = resp?.history || []
    const tbody = document.getElementById('history-table').querySelector('tbody')
    tbody.innerHTML = list.map(h => `
      <tr>
        <td style="font-weight: 500;">${h.domain}</td>
        <td><span class="risk-pill pill-${h.riskLevel}">${h.riskLevel}</span></td>
        <td>${h.score}/100</td>
        <td>
          <div style="font-size: 11px; max-width: 300px; display: flex; flex-wrap: wrap; gap: 4px;">
            ${h.issues?.map(i => `<span style="background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; border: 1px solid var(--border);">${i.type}</span>`).join('') || 'None'}
          </div>
        </td>
        <td style="font-size: 12px; color: var(--text-dim);">${fmtDate(h.scannedAt || h.checkedAt)}</td>
      </tr>
    `).join('')
  })
}

async function renderBlockedList() {
  chrome.runtime.sendMessage({ type: 'GET_BLOCKED' }, resp => {
    const list = resp?.blocked || []
    const tbody = document.getElementById('blocked-table').querySelector('tbody')
    tbody.innerHTML = list.slice(0, 10).map(s => `
      <tr>
        <td style="font-weight: 600;">${s.domain}</td>
        <td style="color: var(--text-dim);">${s.reason || 'Manual'}</td>
        <td><span class="risk-pill pill-${s.severity || 'HIGH'}">${s.severity || 'HIGH'}</span></td>
        <td>${fmtDate(s.blockedAt)}</td>
        <td><button class="btn btn-danger" onclick="unblock('${s.domain}')">Unblock</button></td>
      </tr>
    `).join('')
  })
}

async function unblock(domain) {
  chrome.runtime.sendMessage({ type: 'UNBLOCK_SITE', domain}, () => renderBlockedList())
}

window.unblock = unblock // for buttons

// Helpers
function fmtDate(iso) {
  if (!iso) return 'N/A'
  const d = new Date(iso)
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
}

init()
