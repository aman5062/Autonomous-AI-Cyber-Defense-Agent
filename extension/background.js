// ── AI Cyber Defense Shield — Background Service Worker ──────────────────────
const BACKEND = 'http://localhost:8000'
const DASHBOARD = 'http://localhost:3000'

// ── Storage helpers ───────────────────────────────────────────────────────────
async function getBlocked() {
  const { blockedSites = [] } = await chrome.storage.local.get('blockedSites')
  return blockedSites
}

async function addBlocked(domain, reason, severity) {
  const list = await getBlocked()
  const existing = list.find(s => s.domain === domain)
  if (!existing) {
    list.push({ domain, reason, severity, blockedAt: new Date().toISOString(), source: 'extension' })
    await chrome.storage.local.set({ blockedSites: list })
    await syncBlockedToDNR(list)
    await reportToDashboard({ domain, reason, severity, action: 'BLOCKED' })
  }
}

async function removeBlocked(domain) {
  let list = await getBlocked()
  list = list.filter(s => s.domain !== domain)
  await chrome.storage.local.set({ blockedSites: list })
  await syncBlockedToDNR(list)
  await reportToDashboard({ domain, action: 'UNBLOCKED' })
}

async function getScanHistory() {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory')
  return scanHistory
}

async function addScanResult(result) {
  const history = await getScanHistory()
  history.unshift({ ...result, scannedAt: new Date().toISOString() })
  // Keep last 200 scans
  await chrome.storage.local.set({ scanHistory: history.slice(0, 200) })
}

// ── Declarative Net Request — block sites at network level ───────────────────
async function syncBlockedToDNR(blockedList) {
  try {
    // Remove all existing rules
    const existing = await chrome.declarativeNetRequest.getDynamicRules()
    const removeIds = existing.map(r => r.id)

    const addRules = blockedList.map((site, i) => ({
      id: i + 1,
      priority: 1,
      action: { type: 'block' },
      condition: {
        urlFilter: `||${site.domain}^`,
        resourceTypes: ['main_frame', 'sub_frame'],
      },
    }))

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: removeIds,
      addRules,
    })
  } catch (e) {
    console.warn('DNR update failed:', e)
  }
}

// ── Report to dashboard backend ───────────────────────────────────────────────
async function reportToDashboard(data) {
  try {
    await fetch(`${BACKEND}/api/extension/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
  } catch {
    // Backend may not be running — silent fail
  }
}

// ── Site scanning ─────────────────────────────────────────────────────────────
async function scanSite(url, tabId) {
  const result = await performScan(url)
  await addScanResult(result)

  // Auto-block critical threats
  if (result.riskLevel === 'CRITICAL' || result.riskLevel === 'HIGH') {
    const domain = new URL(url).hostname
    const topIssue = result.issues[0]
    if (topIssue && result.riskLevel === 'CRITICAL') {
      await addBlocked(domain, topIssue.description, result.riskLevel)
    }
  }

  // Update badge
  updateBadge(tabId, result.riskLevel)

  // Show notification for high/critical
  if (['CRITICAL', 'HIGH'].includes(result.riskLevel)) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/shield48.png',
      title: `⚠️ ${result.riskLevel} Risk: ${new URL(url).hostname}`,
      message: result.issues.slice(0, 2).map(i => i.description).join('\n'),
      priority: result.riskLevel === 'CRITICAL' ? 2 : 1,
    })
  }

  return result
}

// ── Core scan logic ───────────────────────────────────────────────────────────
async function performScan(url) {
  const issues = []
  let parsedUrl

  try {
    parsedUrl = new URL(url)
  } catch {
    return { url, riskLevel: 'UNKNOWN', issues: [], score: 100 }
  }

  const domain = parsedUrl.hostname
  const isHTTPS = parsedUrl.protocol === 'https:'
  const isLocalhost = ['localhost', '127.0.0.1', '::1'].includes(domain)

  // ── Check 1: HTTP (no encryption) ─────────────────────────────────────────
  if (!isHTTPS && !isLocalhost) {
    issues.push({
      type: 'NO_HTTPS',
      severity: 'HIGH',
      description: 'Site uses HTTP — all data transmitted in plain text',
      recommendation: 'Never enter passwords or payment info on HTTP sites',
    })
  }

  // ── Check 2: Payment on HTTP ───────────────────────────────────────────────
  if (!isHTTPS && !isLocalhost) {
    issues.push({
      type: 'PAYMENT_RISK',
      severity: 'CRITICAL',
      description: 'Payment data at risk — no HTTPS encryption',
      recommendation: 'Do NOT enter credit card or payment information',
    })
  }

  // ── Check 3: Suspicious domain patterns ───────────────────────────────────
  const suspiciousPatterns = [
    { pattern: /paypa1|paypai|payp4l/i, desc: 'PayPal phishing domain detected' },
    { pattern: /amaz0n|amazom|arnazon/i, desc: 'Amazon phishing domain detected' },
    { pattern: /g00gle|googIe|g0ogle/i, desc: 'Google phishing domain detected' },
    { pattern: /micros0ft|microsofl/i,   desc: 'Microsoft phishing domain detected' },
    { pattern: /app1e|appIe|appl3/i,     desc: 'Apple phishing domain detected' },
    { pattern: /secure.*login.*\.(xyz|tk|ml|ga|cf)/i, desc: 'Suspicious secure-login domain' },
    { pattern: /bank.*\.(xyz|tk|ml|ga|cf|pw)/i,       desc: 'Suspicious banking domain' },
    { pattern: /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/,    desc: 'IP address used as domain (suspicious)' },
  ]
  for (const { pattern, desc } of suspiciousPatterns) {
    if (pattern.test(domain)) {
      issues.push({ type: 'PHISHING', severity: 'CRITICAL', description: desc, recommendation: 'Leave this site immediately' })
    }
  }

  // ── Check 4: Known malicious TLDs ─────────────────────────────────────────
  const maliciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download']
  if (maliciousTLDs.some(tld => domain.endsWith(tld))) {
    issues.push({
      type: 'SUSPICIOUS_TLD',
      severity: 'MEDIUM',
      description: `Domain uses high-risk TLD: .${domain.split('.').pop()}`,
      recommendation: 'Exercise caution — this TLD is commonly used for malicious sites',
    })
  }

  // ── Check 5: Mixed content (HTTP resources on HTTPS page) ─────────────────
  // This is detected by content script and sent via message

  // ── Check 6: Suspicious URL patterns ──────────────────────────────────────
  const urlStr = url.toLowerCase()
  const suspiciousUrlPatterns = [
    { pattern: /\.(exe|bat|cmd|ps1|vbs|jar|msi)(\?|$)/i, desc: 'URL points to executable file download', sev: 'HIGH' },
    { pattern: /redirect.*=.*http/i,  desc: 'Open redirect detected in URL', sev: 'MEDIUM' },
    { pattern: /base64/i,             desc: 'Base64 encoding in URL (obfuscation)', sev: 'MEDIUM' },
    { pattern: /%[0-9a-f]{2}.*%[0-9a-f]{2}.*%[0-9a-f]{2}/i, desc: 'Heavy URL encoding (possible obfuscation)', sev: 'LOW' },
  ]
  for (const { pattern, desc, sev } of suspiciousUrlPatterns) {
    if (pattern.test(urlStr)) {
      issues.push({ type: 'SUSPICIOUS_URL', severity: sev, description: desc, recommendation: 'Verify this URL before proceeding' })
    }
  }

  // ── Check 7: Blocked list ──────────────────────────────────────────────────
  const blocked = await getBlocked()
  if (blocked.find(s => domain.includes(s.domain) || s.domain.includes(domain))) {
    issues.push({
      type: 'BLOCKED',
      severity: 'CRITICAL',
      description: 'This site is on your blocked list',
      recommendation: 'You have previously blocked this site',
    })
  }

  // ── Calculate risk score ───────────────────────────────────────────────────
  const sevScore = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 5 }
  const deduction = issues.reduce((sum, i) => sum + (sevScore[i.severity] || 0), 0)
  const score = Math.max(0, 100 - deduction)

  const riskLevel = score >= 80 ? 'SAFE'
    : score >= 60 ? 'LOW'
    : score >= 40 ? 'MEDIUM'
    : score >= 20 ? 'HIGH'
    : 'CRITICAL'

  return { url, domain, isHTTPS, riskLevel, score, issues, checkedAt: new Date().toISOString() }
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function updateBadge(tabId, riskLevel) {
  const config = {
    SAFE:     { text: '✓',  color: '#22c55e' },
    LOW:      { text: '!',  color: '#84cc16' },
    MEDIUM:   { text: '!!', color: '#eab308' },
    HIGH:     { text: '!!!',color: '#f97316' },
    CRITICAL: { text: '✕',  color: '#ef4444' },
    UNKNOWN:  { text: '?',  color: '#6b7280' },
  }
  const c = config[riskLevel] || config.UNKNOWN
  // Tab may have closed or navigated — ignore errors
  chrome.action.setBadgeText({ text: c.text, tabId }).catch(() => {})
  chrome.action.setBadgeBackgroundColor({ color: c.color, tabId }).catch(() => {})
}

// ── Event listeners ───────────────────────────────────────────────────────────

// Scan on tab navigation
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    try {
      await scanSite(tab.url, tabId)
    } catch {
      // Tab closed mid-scan — ignore
    }
  }
})

// Messages from popup and content script
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  ;(async () => {
    switch (msg.type) {
      case 'SCAN_CURRENT':
        const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
        if (tabs[0]?.url) {
          const result = await scanSite(tabs[0].url, tabs[0].id)
          sendResponse({ result })
        }
        break

      case 'GET_SCAN_RESULT':
        const history = await getScanHistory()
        const latest = history.find(h => h.url === msg.url || h.domain === msg.domain)
        sendResponse({ result: latest || null })
        break

      case 'BLOCK_SITE':
        await addBlocked(msg.domain, msg.reason || 'Manually blocked', msg.severity || 'HIGH')
        sendResponse({ success: true })
        break

      case 'UNBLOCK_SITE':
        await removeBlocked(msg.domain)
        sendResponse({ success: true })
        break

      case 'GET_BLOCKED':
        sendResponse({ blocked: await getBlocked() })
        break

      case 'GET_HISTORY':
        sendResponse({ history: await getScanHistory() })
        break

      case 'CONTENT_ISSUES':
        // Issues detected by content script (mixed content, forms, etc.)
        const tabs2 = await chrome.tabs.query({ active: true, currentWindow: true })
        if (tabs2[0]) updateBadge(tabs2[0].id, msg.riskLevel || 'MEDIUM')
        await addScanResult({ url: msg.url, domain: msg.domain, ...msg.scanData })
        break
    }
  })()
  return true // keep channel open for async
})
