// ── AI Cyber Defense Shield — Standalone Background Service Worker ────────────
// No backend required. All data stored locally in chrome.storage.local

// ── Storage ───────────────────────────────────────────────────────────────────
async function getBlocked() {
  const { blockedSites = [] } = await chrome.storage.local.get('blockedSites')
  return blockedSites
}

async function addBlocked(domain, reason, severity) {
  const list = await getBlocked()
  if (!list.find(s => s.domain === domain)) {
    list.push({ domain, reason, severity, blockedAt: new Date().toISOString() })
    await chrome.storage.local.set({ blockedSites: list })
    await syncDNR(list)
  }
}

async function removeBlocked(domain) {
  let list = await getBlocked()
  list = list.filter(s => s.domain !== domain)
  await chrome.storage.local.set({ blockedSites: list })
  await syncDNR(list)
}

async function getScanHistory() {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory')
  return scanHistory
}

async function addScanResult(result) {
  const history = await getScanHistory()
  // Deduplicate by domain — keep latest
  const filtered = history.filter(h => h.domain !== result.domain)
  filtered.unshift({ ...result, scannedAt: new Date().toISOString() })
  await chrome.storage.local.set({ scanHistory: filtered.slice(0, 500) })
}

async function getStats() {
  const { stats = { totalScans: 0, totalBlocked: 0, totalThreats: 0, byRisk: {} } } =
    await chrome.storage.local.get('stats')
  return stats
}

async function updateStats(riskLevel, threatsFound) {
  const stats = await getStats()
  stats.totalScans++
  if (threatsFound > 0) stats.totalThreats += threatsFound
  stats.byRisk[riskLevel] = (stats.byRisk[riskLevel] || 0) + 1
  await chrome.storage.local.set({ stats })
}

// ── Declarative Net Request — block sites & strip referrers ──────────────────
async function syncDNR(blockedList) {
  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules()
    const removeIds = existing.map(r => r.id)
    
    const addRules = []
    
    blockedList.forEach((site, i) => {
      // Rule 1: BLOCK the site
      addRules.push({
        id: (i * 2) + 1,
        priority: 1,
        action: { type: 'block' },
        condition: { urlFilter: `||${site.domain}^`, resourceTypes: ['main_frame', 'sub_frame'] },
      })
      
      // Rule 2: STRIP REFERRER when visiting this site (privacy layer)
      addRules.push({
        id: (i * 2) + 2,
        priority: 1,
        action: {
          type: 'modifyHeaders',
          requestHeaders: [{ header: 'referer', operation: 'remove' }]
        },
        condition: { 
          urlFilter: `||${site.domain}^`, 
          resourceTypes: ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'other'] 
        },
      })
    })

    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds, addRules })
  } catch (e) {
    console.warn('DNR update failed:', e)
  }
}


// ── Core scan logic ───────────────────────────────────────────────────────────
async function performScan(url) {
  let parsedUrl
  try { parsedUrl = new URL(url) } catch { return { url, riskLevel: 'UNKNOWN', issues: [], score: 100 } }

  const domain = parsedUrl.hostname
  const isHTTPS = parsedUrl.protocol === 'https:'
  const isLocal = ['localhost', '127.0.0.1', '::1'].includes(domain)
  
  // Skip system pages
  if (parsedUrl.protocol.includes('chrome') || parsedUrl.protocol.includes('edge') || domain === 'newtab' || url === 'about:blank') {
    return { url, domain, isHTTPS: true, riskLevel: 'SAFE', score: 100, issues: [], checkedAt: new Date().toISOString() }
  }

  const issues = []

  // 1. No HTTPS
  if (!isHTTPS && !isLocal) {
    issues.push({ type: 'NO_HTTPS', severity: 'HIGH',
      desc: 'No HTTPS — data sent in plain text',
      rec: 'Never enter passwords or payment info on HTTP sites' })
  }

  // 2. Payment risk on HTTP
  if (!isHTTPS && !isLocal) {
    issues.push({ type: 'PAYMENT_RISK', severity: 'CRITICAL',
      desc: 'Payment data at risk — no HTTPS encryption',
      rec: 'Do NOT enter credit card or payment information' })
  }

  // 3. Phishing domain patterns
  const phishPatterns = [
    { re: /paypa[l1].*\.(xyz|tk|ml|ga|cf|pw|top|click|info)/i, brand: 'PayPal' },
    { re: /amaz[o0]n.*\.(xyz|tk|ml|ga|cf|pw|top)/i,            brand: 'Amazon' },
    { re: /g[o0]{2}gle.*\.(xyz|tk|ml|ga|cf|pw)/i,              brand: 'Google' },
    { re: /micros[o0]ft.*\.(xyz|tk|ml|ga|cf|pw)/i,             brand: 'Microsoft' },
    { re: /app[l1]e.*\.(xyz|tk|ml|ga|cf|pw)/i,                 brand: 'Apple' },
    { re: /netfl[i1]x.*\.(xyz|tk|ml|ga|cf|pw)/i,               brand: 'Netflix' },
    { re: /paypa1|paypai|payp4l/i,                              brand: 'PayPal' },
    { re: /amaz0n|amazom|arnazon/i,                             brand: 'Amazon' },
    { re: /g00gle|googIe|g0ogle/i,                              brand: 'Google' },
    { re: /micros0ft|microsofl/i,                               brand: 'Microsoft' },
    { re: /app1e|appIe|appl3/i,                                 brand: 'Apple' },
    { re: /secure.*login.*\.(xyz|tk|ml|ga|cf|pw)/i,             brand: 'Secure Login' },
    { re: /verify.*account.*\.(xyz|tk|ml|ga|cf)/i,              brand: 'Account Verify' },
    { re: /bank.*\.(xyz|tk|ml|ga|cf|pw)/i,                      brand: 'Banking' },
  ]
  for (const { re, brand } of phishPatterns) {
    if (re.test(domain)) {
      issues.push({ type: 'PHISHING', severity: 'CRITICAL',
        desc: `Possible ${brand} phishing domain: ${domain}`,
        rec: 'Leave this site immediately — this is likely a scam' })
      break
    }
  }

  // 4. High-risk TLDs
  const badTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download', '.zip', '.mov']
  if (badTLDs.some(t => domain.endsWith(t))) {
    issues.push({ type: 'SUSPICIOUS_TLD', severity: 'MEDIUM',
      desc: `High-risk domain extension: .${domain.split('.').pop()}`,
      rec: 'This TLD is commonly used for malicious sites — proceed with caution' })
  }

  // 5. IP address as domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
    issues.push({ type: 'IP_DOMAIN', severity: 'HIGH',
      desc: `IP address used as domain: ${domain}`,
      rec: 'Legitimate sites use domain names, not raw IP addresses' })
  }

  // 6. Suspicious URL patterns
  const urlStr = url.toLowerCase()
  if (/\.(exe|bat|cmd|ps1|vbs|jar|msi)(\?|$)/i.test(urlStr)) {
    issues.push({ type: 'EXECUTABLE', severity: 'HIGH',
      desc: 'URL points to an executable file download',
      rec: 'Do not download or run this file unless you trust the source' })
  }
  if (/base64/i.test(urlStr)) {
    issues.push({ type: 'OBFUSCATION', severity: 'MEDIUM',
      desc: 'Base64 encoding detected in URL (possible obfuscation)',
      rec: 'Obfuscated URLs are often used to hide malicious destinations' })
  }

  // 7. URL shorteners
  if (/^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.link|rb\.gy|is\.gd)$/.test(domain)) {
    issues.push({ type: 'URL_SHORTENER', severity: 'LOW',
      desc: `URL shortener detected: ${domain}`,
      rec: 'Shortened URLs hide the real destination — hover to preview before clicking' })
  }

  // 8. Homograph / punycode
  if (domain.startsWith('xn--')) {
    issues.push({ type: 'HOMOGRAPH', severity: 'HIGH',
      desc: 'Punycode/homograph domain detected — may impersonate a trusted site',
      rec: 'Check the actual domain carefully before entering any information' })
  }

  // 9. Blocked list check
  const blocked = await getBlocked()
  if (blocked.find(s => domain === s.domain || domain.endsWith('.' + s.domain))) {
    issues.push({ type: 'BLOCKED', severity: 'CRITICAL',
      desc: 'This site is on your blocked list',
      rec: 'You have previously blocked this site' })
  }

  // ── Score & risk level ────────────────────────────────────────────────────
  const sevScore = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 5 }
  const deduction = issues.reduce((s, i) => s + (sevScore[i.severity] || 0), 0)
  const score = Math.max(0, 100 - deduction)
  const riskLevel = score >= 80 ? 'SAFE' : score >= 60 ? 'LOW' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'HIGH' : 'CRITICAL'

  return { url, domain, isHTTPS, riskLevel, score, issues, checkedAt: new Date().toISOString() }
}

// ── Scan a site and update everything ────────────────────────────────────────
async function scanSite(url, tabId) {
  const result = await performScan(url)
  await addScanResult(result)
  await updateStats(result.riskLevel, result.issues.length)
  updateBadge(tabId, result.riskLevel)

  // Notifications disabled as requested.

  // Auto-block CRITICAL phishing
  if (result.riskLevel === 'CRITICAL') {
    const phishIssue = result.issues.find(i => i.type === 'PHISHING')
    if (phishIssue) {
      await addBlocked(result.domain, phishIssue.desc, 'CRITICAL')
    }
  }

  return result
}

// ── Badge ─────────────────────────────────────────────────────────────────────
function updateBadge(tabId, riskLevel) {
  const cfg = {
    SAFE:     { text: '✓',   color: '#22c55e' },
    LOW:      { text: '!',   color: '#84cc16' },
    MEDIUM:   { text: '!!',  color: '#eab308' },
    HIGH:     { text: '!!!', color: '#f97316' },
    CRITICAL: { text: '✕',   color: '#ef4444' },
    UNKNOWN:  { text: '?',   color: '#6b7280' },
  }
  const c = cfg[riskLevel] || cfg.UNKNOWN
  chrome.action.setBadgeText({ text: c.text, tabId }).catch(() => {})
  chrome.action.setBadgeBackgroundColor({ color: c.color, tabId }).catch(() => {})
}

// ── Event listeners ───────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url?.startsWith('http')) {
    try { await scanSite(tab.url, tabId) } catch {}
  }
})

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  ;(async () => {
    switch (msg.type) {
      case 'SCAN_CURRENT': {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        if (tab?.url) sendResponse({ result: await scanSite(tab.url, tab.id) })
        break
      }
      case 'GET_LATEST': {
        const history = await getScanHistory()
        sendResponse({ result: history.find(h => h.domain === msg.domain) || null })
        break
      }
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
      case 'GET_STATS':
        sendResponse({ stats: await getStats() })
        break
      case 'CLEAR_HISTORY':
        await chrome.storage.local.set({ scanHistory: [], stats: { totalScans: 0, totalBlocked: 0, totalThreats: 0, byRisk: {} } })
        sendResponse({ success: true })
        break
      case 'LOG_ISSUE': {
        const history = await getScanHistory()
        const h = history.find(entry => entry.domain === sender.tab.url.split('/')[2])
        if (h) {
          h.issues.push(msg.data)
          // Update score
          const sevScore = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 5 }
          const deduction = h.issues.reduce((s, i) => s + (sevScore[i.severity] || 0), 0)
          h.score = Math.max(0, 100 - deduction)
          h.riskLevel = h.score >= 80 ? 'SAFE' : h.score >= 60 ? 'LOW' : h.score >= 40 ? 'MEDIUM' : h.score >= 20 ? 'HIGH' : 'CRITICAL'
          await chrome.storage.local.set({ scanHistory: history })
          updateBadge(sender.tab.id, h.riskLevel)
        }
        sendResponse({ success: true })
        break
      }
      case 'CONTENT_SCAN':

        await addScanResult({ ...msg.data, domain: msg.domain })
        await updateStats(msg.data.riskLevel, msg.data.issues?.length || 0)
        const [t] = await chrome.tabs.query({ active: true, currentWindow: true })
        if (t) updateBadge(t.id, msg.data.riskLevel)
        sendResponse({ success: true })
        break
    }
  })()
  return true
})
