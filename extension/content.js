// ── AI Cyber Defense Shield — Content Script ─────────────────────────────────
;(function () {
  if (window.__cyberShieldLoaded) return
  window.__cyberShieldLoaded = true

  const url = window.location.href
  const domain = window.location.hostname
  const isHTTPS = window.location.protocol === 'https:'
  const issues = []

  // ── Inject styles ─────────────────────────────────────────────────────────
  const style = document.createElement('style')
  style.textContent = `
    #cs-shield-popup {
      position: fixed;
      top: 16px;
      right: 16px;
      z-index: 2147483647;
      width: 360px;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 13px;
      color: #e6edf3;
      transform: translateX(400px);
      opacity: 0;
      transition: transform 0.35s cubic-bezier(0.34,1.56,0.64,1), opacity 0.3s ease;
      overflow: hidden;
    }
    #cs-shield-popup.cs-show {
      transform: translateX(0);
      opacity: 1;
    }
    #cs-shield-popup.cs-hide {
      transform: translateX(400px);
      opacity: 0;
    }
    .cs-header {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 14px 16px 10px;
      border-bottom: 1px solid #30363d;
    }
    .cs-logo { font-size: 20px; }
    .cs-title { font-weight: 700; font-size: 13px; flex: 1; }
    .cs-close {
      background: none;
      border: none;
      color: #8b949e;
      cursor: pointer;
      font-size: 16px;
      padding: 2px 6px;
      border-radius: 4px;
      line-height: 1;
    }
    .cs-close:hover { background: #30363d; color: #e6edf3; }
    .cs-risk-bar {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      border-bottom: 1px solid #30363d;
    }
    .cs-risk-icon { font-size: 28px; }
    .cs-risk-info { flex: 1; }
    .cs-risk-label { font-size: 10px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }
    .cs-risk-value { font-size: 18px; font-weight: 800; margin-top: 1px; }
    .cs-risk-domain { font-size: 11px; color: #8b949e; font-family: monospace; margin-top: 1px; }
    .cs-score { text-align: center; }
    .cs-score-num { font-size: 26px; font-weight: 800; }
    .cs-score-label { font-size: 10px; color: #8b949e; }
    .cs-https {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 10px;
      margin-top: 3px;
    }
    .cs-https-ok  { background: #14532d44; color: #22c55e; border: 1px solid #16a34a44; }
    .cs-https-bad { background: #7f1d1d44; color: #ef4444; border: 1px solid #dc262644; }
    .cs-issues { padding: 10px 16px; max-height: 220px; overflow-y: auto; }
    .cs-issues::-webkit-scrollbar { width: 4px; }
    .cs-issues::-webkit-scrollbar-track { background: #161b22; }
    .cs-issues::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
    .cs-issue {
      display: flex;
      gap: 8px;
      padding: 8px 10px;
      border-radius: 8px;
      border: 1px solid;
      margin-bottom: 6px;
    }
    .cs-issue:last-child { margin-bottom: 0; }
    .cs-sev {
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
      white-space: nowrap;
      align-self: flex-start;
      margin-top: 1px;
    }
    .cs-sev-critical { background: #7f1d1d; color: #fca5a5; }
    .cs-sev-high     { background: #7c2d12; color: #fdba74; }
    .cs-sev-medium   { background: #713500; color: #fde68a; }
    .cs-sev-low      { background: #14532d; color: #86efac; }
    .cs-issue-critical { background: #7f1d1d22; border-color: #dc262644; }
    .cs-issue-high     { background: #7c2d1222; border-color: #ea580c44; }
    .cs-issue-medium   { background: #71350022; border-color: #ca8a0444; }
    .cs-issue-low      { background: #14532d22; border-color: #16a34a44; }
    .cs-issue-desc { font-size: 12px; color: #e6edf3; }
    .cs-issue-rec  { font-size: 11px; color: #8b949e; margin-top: 2px; }
    .cs-actions {
      display: flex;
      gap: 8px;
      padding: 10px 16px 14px;
      border-top: 1px solid #30363d;
    }
    .cs-btn {
      flex: 1;
      padding: 8px;
      border-radius: 6px;
      border: 1px solid;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s;
    }
    .cs-btn-block  { background: #7f1d1d; border-color: #dc2626; color: #fca5a5; }
    .cs-btn-block:hover { background: #991b1b; }
    .cs-btn-dismiss { background: #161b22; border-color: #30363d; color: #8b949e; }
    .cs-btn-dismiss:hover { color: #e6edf3; border-color: #8b949e; }
    .cs-safe-msg {
      padding: 16px;
      text-align: center;
      color: #22c55e;
      font-size: 13px;
    }
    .cs-progress {
      height: 3px;
      background: #30363d;
      position: relative;
      overflow: hidden;
    }
    .cs-progress-bar {
      height: 100%;
      transition: width 0.5s ease;
    }
    .cs-no-issues { padding: 12px 16px; text-align: center; color: #8b949e; font-size: 12px; }
  `
  document.head.appendChild(style)

  // ── Checks ────────────────────────────────────────────────────────────────

  // 1. HTTP
  if (!isHTTPS && !['localhost','127.0.0.1'].includes(domain)) {
    issues.push({ type: 'NO_HTTPS', severity: 'HIGH',
      desc: 'No HTTPS — data sent in plain text',
      rec: 'Never enter passwords or payment info on HTTP sites' })
  }

  // 2. Password on HTTP
  if (!isHTTPS) {
    const pwFields = document.querySelectorAll('input[type="password"]')
    if (pwFields.length > 0) {
      issues.push({ type: 'PASSWORD_HTTP', severity: 'CRITICAL',
        desc: `Password field on unencrypted HTTP page`,
        rec: 'Your password will be sent in plain text — leave this site' })
    }
  }

  // 3. Payment fields
  const paySelectors = 'input[name*="card"],input[name*="credit"],input[name*="cvv"],input[name*="cvc"],input[autocomplete*="cc-"],input[placeholder*="card"]'
  const payFields = document.querySelectorAll(paySelectors)
  if (payFields.length > 0 && !isHTTPS) {
    issues.push({ type: 'PAYMENT_HTTP', severity: 'CRITICAL',
      desc: 'Payment/card fields on HTTP page',
      rec: 'DO NOT enter card details — connection is not encrypted' })
  }

  // 4. Mixed content
  if (isHTTPS) {
    let httpCount = 0
    document.querySelectorAll('script[src],link[href],img[src],iframe[src]').forEach(el => {
      const src = el.src || el.href || ''
      if (typeof src === 'string' && src.startsWith('http://')) httpCount++
    })
    if (httpCount > 0) {
      issues.push({ type: 'MIXED_CONTENT', severity: 'MEDIUM',
        desc: `Mixed content: ${httpCount} HTTP resource(s) on HTTPS page`,
        rec: 'HTTP resources can be intercepted even on HTTPS pages' })
    }
  }

  // 5. Suspicious form actions
  document.querySelectorAll('form').forEach(form => {
    const action = form.action || ''
    if (action.startsWith('http://') && !['localhost','127.0.0.1'].includes(domain)) {
      issues.push({ type: 'FORM_HTTP', severity: 'HIGH',
        desc: `Form submits to HTTP: ${action.substring(0, 50)}`,
        rec: 'Form data will be transmitted unencrypted' })
    }
  })

  // 6. Phishing patterns
  const phishPatterns = [
    { re: /paypa1|paypai|payp4l/i, name: 'PayPal' },
    { re: /amaz0n|amazom|arnazon/i, name: 'Amazon' },
    { re: /g00gle|googIe|g0ogle/i, name: 'Google' },
    { re: /micros0ft|microsofl/i,   name: 'Microsoft' },
    { re: /app1e|appIe|appl3/i,     name: 'Apple' },
  ]
  for (const { re, name } of phishPatterns) {
    if (re.test(domain)) {
      issues.push({ type: 'PHISHING', severity: 'CRITICAL',
        desc: `Possible ${name} phishing domain: ${domain}`,
        rec: 'Leave this site immediately — this is likely a scam' })
    }
  }

  // 7. Iframe embedding
  if (window.self !== window.top) {
    issues.push({ type: 'IFRAME', severity: 'MEDIUM',
      desc: 'Page loaded inside an iframe (possible clickjacking)',
      rec: 'Be cautious — buttons may trigger hidden actions' })
  }

  // 8. Suspicious scripts
  document.querySelectorAll('script').forEach(s => {
    const src = s.src || s.textContent || ''
    if (/cryptominer|coinhive|coin-hive|minero/i.test(src)) {
      issues.push({ type: 'MINER', severity: 'CRITICAL',
        desc: 'Cryptominer script detected on this page',
        rec: 'Leave immediately — this site is using your CPU to mine crypto' })
    }
  })

  // ── Calculate risk ────────────────────────────────────────────────────────
  const sevScore = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 5 }
  const deduction = issues.reduce((s, i) => s + (sevScore[i.severity] || 0), 0)
  const score = Math.max(0, 100 - deduction)
  const riskLevel = score >= 80 ? 'SAFE' : score >= 60 ? 'LOW' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'HIGH' : 'CRITICAL'

  // Only show popup for non-safe pages, or safe pages briefly
  const shouldShow = riskLevel !== 'SAFE' || issues.length === 0

  // ── Build popup ───────────────────────────────────────────────────────────
  const RISK_CFG = {
    SAFE:     { icon: '✅', color: '#22c55e', label: 'Safe',        barColor: '#22c55e' },
    LOW:      { icon: '🟡', color: '#84cc16', label: 'Low Risk',    barColor: '#84cc16' },
    MEDIUM:   { icon: '⚠️', color: '#eab308', label: 'Medium Risk', barColor: '#eab308' },
    HIGH:     { icon: '🟠', color: '#f97316', label: 'High Risk',   barColor: '#f97316' },
    CRITICAL: { icon: '🔴', color: '#ef4444', label: 'CRITICAL',    barColor: '#ef4444' },
  }
  const cfg = RISK_CFG[riskLevel] || RISK_CFG.SAFE

  const popup = document.createElement('div')
  popup.id = 'cs-shield-popup'

  const issuesHTML = issues.length === 0
    ? `<div class="cs-no-issues">✅ No security issues detected on this page</div>`
    : issues.map(i => `
        <div class="cs-issue cs-issue-${i.severity.toLowerCase()}">
          <span class="cs-sev cs-sev-${i.severity.toLowerCase()}">${i.severity}</span>
          <div style="flex:1">
            <div class="cs-issue-desc">${i.desc}</div>
            <div class="cs-issue-rec">→ ${i.rec}</div>
          </div>
        </div>
      `).join('')

  popup.innerHTML = `
    <div class="cs-progress">
      <div class="cs-progress-bar" style="width:${score}%; background:${cfg.barColor}"></div>
    </div>
    <div class="cs-header">
      <span class="cs-logo">🛡️</span>
      <span class="cs-title">AI Cyber Defense Shield</span>
      <button class="cs-close" id="cs-close-btn">✕</button>
    </div>
    <div class="cs-risk-bar">
      <span class="cs-risk-icon">${cfg.icon}</span>
      <div class="cs-risk-info">
        <div class="cs-risk-label">Risk Level</div>
        <div class="cs-risk-value" style="color:${cfg.color}">${cfg.label}</div>
        <div class="cs-risk-domain">${domain}</div>
        <span class="cs-https ${isHTTPS ? 'cs-https-ok' : 'cs-https-bad'}">
          ${isHTTPS ? '🔒 HTTPS' : '⚠️ HTTP'}
        </span>
      </div>
      <div class="cs-score">
        <div class="cs-score-num" style="color:${cfg.color}">${score}</div>
        <div class="cs-score-label">/ 100</div>
      </div>
    </div>
    <div class="cs-issues">${issuesHTML}</div>
    <div class="cs-actions">
      ${riskLevel !== 'SAFE' ? `<button class="cs-btn cs-btn-block" id="cs-block-btn">🚫 Block Site</button>` : ''}
      <button class="cs-btn cs-btn-dismiss" id="cs-dismiss-btn">Dismiss</button>
    </div>
  `

  document.body.appendChild(popup)

  // Animate in
  requestAnimationFrame(() => {
    requestAnimationFrame(() => popup.classList.add('cs-show'))
  })

  // Auto-dismiss safe pages after 3s
  let autoDismiss = null
  if (riskLevel === 'SAFE') {
    autoDismiss = setTimeout(() => dismiss(), 3000)
  }

  function dismiss() {
    if (autoDismiss) clearTimeout(autoDismiss)
    popup.classList.remove('cs-show')
    popup.classList.add('cs-hide')
    setTimeout(() => popup.remove(), 400)
  }

  document.getElementById('cs-close-btn')?.addEventListener('click', dismiss)
  document.getElementById('cs-dismiss-btn')?.addEventListener('click', dismiss)

  document.getElementById('cs-block-btn')?.addEventListener('click', () => {
    chrome.runtime.sendMessage(
      { type: 'BLOCK_SITE', domain, reason: `${riskLevel} risk — blocked from page alert`, severity: riskLevel },
      () => {
        const btn = document.getElementById('cs-block-btn')
        if (btn) { btn.textContent = '✅ Site Blocked'; btn.style.background = '#14532d'; btn.style.color = '#86efac' }
        setTimeout(dismiss, 1500)
      }
    )
  })

  // Send to background for dashboard sync
  chrome.runtime.sendMessage({
    type: 'CONTENT_ISSUES',
    url, domain, riskLevel,
    scanData: { riskLevel, score, issues, isHTTPS },
  })
})()

// ── PAGE DEEP SCANNER ─────────────────────────────────────────────────────────
// Runs after DOM is ready, scans all links/text/images and masks threats
;(function pageScanner() {
  if (window.__csPageScanDone) return
  window.__csPageScanDone = true

  // Add scanner styles
  const scanStyle = document.createElement('style')
  scanStyle.textContent = `
    .cs-phish-link {
      position: relative !important;
      outline: 2px solid #ef4444 !important;
      outline-offset: 2px !important;
      border-radius: 3px !important;
    }
    .cs-phish-link::after {
      content: '⚠️ Suspicious Link' !important;
      position: absolute !important;
      bottom: calc(100% + 4px) !important;
      left: 0 !important;
      background: #7f1d1d !important;
      color: #fca5a5 !important;
      font-size: 11px !important;
      font-weight: 600 !important;
      padding: 3px 8px !important;
      border-radius: 4px !important;
      white-space: nowrap !important;
      z-index: 2147483646 !important;
      pointer-events: none !important;
      font-family: sans-serif !important;
      border: 1px solid #dc2626 !important;
      display: none !important;
    }
    .cs-phish-link:hover::after { display: block !important; }

    .cs-masked-link {
      background: #1a0a0a !important;
      color: transparent !important;
      border-radius: 4px !important;
      cursor: not-allowed !important;
      outline: 2px solid #ef4444 !important;
      position: relative !important;
      user-select: none !important;
    }
    .cs-masked-link::before {
      content: '🛡️ Blocked: Phishing Link' !important;
      position: absolute !important;
      inset: 0 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      color: #ef4444 !important;
      font-size: 11px !important;
      font-weight: 700 !important;
      font-family: sans-serif !important;
      background: #1a0a0a !important;
      border-radius: 4px !important;
    }

    .cs-warn-text {
      background: linear-gradient(90deg, #7c2d1244, #71350044) !important;
      outline: 1px solid #f9731644 !important;
      border-radius: 2px !important;
      cursor: help !important;
    }

    .cs-masked-img {
      filter: blur(8px) grayscale(1) !important;
      outline: 3px solid #ef4444 !important;
      position: relative !important;
    }

    .cs-scan-badge {
      position: fixed;
      bottom: 16px;
      right: 16px;
      z-index: 2147483646;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 8px 12px;
      font-family: sans-serif;
      font-size: 12px;
      color: #8b949e;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4);
      cursor: pointer;
      transition: all 0.2s;
    }
    .cs-scan-badge:hover { border-color: #8b949e; color: #e6edf3; }
    .cs-scan-badge-count {
      background: #ef4444;
      color: white;
      font-size: 10px;
      font-weight: 700;
      padding: 1px 6px;
      border-radius: 10px;
    }
  `
  document.head.appendChild(scanStyle)

  // ── Phishing link patterns ────────────────────────────────────────────────
  const PHISH_LINK_PATTERNS = [
    // Brand impersonation in URL
    /paypa[l1].*\.(xyz|tk|ml|ga|cf|pw|top|click|info|biz)/i,
    /amaz[o0]n.*\.(xyz|tk|ml|ga|cf|pw|top)/i,
    /g[o0]{2}gle.*\.(xyz|tk|ml|ga|cf|pw)/i,
    /micros[o0]ft.*\.(xyz|tk|ml|ga|cf|pw)/i,
    /app[l1]e.*\.(xyz|tk|ml|ga|cf|pw)/i,
    /netfl[i1]x.*\.(xyz|tk|ml|ga|cf|pw)/i,
    // Suspicious patterns
    /secure.*login.*\.(xyz|tk|ml|ga|cf|pw)/i,
    /verify.*account.*\.(xyz|tk|ml|ga|cf)/i,
    /update.*payment.*\.(xyz|tk|ml|ga|cf)/i,
    /confirm.*identity.*\.(xyz|tk|ml|ga|cf)/i,
    // IP address links
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    // URL shorteners hiding destination
    /bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|short\.link/,
    // Homograph attacks (unicode lookalikes)
    /xn--/,
  ]

  // ── Suspicious text patterns ──────────────────────────────────────────────
  const WARN_TEXT_PATTERNS = [
    /your account (has been|will be) (suspended|terminated|locked|disabled)/i,
    /verify your (account|identity|payment|card) (immediately|now|urgently)/i,
    /you (have won|are selected|are a winner)/i,
    /claim your (prize|reward|gift card) now/i,
    /urgent.*action required/i,
    /your (password|credit card|bank account) (has been|was) compromised/i,
    /send (bitcoin|crypto|gift card) to/i,
    /irs.*tax.*refund.*click/i,
    /congratulations.*selected.*click/i,
    /your computer (is|has been) (infected|hacked|compromised)/i,
    /call.*microsoft.*support.*immediately/i,
    /free.*iphone.*click.*here/i,
  ]

  // ── Suspicious image src patterns ─────────────────────────────────────────
  const SUSPICIOUS_IMG_PATTERNS = [
    /tracking.*pixel/i,
    /1x1\.(gif|png)/i,
    /pixel\.gif/i,
    /beacon\.(gif|png)/i,
  ]

  let flaggedLinks = 0
  let flaggedText = 0
  let flaggedImages = 0
  const findings = []

  // ── Scan all links ────────────────────────────────────────────────────────
  document.querySelectorAll('a[href]').forEach(el => {
    const href = el.getAttribute('href') || ''
    const text = el.textContent?.trim() || ''
    if (!href || href.startsWith('#') || href.startsWith('javascript:void')) return

    let isSuspicious = false
    let reason = ''

    // Check href against phishing patterns
    for (const pattern of PHISH_LINK_PATTERNS) {
      if (pattern.test(href)) {
        isSuspicious = true
        reason = `Suspicious URL pattern: ${href.substring(0, 60)}`
        break
      }
    }

    // Check if link text says one domain but href goes to another
    if (!isSuspicious && text.includes('.') && href.startsWith('http')) {
      try {
        const linkDomain = new URL(href).hostname
        const textDomain = text.match(/[\w-]+\.(com|org|net|io|co)/)?.[0]
        if (textDomain && !linkDomain.includes(textDomain.split('.')[0])) {
          isSuspicious = true
          reason = `Link text says "${textDomain}" but goes to "${linkDomain}"`
        }
      } catch {}
    }

    // javascript: protocol links (XSS risk)
    if (!isSuspicious && href.toLowerCase().startsWith('javascript:') && !href.includes('void')) {
      isSuspicious = true
      reason = 'javascript: link — possible XSS'
    }

    if (isSuspicious) {
      flaggedLinks++
      findings.push({ type: 'PHISHING_LINK', element: el, reason })

      // Mask critical phishing links completely
      const isCritical = PHISH_LINK_PATTERNS.slice(0, 8).some(p => p.test(href))
      if (isCritical) {
        el.classList.add('cs-masked-link')
        el.addEventListener('click', e => { e.preventDefault(); e.stopPropagation() }, true)
      } else {
        el.classList.add('cs-phish-link')
        el.title = `⚠️ AI Shield: ${reason}`
      }
    }
  })

  // ── Scan text nodes for scam phrases ─────────────────────────────────────
  function walkTextNodes(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent || ''
      for (const pattern of WARN_TEXT_PATTERNS) {
        if (pattern.test(text)) {
          // Wrap in a span with warning style
          const span = document.createElement('span')
          span.className = 'cs-warn-text'
          span.title = '⚠️ AI Shield: Suspicious text pattern detected'
          span.textContent = text
          try {
            node.parentNode?.replaceChild(span, node)
            flaggedText++
            findings.push({ type: 'SCAM_TEXT', reason: text.substring(0, 80) })
          } catch {}
          break
        }
      }
    } else if (
      node.nodeType === Node.ELEMENT_NODE &&
      !['SCRIPT','STYLE','NOSCRIPT','IFRAME','CS-SHIELD-POPUP'].includes(node.nodeName) &&
      !node.id?.startsWith('cs-')
    ) {
      Array.from(node.childNodes).forEach(walkTextNodes)
    }
  }
  walkTextNodes(document.body)

  // ── Scan images ───────────────────────────────────────────────────────────
  document.querySelectorAll('img[src]').forEach(img => {
    const src = img.getAttribute('src') || ''
    // Tracking pixels
    for (const pattern of SUSPICIOUS_IMG_PATTERNS) {
      if (pattern.test(src)) {
        img.classList.add('cs-masked-img')
        img.title = '⚠️ AI Shield: Tracking pixel detected and masked'
        flaggedImages++
        findings.push({ type: 'TRACKING_PIXEL', reason: src.substring(0, 60) })
        break
      }
    }
    // Tiny images (likely tracking pixels) — 1x1 or very small
    if (img.width <= 2 && img.height <= 2 && img.width > 0) {
      img.style.display = 'none'
      flaggedImages++
      findings.push({ type: 'TRACKING_PIXEL', reason: `Tiny image (${img.width}x${img.height}): ${src.substring(0, 40)}` })
    }
  })

  // ── Show scan results badge ───────────────────────────────────────────────
  const total = flaggedLinks + flaggedText + flaggedImages
  if (total > 0) {
    const badge = document.createElement('div')
    badge.className = 'cs-scan-badge'
    badge.id = 'cs-scan-badge'
    badge.innerHTML = `
      🛡️ Page Scan Complete
      <span class="cs-scan-badge-count">${total} threat${total > 1 ? 's' : ''} masked</span>
    `
    badge.title = `${flaggedLinks} phishing links, ${flaggedText} scam texts, ${flaggedImages} trackers`

    // Click to show details
    badge.addEventListener('click', () => {
      showScanReport(flaggedLinks, flaggedText, flaggedImages, findings)
      badge.remove()
    })

    document.body.appendChild(badge)

    // Auto-hide after 8s
    setTimeout(() => badge.remove(), 8000)
  }

  // ── Scan report popup ─────────────────────────────────────────────────────
  function showScanReport(links, texts, images, findings) {
    const existing = document.getElementById('cs-scan-report')
    if (existing) existing.remove()

    const report = document.createElement('div')
    report.id = 'cs-scan-report'
    report.style.cssText = `
      position: fixed; bottom: 16px; right: 16px; z-index: 2147483647;
      width: 340px; max-height: 400px; overflow-y: auto;
      background: #0d1117; border: 1px solid #30363d; border-radius: 12px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.6); font-family: sans-serif;
      font-size: 12px; color: #e6edf3;
    `

    const rows = findings.slice(0, 15).map(f => {
      const icon = f.type === 'PHISHING_LINK' ? '🔗' : f.type === 'SCAM_TEXT' ? '📝' : '👁️'
      const label = f.type === 'PHISHING_LINK' ? 'Phishing Link' : f.type === 'SCAM_TEXT' ? 'Scam Text' : 'Tracker'
      const color = f.type === 'PHISHING_LINK' ? '#fca5a5' : f.type === 'SCAM_TEXT' ? '#fdba74' : '#fde68a'
      return `
        <div style="display:flex;gap:8px;padding:7px 12px;border-bottom:1px solid #30363d22;">
          <span>${icon}</span>
          <div>
            <div style="color:${color};font-weight:600;font-size:11px;">${label}</div>
            <div style="color:#8b949e;font-size:11px;margin-top:1px;">${f.reason?.substring(0, 55) || ''}</div>
          </div>
        </div>
      `
    }).join('')

    report.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:1px solid #30363d;">
        <div style="font-weight:700;">🛡️ Page Scan Report</div>
        <button onclick="this.closest('#cs-scan-report').remove()" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:16px;">✕</button>
      </div>
      <div style="display:flex;gap:8px;padding:10px 14px;border-bottom:1px solid #30363d;">
        <div style="flex:1;text-align:center;background:#7f1d1d22;border:1px solid #dc262644;border-radius:6px;padding:8px;">
          <div style="font-size:20px;font-weight:800;color:#ef4444;">${links}</div>
          <div style="color:#8b949e;font-size:10px;">Phishing Links</div>
        </div>
        <div style="flex:1;text-align:center;background:#7c2d1222;border:1px solid #ea580c44;border-radius:6px;padding:8px;">
          <div style="font-size:20px;font-weight:800;color:#f97316;">${texts}</div>
          <div style="color:#8b949e;font-size:10px;">Scam Texts</div>
        </div>
        <div style="flex:1;text-align:center;background:#71350022;border:1px solid #ca8a0444;border-radius:6px;padding:8px;">
          <div style="font-size:20px;font-weight:800;color:#eab308;">${images}</div>
          <div style="color:#8b949e;font-size:10px;">Trackers</div>
        </div>
      </div>
      ${rows || '<div style="padding:12px;text-align:center;color:#8b949e;">No details available</div>'}
      ${findings.length > 15 ? `<div style="padding:8px;text-align:center;color:#8b949e;font-size:11px;">+${findings.length - 15} more findings</div>` : ''}
    `
    document.body.appendChild(report)
  }

  // ── Watch for dynamic content (SPAs) ─────────────────────────────────────
  // Re-scan new links added after initial load
  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      m.addedNodes.forEach(node => {
        if (node.nodeType !== Node.ELEMENT_NODE) return
        ;(node).querySelectorAll('a[href]').forEach(el => {
          const href = el.getAttribute('href') || ''
          for (const pattern of PHISH_LINK_PATTERNS) {
            if (pattern.test(href)) {
              el.classList.add('cs-phish-link')
              el.title = '⚠️ AI Shield: Suspicious link detected'
              break
            }
          }
        })
      })
    }
  })
  observer.observe(document.body, { childList: true, subtree: true })
})()
