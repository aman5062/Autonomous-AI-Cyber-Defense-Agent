// ── AI Cyber Defense Shield — Content Script (Standalone) ────────────────────
;(function () {
  if (window.__csShieldLoaded) return
  window.__csShieldLoaded = true

  const domain = window.location.hostname
  const isHTTPS = window.location.protocol === 'https:'
  const isLocal = ['localhost', '127.0.0.1', '::1'].includes(domain)
  const issues = []

  // ── Inject styles ─────────────────────────────────────────────────────────
  const style = document.createElement('style')
  style.textContent = `
    #cs-popup {
      position: fixed; top: 16px; right: 16px; z-index: 2147483647;
      width: 360px; background: #0d1117; border: 1px solid #30363d;
      border-radius: 12px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 13px; color: #e6edf3; overflow: hidden;
      box-shadow: 0 8px 32px rgba(0,0,0,0.7);
      transform: translateX(400px); opacity: 0;
      transition: transform 0.35s cubic-bezier(0.34,1.56,0.64,1), opacity 0.3s ease;
    }
    #cs-popup.show { transform: translateX(0); opacity: 1; }
    #cs-popup.hide { transform: translateX(400px); opacity: 0; }
    .cs-bar { height: 4px; }
    .cs-head { display:flex; align-items:center; gap:10px; padding:12px 14px 10px; border-bottom:1px solid #30363d; }
    .cs-head-title { font-weight:700; font-size:13px; flex:1; }
    .cs-close { background:none; border:none; color:#8b949e; cursor:pointer; font-size:16px; padding:2px 6px; border-radius:4px; }
    .cs-close:hover { background:#30363d; color:#e6edf3; }
    .cs-risk { display:flex; align-items:center; gap:12px; padding:12px 14px; border-bottom:1px solid #30363d; }
    .cs-risk-icon { font-size:26px; }
    .cs-risk-label { font-size:10px; color:#8b949e; text-transform:uppercase; letter-spacing:.05em; }
    .cs-risk-val { font-size:17px; font-weight:800; margin-top:1px; }
    .cs-risk-domain { font-size:11px; color:#8b949e; font-family:monospace; margin-top:1px; }
    .cs-https { display:inline-flex; align-items:center; gap:3px; font-size:11px; font-weight:600; padding:2px 7px; border-radius:10px; margin-top:3px; }
    .cs-https-ok  { background:#14532d44; color:#22c55e; border:1px solid #16a34a44; }
    .cs-https-bad { background:#7f1d1d44; color:#ef4444; border:1px solid #dc262644; }
    .cs-score { text-align:center; margin-left:auto; }
    .cs-score-num { font-size:24px; font-weight:800; }
    .cs-score-sub { font-size:10px; color:#8b949e; }
    .cs-issues { padding:10px 14px; max-height:200px; overflow-y:auto; }
    .cs-issues::-webkit-scrollbar { width:4px; }
    .cs-issues::-webkit-scrollbar-thumb { background:#30363d; border-radius:2px; }
    .cs-issue { display:flex; gap:8px; padding:7px 9px; border-radius:7px; border:1px solid; margin-bottom:5px; }
    .cs-issue:last-child { margin-bottom:0; }
    .cs-sev { font-size:10px; font-weight:700; padding:2px 5px; border-radius:3px; white-space:nowrap; align-self:flex-start; margin-top:1px; }
    .sev-CRITICAL { background:#7f1d1d; color:#fca5a5; }
    .sev-HIGH     { background:#7c2d12; color:#fdba74; }
    .sev-MEDIUM   { background:#713500; color:#fde68a; }
    .sev-LOW      { background:#14532d; color:#86efac; }
    .iss-CRITICAL { background:#7f1d1d22; border-color:#dc262644; }
    .iss-HIGH     { background:#7c2d1222; border-color:#ea580c44; }
    .iss-MEDIUM   { background:#71350022; border-color:#ca8a0444; }
    .iss-LOW      { background:#14532d22; border-color:#16a34a44; }
    .cs-issue-desc { font-size:12px; color:#e6edf3; }
    .cs-issue-rec  { font-size:11px; color:#8b949e; margin-top:2px; }
    .cs-no-issues  { padding:12px; text-align:center; color:#8b949e; font-size:12px; }
    .cs-actions { display:flex; gap:7px; padding:10px 14px 13px; border-top:1px solid #30363d; }
    .cs-btn { flex:1; padding:8px; border-radius:6px; border:1px solid; font-size:12px; font-weight:600; cursor:pointer; transition:all .15s; }
    .cs-btn-block   { background:#7f1d1d; border-color:#dc2626; color:#fca5a5; }
    .cs-btn-block:hover { background:#991b1b; }
    .cs-btn-unblock { background:#14532d; border-color:#16a34a; color:#86efac; }
    .cs-btn-dismiss { background:#161b22; border-color:#30363d; color:#8b949e; }
    .cs-btn-dismiss:hover { color:#e6edf3; border-color:#8b949e; }

    /* Page scanner styles */
    .cs-phish-link { outline:2px solid #ef4444 !important; outline-offset:2px !important; border-radius:3px !important; cursor:not-allowed !important; }
    .cs-phish-link::after { content:'⚠️ Suspicious' !important; position:absolute !important; bottom:calc(100% + 4px) !important; left:0 !important; background:#7f1d1d !important; color:#fca5a5 !important; font-size:11px !important; font-weight:600 !important; padding:3px 8px !important; border-radius:4px !important; white-space:nowrap !important; z-index:2147483646 !important; pointer-events:none !important; font-family:sans-serif !important; display:none !important; }
    .cs-phish-link:hover::after { display:block !important; }
    .cs-masked-link { position:relative !important; display:inline-block !important; }
    .cs-masked-link > * { visibility:hidden !important; }
    .cs-masked-link::before { content:'🛡️ Phishing Link Blocked' !important; position:absolute !important; inset:0 !important; display:flex !important; align-items:center !important; justify-content:center !important; background:#1a0a0a !important; color:#ef4444 !important; font-size:11px !important; font-weight:700 !important; font-family:sans-serif !important; border:1px solid #dc2626 !important; border-radius:4px !important; padding:4px 8px !important; white-space:nowrap !important; }
    .cs-warn-text { background:linear-gradient(90deg,#7c2d1244,#71350044) !important; outline:1px solid #f9731644 !important; border-radius:2px !important; cursor:help !important; }
    .cs-scan-toast { position:fixed; bottom:16px; right:16px; z-index:2147483646; background:#161b22; border:1px solid #30363d; border-radius:8px; padding:9px 14px; font-family:sans-serif; font-size:12px; color:#8b949e; display:flex; align-items:center; gap:8px; box-shadow:0 4px 12px rgba(0,0,0,.5); cursor:pointer; animation:cs-slidein .3s ease; }
    .cs-scan-toast:hover { border-color:#8b949e; color:#e6edf3; }
    .cs-toast-count { background:#ef4444; color:white; font-size:10px; font-weight:700; padding:1px 6px; border-radius:10px; }
    @keyframes cs-slidein { from { transform:translateY(20px); opacity:0; } to { transform:translateY(0); opacity:1; } }
    .cs-report { position:fixed; bottom:16px; right:16px; z-index:2147483647; width:320px; max-height:380px; overflow-y:auto; background:#0d1117; border:1px solid #30363d; border-radius:12px; box-shadow:0 8px 32px rgba(0,0,0,.6); font-family:sans-serif; font-size:12px; color:#e6edf3; }
  `
  document.head.appendChild(style)

  // ── Page-level checks ─────────────────────────────────────────────────────

  // 1. HTTP
  if (!isHTTPS && !isLocal) {
    issues.push({ type: 'NO_HTTPS', severity: 'HIGH',
      desc: 'No HTTPS — data sent in plain text',
      rec: 'Never enter passwords or payment info on HTTP sites' })
  }

  // 2. Password on HTTP
  if (!isHTTPS && !isLocal) {
    if (document.querySelectorAll('input[type="password"]').length > 0) {
      issues.push({ type: 'PASSWORD_HTTP', severity: 'CRITICAL',
        desc: 'Password field on unencrypted HTTP page',
        rec: 'Your password will be sent in plain text — leave this site' })
    }
  }

  // 3. Payment fields on HTTP
  const payQ = 'input[name*="card"],input[name*="credit"],input[name*="cvv"],input[name*="cvc"],input[autocomplete*="cc-"],input[placeholder*="card"]'
  if (!isHTTPS && !isLocal && document.querySelectorAll(payQ).length > 0) {
    issues.push({ type: 'PAYMENT_HTTP', severity: 'CRITICAL',
      desc: 'Payment/card fields on HTTP page',
      rec: 'DO NOT enter card details — connection is not encrypted' })
  }

  // 4. Mixed content
  if (isHTTPS) {
    let n = 0
    document.querySelectorAll('script[src],link[href],img[src],iframe[src]').forEach(el => {
      const s = el.src || el.href || ''
      if (typeof s === 'string' && s.startsWith('http://')) n++
    })
    if (n > 0) issues.push({ type: 'MIXED_CONTENT', severity: 'MEDIUM',
      desc: `Mixed content: ${n} HTTP resource(s) on HTTPS page`,
      rec: 'HTTP resources can be intercepted even on HTTPS pages' })
  }

  // 5. Form submits to HTTP
  document.querySelectorAll('form').forEach(f => {
    const a = f.action || ''
    if (a.startsWith('http://') && !isLocal) {
      issues.push({ type: 'FORM_HTTP', severity: 'HIGH',
        desc: `Form submits to HTTP: ${a.substring(0, 50)}`,
        rec: 'Form data will be transmitted unencrypted' })
    }
  })

  // 6. Phishing domain
  const phishRe = [
    [/paypa1|paypai|payp4l/i, 'PayPal'], [/amaz0n|amazom|arnazon/i, 'Amazon'],
    [/g00gle|googIe|g0ogle/i, 'Google'], [/micros0ft|microsofl/i, 'Microsoft'],
    [/app1e|appIe|appl3/i, 'Apple'],
  ]
  for (const [re, name] of phishRe) {
    if (re.test(domain)) {
      issues.push({ type: 'PHISHING', severity: 'CRITICAL',
        desc: `Possible ${name} phishing domain: ${domain}`,
        rec: 'Leave this site immediately — this is likely a scam' })
      break
    }
  }

  // 7. Iframe embedding
  if (window.self !== window.top) {
    issues.push({ type: 'IFRAME', severity: 'MEDIUM',
      desc: 'Page loaded inside an iframe (possible clickjacking)',
      rec: 'Be cautious — buttons may trigger hidden actions' })
  }

  // 8. Cryptominer scripts
  document.querySelectorAll('script').forEach(s => {
    if (/cryptominer|coinhive|coin-hive|minero|cryptoloot/i.test(s.src || s.textContent || '')) {
      issues.push({ type: 'MINER', severity: 'CRITICAL',
        desc: 'Cryptominer script detected',
        rec: 'Leave immediately — this site is mining crypto using your CPU' })
    }
  })

  // ── Risk score ────────────────────────────────────────────────────────────
  const sevScore = { CRITICAL: 40, HIGH: 25, MEDIUM: 10, LOW: 5 }
  const deduction = issues.reduce((s, i) => s + (sevScore[i.severity] || 0), 0)
  const score = Math.max(0, 100 - deduction)
  const riskLevel = score >= 80 ? 'SAFE' : score >= 60 ? 'LOW' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'HIGH' : 'CRITICAL'

  // ── Send to background ────────────────────────────────────────────────────
  chrome.runtime.sendMessage({
    type: 'CONTENT_SCAN',
    domain,
    data: { url: window.location.href, domain, isHTTPS, riskLevel, score, issues }
  })

  // ── Build popup ───────────────────────────────────────────────────────────
  const RISK = {
    SAFE:     { icon: '✅', color: '#22c55e', label: 'Safe',        bar: '#22c55e' },
    LOW:      { icon: '🟡', color: '#84cc16', label: 'Low Risk',    bar: '#84cc16' },
    MEDIUM:   { icon: '⚠️', color: '#eab308', label: 'Medium Risk', bar: '#eab308' },
    HIGH:     { icon: '🟠', color: '#f97316', label: 'High Risk',   bar: '#f97316' },
    CRITICAL: { icon: '🔴', color: '#ef4444', label: 'CRITICAL',    bar: '#ef4444' },
  }
  const cfg = RISK[riskLevel] || RISK.SAFE

  const issuesHTML = issues.length === 0
    ? `<div class="cs-no-issues">✅ No security issues detected</div>`
    : issues.map(i => `
        <div class="cs-issue iss-${i.severity}">
          <span class="cs-sev sev-${i.severity}">${i.severity}</span>
          <div style="flex:1;margin-left:6px">
            <div class="cs-issue-desc">${i.desc}</div>
            <div class="cs-issue-rec">→ ${i.rec}</div>
          </div>
        </div>`).join('')

  const popup = document.createElement('div')
  popup.id = 'cs-popup'
  popup.innerHTML = `
    <div class="cs-bar" style="background:${cfg.bar};width:${score}%;transition:width .5s"></div>
    <div class="cs-head">
      <span style="font-size:18px">🛡️</span>
      <span class="cs-head-title">AI Cyber Defense Shield</span>
      <button class="cs-close" id="cs-x">✕</button>
    </div>
    <div class="cs-risk">
      <span class="cs-risk-icon">${cfg.icon}</span>
      <div>
        <div class="cs-risk-label">Risk Level</div>
        <div class="cs-risk-val" style="color:${cfg.color}">${cfg.label}</div>
        <div class="cs-risk-domain">${domain}</div>
        <span class="cs-https ${isHTTPS ? 'cs-https-ok' : 'cs-https-bad'}">${isHTTPS ? '🔒 HTTPS' : '⚠️ HTTP'}</span>
      </div>
      <div class="cs-score">
        <div class="cs-score-num" style="color:${cfg.color}">${score}</div>
        <div class="cs-score-sub">/ 100</div>
      </div>
    </div>
    <div class="cs-issues">${issuesHTML}</div>
    <div class="cs-actions">
      ${riskLevel !== 'SAFE' ? `<button class="cs-btn cs-btn-block" id="cs-block">🚫 Block Site</button>` : ''}
      <button class="cs-btn cs-btn-dismiss" id="cs-dismiss">Dismiss</button>
    </div>
  `
  document.body.appendChild(popup)
  requestAnimationFrame(() => requestAnimationFrame(() => popup.classList.add('show')))

  let timer = riskLevel === 'SAFE' ? setTimeout(dismiss, 3000) : null

  function dismiss() {
    clearTimeout(timer)
    popup.classList.remove('show')
    popup.classList.add('hide')
    setTimeout(() => popup.remove(), 400)
  }

  document.getElementById('cs-x').onclick = dismiss
  document.getElementById('cs-dismiss').onclick = dismiss
  document.getElementById('cs-block')?.addEventListener('click', () => {
    chrome.runtime.sendMessage(
      { type: 'BLOCK_SITE', domain, reason: `${riskLevel} risk`, severity: riskLevel },
      () => {
        const btn = document.getElementById('cs-block')
        if (btn) { btn.className = 'cs-btn cs-btn-unblock'; btn.textContent = '✅ Blocked' }
        setTimeout(dismiss, 1500)
      }
    )
  })

  // ── Page deep scan ────────────────────────────────────────────────────────
  setTimeout(runPageScan, 800)

  function runPageScan() {
    const PHISH_LINK = [
      /paypa[l1].*\.(xyz|tk|ml|ga|cf|pw|top)/i,
      /amaz[o0]n.*\.(xyz|tk|ml|ga|cf|pw)/i,
      /g[o0]{2}gle.*\.(xyz|tk|ml|ga|cf|pw)/i,
      /micros[o0]ft.*\.(xyz|tk|ml|ga|cf|pw)/i,
      /app[l1]e.*\.(xyz|tk|ml|ga|cf|pw)/i,
      /paypa1|paypai|payp4l/i,
      /amaz0n|amazom|arnazon/i,
      /g00gle|googIe|g0ogle/i,
      /secure.*login.*\.(xyz|tk|ml|ga|cf)/i,
      /verify.*account.*\.(xyz|tk|ml|ga|cf)/i,
      /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
      /xn--/,
    ]
    const SCAM_TEXT = [
      /your account (has been|will be) (suspended|terminated|locked)/i,
      /verify your (account|identity|payment) (immediately|now|urgently)/i,
      /you (have won|are selected|are a winner)/i,
      /claim your (prize|reward|gift card) now/i,
      /urgent.*action required/i,
      /your (password|credit card|bank account) (has been|was) compromised/i,
      /send (bitcoin|crypto|gift card) to/i,
      /your computer (is|has been) (infected|hacked|compromised)/i,
      /call.*microsoft.*support.*immediately/i,
      /congratulations.*selected.*click/i,
    ]

    let flagLinks = 0, flagText = 0, flagImg = 0
    const findings = []

    // Scan links
    document.querySelectorAll('a[href]').forEach(el => {
      const href = el.getAttribute('href') || ''
      if (!href || href.startsWith('#')) return
      let hit = false
      for (const re of PHISH_LINK) {
        if (re.test(href)) { hit = true; break }
      }
      // Mismatched link text vs destination
      if (!hit && href.startsWith('http')) {
        try {
          const linkDomain = new URL(href).hostname
          const text = el.textContent?.trim() || ''
          const textDomain = text.match(/[\w-]+\.(com|org|net|io|co)/)?.[0]
          if (textDomain && !linkDomain.includes(textDomain.split('.')[0])) {
            hit = true
            findings.push({ type: 'MISMATCH', reason: `"${textDomain}" → ${linkDomain}` })
          }
        } catch {}
      }
      // javascript: links
      if (!hit && href.toLowerCase().startsWith('javascript:') && !href.includes('void')) {
        hit = true
        findings.push({ type: 'JS_LINK', reason: href.substring(0, 60) })
      }
      if (hit) {
        flagLinks++
        findings.push({ type: 'PHISH_LINK', reason: href.substring(0, 60) })
        const isCritical = PHISH_LINK.slice(0, 6).some(re => re.test(href))
        if (isCritical) {
          el.classList.add('cs-masked-link')
          el.addEventListener('click', e => { e.preventDefault(); e.stopPropagation() }, true)
        } else {
          el.classList.add('cs-phish-link')
          el.title = '⚠️ AI Shield: Suspicious link'
        }
      }
    })

    // Scan text nodes
    function walkText(node) {
      if (node.nodeType === Node.TEXT_NODE) {
        const t = node.textContent || ''
        for (const re of SCAM_TEXT) {
          if (re.test(t)) {
            const span = document.createElement('span')
            span.className = 'cs-warn-text'
            span.title = '⚠️ AI Shield: Suspicious text pattern'
            span.textContent = t
            try { node.parentNode?.replaceChild(span, node); flagText++; findings.push({ type: 'SCAM_TEXT', reason: t.substring(0, 60) }) } catch {}
            break
          }
        }
      } else if (node.nodeType === Node.ELEMENT_NODE &&
        !['SCRIPT','STYLE','NOSCRIPT','IFRAME'].includes(node.nodeName) &&
        !node.id?.startsWith('cs-')) {
        Array.from(node.childNodes).forEach(walkText)
      }
    }
    walkText(document.body)

    // Scan images (tracking pixels)
    document.querySelectorAll('img').forEach(img => {
      if ((img.width <= 2 && img.height <= 2 && img.width > 0) ||
          /tracking|pixel|beacon|1x1/i.test(img.src || '')) {
        img.style.display = 'none'
        flagImg++
        findings.push({ type: 'TRACKER', reason: (img.src || '').substring(0, 50) })
      }
    })

    const total = flagLinks + flagText + flagImg
    if (total === 0) return

    // Toast
    const toast = document.createElement('div')
    toast.className = 'cs-scan-toast'
    toast.innerHTML = `🛡️ Page scan: <span class="cs-toast-count">${total} threat${total > 1 ? 's' : ''} masked</span>`
    toast.title = `${flagLinks} phishing links, ${flagText} scam texts, ${flagImg} trackers`
    toast.onclick = () => { toast.remove(); showReport(flagLinks, flagText, flagImg, findings) }
    document.body.appendChild(toast)
    setTimeout(() => toast.remove(), 8000)
  }

  function showReport(links, texts, imgs, findings) {
    document.getElementById('cs-report')?.remove()
    const r = document.createElement('div')
    r.id = 'cs-report'
    r.className = 'cs-report'
    r.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;border-bottom:1px solid #30363d;">
        <div style="font-weight:700">🛡️ Page Scan Report</div>
        <button onclick="this.closest('#cs-report').remove()" style="background:none;border:none;color:#8b949e;cursor:pointer;font-size:16px">✕</button>
      </div>
      <div style="display:flex;gap:8px;padding:10px 14px;border-bottom:1px solid #30363d">
        ${[['🔗','Phishing Links',links,'#ef4444'],['📝','Scam Texts',texts,'#f97316'],['👁️','Trackers',imgs,'#eab308']].map(([i,l,c,col]) => `
          <div style="flex:1;text-align:center;background:${col}22;border:1px solid ${col}44;border-radius:6px;padding:8px">
            <div style="font-size:20px;font-weight:800;color:${col}">${c}</div>
            <div style="color:#8b949e;font-size:10px">${l}</div>
          </div>`).join('')}
      </div>
      ${findings.slice(0, 12).map(f => `
        <div style="display:flex;gap:8px;padding:7px 14px;border-bottom:1px solid #30363d22">
          <span>${f.type === 'PHISH_LINK' || f.type === 'MISMATCH' || f.type === 'JS_LINK' ? '🔗' : f.type === 'SCAM_TEXT' ? '📝' : '👁️'}</span>
          <div style="color:#8b949e;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${f.reason || ''}</div>
        </div>`).join('')}
    `
    document.body.appendChild(r)
  }

  // Watch for dynamic content (SPAs)
  new MutationObserver(mutations => {
    for (const m of mutations) {
      m.addedNodes.forEach(node => {
        if (node.nodeType !== Node.ELEMENT_NODE) return
        node.querySelectorAll?.('a[href]').forEach(el => {
          const href = el.getAttribute('href') || ''
          if (/paypa1|paypai|amaz0n|amazom|g00gle|googIe/i.test(href)) {
            el.classList.add('cs-phish-link')
            el.title = '⚠️ AI Shield: Suspicious link'
          }
        })
      })
    }
  }).observe(document.body, { childList: true, subtree: true })
})()
