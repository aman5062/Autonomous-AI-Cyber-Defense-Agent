"""
WiFi Guard — Standalone Local Network Protection Service.

A fully independent FastAPI microservice that:
  - Continuously scans the local LAN/WiFi subnet for connected devices
  - Syncs blocked IPs from the main Cyber Defense backend
  - Flags attackers (CRITICAL) and shows all device risk levels
  - Serves its own beautiful HTML dashboard at GET /
  - Exposes a REST API consumed by the Next.js dashboard (/wifi page)

Port: 8503
"""

import logging
import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from wifi_guard.scanner import NetworkScanner
from wifi_guard.correlator import BackendCorrelator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (from environment)
# ---------------------------------------------------------------------------
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "30"))
TRUSTED_DEVICES = [
    d.strip()
    for d in os.getenv("TRUSTED_DEVICES", "").split(",")
    if d.strip()
]

# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------
scanner: NetworkScanner = None
correlator: BackendCorrelator = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global scanner, correlator
    scanner = NetworkScanner(trusted_ips=TRUSTED_DEVICES, scan_interval=SCAN_INTERVAL)
    correlator = BackendCorrelator(
        backend_url=BACKEND_URL,
        on_update=scanner.set_blocked_ips,
        interval=10,
    )
    scanner.start()
    correlator.start()
    logger.info("WiFi Guard started — scanning network every %ds", SCAN_INTERVAL)
    yield
    scanner.stop()
    correlator.stop()
    logger.info("WiFi Guard stopped")


app = FastAPI(
    title="WiFi Guard",
    description="Local network protection — device discovery & attacker detection",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "wifi-guard",
        "backend_url": BACKEND_URL,
        "scan_interval": SCAN_INTERVAL,
    }


@app.get("/api/devices")
async def get_devices():
    """All devices discovered on the local subnet."""
    if not scanner:
        return {"devices": [], "total": 0}
    return {"devices": scanner.devices, "total": len(scanner.devices)}


@app.get("/api/summary")
async def get_summary():
    """Summary of network state (device counts, subnet info, last scan time)."""
    if not scanner:
        return {
            "total_devices": 0, "blocked_devices": 0, "trusted_devices": 0,
            "risky_devices": 0, "local_ip": "n/a", "subnet": "n/a", "last_scan": "n/a",
        }
    return scanner.summary


@app.post("/api/rescan")
async def rescan():
    """Trigger an immediate network rescan."""
    if not scanner:
        return JSONResponse({"success": False, "message": "Scanner not initialised"}, 503)
    import asyncio
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, scanner._scan)
    return {"success": True, "message": "Rescan triggered"}


# ---------------------------------------------------------------------------
# HTML Dashboard
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>📡 WiFi Guard — Network Protection</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    :root {
      --bg: #0b1120; --surface: #111827; --card: #1a2235;
      --border: #1e2d45; --text: #e2e8f0; --muted: #64748b;
      --accent: #3b82f6; --green: #22c55e; --red: #ef4444;
      --orange: #f97316; --yellow: #eab308;
    }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }

    /* Header */
    .header {
      background: linear-gradient(135deg, #1e3a8a 0%, #1e1b4b 50%, #0f172a 100%);
      padding: 28px 32px;
      border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;
    }
    .header-left { display: flex; align-items: center; gap: 16px; }
    .logo { font-size: 2.8rem; }
    .header h1 { font-size: 1.5rem; font-weight: 800; color: #fff; }
    .header p  { color: #94a3b8; font-size: 0.85rem; margin-top: 3px; }
    .status-pill {
      display: flex; align-items: center; gap: 8px;
      background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3);
      border-radius: 20px; padding: 7px 16px; font-size: 0.8rem; color: #4ade80;
    }
    .pulse { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; animation: pulse 2s infinite; }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }

    /* Layout */
    .container { max-width: 1200px; margin: 0 auto; padding: 28px 24px; }

    /* Summary cards */
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }
    .stat-card {
      background: var(--card); border: 1px solid var(--border); border-radius: 12px;
      padding: 20px; text-align: center;
    }
    .stat-card .icon { font-size: 2rem; margin-bottom: 8px; }
    .stat-card .value { font-size: 2rem; font-weight: 800; }
    .stat-card .label { font-size: 0.75rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }

    /* Network info bar */
    .net-info {
      background: var(--card); border: 1px solid var(--border); border-radius: 10px;
      padding: 14px 20px; margin-bottom: 24px;
      display: flex; flex-wrap: wrap; gap: 24px; font-size: 0.85rem;
    }
    .net-info .item .key { color: var(--muted); margin-bottom: 2px; font-size: 0.75rem; }
    .net-info .item .val { font-family: monospace; font-weight: 600; color: #7dd3fc; }

    /* Toolbar */
    .toolbar {
      display: flex; align-items: center; justify-content: space-between;
      flex-wrap: wrap; gap: 12px; margin-bottom: 16px;
    }
    .toolbar h2 { font-size: 1rem; font-weight: 700; color: #fff; }
    .toolbar-right { display: flex; gap: 8px; align-items: center; }
    .btn {
      padding: 8px 18px; border-radius: 8px; border: none;
      font-size: 0.82rem; font-weight: 600; cursor: pointer; transition: opacity .15s;
    }
    .btn:hover { opacity: 0.85; } .btn:disabled { opacity: 0.45; cursor: not-allowed; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-ghost { background: var(--card); border: 1px solid var(--border); color: var(--text); }

    /* Filter pills */
    .filter-pills { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 16px; }
    .pill {
      padding: 5px 12px; border-radius: 16px; font-size: 0.75rem; font-weight: 600;
      border: 1px solid transparent; cursor: pointer; transition: all .15s;
    }
    .pill:hover { opacity: 0.8; }
    .pill.active-ALL     { background: rgba(100,116,139,.3); border-color: #475569; color: #e2e8f0; }
    .pill.active-SAFE    { background: rgba(34,197,94,.15); border-color: rgba(34,197,94,.4); color: #4ade80; }
    .pill.active-LOW     { background: rgba(59,130,246,.15); border-color: rgba(59,130,246,.4); color: #60a5fa; }
    .pill.active-HIGH    { background: rgba(249,115,22,.15); border-color: rgba(249,115,22,.4); color: #fb923c; }
    .pill.active-CRITICAL{ background: rgba(239,68,68,.15); border-color: rgba(239,68,68,.4); color: #f87171; }
    .pill:not([class*="active-"]) { background: var(--card); border-color: var(--border); color: var(--muted); }

    /* Device table */
    .table-wrap { background: var(--card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
    thead th { padding: 12px 16px; text-align: left; color: var(--muted); font-size: 0.72rem; text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); background: rgba(255,255,255,.02); }
    tbody tr { border-bottom: 1px solid rgba(255,255,255,.04); transition: background .1s; }
    tbody tr:last-child { border: none; }
    tbody tr:hover { background: rgba(255,255,255,.03); }
    tbody td { padding: 12px 16px; vertical-align: middle; }

    /* Risk badges */
    .badge { display:inline-block; padding: 3px 9px; border-radius: 5px; font-size: 0.7rem; font-weight: 700; border: 1px solid; }
    .badge-SAFE     { background:rgba(34,197,94,.1);  border-color:rgba(34,197,94,.3);  color:#4ade80; }
    .badge-LOW      { background:rgba(59,130,246,.1); border-color:rgba(59,130,246,.3); color:#60a5fa; }
    .badge-MEDIUM   { background:rgba(234,179,8,.1);  border-color:rgba(234,179,8,.3);  color:#fbbf24; }
    .badge-HIGH     { background:rgba(249,115,22,.1); border-color:rgba(249,115,22,.3); color:#fb923c; }
    .badge-CRITICAL { background:rgba(239,68,68,.15); border-color:rgba(239,68,68,.4);  color:#f87171; }
    .badge-UNKNOWN  { background:rgba(100,116,139,.1);border-color:rgba(100,116,139,.3);color:#94a3b8; }

    /* Blocked row highlight */
    tr.row-blocked { background: rgba(239,68,68,.05) !important; }
    tr.row-blocked:hover { background: rgba(239,68,68,.09) !important; }

    .tag-blocked { display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:5px;font-size:.7rem;font-weight:700;background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#f87171; }
    .tag-trusted { display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:5px;font-size:.7rem;font-weight:700;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);color:#4ade80; }

    /* Empty state */
    .empty { text-align:center; padding: 48px 16px; color: var(--muted); }
    .empty .big { font-size:3rem; margin-bottom: 12px; }

    /* Tips section */
    .tips {
      background: rgba(30,58,138,.15); border: 1px solid rgba(59,130,246,.25);
      border-radius: 12px; padding: 20px 24px; margin-top: 28px;
    }
    .tips h3 { font-size: 0.95rem; font-weight: 700; color: #93c5fd; margin-bottom: 12px; }
    .tips ul { list-style: none; display: flex; flex-direction: column; gap: 8px; }
    .tips li { font-size: 0.82rem; color: #94a3b8; padding-left: 20px; position: relative; line-height: 1.5; }
    .tips li::before { content: '›'; position: absolute; left: 0; color: #3b82f6; font-weight: 700; }

    /* footer */
    footer { text-align:center; padding: 20px; color: var(--muted); font-size: 0.72rem; border-top: 1px solid var(--border); margin-top: 32px; }

    @media (max-width: 640px) {
      .header { padding: 18px 16px; }
      .container { padding: 16px 12px; }
    }
  </style>
</head>
<body>

<div class="header">
  <div class="header-left">
    <div class="logo">📡</div>
    <div>
      <h1>WiFi Guard</h1>
      <p>Local Network Protection — Real-Time Device Monitoring</p>
    </div>
  </div>
  <div class="status-pill">
    <div class="pulse"></div>
    <span id="status-text">Connecting…</span>
  </div>
</div>

<div class="container">

  <!-- Summary cards -->
  <div class="summary-grid" id="summary-grid">
    <div class="stat-card"><div class="icon">💻</div><div class="value" id="s-total">—</div><div class="label">Total Devices</div></div>
    <div class="stat-card"><div class="icon">🔴</div><div class="value" id="s-blocked" style="color:var(--red)">—</div><div class="label">Blocked</div></div>
    <div class="stat-card"><div class="icon">✅</div><div class="value" id="s-trusted" style="color:var(--green)">—</div><div class="label">Trusted</div></div>
    <div class="stat-card"><div class="icon">⚠️</div><div class="value" id="s-risky" style="color:var(--orange)">—</div><div class="label">Risky</div></div>
  </div>

  <!-- Network info bar -->
  <div class="net-info">
    <div class="item"><div class="key">Local IP</div><div class="val" id="n-localip">—</div></div>
    <div class="item"><div class="key">Subnet</div><div class="val" id="n-subnet">—</div></div>
    <div class="item"><div class="key">Last Scan</div><div class="val" id="n-scan">—</div></div>
    <div class="item"><div class="key">Defense Backend</div><div class="val" id="n-backend">—</div></div>
  </div>

  <!-- Toolbar + filters -->
  <div class="toolbar">
    <h2>Connected Devices</h2>
    <div class="toolbar-right">
      <span id="device-count" style="font-size:.8rem;color:var(--muted);"></span>
      <button class="btn btn-ghost" onclick="fetchData()">🔄 Refresh</button>
      <button class="btn btn-primary" onclick="rescan()" id="rescan-btn">⚡ Rescan Network</button>
    </div>
  </div>

  <div class="filter-pills" id="filter-pills">
    <div class="pill active-ALL" onclick="setFilter('ALL')">All</div>
    <div class="pill" onclick="setFilter('SAFE')">✅ Safe</div>
    <div class="pill" onclick="setFilter('LOW')">🔵 Low</div>
    <div class="pill" onclick="setFilter('HIGH')">🟠 High</div>
    <div class="pill" onclick="setFilter('CRITICAL')">🔴 Critical</div>
  </div>

  <!-- Device table -->
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>IP Address</th>
          <th>Hostname</th>
          <th>MAC Address</th>
          <th>Status</th>
          <th>Notes</th>
          <th>Last Seen</th>
        </tr>
      </thead>
      <tbody id="device-tbody">
        <tr><td colspan="7"><div class="empty"><div class="big">📡</div><div>Scanning network… first scan may take up to 30 seconds.</div></div></td></tr>
      </tbody>
    </table>
  </div>

  <!-- Tips -->
  <div class="tips">
    <h3>🔒 Network Security Recommendations</h3>
    <ul>
      <li>Enable <strong>WPA3</strong> encryption on your router for the strongest wireless protection.</li>
      <li>Isolate IoT / smart devices on a separate <strong>VLAN or guest network</strong> to contain compromises.</li>
      <li>Change <strong>default router credentials</strong> — admin/admin is the first thing attackers try.</li>
      <li>Set <code>TRUSTED_DEVICES</code> in the environment to mark known-safe IPs so they're never flagged.</li>
      <li>CRITICAL devices are those whose IPs were blocked by the main defense engine — they performed a real attack.</li>
      <li>Use the defense dashboard's <strong>Whitelist</strong> feature to permanently exempt admin machines.</li>
      <li>Monitor this page during demos — when an attendee attacks, their device appears as CRITICAL instantly.</li>
    </ul>
  </div>

</div>

<footer>
  WiFi Guard — Part of the <strong>Autonomous AI Cyber Defense Agent</strong> system<br>
  <a href="http://localhost:3000" style="color:#3b82f6;">Defense Dashboard</a> &nbsp;·&nbsp;
  <a href="http://localhost:8000/docs" style="color:#3b82f6;">API Docs</a> &nbsp;·&nbsp;
  <a href="http://localhost:8000/demo" style="color:#3b82f6;">Attack Demo Page</a>
</footer>

<script>
let allDevices = [];
let currentFilter = 'ALL';

async function fetchData() {
  try {
    const [sumRes, devRes, healthRes] = await Promise.all([
      fetch('/api/summary'),
      fetch('/api/devices'),
      fetch('/health'),
    ]);

    if (sumRes.ok) {
      const s = await sumRes.json();
      document.getElementById('s-total').textContent   = s.total_devices ?? '—';
      document.getElementById('s-blocked').textContent = s.blocked_devices ?? '—';
      document.getElementById('s-trusted').textContent = s.trusted_devices ?? '—';
      document.getElementById('s-risky').textContent   = s.risky_devices ?? '—';
      document.getElementById('n-localip').textContent = s.local_ip || '—';
      document.getElementById('n-subnet').textContent  = s.subnet || '—';
      if (s.last_scan && s.last_scan !== 'n/a') {
        document.getElementById('n-scan').textContent = new Date(s.last_scan).toLocaleTimeString();
      }
    }

    if (devRes.ok) {
      const d = await devRes.json();
      allDevices = d.devices || [];
      document.getElementById('device-count').textContent = allDevices.length + ' discovered';
      renderTable();
    }

    if (healthRes.ok) {
      const h = await healthRes.json();
      document.getElementById('n-backend').textContent = h.backend_url || '—';
      document.getElementById('status-text').textContent = '● Scanning — ' + (h.service || 'wifi-guard');
    }
  } catch (e) {
    document.getElementById('status-text').textContent = '❌ Offline';
  }
}

function renderTable() {
  const filtered = currentFilter === 'ALL'
    ? allDevices
    : allDevices.filter(d => d.risk_level === currentFilter);

  const tbody = document.getElementById('device-tbody');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7"><div class="empty"><div class="big">🔍</div><div>No devices match this filter.</div></div></td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(d => `
    <tr class="${d.is_blocked ? 'row-blocked' : ''}">
      <td><span class="badge badge-${d.risk_level}">${riskIcon(d.risk_level)} ${d.risk_level}</span></td>
      <td style="font-family:monospace;font-weight:700;color:#f1f5f9;">${esc(d.ip)}</td>
      <td style="color:#94a3b8;">${esc(d.hostname || '—')}</td>
      <td style="font-family:monospace;font-size:.75rem;color:#64748b;">${esc(d.mac || '—')}</td>
      <td>
        ${d.is_blocked ? '<span class="tag-blocked">🚫 BLOCKED</span>' : ''}
        ${d.is_trusted && !d.is_blocked ? '<span class="tag-trusted">✅ Trusted</span>' : ''}
        ${!d.is_blocked && !d.is_trusted ? '<span style="color:var(--muted);font-size:.75rem;">Active</span>' : ''}
      </td>
      <td style="color:#64748b;font-size:.75rem;">${d.notes.slice(0,2).join(' · ') || '—'}</td>
      <td style="color:#475569;font-size:.75rem;">${fmtTime(d.last_seen)}</td>
    </tr>
  `).join('');
}

function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.pill').forEach(p => {
    p.className = 'pill';
    if (p.textContent.includes(f) || (f === 'ALL' && p.textContent === 'All')) {
      p.classList.add('active-' + f);
    }
  });
  renderTable();
}

async function rescan() {
  const btn = document.getElementById('rescan-btn');
  btn.disabled = true; btn.textContent = '⏳ Scanning…';
  try {
    await fetch('/api/rescan', { method: 'POST' });
    setTimeout(() => { fetchData(); btn.disabled=false; btn.textContent='⚡ Rescan Network'; }, 8000);
  } catch(e) {
    btn.disabled=false; btn.textContent='⚡ Rescan Network';
  }
}

const RISK_ICONS = {SAFE:'✅',LOW:'🔵',MEDIUM:'🟡',HIGH:'🟠',CRITICAL:'🔴',UNKNOWN:'⚪'};
function riskIcon(r) { return RISK_ICONS[r] || '⚪'; }
function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function fmtTime(iso) {
  if (!iso || iso === 'n/a') return '—';
  try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
}

// Auto-refresh every 15 seconds
fetchData();
setInterval(fetchData, 15000);
</script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the WiFi Guard HTML dashboard."""
    return HTMLResponse(content=_DASHBOARD_HTML)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8503"))
    uvicorn.run("wifi_guard.main:app", host="0.0.0.0", port=port, reload=False)
