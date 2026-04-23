# 🛡️ Autonomous AI Cyber Defense Agent

Real-time AI-powered cybersecurity defense system — 13 backend modules, Next.js dashboard, interactive attack demo, email alerts, local WiFi protection, and a Chrome extension.

---

## Quick Start

```bash
cp .env.example .env
docker compose up --build -d
```

> First run pulls `llama3.2:3b` (~2GB). Ollama starts first — everything else waits for it.

**Rebuild only your code (Ollama/Qdrant keep running, no re-download):**
```bash
docker compose up --build -d backend frontend testapp
```

---

## Services & Ports

| Service | URL | Description |
|---------|-----|-------------|
| Next.js Dashboard | http://localhost:3000 | Main UI — all features |
| **Live Attack Demo** | **http://localhost:8000/demo** | **🆕 Attack demo page — anyone on local WiFi can test** |
| Backend API | http://localhost:8000 | FastAPI REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Test App | http://localhost:5000 | Vulnerable Flask app (attack target) |
| NGINX Proxy | http://localhost:80 | Reverse proxy → test app |
| Streamlit Dashboard | http://localhost:8501 | Legacy Streamlit UI |
| Demo Dashboard | http://localhost:8502 | Attack launcher demo UI |
| Qdrant UI | http://localhost:6333/dashboard | Vector DB UI |
| Ollama | http://localhost:11434 | LLM API |

---

## 🎓 College / School Demo Guide

### Setting up for a live WiFi demo

1. Run the system on a laptop connected to your school/college WiFi:
   ```bash
   docker compose up --build -d
   ```

2. Find your machine's local IP:
   ```bash
   # Linux/macOS
   hostname -I | awk '{print $1}'
   # Windows
   ipconfig | findstr "IPv4"
   ```

3. Share the demo URL with your audience:
   ```
   http://<YOUR-IP>:8000/demo
   ```
   Anyone on the same WiFi can open this page on their mobile or laptop.

4. Open the defense dashboard on the presenter's screen:
   ```
   http://localhost:3000
   ```

5. Ask attendees to click "Launch Attack" on the demo page — their IP gets detected and blocked instantly. They see the result in real time!

6. Show blocked IPs at http://localhost:3000/blocked

7. Show the WiFi monitor at http://localhost:3000/wifi to see all connected devices.

8. Unblock after demo: http://localhost:3000/controls → "Emergency Unblock All"

---

## Next.js Dashboard Pages

| Page | URL | Description |
|------|-----|-------------|
| Overview | /  | Live stats, charts, WebSocket feed |
| Live Attacks | /attacks | Real-time attack feed (1s polling + WebSocket) |
| Analytics | /analytics | Attack type/severity charts, timeline |
| Blocked IPs | /blocked | Currently blocked IPs, unblock controls |
| Controls | /controls | Auto-block toggle, dry-run, manual block/unblock |
| Whitelist | /whitelist | IPs that are never blocked |
| Attack Launcher | /launcher | Fire test attacks against the system |
| **WiFi Protection** | **/wifi** | **🆕 Monitor all LAN/WiFi devices in real time** |
| Attack Guide | /guide | Educational reference for all attack types |
| Browser Extension | /extension | Chrome extension scan history & install guide |

---

## Backend Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | Monitoring Agent | Real-time NGINX log tailing & parsing |
| 2 | Attack Detection | SQL Injection, XSS, Path Traversal, Brute Force, Command Injection, Bot Scan |
| 3 | Anomaly Detection | Isolation Forest ML model |
| 4 | Threat Intelligence | RAG + Qdrant vector DB + NVD CVE data |
| 5 | Knowledge Graph | NetworkX attack relationship graph |
| 6 | LLM Analysis | Ollama llama3.2:3b — plain-English attack explanations + code fixes |
| 7 | Defense Automation | iptables IP blocking + NGINX rate limiting + auto-unblock scheduler |
| 8 | Vulnerability Scanner | Port scan + HTTP security header checks |
| 9 | Attack Simulator | Automated test attack generation |
| 10 | Security Dashboard | Next.js + Streamlit real-time dashboards |
| 11 | **Email Reporter** | **🆕 AI-generated HTML attack reports sent via SMTP** |
| 12 | **WiFi Monitor** | **🆕 Local network scanner — discovers & monitors all LAN devices** |
| 13 | **Attack Demo Page** | **🆕 Interactive demo served from the backend — works from mobile** |

---

## 🆕 New Features

### 1. Interactive Attack Demo Page (`/demo`)

Served by the backend at `http://<server-ip>:8000/demo`.

- **Any device on the local network** can open this page (mobile, laptop, tablet)
- Select an attack type: SQL Injection, Command Injection, XSS, Path Traversal, Brute Force
- Choose a payload and click **Launch Attack**
- The AI defense engine detects the attack from the **real client IP** and blocks it instantly
- The page shows a real-time result: what was detected, severity, and why the IP was blocked
- The defense dashboard at `:3000` updates in real time via WebSocket

### 2. Email Attack Reports

When an attack is detected and blocked, an AI-generated HTML report is automatically emailed to the configured administrator.

**Enable in `.env`:**
```env
ENABLE_EMAIL_REPORTS=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=admin@yourschool.edu
```

**What the email includes:**
- Attack type, severity, timestamp
- Attacker IP address
- Target path and HTTP method
- User-agent string
- AI-generated plain-English explanation
- Impact assessment
- Step-by-step mitigation recommendations
- Secure code fix (before/after)
- OWASP/CWE references

> For Gmail: use an App Password (Google Account → Security → 2FA → App Passwords)

### 3. WiFi / LAN Protection (`/wifi`)

A real-time dashboard showing every device connected to the local network.

- **Automatic subnet scanning** every 30 seconds (ping sweep)
- **ARP cache integration** — shows MAC addresses when available
- **Reverse DNS** hostname resolution
- **Blocked device highlighting** — devices that attacked are shown as CRITICAL and linked to the defense engine's block list
- **Trusted device list** — set `TRUSTED_DEVICES=192.168.1.10,192.168.1.20` in `.env` to mark safe devices
- **Risk levels**: SAFE / LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN
- **Network summary**: total devices, blocked count, risky devices, subnet info
- **Manual rescan** button for immediate discovery

**WiFi use case (school/college):**
> Imagine a school WiFi where 200 students and teachers are connected. Some students may try to attack the test server or each other. The WiFi Monitor discovers all devices, and when the defense engine blocks an attacker IP, it immediately shows that device as CRITICAL/BLOCKED on the WiFi dashboard. The teacher/admin sees which device is the attacker.

### 4. Real-Time Attack Detection from Vulnerable App

The vulnerable test app (`test_app/`) now:

- **Automatically reports ALL requests** to the backend detection pipeline (including POST bodies)
- **Blocks banned IPs** before serving any content — shows a styled block page
- **SQL injection via login form** (POST body) is now detected
- **Command injection payloads** in query strings are always detected
- Syncs the blocked-IP list from the backend every 5 seconds

---

## Attack Detection (Updated)

| Attack | Severity | Auto Response | Ban Duration | Detection Source |
|--------|----------|---------------|--------------|-----------------|
| SQL Injection | CRITICAL | Block IP | 24 hours | URL path + POST body |
| Command Injection | CRITICAL | Block IP | 24 hours | URL path + POST body |
| Path Traversal | CRITICAL | Block IP | 24 hours | URL path + POST body |
| Brute Force | HIGH | Block IP | 1 hour | Failed login tracking |
| XSS | HIGH | Rate Limit | 6 hours | URL path + body |
| Bot Scanner | MEDIUM | Rate Limit | ongoing | User-agent fingerprint |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | System health + service status |
| GET | `/api/attacks/recent` | Recent attack log |
| GET | `/api/stats/attacks` | Attack statistics |
| GET | `/api/defense/blocked-ips` | Currently blocked IPs |
| POST | `/api/defense/block-ip` | Manually block an IP |
| POST | `/api/defense/unblock-ip` | Unblock an IP |
| POST | `/api/defense/emergency-unblock` | Unblock all IPs |
| POST | `/api/defense/mode` | Set auto-block / dry-run mode |
| GET | `/api/whitelist` | Get whitelisted IPs |
| POST | `/api/whitelist/add` | Add IP to whitelist |
| GET | `/api/metrics/system` | CPU / memory / disk metrics |
| GET | `/api/analysis/ollama-health` | LLM service status |
| POST | `/api/test/inject` | Inject test attacks (28 lines, mixed normal + attacks) |
| POST | `/api/test/inject-custom` | Inject custom log lines |
| **GET** | **`/demo`** | **🆕 Interactive attack demo HTML page** |
| **POST** | **`/api/demo/attack`** | **🆕 Perform attack from real client IP** |
| **GET** | **`/api/demo/whoami`** | **🆕 Returns caller's real IP** |
| **POST** | **`/api/demo/report`** | **🆕 Receive request reports from test app** |
| **GET** | **`/api/wifi/devices`** | **🆕 All discovered LAN devices** |
| **GET** | **`/api/wifi/summary`** | **🆕 Network summary stats** |
| **POST** | **`/api/wifi/rescan`** | **🆕 Trigger immediate network scan** |
| POST | `/api/extension/report` | Receive Chrome extension scan reports |
| GET | `/api/extension/scans` | Extension scan history |
| GET | `/api/extension/stats` | Extension aggregated stats |
| WS | `/ws/attacks` | WebSocket live attack feed |

---

## Chrome Extension

Located in `extension/` — scans every website you visit for security threats.

### Install
1. Go to `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` folder
4. The 🛡️ shield icon appears in your toolbar

### What it detects
- HTTP sites (no encryption)
- Password / payment fields on HTTP pages
- Phishing domains (brand impersonation patterns)
- Mixed content (HTTP resources on HTTPS pages)
- Suspicious form actions
- Cryptominer / keylogger scripts
- Clickjacking (iframe embedding)
- Malicious file downloads
- High-risk TLDs (.tk, .ml, .ga, .cf)
- Phishing links anywhere on the page
- Scam text patterns (fake prizes, account suspension threats)
- Tracking pixels

### In-page alerts
- Slides in from top-right with risk score (0–100)
- Red outline + tooltip on suspicious links
- Complete mask on confirmed phishing links (click blocked)
- Orange highlight on scam text
- Bottom badge showing total threats masked
- Block/Unblock site directly from the popup

### Dashboard sync
All scan data syncs to **http://localhost:3000/extension** in real time.

---

## Project Structure

```
├── backend/                  # FastAPI backend
│   ├── main.py               # App entry point + monitoring loop
│   ├── config.py             # All configuration (incl. email + wifi)
│   ├── monitoring/
│   │   ├── log_collector.py  # NGINX log tailing
│   │   ├── log_parser.py     # Log line parser
│   │   ├── storage.py        # SQLite storage
│   │   └── wifi_monitor.py   # 🆕 LAN/WiFi device scanner
│   ├── detection/            # Attack detectors (6 types + anomaly)
│   ├── defense/              # IP blocker, rate limiter, whitelist, scheduler
│   ├── analysis/
│   │   ├── llm_analyzer.py   # Ollama LLM analysis
│   │   ├── email_reporter.py # 🆕 SMTP email attack reports
│   │   ├── rag_engine.py     # RAG + Qdrant
│   │   └── knowledge_graph.py
│   ├── intelligence/         # CVE fetcher, embeddings, Qdrant threat DB
│   ├── scanning/             # Vulnerability scanner, attack simulator
│   └── api/
│       ├── routes.py         # All FastAPI endpoints (incl. /demo, /wifi)
│       └── models.py         # Pydantic models
├── frontend/                 # Next.js dashboard (port 3000)
│   └── src/
│       ├── app/
│       │   ├── wifi/         # 🆕 WiFi Protection page
│       │   └── ...           # Other pages
│       ├── components/       # Sidebar (updated with WiFi link), AttackCard…
│       └── lib/              # API client (incl. wifi + demo endpoints)
├── test_app/
│   └── vulnerable_app.py     # 🔄 Updated: auto-reports to backend, blocks IPs
├── extension/                # Chrome extension (Manifest V3)
├── dashboard/                # Streamlit dashboard (port 8501)
├── config/                   # NGINX config, settings.yaml, whitelist.txt
├── docker/                   # Dockerfiles
├── docker-compose.yml        # All services (updated with email/wifi env vars)
├── requirements.txt          # Python dependencies
└── .env.example              # 🔄 Updated: email + wifi settings
```

---

## Configuration Reference

### Email Reporting
```env
ENABLE_EMAIL_REPORTS=true      # Enable/disable email alerts
SMTP_HOST=smtp.gmail.com       # SMTP server hostname
SMTP_PORT=587                  # SMTP port (587=STARTTLS, 465=SSL)
SMTP_USER=sender@gmail.com     # SMTP login username
SMTP_PASSWORD=app-password     # SMTP password / app password
ALERT_EMAIL=admin@company.com  # Who receives the reports
```

### WiFi Protection
```env
TRUSTED_DEVICES=192.168.1.1,192.168.1.100  # Comma-separated trusted IPs
NETWORK_INTERFACE=eth0                       # Force interface (auto-detect if blank)
```

### Defense Settings
```env
ENABLE_AUTO_BLOCK=true   # Automatically block attacking IPs
DRY_RUN_MODE=false       # true = log only, no real iptables blocks
WHITELIST_IPS=           # Comma-separated IPs that are never blocked
BRUTE_FORCE_THRESHOLD=5  # Failed logins before brute-force trigger
BRUTE_FORCE_WINDOW=60    # Time window (seconds) for brute force counting
```

---

## Useful Commands

```bash
# View logs
docker compose logs -f backend
docker compose logs -f frontend

# Stop everything (keep volumes — Ollama model preserved)
docker compose down

# Full reset including volumes
docker compose down -v

# Run tests
docker exec cyber_defense_backend python -m pytest tests/ -v

# Emergency unblock all IPs
curl -X POST http://localhost:8000/api/defense/emergency-unblock

# Fire test attacks via API
curl -X POST http://localhost:8000/api/test/inject

# Perform a demo SQL injection (from your real IP)
curl -X POST http://localhost:8000/api/demo/attack \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "SQL_INJECTION"}'

# Check WiFi devices
curl http://localhost:8000/api/wifi/summary
```

---

## Notes

- First startup pulls `llama3.2:3b` (~2GB) — takes a few minutes
- iptables blocking requires `privileged: true` on the backend container
- Docker internal IPs (`172.16.0.0/12`) are whitelisted — the system never blocks itself
- Add your IP to `config/whitelist.txt` to avoid self-blocking
- Set `DRY_RUN_MODE=true` in `.env` to test without real blocking
- The Next.js frontend polls every 1s and uses WebSocket for instant attack notifications
- WiFi scanning uses ICMP ping + ARP cache — no raw sockets needed
- Email reports are sent asynchronously and do not delay the detection pipeline

