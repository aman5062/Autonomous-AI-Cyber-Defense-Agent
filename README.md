# 🛡️ Autonomous AI Cyber Defense Agent

Real-time AI-powered cybersecurity defense system — 10 backend modules, Next.js dashboard, and a Chrome extension.

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
| Backend API | http://localhost:8000 | FastAPI REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Test App | http://localhost:5000 | Vulnerable Flask app (attack target) |
| NGINX Proxy | http://localhost:80 | Reverse proxy → test app |
| Streamlit Dashboard | http://localhost:8501 | Legacy Streamlit UI |
| Demo Dashboard | http://localhost:8502 | Attack launcher demo UI |
| Qdrant UI | http://localhost:6333/dashboard | Vector DB UI |
| Ollama | http://localhost:11434 | LLM API |

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
├── backend/                  # FastAPI backend (all 10 modules)
│   ├── main.py               # App entry point + monitoring loop
│   ├── config.py             # All configuration
│   ├── monitoring/           # Log collection, parsing, storage
│   ├── detection/            # Attack detectors (6 types + anomaly)
│   ├── defense/              # IP blocker, rate limiter, whitelist, scheduler
│   ├── analysis/             # LLM analyzer, RAG engine, knowledge graph
│   ├── intelligence/         # CVE fetcher, embeddings, Qdrant threat DB
│   ├── scanning/             # Vulnerability scanner, attack simulator
│   └── api/                  # FastAPI routes + Pydantic models
├── frontend/                 # Next.js dashboard (port 3000)
│   └── src/
│       ├── app/              # Pages (overview, attacks, analytics, etc.)
│       ├── components/       # Sidebar, AttackCard, Charts, StatCard
│       ├── hooks/            # useLiveData (1s polling + WebSocket)
│       └── lib/              # API client + TypeScript types
├── extension/                # Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── background.js         # Service worker — scanning, blocking, badge
│   ├── content.js            # In-page scanner — links, text, images
│   ├── popup.html/js         # Extension popup UI
│   └── icons/                # Shield PNG icons
├── dashboard/                # Streamlit dashboard (port 8501)
├── demo/                     # Demo attack launcher (port 8502)
├── test_app/                 # Deliberately vulnerable Flask app
├── config/                   # NGINX config, settings.yaml, whitelist.txt
├── docker/                   # Dockerfiles (backend, frontend, dashboard, demo, testapp)
├── scripts/                  # Setup, demo attacks, emergency unblock
├── tests/                    # Unit tests (detection, defense, analysis)
├── docs/                     # Module documentation (10 files)
├── data/                     # Runtime data (DB, logs, ML models)
├── docker-compose.yml        # All services
├── requirements.txt          # Python dependencies
└── .env.example              # Environment variables template
```

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
| POST | `/api/extension/report` | Receive Chrome extension scan reports |
| GET | `/api/extension/scans` | Extension scan history |
| GET | `/api/extension/stats` | Extension aggregated stats |
| WS | `/ws/attacks` | WebSocket live attack feed |

---

## Attack Detection

| Attack | Severity | Auto Response | Ban Duration |
|--------|----------|---------------|--------------|
| SQL Injection | CRITICAL | Block IP | 24 hours |
| Command Injection | CRITICAL | Block IP | 24 hours |
| Path Traversal | CRITICAL | Block IP | 24 hours |
| Brute Force | HIGH | Block IP | 1 hour |
| XSS | HIGH | Rate Limit | 6 hours |
| Bot Scanner | MEDIUM | Rate Limit | ongoing |

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
```

---

## Notes

- First startup pulls `llama3.2:3b` (~2GB) — takes a few minutes
- iptables blocking requires `privileged: true` on the backend container
- Docker internal IPs (`172.16.0.0/12`) are whitelisted — the system never blocks itself
- Add your IP to `config/whitelist.txt` to avoid self-blocking
- Set `DRY_RUN_MODE=true` in `.env` to test without real blocking
- The Next.js frontend polls every 1s and uses WebSocket for instant attack notifications
