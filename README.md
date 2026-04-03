# 🛡️ Autonomous AI Cyber Defense Agent

A real-time, AI-powered cybersecurity defense system that monitors web traffic, automatically detects attacks, blocks threats, and provides LLM-powered analysis.

---

## 🎯 What It Does

| Feature | Detail |
|---------|--------|
| **Real-time Monitoring** | Tails NGINX access logs and parses every request |
| **Attack Detection** | SQL Injection, Brute Force, Path Traversal, XSS, Command Injection, Bot Scanning |
| **Automated Defense** | Blocks attacker IPs via `iptables`, rate-limits via NGINX |
| **Auto-Unblock** | Bans expire automatically (e.g. SQL Injection = 24h, Brute Force = 1h) |
| **AI Analysis** | Sends attacks to a local Ollama LLM for plain-English explanations + fix recommendations |
| **Live Dashboard** | Streamlit dashboard with real-time attack feed, charts, and manual controls |
| **REST API** | FastAPI backend with WebSocket live feed |

---

## 🏗️ Architecture

```
NGINX Access Logs
       ↓
 Log Collector (tail)
       ↓
 NginxLogParser
       ↓
 AttackDetectionEngine ──→ SQLInjectionDetector
  (all detectors run)   ──→ BruteForceDetector
                        ──→ PathTraversalDetector
                        ──→ XSSDetector
                        ──→ CommandInjectionDetector
                        ──→ BotDetector
       ↓
 DefenseEngine ──→ IPBlocker (iptables)
               ──→ RateLimiter (NGINX)
               ──→ UnblockScheduler (APScheduler)
       ↓
 LLMAnalyzer (Ollama llama3.2:3b)
       ↓
 SQLite Database ←── FastAPI REST API ←── Streamlit Dashboard
```

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose

### 1. Clone & start

```bash
git clone https://github.com/aman5062/Autonomous-AI-Cyber-Defense-Agent.git
cd Autonomous-AI-Cyber-Defense-Agent
bash scripts/setup.sh
```

Or manually:

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml up --build -d
```

### 2. Pull the LLM model (required once)

```bash
docker exec cyber_defense_ollama ollama pull llama3.2:3b
```

### 3. Open the dashboard

```
http://localhost:8501    ← Streamlit dashboard
http://localhost:8000    ← FastAPI backend
http://localhost:8000/docs ← Swagger API docs
http://localhost:5000    ← Vulnerable test app
```

### 4. Generate demo attacks

```bash
bash scripts/demo_attacks.sh
```

This sends SQL injection, brute force, XSS, path traversal, and command injection payloads to the test app — and you'll see them appear in the dashboard in real time.

---

## 🗂️ Project Structure

```
├── backend/
│   ├── main.py                  # FastAPI app + monitoring loop
│   ├── config.py                # All configuration
│   ├── monitoring/              # Log collection, parsing, storage
│   ├── detection/               # All attack detectors
│   ├── defense/                 # Defense engine, IP blocker, scheduler
│   ├── analysis/                # LLM analyzer + prompt templates
│   └── api/                     # REST routes + Pydantic models
├── dashboard/
│   ├── app.py                   # Streamlit dashboard
│   └── utils/data_fetcher.py    # Backend API client
├── test_app/
│   └── vulnerable_app.py        # Deliberately vulnerable Flask app (testing)
├── config/
│   ├── settings.yaml            # App configuration
│   ├── nginx.conf               # NGINX with rate limiting
│   └── whitelist.txt            # IPs that are never blocked
├── docker/
│   ├── docker-compose.yml       # All services
│   ├── Dockerfile.backend
│   ├── Dockerfile.dashboard
│   └── Dockerfile.testapp
├── scripts/
│   ├── setup.sh                 # One-command setup
│   ├── demo_attacks.sh          # Generate test attacks
│   └── emergency_unblock.sh     # Unblock all IPs
├── tests/
│   ├── test_detection.py        # Detection unit tests
│   ├── test_defense.py          # Defense unit tests
│   └── test_analysis.py         # LLM/parser tests
└── requirements.txt
```

---

## 🔍 Detected Attack Types

| Attack | Severity | Default Ban |
|--------|----------|-------------|
| SQL Injection | CRITICAL | 24 hours |
| Command Injection | CRITICAL | 24 hours |
| Brute Force | HIGH | 1 hour |
| Path Traversal | HIGH → CRITICAL | 24 hours |
| XSS | MEDIUM → HIGH | 6 hours (rate limit) |
| Bot/Scanner | MEDIUM | Rate limit |

---

## ⚙️ Configuration

Edit `.env` or `config/settings.yaml`:

```env
ENABLE_AUTO_BLOCK=true    # Enable/disable auto IP blocking
DRY_RUN_MODE=false        # true = log only, no real blocks
OLLAMA_MODEL=llama3.2:3b  # LLM model for AI analysis
BRUTE_FORCE_THRESHOLD=5   # Failed attempts before block
WHITELIST_IPS=10.0.0.1    # IPs never to block
```

---

## 🧪 Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## 🛡️ Safety Features

- **Whitelist**: `127.0.0.1`, `::1`, and any IPs in `config/whitelist.txt` are **never blocked**
- **Dry-run mode**: Test without real firewall changes
- **Auto-unblock**: All bans expire automatically
- **Emergency unblock**: One API call clears all blocks

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | System health check |
| GET | `/api/attacks/recent` | Recent attack log |
| GET | `/api/defense/blocked-ips` | Currently blocked IPs |
| POST | `/api/defense/block-ip` | Manually block an IP |
| POST | `/api/defense/unblock-ip` | Unblock an IP |
| POST | `/api/defense/emergency-unblock` | Unblock all IPs |
| POST | `/api/defense/mode` | Set auto-block / dry-run mode |
| GET | `/api/stats/attacks` | Attack statistics |
| WS | `/ws/attacks` | WebSocket live attack feed |
| GET | `/docs` | Interactive Swagger UI |

---

## 📋 Full Plan

See [Plan.md](Plan.md) for the complete development specification.
