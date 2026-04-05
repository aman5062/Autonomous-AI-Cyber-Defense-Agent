# 🛡️ Autonomous AI Cyber Defense Agent

Real-time AI-powered cybersecurity defense system — 10 modules, fully autonomous.

## Quick Start

```bash
cp .env.example .env
docker compose up --build -d
```

> First run pulls `llama3.2:3b` (~2GB). Ollama starts first and the rest wait for it to be healthy.

**Rebuild only your code (Ollama/Qdrant keep running, no re-download):**
```bash
docker compose up --build -d --no-recreate ollama qdrant nginx
# or just restart the services you changed:
docker compose up --build -d backend dashboard testapp
```

## Services & Ports

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:8501 | Streamlit live dashboard |
| Backend API | http://localhost:8000 | FastAPI REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Test App | http://localhost:5000 | Vulnerable Flask app (attack target) |
| NGINX Proxy | http://localhost:80 | Reverse proxy → test app |
| Qdrant UI | http://localhost:6333/dashboard | Vector DB dashboard |
| Ollama | http://localhost:11434 | LLM API |

## Useful Commands

```bash
# View logs
docker compose logs -f backend
docker compose logs -f dashboard

# Stop everything
docker compose down

# Stop but keep volumes (Ollama model, DB)
docker compose down --volumes=false

# Full reset including volumes
docker compose down -v
```

## Services

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:8501 |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Test App (target) | http://localhost:5000 |
| NGINX proxy | http://localhost:80 |
| Qdrant UI | http://localhost:6333/dashboard |

## Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | Monitoring Agent | Real-time NGINX log tailing & parsing |
| 2 | Attack Detection | SQL Injection, XSS, Path Traversal, Brute Force, Command Injection, Bot Scan |
| 3 | Anomaly Detection | Isolation Forest ML model |
| 4 | Threat Intelligence | RAG + Qdrant vector DB + NVD CVE data |
| 5 | Knowledge Graph | NetworkX attack relationship graph |
| 6 | LLM Analysis | Ollama llama3.2:3b AI-powered explanations |
| 7 | Defense Automation | iptables IP blocking + NGINX rate limiting |
| 8 | Vulnerability Scanner | Port scan + HTTP header checks |
| 9 | Attack Simulator | Automated test attack generation |
| 10 | Security Dashboard | Streamlit real-time dashboard |

## Project Structure

```
├── backend/                  # FastAPI backend (all 10 modules)
│   ├── main.py               # App entry point + monitoring loop
│   ├── config.py             # All configuration
│   ├── monitoring/           # Log collection, parsing, storage
│   ├── detection/            # Attack detectors (8 types)
│   ├── defense/              # IP blocker, rate limiter, scheduler
│   ├── analysis/             # LLM analyzer, RAG engine, knowledge graph
│   ├── intelligence/         # CVE fetcher, embeddings, threat DB
│   ├── scanning/             # Vulnerability scanner, attack simulator
│   └── api/                  # FastAPI routes + Pydantic models
├── dashboard/                # Streamlit dashboard
├── test_app/                 # Deliberately vulnerable Flask app
├── config/                   # NGINX config, settings.yaml, whitelist
├── docker/                   # Dockerfiles
├── scripts/                  # Setup, demo attacks, emergency unblock
├── tests/                    # Unit tests
├── docs/                     # Module documentation
├── data/                     # Runtime data (DB, logs, models)
├── docker-compose.yml        # All 6 services
├── requirements.txt          # Python dependencies
└── .env.example              # Environment variables template
```

## Test Attacks

```bash
bash scripts/demo_attacks.sh

# Or manually:
curl "http://localhost/login?user=' OR '1'='1--"
curl "http://localhost/file?name=../../../../etc/passwd"
curl "http://localhost/search?q=<script>alert(1)</script>"
```

## Notes

- First startup pulls `llama3.2:3b` (~2GB) — takes a few minutes
- iptables blocking requires `privileged: true` on the backend container
- Add your IP to `config/whitelist.txt` to avoid self-blocking
- Set `DRY_RUN_MODE=true` in `.env` to test without real blocking
