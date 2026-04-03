# AI Cyber Defense Agent

Autonomous AI-powered cybersecurity defense system — full version with all 10 modules.

## Run (single command)

```bash
docker compose up --build -d
```

## Access

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:8501 |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| Test App (target) | http://localhost:5000 |
| NGINX proxy | http://localhost:80 |
| Qdrant UI | http://localhost:6333/dashboard |

## Modules

| # | Module | Status |
|---|--------|--------|
| 1 | Monitoring Agent | ✅ |
| 2 | Attack Detection Engine | ✅ |
| 3 | Anomaly Detection (ML) | ✅ |
| 4 | Threat Intelligence (RAG + Qdrant) | ✅ |
| 5 | Knowledge Graph (NetworkX) | ✅ |
| 6 | LLM Analysis (Ollama llama3.2:3b) | ✅ |
| 7 | Defense Automation (iptables) | ✅ |
| 8 | Vulnerability Scanner | ✅ |
| 9 | Attack Simulator | ✅ |
| 10 | Security Dashboard (Streamlit) | ✅ |

## Stop

```bash
docker compose down
```

## Logs

```bash
docker compose logs -f backend
```

## Test detection manually

```bash
# SQL injection
curl "http://localhost/login?user=' OR '1'='1--"

# Path traversal
curl "http://localhost/file?name=../../../../etc/passwd"

# XSS
curl "http://localhost/search?q=<script>alert(1)</script>"
```

## Notes

- First startup pulls `llama3.2:3b` (~2GB) — takes a few minutes
- iptables blocking requires the backend container to run with `privileged: true`
- Whitelist in `config/whitelist.txt` — add your IP to avoid self-blocking
- Set `DRY_RUN_MODE=true` in environment to test without actual blocking
