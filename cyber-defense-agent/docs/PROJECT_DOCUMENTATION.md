# AI Cyber Defense Agent — Full Project Documentation

**Version:** 1.0.0 | **Stack:** Python 3.11 · FastAPI · Streamlit · Ollama · Qdrant · SQLite · Docker

---

## 1. Project Overview

An autonomous AI-powered cybersecurity defense system that:
- Monitors NGINX web traffic in real-time by tailing access logs
- Detects attacks using rule-based pattern matching (SQL injection, XSS, path traversal, brute force, DDoS, bots)
- Detects unknown attacks using ML anomaly detection (Isolation Forest)
- Automatically blocks malicious IPs via iptables with timed auto-unblock
- Analyzes every attack using a local LLM (Ollama llama3.2:3b) enriched with CVE data from Qdrant (RAG)
- Maps attack relationships using a NetworkX knowledge graph
- Scans the target app for vulnerabilities proactively
- Simulates attacks against the test app to validate defenses
- Displays everything on a real-time Streamlit dashboard

---

## 2. System Architecture

```
Internet Traffic
      │
   NGINX (:80)  ──── writes access.log
      │
 LogCollector → LogParser → parsed request dict
      │
 AttackDetectionEngine
  ├── SQLInjectionDetector    (regex patterns)
  ├── PathTraversalDetector   (regex + sensitive file list)
  ├── XSSDetector             (regex patterns)
  ├── BruteForceDetector      (sliding window counter)
  ├── DDoS detection          (request rate per IP)
  ├── Bot detection           (User-Agent matching)
  └── AnomalyDetector         (Isolation Forest ML)
      │
 DefenseEngine
  ├── WhitelistManager        (never block safe IPs)
  ├── IPBlocker               (iptables -A INPUT -s IP -j DROP)
  ├── RateLimiter             (in-memory per-IP counter)
  └── UnblockScheduler        (APScheduler timed unblock)
      │
 LLMAnalyzer  [async, non-blocking]
  ├── RAGEngine               (Qdrant semantic search for CVE context)
  ├── KnowledgeGraph          (NetworkX mitigations + attack chain)
  └── Ollama API              (llama3.2:3b generates JSON analysis)
      │
 LogStorage (SQLite)
      │
 Streamlit Dashboard (:8501)
```

---

## 3. How to Run

### Prerequisites
- Docker Desktop or Docker Engine + Compose v2
- ~6GB free disk (Ollama model ~2GB, images ~3GB)
- Ports free: 80, 5000, 8000, 8501, 11434, 6333

### Start (single command)
```bash
cd cyber-defense-agent
docker compose up --build -d
```

First startup pulls `llama3.2:3b` (~2GB). Monitor progress:
```bash
docker compose logs -f ollama
```

### Access Points

| Service            | URL                             |
|--------------------|---------------------------------|
| Dashboard          | http://localhost:8501           |
| Backend API        | http://localhost:8000           |
| API Docs (Swagger) | http://localhost:8000/docs      |
| Test App (target)  | http://localhost:5000           |
| NGINX proxy        | http://localhost:80             |
| Qdrant UI          | http://localhost:6333/dashboard |

### Stop / Reset
```bash
docker compose down          # stop, keep data
docker compose down -v       # stop + wipe all volumes
```

---

## 4. How to Test

### 4.1 Unit Tests
```bash
docker compose exec backend python -m pytest tests/ -v
```

Expected: 17 tests pass covering SQL injection, brute force, path traversal, XSS, whitelist, and rate limiter.

### 4.2 Manual Attack Testing via curl

All requests must go through NGINX on port 80 so they appear in the access log.

**SQL Injection:**
```bash
curl "http://localhost/login?user=' OR '1'='1--&pass=x"
curl "http://localhost/api/user?id=1 UNION SELECT username,password FROM users--"
curl "http://localhost/search?q=1'; DROP TABLE users--"
```

**XSS:**
```bash
curl "http://localhost/search?q=<script>alert('xss')</script>"
curl "http://localhost/search?q=<img src=x onerror=alert(document.cookie)>"
```

**Path Traversal:**
```bash
curl "http://localhost/file?name=../../../../etc/passwd"
curl "http://localhost/static/%2e%2e%2f%2e%2e%2fetc%2fpasswd"
```

**Brute Force (run 6+ times quickly):**
```bash
for i in {1..8}; do
  curl -s -o /dev/null -X POST http://localhost/login \
    -d "username=admin&password=wrong$i"
done
```

**Bot scan:**
```bash
curl -A "sqlmap/1.7" "http://localhost/"
curl -A "nikto/2.1.6" "http://localhost/"
```

After each attack, check http://localhost:8501 — it appears in the Live Feed tab within seconds.

### 4.3 Built-in Attack Simulator
```bash
# All attack types
curl -X POST http://localhost:8000/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"attack_type": "all"}'

# Individual types: sql_injection | xss | path_traversal | brute_force
curl -X POST http://localhost:8000/api/simulate \
  -d '{"attack_type": "sql_injection"}'
```

Also available in the dashboard sidebar.

### 4.4 Vulnerability Scanner
```bash
curl -X POST http://localhost:8000/api/scan/run
# Wait ~10 seconds, then:
curl http://localhost:8000/api/scan/latest | python3 -m json.tool
```

### 4.5 Verify Defense Actions
```bash
# Check blocked IPs
curl http://localhost:8000/api/defense/blocked-ips

# Check iptables inside container
docker compose exec backend sudo iptables -L INPUT -n

# Unblock an IP
curl -X POST http://localhost:8000/api/defense/unblock-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "172.18.0.1"}'

# Emergency unblock all
curl -X POST http://localhost:8000/api/defense/emergency-unblock
```

### 4.6 Verify LLM Analysis
```bash
curl "http://localhost:8000/api/attacks/recent?limit=3" | python3 -m json.tool
```
Look for `explanation`, `impact`, `mitigation`, `code_fix` fields.

### 4.7 Safe Testing (Dry-Run Mode)
```bash
# Enable dry-run (detects but does NOT block)
curl -X POST http://localhost:8000/api/defense/mode \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'

# Re-enable active defense
curl -X POST http://localhost:8000/api/defense/mode \
  -d '{"dry_run": false, "auto_defense": true}'
```

---

## 5. Module Reference

### Module 1: Monitoring Agent — `backend/monitoring/`

| Class | File | Key Method | Purpose |
|-------|------|-----------|---------|
| `LogCollector` | `log_collector.py` | `tail_logs_async()` | Async generator, yields parsed dict per new log line |
| `NginxLogParser` | `log_parser.py` | `parse(line)` | Regex parse combined log format → dict |
| `MetricsCollector` | `metrics_collector.py` | `get_snapshot()` | CPU/memory/network snapshot via psutil |
| `LogStorage` | `storage.py` | `save_request()`, `get_recent_attacks()` | All SQLite operations |

`tail_logs_async()` waits for log file to exist, seeks to end on startup, polls every 100ms for new lines.

---

### Module 2: Attack Detection Engine — `backend/detection/`

| Class | Detect Method | Technique |
|-------|--------------|-----------|
| `AttackDetectionEngine` | `analyze_request(request)` | Orchestrates all detectors, returns list |
| `SQLInjectionDetector` | `detect(path, method)` | 18 regex patterns, CRITICAL/HIGH/MEDIUM severity |
| `BruteForceDetector` | `detect(ip, path, status)` | Sliding window: 5 failures in 60s |
| `PathTraversalDetector` | `detect(path)` | 17 patterns + 19 sensitive file paths |
| `XSSDetector` | `detect(path, method)` | 20 patterns, script/event handler matching |

Detection dict format:
```json
{"detected": true, "attack_type": "SQL_INJECTION", "severity": "CRITICAL",
 "confidence": 0.95, "recommended_action": "BLOCK_IP", "details": "..."}
```

---

### Module 3: Anomaly Detection — `backend/detection/anomaly_model.py`

| Method | Purpose |
|--------|---------|
| `train(requests)` | Fits Isolation Forest (min 50 samples, contamination=0.05) |
| `detect(request)` | Returns anomaly score; flags if prediction == -1 |
| `update_stats(request)` | Maintains per-IP feature statistics in memory |

Features: request count, GET/POST ratio, error rate, avg payload size, unique user-agents, path length, hour, day of week, HTTP status. Model saved to `/app/data/models/isolation_forest.pkl`.

---

### Module 4: Threat Intelligence (RAG) — `backend/intelligence/`

| Class | File | Purpose |
|-------|------|---------|
| `CVEFetcher` | `cve_fetcher.py` | Fetches CVEs from NVD API for 9 security keywords, embeds, stores in Qdrant |
| `ThreatDB` | `threat_db.py` | `get_context_for_attack(type)` → formatted CVE string for LLM |
| `get_embedding_model()` | `embeddings.py` | Loads bge-small-en-v1.5 (384-dim vectors) |

Flow: startup → NVD API → embed with bge-small-en-v1.5 → upsert Qdrant → at analysis time, semantic search → top-5 CVEs as context string.

---

### Module 5: Knowledge Graph — `backend/analysis/knowledge_graph.py`

| Method | Purpose |
|--------|---------|
| `get_mitigations(attack_type)` | Graph traversal: attack → CWE → mitigation nodes |
| `get_attack_chain(attack_type)` | Kill chain stages for the attack |
| `get_related_attacks(attack_type)` | Other attacks sharing same CWE |

Nodes: AttackType, Vulnerability (CWE), Software, Mitigation, AttackStage.
Edges: exploits, affects, mitigates, leads_to. Pre-built with OWASP/CWE taxonomy.

---

### Module 6: LLM Analysis Engine — `backend/analysis/`

| Class/Function | File | Purpose |
|----------------|------|---------|
| `LLMAnalyzer` | `llm_analyzer.py` | `analyze_attack()` → prompt → Ollama → JSON |
| `get_prompt()` | `prompts.py` | Attack-type-specific prompt templates |
| `get_enriched_context()` | `rag_engine.py` | CVE context + graph mitigations combined |

Flow: attack detected → RAG context fetched → prompt built → POST to `ollama:11434/api/generate` → JSON extracted → enriched with graph data → stored in `ai_analysis` table.

Output fields: `explanation`, `impact`, `mitigation[]`, `code_fix{vulnerable, secure}`, `references[]`, `related_attacks[]`, `attack_chain[]`.

---

### Module 7: Defense Automation — `backend/defense/`

| Class | File | Key Methods |
|-------|------|-------------|
| `DefenseEngine` | `defense_engine.py` | `execute_defense()`, `block_ip_manual()`, `unblock_ip()`, `emergency_unblock_all()` |
| `IPBlocker` | `ip_blocker.py` | `block_ip()`, `unblock_ip()`, `is_blocked()`, `list_blocked()` |
| `WhitelistManager` | `whitelist_manager.py` | `is_whitelisted(ip)` — checks static list + CIDR ranges |
| `RateLimiter` | `rate_limiter.py` | `check(ip)` — sliding window, returns True if over limit |
| `UnblockScheduler` | `unblock_scheduler.py` | `schedule_unblock(ip, seconds)` — APScheduler date trigger |

Ban durations: SQL_INJECTION=24h, BRUTE_FORCE=1h, PATH_TRAVERSAL=24h, XSS=6h, DDOS=indefinite, DEFAULT=1h.

---

### Module 8: Vulnerability Scanner — `backend/scanning/vulnerability_scanner.py`

| Method | Checks |
|--------|--------|
| `_port_scan()` | Async TCP connect to 13 common ports |
| `_http_header_check()` | X-Frame-Options, CSP, HSTS, X-Content-Type-Options, server disclosure |
| `_ssl_check()` | HTTPS availability on port 443 |

Results stored in `vulnerability_scans` table and shown in dashboard tab 4.

---

### Module 9: Attack Simulator — `backend/scanning/attack_simulator.py`

| Method | Payloads Sent |
|--------|--------------|
| `simulate_sql_injection()` | 4 SQL injection variants |
| `simulate_xss()` | 3 XSS payloads |
| `simulate_path_traversal()` | 3 traversal paths |
| `simulate_brute_force()` | 8 login attempts |
| `run_all()` | All above sequentially |

Target: `http://testapp:5000` only. 300ms delay between requests to avoid overwhelming.

---

### Module 10: Security Dashboard — `dashboard/`

| File | Purpose |
|------|---------|
| `app.py` | Main Streamlit app, 4 tabs + sidebar |
| `components/charts.py` | Plotly pie (attack types), bar (severity), line (timeline) |
| `utils/data_fetcher.py` | HTTP client wrapping all backend API calls |

Tabs: (1) Live Feed with expandable AI analysis cards, (2) Analytics charts, (3) Blocked IPs table + manual controls, (4) Vulnerability scan results. Sidebar: defense mode, dry-run, run scan, run simulation, emergency unblock, auto-refresh.

---

## 6. API Reference

Base URL: `http://localhost:8000` | Swagger UI: `http://localhost:8000/docs`

| Method | Endpoint | Body / Params | Description |
|--------|----------|---------------|-------------|
| GET | `/health` | — | Service health check |
| GET | `/api/attacks/recent` | `?limit=50` | Recent attacks with AI analysis |
| GET | `/api/defense/blocked-ips` | — | Active blocked IPs |
| POST | `/api/defense/block-ip` | `{ip, reason, duration}` | Manual IP block |
| POST | `/api/defense/unblock-ip` | `{ip}` | Unblock IP |
| POST | `/api/defense/emergency-unblock` | — | Unblock all IPs |
| POST | `/api/defense/mode` | `{auto_defense, dry_run}` | Toggle defense mode |
| GET | `/api/stats/attacks` | `?days=7` | Attack statistics |
| GET | `/api/scan/latest` | — | Latest vulnerability scan |
| POST | `/api/scan/run` | — | Trigger scan (background) |
| POST | `/api/simulate` | `{attack_type}` | Trigger attack simulation |
| WS | `/ws/attacks` | — | Live attack WebSocket stream |

---

## 7. Database Schema (SQLite)

Path: `/app/data/db/cyber_defense.db`

**requests** — every HTTP request from NGINX log
`id, timestamp, ip, method, path, status, size, user_agent, referrer, is_suspicious, attack_type, severity, blocked, raw_log, created_at`

**defense_actions** — audit log of every defense action
`id, timestamp, action_type, target_ip, attack_type, severity, duration, status, details, performed_by`

**blocked_ips** — blocked IP records
`id, ip, attack_type, severity, block_time, unblock_time, status, reason, blocked_by`

**ai_analysis** — LLM analysis results
`id, request_id, attack_type, analysis_time, explanation, impact, mitigation, code_fix, references`

**vulnerability_scans** — scanner results
`id, scan_time, target, open_ports, vulnerabilities, raw_output`

**config** — runtime key-value config
`key, value, updated_at`

**whitelist** — manually added safe IPs
`id, ip, reason, added_at, added_by`

---

## 8. Full Data Flow

```
1. HTTP request → NGINX (:80) → proxied to testapp (:5000)
2. NGINX writes line to access.log
3. LogCollector detects new line → LogParser parses it
4. LogStorage.save_request() stores raw request in DB
5. AttackDetectionEngine.analyze_request() runs all 6 detectors
6. If attack(s) detected:
   a. Highest severity detection selected
   b. LogStorage.mark_suspicious() updates request record
   c. DefenseEngine.execute_defense():
      - WhitelistManager.is_whitelisted() checked first
      - If not whitelisted + auto_block=true:
        → IPBlocker.block_ip() runs iptables command
        → LogStorage.add_blocked_ip() records block
        → UnblockScheduler.schedule_unblock() sets timer
      - If RATE_LIMIT recommended:
        → RateLimiter.check() tracks request count
   d. asyncio.create_task(run_llm_analysis()):
      → RAGEngine.get_enriched_context() queries Qdrant
      → KnowledgeGraph.get_mitigations() traverses graph
      → LLMAnalyzer builds prompt with all context
      → POST to ollama:11434/api/generate
      → JSON response parsed and stored in ai_analysis table
7. Dashboard polls /api/attacks/recent every 5s
8. Live feed renders attack card with expandable AI analysis
```

---

## 9. Configuration Reference

**`config/settings.yaml`** key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `ollama.model` | `llama3.2:3b` | LLM model |
| `ollama.timeout` | `120` | LLM request timeout (seconds) |
| `defense.auto_block_enabled` | `true` | Enable automatic IP blocking |
| `defense.dry_run_mode` | `false` | Log only, no actual blocking |
| `detection.brute_force_threshold` | `5` | Failed logins before alert |
| `detection.brute_force_window` | `60` | Time window in seconds |
| `detection.ddos_threshold` | `100` | Requests per window for DDoS |
| `nvd.fetch_on_startup` | `true` | Load CVE data into Qdrant on start |

**Environment variables** (override settings.yaml):

| Variable | Purpose |
|----------|---------|
| `OLLAMA_BASE_URL` | Ollama service URL |
| `OLLAMA_MODEL` | Override LLM model |
| `QDRANT_HOST` | Qdrant hostname |
| `DRY_RUN_MODE=true` | Disable actual blocking |
| `NVD_API_KEY` | NVD API key (optional, higher rate limit) |
| `LOG_LEVEL` | DEBUG / INFO / WARNING |

**`config/whitelist.txt`** — add your IP here before testing to avoid self-blocking:
```
127.0.0.1
::1
192.168.0.0/16
10.0.0.0/8
# Add your IP:
# 203.0.113.50
```

---

## 10. Troubleshooting

| Problem | Fix |
|---------|-----|
| No attacks appear in dashboard after curl | Requests must go through port 80 (NGINX), not 5000 directly |
| LLM analysis shows fallback message | Ollama still downloading model — `docker compose logs ollama` |
| IP not being blocked | Check whitelist, check dry-run mode via `/health` |
| Qdrant unavailable | Non-critical — LLM works with less context |
| Container fails to start | Port conflict — ensure 80, 5000, 8000, 8501, 11434, 6333 are free |
| Want to reset all data | `docker compose down -v && docker compose up --build -d` |

---

## 11. Convert This Document to PDF

**Option 1 — VS Code / Kiro:**
Install the "Markdown PDF" extension, open this file, right-click → "Markdown PDF: Export (pdf)"

**Option 2 — Pandoc (command line):**
```bash
pandoc PROJECT_DOCUMENTATION.md -o project_documentation.pdf \
  --pdf-engine=wkhtmltopdf \
  -V geometry:margin=2cm \
  -V fontsize=11pt
```

**Option 3 — Browser:**
Open this file in a Markdown viewer (e.g. https://markdownlivepreview.com), paste content, then File → Print → Save as PDF.
