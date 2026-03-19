# PROJECT_PLAN.md

# Autonomous AI Cyber Defense Agent
## Complete Development Plan & Specification

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [System Architecture](#system-architecture)
3. [Complete Feature Set](#complete-feature-set)
4. [MVP Version (Recommended Start)](#mvp-version-recommended-start)
5. [Technology Stack](#technology-stack)
6. [Project Structure](#project-structure)
7. [Development Timeline](#development-timeline)
8. [Module Specifications](#module-specifications)
9. [Docker Configuration](#docker-configuration)
10. [API Specifications](#api-specifications)
11. [Database Schema](#database-schema)
12. [Testing Strategy](#testing-strategy)
13. [Deployment Guide](#deployment-guide)

---

## Project Overview

### Objective
Build an AI-powered autonomous cybersecurity defense system that:
- Monitors web traffic in real-time
- Detects cyber attacks using rule-based and ML methods
- Automatically applies defensive measures (IP blocking, rate limiting)
- Analyzes attacks using LLM and provides fix recommendations
- Maintains threat intelligence using RAG + Knowledge Graph
- Provides a real-time security dashboard

### Project Type
Final Year Engineering Project

### Estimated Complexity
- **Full Version**: 16-20 weeks (10 modules)
- **MVP Version**: 8 weeks (5 modules with auto-defense)

### Expected Grade
- **MVP**: 8.5-9/10
- **Full Version**: 9.5/10

---

## System Architecture

### High-Level Architecture (Full Version)

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet Traffic                      │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Web Server (NGINX)                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│                   Monitoring Agent                           │
│  (Log Collection, Parsing, Real-time Streaming)             │
└──────┬───────────────┬──────────────────────────────────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │  Attack Detection  │
       │     │   Rule-Based +     │
       │     │   Pattern Matching │
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │ Anomaly Detection  │
       │     │   (ML Models)      │
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │ Threat Intelligence│
       │     │  RAG + CVE Data    │
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │  Knowledge Graph   │
       │     │  (Attack Relations)│
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │  LLM Analysis      │
       │     │  (Ollama/Llama3)   │
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │ Defense Automation │
       │     │ (iptables/fail2ban)│
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │ Vulnerability Scan │
       │     │  (nmap/nikto)      │
       │     └─────────┬──────────┘
       │               │
       │     ┌─────────▼──────────┐
       │     │ Attack Simulator   │
       │     │  (Testing)         │
       │     └─────────┬──────────┘
       │               │
       └───────────────┼──────────────────────┐
                       │                      │
              ┌────────▼─────────┐   ┌───────▼────────┐
              │  Security        │   │   Database     │
              │  Dashboard       │   │   (SQLite/     │
              │  (Streamlit)     │   │    PostgreSQL) │
              └──────────────────┘   └────────────────┘
```

### MVP Architecture (Simplified)

```
┌─────────────────────────────────────┐
│         Internet Traffic            │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Web Server (NGINX)             │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│      Monitoring Agent               │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Attack Detection Engine           │
│   (SQL Injection, Brute Force,      │
│    Path Traversal, XSS)             │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Defense Automation Engine         │
│   (IP Blocking, Rate Limiting)      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   LLM Analysis Engine               │
│   (Attack Explanation + Fixes)      │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Security Dashboard                │
│   (Real-time monitoring)            │
└─────────────────────────────────────┘
```

---

## Complete Feature Set

### Full Version (10 Modules)

#### Module 1: Monitoring Agent
**Purpose**: Real-time traffic and system monitoring

**Features**:
- Real-time log streaming from NGINX/Apache
- Log parsing (access logs, error logs, auth logs)
- Traffic metrics collection (requests/sec, bandwidth, connections)
- System resource monitoring (CPU, memory, network)
- Log aggregation and storage
- Multi-source log collection

**Technologies**:
- Python (asyncio for real-time streaming)
- psutil (system monitoring)
- watchdog (file monitoring)
- Regular expressions (log parsing)

**Outputs**:
- Parsed log data in structured format (JSON)
- System metrics time-series data
- Stored in SQLite/PostgreSQL

---

#### Module 2: Attack Detection Engine
**Purpose**: Rule-based attack detection

**Features**:
- SQL Injection detection (pattern matching)
- Brute Force detection (frequency analysis)
- Path Traversal detection
- XSS (Cross-Site Scripting) detection
- CSRF detection
- Command Injection detection
- DDoS detection (traffic spike analysis)
- Port Scan detection
- Bot detection (user-agent analysis)
- Signature-based attack detection

**Detection Methods**:
- Regular expression pattern matching
- Threshold-based detection (rate limiting)
- Signature database lookup
- Request frequency analysis
- IP reputation checking

**Technologies**:
- Python
- Regular expressions
- Pattern matching algorithms
- Time-series analysis

**Outputs**:
- Attack alerts with severity levels
- Detected attack type
- Attacker IP and details
- Recommended action (block/monitor/alert)

---

#### Module 3: Anomaly Detection Model
**Purpose**: Machine learning-based anomaly detection

**Features**:
- Unsupervised learning for unknown attack patterns
- Traffic behavior analysis
- User behavior profiling
- Baseline traffic pattern establishment
- Real-time anomaly scoring

**ML Models**:
- Isolation Forest (primary)
- One-Class SVM (secondary)
- Autoencoder (for complex patterns)
- LSTM (for time-series anomalies - optional)

**Features for ML**:
- Request frequency per IP
- Request patterns (GET/POST ratio)
- Response time distribution
- HTTP status code distribution
- User-Agent entropy
- Request payload size
- Time-based features (hour, day, week)
- Geographic features (if GeoIP available)

**Technologies**:
- scikit-learn
- pandas
- numpy
- joblib (model persistence)

**Outputs**:
- Anomaly score (0-1)
- Anomalous behavior flag
- Feature importance for explainability

---

#### Module 4: Threat Intelligence Engine
**Purpose**: External threat knowledge integration using RAG

**Features**:
- CVE (Common Vulnerabilities and Exposures) database integration
- NVD (National Vulnerability Database) feed
- Security advisory scraping
- Malware signature database
- Known attack patterns repository
- Threat actor attribution data

**RAG Architecture**:
- Document ingestion (CVE reports, security advisories)
- Text chunking and embedding
- Vector database storage (Qdrant)
- Semantic search for relevant threats
- Context retrieval for LLM analysis

**Data Sources**:
- NVD API: https://nvd.nist.gov/developers
- CVE List: https://cve.mitre.org/
- OWASP Top 10
- ExploitDB
- SecurityFocus

**Technologies**:
- LangChain (RAG framework)
- Qdrant (vector database)
- bge-small-en-v1.5 (embedding model)
- BeautifulSoup (web scraping)
- requests (API calls)

**Outputs**:
- Relevant CVE information
- Known exploits for detected vulnerabilities
- Severity scores (CVSS)
- Mitigation recommendations from official sources

---

#### Module 5: Knowledge Graph
**Purpose**: Attack relationship mapping and explainable AI

**Features**:
- Attack taxonomy visualization
- Attack chain mapping (kill chain)
- Vulnerability relationships
- Affected software mapping
- Mitigation technique linking
- Attack pattern correlation

**Graph Structure**:
```
Nodes:
- Attack Types (SQL Injection, XSS, etc.)
- Vulnerabilities (CVE entries)
- Software (MySQL, Apache, etc.)
- Mitigation Techniques
- Attack Stages (Reconnaissance, Exploitation, etc.)

Edges:
- "exploits" (Attack -> Vulnerability)
- "affects" (Vulnerability -> Software)
- "mitigates" (Technique -> Vulnerability)
- "leads_to" (Attack Stage -> Attack Stage)
```

**Technologies**:
- Neo4j (graph database) OR
- NetworkX (Python graph library)
- Cypher query language (if Neo4j)
- Graph visualization (matplotlib, networkx)

**Outputs**:
- Attack path visualization
- Related attack suggestions
- Comprehensive mitigation strategies
- Attack impact analysis

---

#### Module 6: LLM Analysis Engine
**Purpose**: AI-powered attack analysis and recommendations

**Features**:
- Natural language attack explanations
- Context-aware analysis using RAG
- Code-level fix recommendations
- Security best practices suggestions
- Attack severity assessment
- Impact analysis
- Custom security reports

**LLM Models** (run locally via Ollama):
- Llama 3.2 3B (lightweight, fast)
- Llama 3 8B (better quality)
- Mistral 7B (alternative)
- CodeLlama (for code fixes)

**Prompt Engineering**:
- System prompts for security expert persona
- Few-shot examples for consistent formatting
- Chain-of-thought for complex analysis
- RAG integration for context injection

**Technologies**:
- Ollama (local LLM runtime)
- LangChain (LLM orchestration)
- Qdrant (RAG context retrieval)

**Input Format**:
```json
{
  "attack_type": "SQL_INJECTION",
  "severity": "CRITICAL",
  "request_details": {
    "ip": "192.168.1.100",
    "path": "/login?user=' OR '1'='1--",
    "method": "GET"
  },
  "context": "Retrieved CVE and mitigation data from RAG"
}
```

**Output Format**:
```json
{
  "explanation": "Detailed attack explanation in plain English",
  "impact": "Potential data breach, authentication bypass",
  "severity_justification": "Why this is critical",
  "mitigation_steps": [
    "Immediate: Block IP 192.168.1.100",
    "Short-term: Implement input validation",
    "Long-term: Use parameterized queries"
  ],
  "code_fix": "Example code showing the fix",
  "references": ["CVE-2023-xxxx", "OWASP A03:2021"]
}
```

---

#### Module 7: Security Automation Engine
**Purpose**: Automated defense actions

**Features**:
- Automatic IP blocking (iptables/firewall)
- Rate limiting (NGINX configuration)
- fail2ban integration
- Temporary ban management (auto-unblock)
- Whitelist/blacklist management
- WAF (Web Application Firewall) rule updates
- Emergency lockdown mode
- Rollback mechanisms

**Defense Actions**:

| Attack Type | Automatic Response | Duration | Priority |
|------------|-------------------|----------|----------|
| SQL Injection | Block IP immediately | 24 hours | CRITICAL |
| Brute Force (5+ attempts) | Block IP | 1 hour | HIGH |
| Path Traversal | Block IP | 24 hours | HIGH |
| XSS Attempt | Rate limit IP | 6 hours | MEDIUM |
| DDoS Pattern | Rate limit + CAPTCHA | Until review | CRITICAL |
| Port Scan | Block IP | 48 hours | MEDIUM |

**Safety Features**:
- Never block localhost (127.0.0.1)
- Never block configured safe IPs
- Whitelist management
- Auto-unblock after duration
- Manual override capability
- Dry-run mode (testing without blocking)
- Logging all defense actions

**Technologies**:
- iptables (Linux firewall)
- fail2ban (automated ban system)
- NGINX (rate limiting configuration)
- subprocess (Python system commands)
- APScheduler (scheduled unblocking)

**Commands Used**:
```bash
# Block IP
iptables -A INPUT -s <IP> -j DROP

# Unblock IP
iptables -D INPUT -s <IP> -j DROP

# List rules
iptables -L -n

# NGINX rate limiting
limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;

# fail2ban
fail2ban-client set <jail> banip <IP>
fail2ban-client set <jail> unbanip <IP>
```

---

#### Module 8: Vulnerability Scanner
**Purpose**: Proactive security assessment

**Features**:
- Port scanning
- Service detection
- Vulnerability identification
- Outdated software detection
- Misconfigurations detection
- SSL/TLS certificate checking
- HTTP header analysis
- Directory/file enumeration

**Scanning Tools**:
- nmap (port scanning, service detection)
- nikto (web server scanning)
- sqlmap (SQL injection testing)
- dirb/dirsearch (directory enumeration)
- testssl.sh (SSL/TLS testing)

**Scan Types**:
- Quick scan (common ports)
- Full scan (all ports)
- Service version detection
- OS detection
- Vulnerability scripts (nmap NSE)

**Technologies**:
- python-nmap (nmap Python wrapper)
- subprocess (for external tools)
- requests (HTTP testing)
- BeautifulSoup (response parsing)

**Output Format**:
```json
{
  "scan_time": "2024-03-19T10:30:00",
  "target": "192.168.1.50",
  "open_ports": [
    {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
    {"port": 80, "service": "http", "version": "nginx 1.18"},
    {"port": 3306, "service": "mysql", "version": "5.7.33"}
  ],
  "vulnerabilities": [
    {
      "severity": "HIGH",
      "description": "Outdated MySQL version",
      "recommendation": "Upgrade to MySQL 8.0"
    },
    {
      "severity": "MEDIUM",
      "description": "Exposed database port",
      "recommendation": "Restrict port 3306 to localhost"
    }
  ]
}
```

---

#### Module 9: Attack Simulation Engine
**Purpose**: Security testing and validation

**Features**:
- Automated attack simulation
- Defense mechanism testing
- False positive/negative detection
- System stress testing
- Attack scenario playback

**Simulated Attacks**:
- SQL Injection variants
- Brute force login attempts
- Path traversal attempts
- XSS injections
- Port scanning
- DDoS simulation (traffic spike)
- Directory enumeration
- Session hijacking attempts

**Simulation Workflow**:
```
1. Select attack type
2. Configure attack parameters (intensity, target)
3. Execute simulation
4. Monitor system response
5. Verify detection occurred
6. Verify defense action taken
7. Generate test report
```

**Technologies**:
- sqlmap (SQL injection testing)
- hydra (brute force testing)
- nmap (port scanning)
- ab/wrk (load testing for DDoS)
- Custom Python scripts

**Safety Measures**:
- Only run on test environment
- Configurable attack intensity
- Emergency stop mechanism
- Isolated test network

---

#### Module 10: Security Dashboard
**Purpose**: Real-time monitoring and control interface

**Features**:

**Real-time Monitoring**:
- Active attacks feed (live updates)
- Blocked IPs list
- Attack type distribution (pie chart)
- Attack timeline (time-series graph)
- System health metrics
- Traffic statistics

**Attack Details**:
- IP address
- Attack type
- Timestamp
- Defense action taken
- Severity level
- AI analysis result
- Source country (GeoIP)

**Controls**:
- Manual IP block/unblock
- Whitelist management
- Defense mode toggle (active/passive/dry-run)
- Emergency lockdown button
- System configuration

**Reports**:
- Daily security summary
- Attack trends
- Top attacking IPs/countries
- Most targeted endpoints
- Vulnerability scan results

**Visualizations**:
- Real-time attack map (geographic)
- Attack type distribution (pie chart)
- Hourly traffic patterns (line graph)
- Risk score gauge
- Blocked vs allowed requests

**Technologies**:
- Streamlit (web framework)
- Plotly (interactive charts)
- pandas (data manipulation)
- WebSocket (real-time updates)
- SQLite/PostgreSQL (data source)

**Dashboard Layout**:
```
┌─────────────────────────────────────────────────┐
│  SECURITY DASHBOARD                             │
├─────────────────────────────────────────────────┤
│  Status: ACTIVE  |  Risk: MEDIUM  |  Uptime: 5d │
├─────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐            │
│  │ Active       │  │ Blocked IPs  │            │
│  │ Attacks: 3   │  │ Total: 15    │            │
│  └──────────────┘  └──────────────┘            │
├─────────────────────────────────────────────────┤
│  LIVE ATTACK FEED                               │
│  ┌───────────────────────────────────────────┐ │
│  │ [14:23:45] SQL Injection | 192.168.1.50   │ │
│  │ Action: BLOCKED | Severity: CRITICAL      │ │
│  ├───────────────────────────────────────────┤ │
│  │ [14:22:10] Brute Force | 10.0.0.25        │ │
│  │ Action: RATE LIMITED | Severity: HIGH     │ │
│  └───────────────────────────────────────────┘ │
├─────────────────────────────────────────────────┤
│  ATTACK DISTRIBUTION        TIMELINE GRAPH      │
│  [Pie Chart]                [Line Chart]        │
└─────────────────────────────────────────────────┘
```

---

## MVP Version (Recommended Start)

### MVP Feature Set (5 Modules)

**✅ Module 1: Monitoring Agent**
- Real-time log collection from NGINX
- Log parsing (access logs only)
- Traffic metrics
- SQLite storage

**✅ Module 2: Attack Detection Engine**
- SQL Injection detection (pattern-based)
- Brute Force detection (threshold-based)
- Path Traversal detection
- XSS detection
- Basic severity scoring

**✅ Module 3: Defense Automation Engine** ⭐
- Automatic IP blocking (iptables)
- Temporary bans with auto-unblock
- Whitelist protection (never block localhost/own IP)
- Manual unblock capability
- Defense action logging

**✅ Module 4: LLM Analysis Engine**
- Attack explanation using Ollama (Llama 3.2 3B)
- Fix recommendations
- Code examples
- Basic prompt templates

**✅ Module 5: Security Dashboard**
- Real-time attack feed
- Blocked IP list
- Attack type breakdown
- Manual controls (block/unblock)
- System status

### MVP Exclusions (Add Later If Time Allows)

**❌ Skipped in MVP**:
- Machine learning anomaly detection
- Knowledge graphs
- RAG threat intelligence
- Vulnerability scanner
- Attack simulator (use manual tools instead)
- Advanced visualizations
- GeoIP mapping

**Reasoning**: These add complexity without being essential for a working defense system. Build MVP first, then add incrementally.

---

## Technology Stack

### Backend
```yaml
Language: Python 3.11+
Framework: FastAPI
Async Runtime: asyncio, uvicorn
```

### AI/ML
```yaml
LLM Runtime: Ollama
Models:
  - llama3.2:3b (MVP - lightweight)
  - llama3:8b (Full version - better quality)
  - codellama:7b (Code analysis)
  
ML Framework: scikit-learn
Libraries:
  - pandas (data manipulation)
  - numpy (numerical operations)
  - joblib (model persistence)

RAG Stack: (Full version only)
  - LangChain (orchestration)
  - Qdrant (vector database)
  - bge-small-en-v1.5 (embeddings)
```

### Security Tools
```yaml
Firewall: iptables
Ban Management: fail2ban (optional)
Web Server: NGINX
Scanning Tools:
  - nmap (port scanning)
  - nikto (web vulnerability)
  - sqlmap (SQL injection testing)
  - hydra (brute force testing)
```

### Database
```yaml
Primary: SQLite (MVP)
Alternative: PostgreSQL (Full version, production)
Vector DB: Qdrant (RAG in full version)
Graph DB: Neo4j or NetworkX (Knowledge graph in full version)
```

### Dashboard
```yaml
Framework: Streamlit
Visualization: Plotly, matplotlib
Real-time: WebSocket (optional)
```

### DevOps
```yaml
Containerization: Docker, Docker Compose
Process Management: systemd (production)
Logging: Python logging, logrotate
Monitoring: psutil
```

---

## Project Structure

```
cyber-defense-agent/
│
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.dashboard
│   ├── Dockerfile.testapp
│   └── docker-compose.yml
│
├── backend/
│   ├── __init__.py
│   ├── main.py                      # FastAPI entry point
│   ├── config.py                    # Configuration management
│   │
│   ├── monitoring/
│   │   ├── __init__.py
│   │   ├── log_collector.py         # Real-time log streaming
│   │   ├── log_parser.py            # Log parsing logic
│   │   ├── metrics_collector.py     # System metrics
│   │   └── storage.py               # Database operations
│   │
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── detection_engine.py      # Main detection orchestrator
│   │   ├── sql_injection.py         # SQL injection detector
│   │   ├── brute_force.py           # Brute force detector
│   │   ├── path_traversal.py        # Path traversal detector
│   │   ├── xss_detector.py          # XSS detector
│   │   ├── patterns.py              # Attack patterns database
│   │   └── anomaly_model.py         # ML anomaly detection (Full version)
│   │
│   ├── defense/
│   │   ├── __init__.py
│   │   ├── defense_engine.py        # Defense orchestrator
│   │   ├── ip_blocker.py            # iptables management
│   │   ├── rate_limiter.py          # NGINX rate limiting
│   │   ├── whitelist_manager.py     # Whitelist/blacklist
│   │   └── unblock_scheduler.py     # Auto-unblock timer
│   │
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── llm_analyzer.py          # Ollama integration
│   │   ├── prompts.py               # Prompt templates
│   │   ├── rag_engine.py            # RAG system (Full version)
│   │   └── knowledge_graph.py       # Graph operations (Full version)
│   │
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── cve_fetcher.py           # CVE database integration (Full)
│   │   ├── threat_db.py             # Threat intelligence (Full)
│   │   └── embeddings.py            # Vector embeddings (Full)
│   │
│   ├── scanning/
│   │   ├── __init__.py
│   │   ├── vulnerability_scanner.py # nmap/nikto wrapper (Full)
│   │   └── attack_simulator.py      # Attack simulation (Full)
│   │
│   └── api/
│       ├── __init__.py
│       ├── routes.py                # API endpoints
│       └── models.py                # Pydantic models
│
├── dashboard/
│   ├── __init__.py
│   ├── app.py                       # Streamlit main app
│   ├── components/
│   │   ├── __init__.py
│   │   ├── attack_feed.py           # Live attack component
│   │   ├── blocked_ips.py           # Blocked IPs component
│   │   ├── charts.py                # Visualization components
│   │   └── controls.py              # Manual controls
│   └── utils/
│       ├── __init__.py
│       └── data_fetcher.py          # Backend API client
│
├── test_app/
│   ├── __init__.py
│   ├── vulnerable_app.py            # Deliberately vulnerable Flask app
│   ├── templates/
│   │   └── login.html
│   └── init_db.py                   # Test database setup
│
├── data/
│   ├── logs/                        # Log files
│   ├── db/                          # SQLite databases
│   ├── models/                      # Trained ML models
│   ├── vectors/                     # Qdrant vector data (Full)
│   └── graphs/                      # Neo4j data (Full)
│
├── config/
│   ├── nginx.conf                   # NGINX configuration
│   ├── settings.yaml                # Application settings
│   ├── whitelist.txt                # Safe IPs
│   └── attack_patterns.json         # Attack signatures
│
├── scripts/
│   ├── setup.sh                     # Initial setup script
│   ├── start_services.sh            # Start all services
│   ├── stop_services.sh             # Stop all services
│   ├── emergency_unblock.sh         # Emergency IP unblock
│   └── backup.sh                    # Backup data
│
├── tests/
│   ├── __init__.py
│   ├── test_detection.py
│   ├── test_defense.py
│   ├── test_analysis.py
│   └── test_integration.py
│
├── docs/
│   ├── API.md                       # API documentation
│   ├── SETUP.md                     # Setup instructions
│   ├── ARCHITECTURE.md              # Architecture details
│   └── DEMO.md                      # Demo scenario
│
├── requirements.txt                 # Python dependencies
├── requirements-full.txt            # Full version dependencies
├── requirements-mvp.txt             # MVP version dependencies
├── .env.example                     # Environment variables template
├── .gitignore
├── README.md
└── PROJECT_PLAN.md                  # This file
```

---

## Development Timeline

### MVP Timeline (8 Weeks)

```
Week 1: Environment Setup & Project Structure
├── Day 1-2: Docker setup, Python environment
├── Day 3-4: Project structure creation
├── Day 5-6: Vulnerable test app deployment
└── Day 7: NGINX configuration

Week 2: Monitoring Agent
├── Day 1-3: Log collector implementation
├── Day 4-5: Log parser development
├── Day 6-7: Database storage & testing
└── Deliverable: Real-time log monitoring working

Week 3: Attack Detection Engine (Part 1)
├── Day 1-2: SQL injection detector
├── Day 3-4: Brute force detector
├── Day 5-6: Path traversal detector
└── Day 7: Testing & validation

Week 4: Attack Detection + Defense Integration
├── Day 1-2: XSS detector
├── Day 3-4: Defense engine foundation
├── Day 5-6: iptables integration
└── Day 7: Testing defense actions
└── Deliverable: Detection + Blocking working

Week 5: LLM Analysis Engine
├── Day 1-2: Ollama setup & testing
├── Day 3-4: Prompt engineering
├── Day 5-6: Analysis pipeline integration
└── Day 7: Testing AI responses
└── Deliverable: AI analysis working

Week 6: Defense Refinement
├── Day 1-2: Auto-unblock scheduler
├── Day 3-4: Whitelist management
├── Day 5-6: Safety mechanisms
└── Day 7: Comprehensive defense testing
└── Deliverable: Robust defense system

Week 7: Dashboard Development
├── Day 1-3: Streamlit dashboard foundation
├── Day 4-5: Real-time components
├── Day 6-7: Manual controls & visualizations
└── Deliverable: Working dashboard

Week 8: Testing, Documentation & Demo Prep
├── Day 1-2: Integration testing
├── Day 3-4: Demo scenario preparation
├── Day 5-6: Documentation
└── Day 7: Final presentation rehearsal
└── Deliverable: Complete MVP ready for demo
```

### Full Version Timeline (16 Weeks)

```
Weeks 1-8: Complete MVP (as above)

Week 9: Anomaly Detection Model
├── Data collection & feature engineering
├── Model training (Isolation Forest)
├── Integration with detection engine
└── Deliverable: ML-based anomaly detection

Week 10: RAG System Foundation
├── Qdrant setup
├── CVE data ingestion
├── Embedding generation
└── Deliverable: Vector search working

Week 11: Threat Intelligence Integration
├── CVE API integration
├── Security feed scraping
├── RAG query optimization
└── Deliverable: Context-aware LLM analysis

Week 12: Knowledge Graph
├── Neo4j/NetworkX setup
├── Graph schema design
├── Attack relationship mapping
└── Deliverable: Graph-based analysis

Week 13: Vulnerability Scanner
├── nmap integration
├── nikto integration
├── Scan scheduling
└── Deliverable: Automated vulnerability scanning

Week 14: Attack Simulator
├── Simulation framework
├── Attack scenarios
├── Automated testing
└── Deliverable: Continuous security testing

Week 15: Dashboard Enhancement
├── Advanced visualizations
├── GeoIP mapping
├── Reporting system
└── Deliverable: Production-grade dashboard

Week 16: Final Testing & Documentation
├── Load testing
├── Security audit
├── Complete documentation
└── Deliverable: Production-ready system
```

---

## Module Specifications

### Module 1: Monitoring Agent

**File**: `backend/monitoring/log_collector.py`

**Class**: `LogCollector`

**Purpose**: Stream logs in real-time from NGINX access logs

**Key Methods**:
```python
def __init__(self, log_path: str):
    """Initialize with log file path"""
    
def tail_logs(self) -> Generator[str]:
    """Generator that yields new log lines in real-time"""
    
def start_monitoring(self, callback: Callable):
    """Start monitoring and call callback for each log line"""
```

**Dependencies**:
- `pathlib` (file operations)
- `time` (polling)
- `asyncio` (async version - optional)

---

**File**: `backend/monitoring/log_parser.py`

**Class**: `NginxLogParser`

**Purpose**: Parse NGINX combined log format into structured data

**Input** (Raw Log Line):
```
192.168.1.100 - - [19/Mar/2024:14:23:45 +0000] "GET /login?user=admin HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

**Output** (Parsed Dictionary):
```python
{
    'ip': '192.168.1.100',
    'timestamp': '19/Mar/2024:14:23:45 +0000',
    'method': 'GET',
    'path': '/login?user=admin',
    'status': 200,
    'size': 1234,
    'user_agent': 'Mozilla/5.0',
    'referrer': '-',
    'raw_log': '...'  # Original line
}
```

**Key Methods**:
```python
def parse(self, log_line: str) -> Optional[Dict]:
    """Parse single log line, return None if invalid"""
```

**Regular Expression**:
```python
LOG_PATTERN = re.compile(
    r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\w+) (?P<path>[^\s]+) HTTP/[\d.]+" '
    r'(?P<status>\d+) (?P<size>\d+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)
```

---

**File**: `backend/monitoring/storage.py`

**Class**: `LogStorage`

**Purpose**: Store parsed logs in SQLite database

**Database Schema**:
```sql
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    size INTEGER,
    user_agent TEXT,
    referrer TEXT,
    is_suspicious BOOLEAN DEFAULT 0,
    attack_type TEXT,
    blocked BOOLEAN DEFAULT 0,
    raw_log TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip),
    INDEX idx_timestamp (timestamp),
    INDEX idx_attack_type (attack_type)
);
```

**Key Methods**:
```python
def save_request(self, parsed_log: Dict) -> int:
    """Save parsed log to database, return row ID"""
    
def mark_suspicious(self, request_id: int, attack_type: str):
    """Mark request as suspicious"""
    
def get_recent_requests(self, limit: int = 100) -> List[Dict]:
    """Get recent requests"""
    
def get_requests_by_ip(self, ip: str, hours: int = 24) -> List[Dict]:
    """Get all requests from an IP in last N hours"""
```

---

### Module 2: Attack Detection Engine

**File**: `backend/detection/sql_injection.py`

**Class**: `SQLInjectionDetector`

**Purpose**: Detect SQL injection attempts using pattern matching

**Attack Patterns**:
```python
PATTERNS = [
    # Meta-characters
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    
    # SQL operators with quotes
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    
    # OR keyword variations
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    
    # UNION attacks
    r"((\%27)|(\'))union",
    r"UNION.*SELECT",
    
    # Common SQL commands
    r"SELECT.*FROM",
    r"INSERT.*INTO",
    r"DELETE.*FROM",
    r"DROP.*TABLE",
    r"UPDATE.*SET",
    
    # Classic injections
    r"' or '1'='1",
    r"' or 1=1--",
    r"admin'--",
    
    # Comment techniques
    r"';.*--",
    r"/\*.*\*/",
    
    # Stored procedures
    r"exec(\s|\+)+(s|x)p\w+",
]
```

**Key Methods**:
```python
def detect(self, request_path: str, method: str) -> Dict:
    """
    Returns:
    {
        'detected': bool,
        'attack_type': 'SQL_INJECTION',
        'severity': 'CRITICAL' | 'HIGH' | 'MEDIUM',
        'pattern': str,  # Matched pattern
        'confidence': float  # 0-1
    }
    """
```

**Severity Logic**:
- `CRITICAL`: DROP, DELETE, EXEC, UNION SELECT
- `HIGH`: OR 1=1, authentication bypass
- `MEDIUM`: Generic SQL keywords

---

**File**: `backend/detection/brute_force.py`

**Class**: `BruteForceDetector`

**Purpose**: Detect brute force login attempts

**Configuration**:
```python
THRESHOLD = 5          # Max failed attempts
TIME_WINDOW = 60       # Seconds
LOCKOUT_DURATION = 3600  # 1 hour in seconds
```

**Detection Logic**:
```python
# Track failed login attempts per IP
failed_attempts = {
    'ip_address': [timestamp1, timestamp2, ...]
}

# Algorithm:
1. Check if request is a failed login (path contains /login and status 401/403)
2. Add timestamp to IP's attempt list
3. Remove timestamps older than TIME_WINDOW
4. If remaining attempts >= THRESHOLD, trigger alert
```

**Key Methods**:
```python
def detect(self, ip: str, path: str, status: int) -> Dict:
    """
    Returns:
    {
        'detected': bool,
        'attack_type': 'BRUTE_FORCE',
        'severity': 'HIGH',
        'attempt_count': int,
        'time_window': int
    }
    """
    
def reset_attempts(self, ip: str):
    """Clear attempt history for IP (after successful login)"""
```

---

**File**: `backend/detection/path_traversal.py`

**Class**: `PathTraversalDetector`

**Purpose**: Detect directory traversal attacks

**Attack Patterns**:
```python
PATTERNS = [
    r'\.\.',                    # Basic traversal
    r'%2e%2e',                  # URL encoded ..
    r'\.\./',                   # Unix path
    r'\.\.\',                   # Windows path
    r'/etc/passwd',             # Linux sensitive file
    r'/etc/shadow',
    r'C:\\Windows\\',           # Windows system
    r'%00',                     # Null byte injection
    r'....//....//....//etc',   # Obfuscated traversal
]
```

**Sensitive Files Database**:
```python
SENSITIVE_FILES = [
    '/etc/passwd', '/etc/shadow', '/etc/hosts',
    'C:\\Windows\\System32\\config\\SAM',
    '/proc/self/environ',
    '/.ssh/id_rsa',
    '/var/www/html/.htpasswd'
]
```

**Key Methods**:
```python
def detect(self, path: str) -> Dict:
    """Returns detection result with matched pattern"""
```

---

**File**: `backend/detection/detection_engine.py`

**Class**: `AttackDetectionEngine`

**Purpose**: Orchestrate all detectors and produce unified results

**Architecture**:
```python
class AttackDetectionEngine:
    def __init__(self):
        self.sql_detector = SQLInjectionDetector()
        self.brute_force_detector = BruteForceDetector()
        self.path_traversal_detector = PathTraversalDetector()
        self.xss_detector = XSSDetector()
        # Full version adds:
        # self.anomaly_detector = AnomalyDetector()
    
    def analyze_request(self, request_data: Dict) -> List[Dict]:
        """
        Run all detectors and return list of detected attacks
        """
```

**Workflow**:
```
1. Receive parsed request data
2. Run through all detectors in parallel (asyncio)
3. Collect positive detections
4. Aggregate results
5. Determine highest severity
6. Return detection list
```

**Output Format**:
```python
[
    {
        'attack_type': 'SQL_INJECTION',
        'severity': 'CRITICAL',
        'detector': 'sql_injection',
        'confidence': 0.95,
        'details': 'Pattern matched: UNION SELECT',
        'recommended_action': 'BLOCK_IP'
    },
    # ... more detections if multiple attacks in one request
]
```

---

### Module 3: Defense Automation Engine

**File**: `backend/defense/defense_engine.py`

**Class**: `DefenseEngine`

**Purpose**: Execute automated defensive actions

**Defense Actions**:
```python
ACTIONS = {
    'BLOCK_IP': block_ip_via_iptables,
    'RATE_LIMIT': apply_nginx_rate_limit,
    'TEMP_BAN': temporary_ip_ban,
    'CAPTCHA': serve_captcha_challenge,
    'ALERT_ONLY': log_without_action
}
```

**Configuration**:
```python
class DefenseConfig:
    ENABLE_AUTO_BLOCK = True  # Set False for dry-run mode
    WHITELIST = ['127.0.0.1', 'YOUR_IP_HERE']
    
    BAN_DURATIONS = {
        'SQL_INJECTION': 86400,    # 24 hours
        'BRUTE_FORCE': 3600,       # 1 hour
        'PATH_TRAVERSAL': 86400,   # 24 hours
        'XSS': 21600,              # 6 hours
        'DEFAULT': 3600            # 1 hour
    }
```

**Key Methods**:
```python
def execute_defense(self, attack_info: Dict) -> Dict:
    """
    Execute defensive action based on attack type
    Returns action result
    """
    
def is_whitelisted(self, ip: str) -> bool:
    """Check if IP is in whitelist"""
    
def log_defense_action(self, action: str, ip: str, details: Dict):
    """Log all defensive actions to database"""
```

---

**File**: `backend/defense/ip_blocker.py`

**Class**: `IPBlocker`

**Purpose**: Manage iptables rules for IP blocking

**Key Methods**:
```python
def block_ip(self, ip: str, reason: str) -> bool:
    """
    Block IP using iptables
    Command: sudo iptables -A INPUT -s <IP> -j DROP
    Returns True if successful
    """
    
def unblock_ip(self, ip: str) -> bool:
    """
    Unblock IP
    Command: sudo iptables -D INPUT -s <IP> -j DROP
    """
    
def list_blocked_ips(self) -> List[str]:
    """
    Get list of currently blocked IPs
    Command: sudo iptables -L INPUT -n | grep DROP
    """
    
def is_blocked(self, ip: str) -> bool:
    """Check if IP is currently blocked"""
```

**iptables Commands Reference**:
```bash
# Block IP
sudo iptables -A INPUT -s 192.168.1.100 -j DROP

# Unblock IP
sudo iptables -D INPUT -s 192.168.1.100 -j DROP

# List all rules
sudo iptables -L INPUT -n -v

# Save rules (persistent across reboots)
sudo iptables-save > /etc/iptables/rules.v4

# Restore rules
sudo iptables-restore < /etc/iptables/rules.v4

# Flush all rules (EMERGENCY ONLY)
sudo iptables -F
```

**Safety Checks**:
```python
def _is_safe_to_block(self, ip: str) -> bool:
    """
    Safety checks before blocking:
    - Not in whitelist
    - Not localhost
    - Not private IP (configurable)
    - Valid IP format
    """
```

---

**File**: `backend/defense/unblock_scheduler.py`

**Class**: `UnblockScheduler`

**Purpose**: Auto-unblock IPs after ban duration expires

**Implementation**:
```python
from apscheduler.schedulers.background import BackgroundScheduler

class UnblockScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()
    
    def schedule_unblock(self, ip: str, duration_seconds: int):
        """Schedule IP unblock after duration"""
        self.scheduler.add_job(
            func=self._unblock_ip,
            trigger='date',
            run_date=datetime.now() + timedelta(seconds=duration_seconds),
            args=[ip]
        )
    
    def _unblock_ip(self, ip: str):
        """Called automatically when timer expires"""
        # Unblock IP
        # Log action
        # Send notification
```

**Database Tracking**:
```sql
CREATE TABLE scheduled_unblocks (
    id INTEGER PRIMARY KEY,
    ip TEXT,
    block_time DATETIME,
    unblock_time DATETIME,
    attack_type TEXT,
    status TEXT  -- 'PENDING', 'COMPLETED', 'CANCELLED'
);
```

---

### Module 4: LLM Analysis Engine

**File**: `backend/analysis/llm_analyzer.py`

**Class**: `LLMAnalyzer`

**Purpose**: Analyze attacks using local LLM (Ollama)

**Configuration**:
```python
class LLMConfig:
    MODEL = 'llama3.2:3b'  # MVP: lightweight model
    # Full version: 'llama3:8b' or 'codellama:7b'
    
    API_URL = 'http://localhost:11434/api/generate'
    
    TEMPERATURE = 0.3  # Lower = more consistent
    MAX_TOKENS = 1000
```

**Key Methods**:
```python
def analyze_attack(self, attack_data: Dict, request_data: Dict) -> Dict:
    """
    Send attack to LLM for analysis
    Returns structured analysis
    """
    
def _build_prompt(self, attack_data: Dict, request_data: Dict) -> str:
    """Create analysis prompt from template"""
    
def _parse_response(self, llm_output: str) -> Dict:
    """Extract JSON from LLM response"""
```

---

**File**: `backend/analysis/prompts.py`

**Prompt Templates**:

```python
SQL_INJECTION_ANALYSIS_PROMPT = """You are a cybersecurity expert analyzing a detected SQL injection attack.

ATTACK DETAILS:
- Type: {attack_type}
- Severity: {severity}
- Confidence: {confidence}

REQUEST DETAILS:
- IP Address: {ip}
- HTTP Method: {method}
- Request Path: {path}
- Status Code: {status}
- User Agent: {user_agent}
- Matched Pattern: {pattern}

TASK:
Provide a comprehensive security analysis in the following format:

1. ATTACK EXPLANATION (2-3 sentences):
   - What SQL injection technique was attempted?
   - What was the attacker trying to achieve?

2. POTENTIAL IMPACT:
   - What data could be compromised?
   - What system damage is possible?

3. MITIGATION STEPS (prioritized list):
   - Immediate actions (already taken: IP blocked)
   - Short-term fixes
   - Long-term security improvements

4. CODE FIX EXAMPLE:
   - Show vulnerable code vs secure code
   - Use the specific framework/language if detectable

Respond in valid JSON format:
{{
    "explanation": "...",
    "impact": "...",
    "mitigation": ["step 1", "step 2", "step 3"],
    "code_fix": {{
        "vulnerable": "...",
        "secure": "..."
    }},
    "references": ["OWASP A03", "CWE-89"]
}}
"""

BRUTE_FORCE_ANALYSIS_PROMPT = """You are a cybersecurity expert analyzing a brute force attack.

ATTACK DETAILS:
- Failed Attempts: {attempt_count}
- Time Window: {time_window} seconds
- Target: {path}

REQUEST DETAILS:
- IP Address: {ip}
- User Agent: {user_agent}

TASK:
Provide analysis in JSON format:
{{
    "explanation": "Description of the attack pattern",
    "impact": "Potential consequences",
    "mitigation": [
        "Immediate actions",
        "Account security improvements",
        "Long-term prevention"
    ],
    "code_fix": {{
        "recommendation": "Implement rate limiting, account lockout, 2FA"
    }}
}}
"""

# Additional prompts for XSS, Path Traversal, etc.
```

---

**Ollama API Integration**:
```python
import requests
import json

def call_ollama(prompt: str, model: str = 'llama3.2:3b') -> str:
    """Call Ollama API"""
    
    response = requests.post(
        'http://localhost:11434/api/generate',
        json={
            'model': model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': 0.3,
                'num_predict': 1000
            }
        }
    )
    
    if response.status_code == 200:
        return response.json()['response']
    else:
        raise Exception(f"Ollama API error: {response.status_code}")
```

**Response Parsing**:
```python
def parse_llm_json(response: str) -> Dict:
    """Extract JSON from LLM response (which might have extra text)"""
    
    # Try to find JSON block
    start = response.find('{')
    end = response.rfind('}') + 1
    
    if start != -1 and end != 0:
        json_str = response[start:end]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # Fallback: clean and retry
            json_str = json_str.replace('\n', ' ').strip()
            return json.loads(json_str)
    
    # Fallback: return as plain text
    return {
        'explanation': response,
        'impact': 'Unable to parse',
        'mitigation': [],
        'code_fix': {}
    }
```

---

### Module 5: Security Dashboard

**File**: `dashboard/app.py`

**Framework**: Streamlit

**Page Structure**:
```python
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

def main():
    st.set_page_config(
        page_title="AI Cyber Defense Dashboard",
        page_icon="🛡️",
        layout="wide"
    )
    
    # Sidebar
    with st.sidebar:
        render_sidebar()
    
    # Main content
    render_header()
    render_metrics_row()
    render_live_feed()
    render_charts()
    render_controls()

if __name__ == '__main__':
    main()
```

---

**Components**:

**1. Header & Status**:
```python
def render_header():
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            "System Status",
            "ACTIVE" if defense_active else "PASSIVE",
            delta="Monitoring" if defense_active else "Dry-run mode"
        )
    
    with col2:
        st.metric(
            "Risk Level",
            calculate_risk_level(),
            delta=f"{active_attacks_count} active attacks"
        )
    
    with col3:
        st.metric(
            "Uptime",
            calculate_uptime(),
            delta="Since last restart"
        )
```

**2. Live Attack Feed**:
```python
def render_live_feed():
    st.subheader("🚨 Live Attack Feed")
    
    # Auto-refresh every 2 seconds
    placeholder = st.empty()
    
    recent_attacks = fetch_recent_attacks(limit=10)
    
    for attack in recent_attacks:
        with st.container():
            col1, col2, col3, col4 = st.columns([3, 2, 2, 2])
            
            col1.write(f"**{attack['attack_type']}**")
            col2.write(f"IP: `{attack['ip']}`")
            col3.write(f"Severity: {get_severity_badge(attack['severity'])}")
            col4.write(f"{attack['timestamp']}")
            
            # Expandable details
            with st.expander("View Details"):
                st.json(attack)
                if attack.get('ai_analysis'):
                    st.subheader("AI Analysis")
                    st.write(attack['ai_analysis']['explanation'])
                    st.code(attack['ai_analysis']['code_fix'])
```

**3. Blocked IPs Management**:
```python
def render_blocked_ips():
    st.subheader("🚫 Blocked IPs")
    
    blocked_ips = fetch_blocked_ips()
    
    df = pd.DataFrame(blocked_ips)
    
    # Display table
    st.dataframe(df[['ip', 'attack_type', 'block_time', 'unblock_time', 'status']])
    
    # Manual unblock
    st.write("**Manual Controls**")
    ip_to_unblock = st.selectbox("Select IP to unblock", df['ip'].tolist())
    
    if st.button("Unblock IP"):
        unblock_ip(ip_to_unblock)
        st.success(f"IP {ip_to_unblock} has been unblocked")
        st.experimental_rerun()
```

**4. Attack Distribution Chart**:
```python
def render_attack_distribution():
    st.subheader("📊 Attack Type Distribution (Last 24h)")
    
    attack_counts = fetch_attack_distribution()
    
    fig = px.pie(
        values=attack_counts.values(),
        names=attack_counts.keys(),
        title="Attack Types",
        color_discrete_sequence=px.colors.qualitative.Set3
    )
    
    st.plotly_chart(fig, use_container_width=True)
```

**5. Attack Timeline**:
```python
def render_attack_timeline():
    st.subheader("📈 Attack Timeline (Last 7 Days)")
    
    timeline_data = fetch_attack_timeline(days=7)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=timeline_data['timestamp'],
        y=timeline_data['attack_count'],
        mode='lines+markers',
        name='Attacks',
        line=dict(color='red', width=2)
    ))
    
    fig.update_layout(
        title="Attacks Over Time",
        xaxis_title="Time",
        yaxis_title="Number of Attacks"
    )
    
    st.plotly_chart(fig, use_container_width=True)
```

**6. Manual Controls**:
```python
def render_controls():
    st.subheader("⚙️ Manual Controls")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🛡️ Enable Auto-Defense"):
            enable_auto_defense()
            st.success("Auto-defense enabled")
    
    with col2:
        if st.button("⏸️ Pause Defense"):
            pause_defense()
            st.warning("Defense paused (dry-run mode)")
    
    with col3:
        if st.button("🚨 Emergency Unblock All"):
            if st.checkbox("Confirm emergency unblock"):
                emergency_unblock_all()
                st.success("All IPs unblocked")
    
    # Manual IP block
    st.write("**Manual IP Blocking**")
    manual_ip = st.text_input("IP Address to block")
    manual_reason = st.text_input("Reason")
    
    if st.button("Block IP"):
        if validate_ip(manual_ip):
            block_ip_manual(manual_ip, manual_reason)
            st.success(f"IP {manual_ip} blocked")
        else:
            st.error("Invalid IP address")
```

---

## Docker Configuration

### Project Dockerization Strategy

**Services**:
1. `backend` - FastAPI application
2. `dashboard` - Streamlit dashboard
3. `ollama` - LLM service
4. `testapp` - Vulnerable test application
5. `nginx` - Web server (production mode)
6. `postgres` - Database (optional, for production)
7. `qdrant` - Vector database (full version only)

---

### Dockerfile: Backend

**File**: `docker/Dockerfile.backend`

```dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    sudo \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -u 1000 appuser && \
    echo "appuser ALL=(ALL) NOPASSWD: /sbin/iptables" >> /etc/sudoers

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ ./backend/
COPY config/ ./config/

# Create necessary directories
RUN mkdir -p /app/data/logs /app/data/db && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

---

### Dockerfile: Dashboard

**File**: `docker/Dockerfile.dashboard`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy dashboard code
COPY dashboard/ ./dashboard/

# Create user
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8501

CMD ["streamlit", "run", "dashboard/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

---

### Dockerfile: Test Application

**File**: `docker/Dockerfile.testapp`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install Flask
RUN pip install flask

# Copy vulnerable test app
COPY test_app/ ./test_app/

# Create database
RUN python test_app/init_db.py

EXPOSE 5000

CMD ["python", "test_app/vulnerable_app.py"]
```

---

### Docker Compose Configuration

**File**: `docker/docker-compose.yml`

```yaml
version: '3.8'

services:
  # Backend API
  backend:
    build:
      context: ..
      dockerfile: docker/Dockerfile.backend
    container_name: cyber_defense_backend
    privileged: true  # Required for iptables
    volumes:
      - ../backend:/app/backend
      - ../config:/app/config
      - ../data:/app/data
      - /var/log/nginx:/var/log/nginx:ro  # Mount host NGINX logs
    ports:
      - "8000:8000"
    environment:
      - PYTHONUNBUFFERED=1
      - LOG_LEVEL=INFO
      - DATABASE_URL=sqlite:///data/db/cyber_defense.db
    networks:
      - cyber_defense_network
    restart: unless-stopped

  # Streamlit Dashboard
  dashboard:
    build:
      context: ..
      dockerfile: docker/Dockerfile.dashboard
    container_name: cyber_defense_dashboard
    volumes:
      - ../dashboard:/app/dashboard
    ports:
      - "8501:8501"
    environment:
      - BACKEND_URL=http://backend:8000
    depends_on:
      - backend
    networks:
      - cyber_defense_network
    restart: unless-stopped

  # Ollama LLM Service
  ollama:
    image: ollama/ollama:latest
    container_name: cyber_defense_ollama
    volumes:
      - ollama_data:/root/.ollama
    ports:
      - "11434:11434"
    networks:
      - cyber_defense_network
    restart: unless-stopped
    # Pull model on startup
    entrypoint: ["/bin/sh", "-c"]
    command:
      - |
        ollama serve &
        sleep 5
        ollama pull llama3.2:3b
        wait

  # Vulnerable Test Application
  testapp:
    build:
      context: ..
      dockerfile: docker/Dockerfile.testapp
    container_name: cyber_defense_testapp
    ports:
      - "5000:5000"
    networks:
      - cyber_defense_network
    restart: unless-stopped

  # NGINX (Production Mode)
  nginx:
    image: nginx:latest
    container_name: cyber_defense_nginx
    volumes:
      - ../config/nginx.conf:/etc/nginx/nginx.conf:ro
      - nginx_logs:/var/log/nginx
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - testapp
    networks:
      - cyber_defense_network
    restart: unless-stopped

  # PostgreSQL (Optional - for production)
  # postgres:
  #   image: postgres:15
  #   container_name: cyber_defense_postgres
  #   environment:
  #     POSTGRES_DB: cyber_defense
  #     POSTGRES_USER: admin
  #     POSTGRES_PASSWORD: changeme
  #   volumes:
  #     - postgres_data:/var/lib/postgresql/data
  #   ports:
  #     - "5432:5432"
  #   networks:
  #     - cyber_defense_network
  #   restart: unless-stopped

  # Qdrant Vector Database (Full Version Only)
  # qdrant:
  #   image: qdrant/qdrant:latest
  #   container_name: cyber_defense_qdrant
  #   volumes:
  #     - qdrant_data:/qdrant/storage
  #   ports:
  #     - "6333:6333"
  #   networks:
  #     - cyber_defense_network
  #   restart: unless-stopped

volumes:
  ollama_data:
  nginx_logs:
  # postgres_data:
  # qdrant_data:

networks:
  cyber_defense_network:
    driver: bridge
```

---

### Docker Commands Reference

```bash
# Build and start all services
docker-compose -f docker/docker-compose.yml up --build -d

# View logs
docker-compose -f docker/docker-compose.yml logs -f backend

# Stop all services
docker-compose -f docker/docker-compose.yml down

# Restart a specific service
docker-compose -f docker/docker-compose.yml restart backend

# Execute command in container
docker-compose -f docker/docker-compose.yml exec backend bash

# View blocked IPs (inside backend container)
docker-compose -f docker/docker-compose.yml exec backend sudo iptables -L

# Pull Ollama model manually
docker-compose -f docker/docker-compose.yml exec ollama ollama pull llama3.2:3b
```

---

## API Specifications

### Backend API Endpoints

**Base URL**: `http://localhost:8000`

---

#### 1. Health Check

```http
GET /health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-03-19T14:23:45Z",
  "services": {
    "database": "connected",
    "ollama": "ready",
    "defense_engine": "active"
  }
}
```

---

#### 2. Get Recent Attacks

```http
GET /api/attacks/recent?limit=10
```

**Parameters**:
- `limit` (optional, default=10): Number of attacks to return

**Response**:
```json
{
  "attacks": [
    {
      "id": 1,
      "timestamp": "2024-03-19T14:23:45Z",
      "ip": "192.168.1.100",
      "attack_type": "SQL_INJECTION",
      "severity": "CRITICAL",
      "path": "/login?user=' OR '1'='1--",
      "method": "GET",
      "blocked": true,
      "ai_analysis": {
        "explanation": "...",
        "impact": "...",
        "mitigation": [...]
      }
    }
  ],
  "total": 1
}
```

---

#### 3. Get Blocked IPs

```http
GET /api/defense/blocked-ips
```

**Response**:
```json
{
  "blocked_ips": [
    {
      "ip": "192.168.1.100",
      "attack_type": "SQL_INJECTION",
      "block_time": "2024-03-19T14:23:45Z",
      "unblock_time": "2024-03-20T14:23:45Z",
      "status": "ACTIVE",
      "reason": "Automated block - SQL injection detected"
    }
  ],
  "total": 1
}
```

---

#### 4. Block IP Manually

```http
POST /api/defense/block-ip
Content-Type: application/json

{
  "ip": "192.168.1.100",
  "reason": "Manual block by admin",
  "duration": 3600
}
```

**Response**:
```json
{
  "success": true,
  "message": "IP 192.168.1.100 blocked successfully",
  "unblock_time": "2024-03-19T15:23:45Z"
}
```

---

#### 5. Unblock IP

```http
POST /api/defense/unblock-ip
Content-Type: application/json

{
  "ip": "192.168.1.100"
}
```

**Response**:
```json
{
  "success": true,
  "message": "IP 192.168.1.100 unblocked successfully"
}
```

---

#### 6. Get Attack Statistics

```http
GET /api/stats/attacks?days=7
```

**Parameters**:
- `days` (optional, default=7): Time range in days

**Response**:
```json
{
  "total_attacks": 150,
  "by_type": {
    "SQL_INJECTION": 45,
    "BRUTE_FORCE": 60,
    "PATH_TRAVERSAL": 30,
    "XSS": 15
  },
  "by_severity": {
    "CRITICAL": 45,
    "HIGH": 60,
    "MEDIUM": 30,
    "LOW": 15
  },
  "blocked_count": 145,
  "timeline": [
    {"date": "2024-03-19", "count": 25},
    {"date": "2024-03-18", "count": 30}
  ]
}
```

---

#### 7. WebSocket: Live Attacks

```http
WS /ws/attacks
```

**Message Format** (Server → Client):
```json
{
  "type": "new_attack",
  "data": {
    "id": 123,
    "timestamp": "2024-03-19T14:23:45Z",
    "ip": "192.168.1.100",
    "attack_type": "SQL_INJECTION",
    "severity": "CRITICAL",
    "blocked": true
  }
}
```

---

## Database Schema

### SQLite Schema (MVP)

**File**: `backend/monitoring/schema.sql`

```sql
-- Requests table (all traffic)
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    ip TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status INTEGER NOT NULL,
    size INTEGER,
    user_agent TEXT,
    referrer TEXT,
    is_suspicious BOOLEAN DEFAULT 0,
    attack_type TEXT,
    severity TEXT,
    blocked BOOLEAN DEFAULT 0,
    raw_log TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ip ON requests(ip);
CREATE INDEX idx_timestamp ON requests(timestamp);
CREATE INDEX idx_attack_type ON requests(attack_type);
CREATE INDEX idx_blocked ON requests(blocked);

-- Defense actions table
CREATE TABLE IF NOT EXISTS defense_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action_type TEXT NOT NULL,  -- BLOCK_IP, UNBLOCK_IP, RATE_LIMIT
    target_ip TEXT NOT NULL,
    attack_type TEXT,
    severity TEXT,
    duration INTEGER,  -- seconds
    status TEXT,  -- SUCCESS, FAILED
    details TEXT,
    performed_by TEXT  -- SYSTEM, MANUAL
);

CREATE INDEX idx_defense_ip ON defense_actions(target_ip);
CREATE INDEX idx_defense_timestamp ON defense_actions(timestamp);

-- Blocked IPs table
CREATE TABLE IF NOT EXISTS blocked_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    attack_type TEXT,
    severity TEXT,
    block_time DATETIME NOT NULL,
    unblock_time DATETIME,
    status TEXT,  -- ACTIVE, EXPIRED, UNBLOCKED
    reason TEXT,
    blocked_by TEXT  -- SYSTEM, MANUAL
);

CREATE INDEX idx_blocked_status ON blocked_ips(status);

-- AI Analysis results
CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    attack_type TEXT,
    analysis_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    explanation TEXT,
    impact TEXT,
    mitigation TEXT,  -- JSON array
    code_fix TEXT,
    references TEXT,  -- JSON array
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

-- Whitelist
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    added_by TEXT
);

-- System configuration
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default config
INSERT OR IGNORE INTO config (key, value) VALUES
    ('auto_defense_enabled', 'true'),
    ('dry_run_mode', 'false'),
    ('brute_force_threshold', '5'),
    ('brute_force_window', '60');
```

---

## Testing Strategy

### Unit Tests

**File**: `tests/test_detection.py`

```python
import pytest
from backend.detection.sql_injection import SQLInjectionDetector

def test_sql_injection_detection():
    detector = SQLInjectionDetector()
    
    # Test positive case
    result = detector.detect("/login?user=' OR '1'='1--", "GET")
    assert result['detected'] == True
    assert result['attack_type'] == 'SQL_INJECTION'
    
    # Test negative case
    result = detector.detect("/login?user=admin", "GET")
    assert result['detected'] == False

def test_brute_force_detection():
    from backend.detection.brute_force import BruteForceDetector
    
    detector = BruteForceDetector(threshold=5, time_window=60)
    
    # Simulate 5 failed attempts
    for i in range(5):
        result = detector.detect("192.168.1.100", "/login", 401)
    
    assert result['detected'] == True
    assert result['attack_type'] == 'BRUTE_FORCE'
```

---

### Integration Tests

**File**: `tests/test_integration.py`

```python
import pytest
import requests

def test_full_attack_flow():
    """Test: SQL injection → Detection → Blocking → AI Analysis"""
    
    # 1. Send malicious request
    response = requests.get(
        "http://localhost:5000/login?user=' OR '1'='1--"
    )
    
    # 2. Wait for detection
    import time
    time.sleep(2)
    
    # 3. Check if attack was detected
    api_response = requests.get("http://localhost:8000/api/attacks/recent?limit=1")
    data = api_response.json()
    
    assert len(data['attacks']) > 0
    assert data['attacks'][0]['attack_type'] == 'SQL_INJECTION'
    
    # 4. Check if IP was blocked
    blocked_response = requests.get("http://localhost:8000/api/defense/blocked-ips")
    blocked_data = blocked_response.json()
    
    assert len(blocked_data['blocked_ips']) > 0
    
    # 5. Check AI analysis exists
    attack = data['attacks'][0]
    assert 'ai_analysis' in attack
    assert attack['ai_analysis']['explanation'] is not None
```

---

### Performance Tests

**File**: `tests/test_performance.py`

```python
import time
import concurrent.futures

def test_detection_performance():
    """Test detection engine can handle 100 requests/second"""
    
    from backend.detection.detection_engine import AttackDetectionEngine
    
    detector = AttackDetectionEngine()
    
    test_requests = [
        {'ip': '192.168.1.1', 'path': '/test', 'method': 'GET', 'status': 200}
        for _ in range(1000)
    ]
    
    start = time.time()
    
    for request in test_requests:
        detector.analyze_request(request)
    
    end = time.time()
    elapsed = end - start
    
    # Should process 1000 requests in < 10 seconds
    assert elapsed < 10
    print(f"Processed 1000 requests in {elapsed:.2f} seconds")
```

---

## Deployment Guide

### Development Deployment

```bash
# 1. Clone repository
git clone <repo_url>
cd cyber-defense-agent

# 2. Start services
docker-compose -f docker/docker-compose.yml up --build -d

# 3. Verify services
docker-compose -f docker/docker-compose.yml ps

# 4. Access dashboard
open http://localhost:8501

# 5. Test vulnerable app
curl http://localhost:5000/login
```

---

### Production Deployment

```bash
# 1. Update configuration
cp .env.example .env
nano .env  # Set production values

# 2. Use PostgreSQL instead of SQLite
# Uncomment postgres service in docker-compose.yml

# 3. Set up SSL certificates (for NGINX)
certbot certonly --standalone -d yourdomain.com

# 4. Configure firewall
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# 5. Deploy
docker-compose -f docker/docker-compose.yml up -d

# 6. Set up log rotation
sudo nano /etc/logrotate.d/cyber-defense

# 7. Monitor logs
docker-compose -f docker/docker-compose.yml logs -f
```

---

## Development Workflow for AI Code Generation

### Using This Plan with AI Coding Tools

**Recommended AI Coding Extensions**:
- GitHub Copilot
- Cursor
- Tabnine
- Codeium

---

### Step-by-Step AI-Assisted Development

#### Week 1: Setup

**Prompt to AI**:
```
Based on PROJECT_PLAN.md Module 1 (Monitoring Agent):

1. Create the project structure as defined in "Project Structure" section
2. Create docker/Dockerfile.backend with Python 3.11, FastAPI, and iptables
3. Create docker/docker-compose.yml with services: backend, dashboard, ollama, testapp
4. Create backend/monitoring/log_collector.py implementing the LogCollector class
5. Create backend/monitoring/log_parser.py with NginxLogParser class
6. Create backend/monitoring/storage.py with LogStorage class and SQLite schema

Follow the exact specifications in the plan.
```

---

#### Week 2: Attack Detection

**Prompt to AI**:
```
Based on PROJECT_PLAN.md Module 2 (Attack Detection Engine):

1. Create backend/detection/sql_injection.py with SQLInjectionDetector class
2. Implement all SQL injection patterns listed in the plan
3. Create backend/detection/brute_force.py with BruteForceDetector class
4. Use the exact threshold logic (5 attempts in 60 seconds)
5. Create backend/detection/path_traversal.py with patterns from the plan
6. Create backend/detection/detection_engine.py that orchestrates all detectors

Test each detector with the examples provided in the plan.
```

---

#### Week 3-4: Defense Engine

**Prompt to AI**:
```
Based on PROJECT_PLAN.md Module 3 (Defense Automation Engine):

1. Create backend/defense/defense_engine.py with DefenseEngine class
2. Create backend/defense/ip_blocker.py with IPBlocker class
3. Implement iptables commands exactly as shown in the plan
4. Add whitelist protection (never block 127.0.0.1)
5. Create backend/defense/unblock_scheduler.py using APScheduler
6. Implement auto-unblock with durations from DefenseConfig

Include all safety checks from the plan.
```

---

#### Week 5-6: LLM Analysis

**Prompt to AI**:
```
Based on PROJECT_PLAN.md Module 4 (LLM Analysis Engine):

1. Create backend/analysis/llm_analyzer.py with LLMAnalyzer class
2. Create backend/analysis/prompts.py with all prompt templates from the plan
3. Implement Ollama API integration (localhost:11434)
4. Use the exact prompt format for SQL injection analysis
5. Implement JSON response parsing with fallback
6. Create analysis storage in database

Use llama3.2:3b model for MVP.
```

---

#### Week 7-8: Dashboard

**Prompt to AI**:
```
Based on PROJECT_PLAN.md Module 5 (Security Dashboard):

1. Create dashboard/app.py using Streamlit
2. Implement render_header() with 3 metrics (Status, Risk, Uptime)
3. Implement render_live_feed() with real-time attack display
4. Implement render_blocked_ips() with unblock button
5. Implement render_attack_distribution() using Plotly pie chart
6. Implement render_attack_timeline() using Plotly line chart
7. Add manual controls (block/unblock IP)

Follow the exact layout from the Dashboard Layout section.
```

---

### AI Code Review Checklist

After AI generates code, verify:

- ✅ Follows exact class names from plan
- ✅ Implements all methods specified
- ✅ Uses correct database schema
- ✅ Includes error handling
- ✅ Has logging statements
- ✅ Matches Docker configuration
- ✅ Uses correct API endpoints
- ✅ Implements safety checks (whitelist, localhost)

---

## Quick Reference: Command Cheatsheet

```bash
# Docker
docker-compose up -d                 # Start all services
docker-compose down                  # Stop all services
docker-compose logs -f backend       # View backend logs
docker-compose restart backend       # Restart backend

# iptables (inside container)
sudo iptables -L                     # List all rules
sudo iptables -A INPUT -s IP -j DROP # Block IP
sudo iptables -D INPUT -s IP -j DROP # Unblock IP
sudo iptables -F                     # Flush all (EMERGENCY)

# Ollama
ollama pull llama3.2:3b             # Download model
ollama run llama3.2:3b              # Test model
ollama list                          # List models

# Testing
curl http://localhost:5000/login     # Test vulnerable app
curl "http://localhost:5000/login?user=' OR '1'='1--"  # SQL injection test

# Database
sqlite3 data/db/cyber_defense.db     # Open database
.tables                              # List tables
SELECT * FROM requests LIMIT 10;     # Query
```

---

## Success Criteria

### MVP Success Criteria (Week 8)

- ✅ Real-time log monitoring working
- ✅ Detects SQL injection, brute force, path traversal
- ✅ Automatically blocks malicious IPs
- ✅ AI analysis provides explanations
- ✅ Dashboard shows live attacks
- ✅ Demo runs successfully
- ✅ All Docker containers stable
- ✅ Documentation complete

### Full Version Success Criteria (Week 16)

- ✅ All MVP features working
- ✅ ML anomaly detection functional
- ✅ RAG provides CVE context
- ✅ Knowledge graph visualization
- ✅ Vulnerability scanner runs
- ✅ Attack simulator validates defenses
- ✅ Production-ready deployment
- ✅ Comprehensive test coverage

---

## Final Notes for AI Code Generation

### Important Instructions for AI Tools:

1. **Always reference this plan** before generating code
2. **Use exact class names, method names, and file paths** from the plan
3. **Implement safety features first** (whitelist, localhost protection)
4. **Include comprehensive error handling**
5. **Add logging to all critical operations**
6. **Follow the Docker structure exactly**
7. **Test each module independently** before integration
8. **Document all deviations** from the plan

### Priority Order:

1. **Safety mechanisms** (whitelist, emergency unblock)
2. **Core detection** (SQL injection, brute force)
3. **Defense automation** (IP blocking)
4. **LLM analysis** (attack explanation)
5. **Dashboard** (visualization)
6. **Advanced features** (ML, RAG, etc.)

---

## Conclusion

This plan provides:

✅ **Complete system architecture**  
✅ **Detailed module specifications**  
✅ **MVP path (8 weeks, realistic)**  
✅ **Full version roadmap (16 weeks)**  
✅ **Docker containerization**  
✅ **Database schemas**  
✅ **API specifications**  
✅ **AI code generation instructions**

**Recommended approach**: Start with MVP, get it working perfectly, then incrementally add full features.

**For AI code generation**: Copy relevant sections from this plan and provide them as context to your AI coding tool.

---

**Project Status**: Ready for development  
**Estimated MVP Completion**: 8 weeks  
**Estimated Full Version Completion**: 16 weeks  
**Difficulty**: High (manageable with AI assistance)  
**Expected Grade**: 8.5-9.5/10

Good luck with your project! 🚀🛡️
