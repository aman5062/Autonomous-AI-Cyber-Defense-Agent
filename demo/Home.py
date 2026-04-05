"""
Autonomous AI Cyber Defense Agent — Demo Dashboard
Main entry point
"""
import sys
sys.path.insert(0, "/app")

import streamlit as st

st.set_page_config(
    page_title="Cyber Defense Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
[data-testid="stSidebar"] { background: #0d1117; }
.attack-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 8px 0; }
.severity-critical { color: #ff4444; font-weight: bold; }
.severity-high     { color: #ff8800; font-weight: bold; }
.severity-medium   { color: #ffcc00; }
.severity-low      { color: #44ff44; }
.metric-box { background: #161b22; border-radius: 8px; padding: 12px; text-align: center; border: 1px solid #30363d; }
</style>
""", unsafe_allow_html=True)

import requests, os
BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")

def get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", timeout=5)
        return r.json()
    except:
        return None

# ── Header ────────────────────────────────────────────────────────────────────
st.title("🛡️ Autonomous AI Cyber Defense Agent")
st.markdown("**Live demonstration system** — launch real attacks and watch the AI defend in real time.")
st.divider()

# ── System Status ─────────────────────────────────────────────────────────────
health = get("/health")
stats  = get("/api/stats/attacks?days=7")
blocked = get("/api/defense/blocked-ips")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    status = "🟢 ONLINE" if health else "🔴 OFFLINE"
    st.metric("System", status)

with col2:
    ollama = (health or {}).get("services", {}).get("ollama", "unknown")
    icon = "🟢" if ollama in ("ready", "available") else "🟡"
    st.metric("AI (Ollama)", f"{icon} {ollama}")

with col3:
    st.metric("Attacks (7d)", (stats or {}).get("total_attacks", 0))

with col4:
    st.metric("Blocked (7d)", (stats or {}).get("blocked_count", 0))

with col5:
    st.metric("IPs Blocked Now", (blocked or {}).get("total", 0))

st.divider()

# ── Architecture ──────────────────────────────────────────────────────────────
col_a, col_b = st.columns([1, 1])

with col_a:
    st.subheader("🏗️ How It Works")
    st.markdown("""
    ```
    Attacker Request
          ↓
    NGINX (port 80)
          ↓
    Log Collector (tail access.log)
          ↓
    Attack Detection Engine
      ├── SQL Injection Detector
      ├── Brute Force Detector
      ├── Path Traversal Detector
      ├── XSS Detector
      ├── Command Injection Detector
      └── Bot Scanner Detector
          ↓
    Defense Engine
      ├── IP Blocker (iptables)
      └── Rate Limiter (NGINX)
          ↓
    LLM Analyzer (Ollama llama3.2:3b)
          ↓
    SQLite DB ← FastAPI ← Streamlit
    ```
    """)

with col_b:
    st.subheader("📋 Attack Types & Response")
    import pandas as pd
    df = pd.DataFrame([
        {"Attack", "Severity", "Auto Response", "Ban Duration"},
    ])
    st.table(pd.DataFrame([
        {"Attack": "SQL Injection",     "Severity": "🔴 CRITICAL", "Response": "Block IP",      "Duration": "24 hours"},
        {"Attack": "Command Injection", "Severity": "🔴 CRITICAL", "Response": "Block IP",      "Duration": "24 hours"},
        {"Attack": "Path Traversal",    "Severity": "🔴 CRITICAL", "Response": "Block IP",      "Duration": "24 hours"},
        {"Attack": "Brute Force",       "Severity": "🟠 HIGH",     "Response": "Block IP",      "Duration": "1 hour"},
        {"Attack": "XSS",               "Severity": "🟠 HIGH",     "Response": "Rate Limit",    "Duration": "6 hours"},
        {"Attack": "Bot Scanner",       "Severity": "🟡 MEDIUM",   "Response": "Rate Limit",    "Duration": "ongoing"},
    ]))

st.divider()
st.info("👈 Use the sidebar to navigate: **Launch Attacks**, **Live Monitor**, **Attack Guide**, or **Defense Controls**")
