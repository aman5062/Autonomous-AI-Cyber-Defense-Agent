"""
Deliberately vulnerable Flask application for testing the defense system.

WARNING: This app is intentionally insecure. Never expose to the internet.

CodeQL/SAST alerts in this file are EXPECTED and intentional:
  - SQL injection (test_app/vulnerable_app.py) – tests the defense system
  - Path injection (test_app/vulnerable_app.py) – tests path traversal detection
  - Command injection (test_app/vulnerable_app.py) – tests command injection detection
  - Flask debug mode (test_app/vulnerable_app.py) – local testing only
All vulnerabilities are here so that the Cyber Defense Agent has real attacks to detect.
"""

import os
import sqlite3
import threading
import time
from pathlib import Path

import requests as _http
from flask import Flask, request, render_template_string, redirect, url_for, session, g

app = Flask(__name__)
app.secret_key = "super-insecure-secret-key-for-testing"

DB_PATH = Path(os.getenv("TEST_DB_PATH", str(Path(__file__).parent / "test.db")))
_BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

# ---------------------------------------------------------------------------
# Blocked-IP cache — synced from the backend every 5 seconds
# ---------------------------------------------------------------------------
_blocked_ips: set = set()
_blocked_lock = threading.Lock()


def _sync_blocked_ips_loop():
    global _blocked_ips
    while True:
        try:
            r = _http.get(f"{_BACKEND_URL}/api/defense/blocked-ips", timeout=2)
            if r.status_code == 200:
                data = r.json()
                ips = {item["ip"] for item in data.get("blocked_ips", [])}
                with _blocked_lock:
                    _blocked_ips = ips
        except Exception:
            pass
        time.sleep(5)


_sync_thread = threading.Thread(target=_sync_blocked_ips_loop, daemon=True)
_sync_thread.start()


def _report_to_backend(ip: str, method: str, path: str, body: str, ua: str):
    """Fire-and-forget: report request to the backend detection pipeline."""
    try:
        _http.post(
            f"{_BACKEND_URL}/api/demo/report",
            json={"ip": ip, "method": method, "path": path, "body": body, "user_agent": ua},
            timeout=1,
        )
    except Exception:
        pass


def _client_ip() -> str:
    return (
        request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
        or "127.0.0.1"
    )


# ---------------------------------------------------------------------------
# Before-request hook: block banned IPs and report all requests
# ---------------------------------------------------------------------------

BLOCKED_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>🚫 Access Blocked — AI Cyber Defense</title>
<style>
body {
  font-family: 'Segoe UI', sans-serif;
  background: #0f172a;
  color: #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  margin: 0;
}
.card {
  background: #1e293b;
  border: 2px solid #dc2626;
  border-radius: 16px;
  padding: 40px;
  max-width: 480px;
  text-align: center;
  box-shadow: 0 0 40px rgba(220,38,38,0.3);
}
.icon { font-size: 4rem; margin-bottom: 16px; }
h1 { color: #ef4444; font-size: 1.5rem; margin-bottom: 12px; }
.ip { font-family: monospace; background: #0f172a; padding: 6px 14px;
      border-radius: 6px; color: #f87171; font-size: 1.1rem; display: inline-block; margin: 8px 0; }
p { color: #94a3b8; font-size: 0.9rem; line-height: 1.6; margin-top: 12px; }
a { color: #7c3aed; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">🛡️</div>
  <h1>Access Blocked</h1>
  <p>Your IP address has been blocked by the AI Cyber Defense Agent.</p>
  <div class="ip">{{ ip }}</div>
  <p>
    Your request contained a malicious payload that was detected and blocked automatically.<br><br>
    To restore access, contact your administrator or visit the
    <a href="http://localhost:3000/blocked" target="_blank">Defense Dashboard</a>.
  </p>
</div>
</body>
</html>
"""


@app.before_request
def enforce_block():
    """Block IPs that are in the backend's blocked list."""
    ip = _client_ip()
    with _blocked_lock:
        blocked = ip in _blocked_ips
    if blocked:
        return render_template_string(BLOCKED_HTML, ip=ip), 403

    # Asynchronously report the request to the backend for detection
    body = ""
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            body = request.get_data(as_text=True)[:2000]
        except Exception:
            pass
    threading.Thread(
        target=_report_to_backend,
        args=(ip, request.method, request.full_path, body, request.user_agent.string),
        daemon=True,
    ).start()



# ------------------------------------------------------------------
# HTML templates (inline for simplicity)
# ------------------------------------------------------------------

BASE_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>VulnApp - Security Testing Target</title>
<style>
body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
.vuln { background: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 4px; }
input, textarea { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
button { padding: 10px 20px; background: #007bff; color: white; border: none; cursor: pointer; }
button:hover { background: #0056b3; }
.error { color: red; }
.success { color: green; }
nav a { margin-right: 15px; }
</style>
</head>
<body>
<nav>
  <a href="/">Home</a>
  <a href="/login">Login</a>
  <a href="/search">Search</a>
  <a href="/files">Files</a>
  <a href="/comments">Comments</a>
  <a href="/cmd">Command</a>
  <a href="http://localhost:8000/demo" style="color:#dc2626;font-weight:bold;">🛡️ Live Demo</a>
</nav>
<hr>
{% block content %}{% endblock %}
</body>
</html>
"""

LOGIN_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
<h2>Login (Vulnerable to SQL Injection)</h2>
<div class="vuln">⚠️ This form is intentionally vulnerable to SQL injection</div>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
{% if success %}<p class="success">{{ success }}</p>{% endif %}
<form method="POST">
  <input type="text" name="username" placeholder="Username (try: ' OR '1'='1--)">
  <input type="password" name="password" placeholder="Password (try: anything)">
  <button type="submit">Login</button>
</form>
<p><small>Try: username = <code>' OR '1'='1--</code></small></p>
""")

SEARCH_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
<h2>Search (Vulnerable to XSS)</h2>
<div class="vuln">⚠️ This search reflects input without encoding</div>
<form method="GET">
  <input type="text" name="q" placeholder="Search... (try: &lt;script&gt;alert(1)&lt;/script&gt;)"
         value="{{ query }}">
  <button type="submit">Search</button>
</form>
{% if query %}
<p>Results for: {{ query|safe }}</p>
{% endif %}
""")

FILES_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
<h2>File Viewer (Vulnerable to Path Traversal)</h2>
<div class="vuln">⚠️ This endpoint is intentionally vulnerable to path traversal</div>
<form method="GET">
  <input type="text" name="file" placeholder="Enter filename (try: ../../../etc/passwd)"
         value="{{ filename }}">
  <button type="submit">View File</button>
</form>
{% if content %}<pre>{{ content }}</pre>{% endif %}
{% if error %}<p class="error">{{ error }}</p>{% endif %}
""")

CMD_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
<h2>Diagnostics (Vulnerable to Command Injection)</h2>
<div class="vuln">⚠️ This endpoint is intentionally vulnerable to command injection</div>
<form method="GET">
  <input type="text" name="host" placeholder="Hostname to ping (try: localhost; ls /etc)"
         value="{{ host }}">
  <button type="submit">Ping</button>
</form>
{% if output %}<pre>{{ output }}</pre>{% endif %}
""")

COMMENTS_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
<h2>Comments (Stored XSS)</h2>
<div class="vuln">⚠️ Comments are stored and displayed without sanitization</div>
<form method="POST">
  <textarea name="comment" rows="3" placeholder="Leave a comment..."></textarea>
  <button type="submit">Post</button>
</form>
<h3>Comments:</h3>
{% for c in comments %}
  <div style="border:1px solid #ccc; padding:8px; margin:5px 0;">
    {{ c|safe }}
  </div>
{% endfor %}
""")

INDEX_HTML = BASE_HTML.replace("{% block content %}{% endblock %}", """
<h2>🎯 Vulnerable Test Application</h2>
<div class="vuln">⚠️ This app is intentionally vulnerable for security testing purposes only!</div>
<p>Use this app to test the Cyber Defense Agent. It contains:</p>
<ul>
  <li><a href="/login">SQL Injection</a> – Login bypass via SQL injection</li>
  <li><a href="/search">XSS</a> – Reflected cross-site scripting</li>
  <li><a href="/files">Path Traversal</a> – Directory traversal attacks</li>
  <li><a href="/cmd">Command Injection</a> – OS command injection</li>
  <li><a href="/comments">Stored XSS</a> – Persistent XSS via comments</li>
</ul>
""")


# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    with app.app_context():
        db = sqlite3.connect(str(DB_PATH))
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                role TEXT DEFAULT 'user'
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Add role column if it doesn't exist (handles old DBs)
        try:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
        except sqlite3.OperationalError:
            pass  # column already exists
        db.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', 'secret123', 'admin')")
        db.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('user1', 'password', 'user')")
        db.commit()
        db.close()


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: direct string interpolation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            db = get_db()
            user = db.execute(query).fetchone()
            if user:
                session["user"] = dict(user)
                success = f"Welcome {user['username']}! (role: {user['role']})"
            else:
                return render_template_string(LOGIN_HTML, error="Invalid credentials"), 401
        except Exception as e:
            return render_template_string(LOGIN_HTML, error=f"DB error: {e}"), 500

    return render_template_string(LOGIN_HTML, error=error, success=success)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: rendered without escaping
    return render_template_string(SEARCH_HTML, query=query)


@app.route("/files")
def view_file():
    filename = request.args.get("file", "")
    content = None
    error = None

    if filename:
        # VULNERABLE: no path validation
        try:
            with open(filename) as fh:
                content = fh.read(4096)
        except PermissionError:
            error = "Permission denied"
        except FileNotFoundError:
            error = f"File not found: {filename}"
        except Exception as e:
            error = str(e)

    return render_template_string(FILES_HTML, filename=filename,
                                   content=content, error=error)


@app.route("/cmd")
def cmd():
    host = request.args.get("host", "")
    output = None

    if host:
        # VULNERABLE: shell injection
        import subprocess
        try:
            result = subprocess.run(
                f"ping -c 1 {host}",
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout + result.stderr
        except Exception as e:
            output = str(e)

    return render_template_string(CMD_HTML, host=host, output=output)


@app.route("/comments", methods=["GET", "POST"])
def comments():
    db = get_db()
    if request.method == "POST":
        comment = request.form.get("comment", "")
        # VULNERABLE: stored without sanitization
        db.execute("INSERT INTO comments (content) VALUES (?)", (comment,))
        db.commit()

    rows = db.execute("SELECT content FROM comments ORDER BY id DESC LIMIT 20").fetchall()
    comment_list = [r["content"] for r in rows]
    return render_template_string(COMMENTS_HTML, comments=comment_list)


# Admin panel (useful for brute-force testing)
@app.route("/admin")
def admin():
    if not session.get("user") or session["user"].get("role") != "admin":
        return "Unauthorized", 403
    return "<h2>Admin Panel</h2><p>Welcome, admin!</p>"


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
