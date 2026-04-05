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
from pathlib import Path
from flask import Flask, request, render_template_string, redirect, url_for, session, g

app = Flask(__name__)
app.secret_key = "super-insecure-secret-key-for-testing"

DB_PATH = Path(os.getenv("TEST_DB_PATH", str(Path(__file__).parent / "test.db")))

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
