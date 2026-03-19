"""
Deliberately vulnerable Flask application for testing the defense system.
DO NOT deploy this in production.
"""
import sqlite3
import os
from flask import Flask, request, render_template_string, g

app = Flask(__name__)
DB_PATH = "/app/test_app/test.db"

LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Login</h2>
  <form method="POST" action="/login">
    <input name="username" placeholder="Username"><br>
    <input name="password" type="password" placeholder="Password"><br>
    <button type="submit">Login</button>
  </form>
  {% if message %}<p style="color:red">{{ message }}</p>{% endif %}
</body>
</html>
"""

SEARCH_HTML = """
<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
  <h2>Search Products</h2>
  <form method="GET" action="/search">
    <input name="q" placeholder="Search...">
    <button type="submit">Search</button>
  </form>
  {% if results %}<pre>{{ results }}</pre>{% endif %}
</body>
</html>
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


@app.route("/")
def index():
    return "<h1>Vulnerable Test App</h1><a href='/login'>Login</a> | <a href='/search'>Search</a>"


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULNERABLE: direct string interpolation (SQL injection)
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            db = get_db()
            cursor = db.execute(query)
            user = cursor.fetchone()
            if user:
                return f"<h2>Welcome, {username}!</h2>"
            else:
                message = "Invalid credentials"
                return render_template_string(LOGIN_HTML, message=message), 401
        except Exception as e:
            return render_template_string(LOGIN_HTML, message=f"Error: {e}"), 500
    return render_template_string(LOGIN_HTML, message=message)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = ""
    if q:
        # VULNERABLE: reflects user input (XSS)
        results = f"Results for: {q}"
    return render_template_string(SEARCH_HTML, results=results)


@app.route("/file")
def read_file():
    # VULNERABLE: path traversal
    filename = request.args.get("name", "")
    if not filename:
        return "Provide ?name=filename"
    try:
        with open(filename) as f:
            return f"<pre>{f.read()}</pre>"
    except Exception as e:
        return f"Error: {e}", 404


@app.route("/api/user")
def api_user():
    user_id = request.args.get("id", "1")
    # VULNERABLE: SQL injection in API
    query = f"SELECT id, username FROM users WHERE id={user_id}"
    try:
        db = get_db()
        cursor = db.execute(query)
        row = cursor.fetchone()
        if row:
            return {"id": row[0], "username": row[1]}
        return {"error": "Not found"}, 404
    except Exception as e:
        return {"error": str(e)}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
