"""Initialize the test application database."""

import sqlite3
import os
from pathlib import Path

# Works both locally and inside Docker (/app/test_app/test.db)
DB_PATH = Path(os.getenv("TEST_DB_PATH", str(Path(__file__).parent / "test.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

conn = sqlite3.connect(str(DB_PATH))
conn.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    email TEXT
);

INSERT OR IGNORE INTO users (username, password, email) VALUES
    ('admin', 'admin123', 'admin@example.com'),
    ('user1', 'password1', 'user1@example.com'),
    ('testuser', 'test123', 'test@example.com');

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    description TEXT,
    price REAL
);

INSERT OR IGNORE INTO products (name, description, price) VALUES
    ('Widget A', 'A basic widget', 9.99),
    ('Widget B', 'An advanced widget', 19.99),
    ('Gadget X', 'A cool gadget', 49.99);

CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
""")
conn.commit()
conn.close()
print(f"Test database initialized at {DB_PATH}")
