import sqlite3
import os

DB_PATH = "/app/test_app/test.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

conn = sqlite3.connect(DB_PATH)
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
""")
conn.commit()
conn.close()
print("Test database initialized.")
