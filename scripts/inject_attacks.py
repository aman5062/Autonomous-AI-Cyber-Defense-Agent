"""
Injects realistic NGINX log lines directly into the access.log
so the backend detection engine processes them.
Run inside the backend container:
  docker exec cyber_defense_backend python /tmp/inject_attacks.py
"""
import time
from datetime import datetime

LOG_PATH = "/var/log/nginx/access.log"

def ts():
    return datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

ATTACKS = [
    # SQL Injection
    '192.168.1.100 - - [{ts}] "GET /login?user=\' OR \'1\'=\'1-- HTTP/1.1" 401 512 "-" "sqlmap/1.7.8"',
    '192.168.1.100 - - [{ts}] "GET /login?user=admin\' UNION SELECT 1,2,3-- HTTP/1.1" 401 256 "-" "sqlmap/1.7.8"',
    '192.168.1.100 - - [{ts}] "GET /login?user=1\'; DROP TABLE users-- HTTP/1.1" 401 256 "-" "sqlmap/1.7.8"',
    # Brute Force (6 attempts same IP)
    '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
    '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
    '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
    '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
    '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
    '10.0.0.25 - - [{ts}] "POST /login HTTP/1.1" 401 256 "-" "python-requests/2.31"',
    # Path Traversal
    '172.16.0.50 - - [{ts}] "GET /files?file=../../../../etc/passwd HTTP/1.1" 200 1024 "-" "curl/7.68"',
    '172.16.0.50 - - [{ts}] "GET /files?file=../../../../.ssh/id_rsa HTTP/1.1" 200 512 "-" "curl/7.68"',
    '172.16.0.50 - - [{ts}] "GET /files?file=%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1" 200 512 "-" "curl/7.68"',
    # XSS
    '192.168.2.200 - - [{ts}] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    '192.168.2.200 - - [{ts}] "GET /search?q=<img src=x onerror=alert(1)> HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    '192.168.2.200 - - [{ts}] "GET /search?q=javascript:alert(1) HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    # Command Injection
    '203.0.113.10 - - [{ts}] "GET /cmd?host=localhost;cat /etc/passwd HTTP/1.1" 200 512 "-" "curl/7.68"',
    '203.0.113.10 - - [{ts}] "GET /cmd?host=127.0.0.1|id HTTP/1.1" 200 256 "-" "curl/7.68"',
    '203.0.113.10 - - [{ts}] "GET /cmd?host=x;/bin/bash -i HTTP/1.1" 200 256 "-" "curl/7.68"',
    # Bot Scanners
    '8.8.4.4 - - [{ts}] "GET / HTTP/1.1" 200 4096 "-" "sqlmap/1.7.8"',
    '8.8.4.4 - - [{ts}] "GET / HTTP/1.1" 200 4096 "-" "Nikto/2.1.6"',
    '8.8.4.4 - - [{ts}] "GET / HTTP/1.1" 200 4096 "-" "masscan/1.0"',
]

print(f"Injecting {len(ATTACKS)} attack log lines into {LOG_PATH}")
with open(LOG_PATH, "a") as f:
    for line in ATTACKS:
        entry = line.replace("{ts}", ts())
        f.write(entry + "\n")
        f.flush()
        print(f"  -> {entry[:80]}")
        time.sleep(0.8)

print("Done! Check http://localhost:8000/api/attacks/recent")
