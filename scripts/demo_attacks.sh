#!/usr/bin/env bash
# Generate demo attack traffic against the vulnerable test app
set -eu

TARGET="${1:-http://localhost:5000}"
echo "Sending demo attacks to $TARGET"
echo "Make sure the test app is running first."
echo ""

# Helper
send() {
  echo "→ $1"
  curl -s -o /dev/null -w "  HTTP %{http_code}\n" "$2" || true
  sleep 0.5
}

echo "=== SQL Injection ==="
send "Classic OR injection"      "$TARGET/login?user=' OR '1'='1--&password=x"
send "UNION SELECT"               "$TARGET/login?user=admin' UNION SELECT 1,2,3--"
send "Drop table"                 "$TARGET/login?user=1'; DROP TABLE users--"

echo ""
echo "=== Brute Force (6 attempts) ==="
for i in $(seq 1 6); do
  send "Attempt $i"  "$TARGET/login" \
    --data "username=admin&password=wrong$i" -X POST 2>/dev/null || \
  curl -s -o /dev/null -w "  HTTP %{http_code}\n" -X POST \
    -d "username=admin&password=wrong$i" "$TARGET/login" || true
  sleep 0.3
done

echo ""
echo "=== Path Traversal ==="
send "etc/passwd"    "$TARGET/files?file=../../../../etc/passwd"
send "SSH key"       "$TARGET/files?file=../../../../.ssh/id_rsa"
send "Encoded"       "$TARGET/files?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

echo ""
echo "=== XSS ==="
send "Script tag"    "$TARGET/search?q=<script>alert(document.cookie)</script>"
send "Event handler" "$TARGET/search?q=<img src=x onerror=alert(1)>"
send "JS protocol"   "$TARGET/search?q=javascript:alert(1)"

echo ""
echo "=== Command Injection ==="
send "Semicolon"     "$TARGET/cmd?host=localhost;cat /etc/passwd"
send "Pipe"          "$TARGET/cmd?host=127.0.0.1|id"

echo ""
echo "=== Bot Scanner ==="
send "sqlmap UA"     "$TARGET/" -H "User-Agent: sqlmap/1.7.8"
send "nikto UA"      "$TARGET/" -H "User-Agent: Nikto/2.1.6"

echo ""
echo "✅ Demo attacks sent. Check the dashboard at http://localhost:8501"
