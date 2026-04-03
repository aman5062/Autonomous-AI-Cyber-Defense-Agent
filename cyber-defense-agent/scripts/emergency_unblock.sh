#!/usr/bin/env bash
# Emergency: unblock all IPs
set -euo pipefail

echo "⚠️  Emergency unblock all blocked IPs..."
BACKEND="${BACKEND_URL:-http://localhost:8000}"
curl -s -X POST "$BACKEND/api/defense/emergency-unblock" | python3 -m json.tool
echo ""
echo "All IPs unblocked."
