#!/usr/bin/env bash
# Setup script for Autonomous AI Cyber Defense Agent
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "  Autonomous AI Cyber Defense Agent Setup   "
echo "============================================"
echo ""

# Check Docker
if ! command -v docker &>/dev/null; then
  echo "❌ Docker not found. Install Docker first: https://docs.docker.com/get-docker/"
  exit 1
fi
if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
  echo "❌ Docker Compose not found."
  exit 1
fi
echo "✅ Docker found: $(docker --version)"

# Create .env if it doesn't exist
if [ ! -f "$PROJECT_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  echo "✅ Created .env from .env.example"
fi

# Create data directories
mkdir -p "$PROJECT_DIR/data/logs" "$PROJECT_DIR/data/db" "$PROJECT_DIR/data/models"
touch "$PROJECT_DIR/data/logs/access.log"
echo "✅ Created data directories"

# Build and start
echo ""
echo "Building Docker containers (this may take a few minutes)..."
cd "$PROJECT_DIR"
docker compose up --build -d

echo ""
echo "============================================"
echo "  Services Starting...                      "
echo "============================================"
echo ""
echo "  🖥️  Dashboard:     http://localhost:8501"
echo "  🔌  Backend API:   http://localhost:8000"
echo "  🎯  Test App:      http://localhost:5000"
echo "  📊  API Docs:      http://localhost:8000/docs"
echo "  🔍  Qdrant UI:     http://localhost:6333/dashboard"
echo "  🌐  NGINX Proxy:   http://localhost:80"
echo ""
echo "Wait 60 seconds for all services to start (Ollama model pull takes time)."
echo ""
echo "To view logs:"
echo "  docker compose logs -f backend"
echo ""
echo "To generate demo attacks:"
echo "  bash scripts/demo_attacks.sh"
