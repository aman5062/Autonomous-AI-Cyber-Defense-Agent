# Module 01: Monitoring Agent

## Purpose
Real-time traffic and system monitoring — collects, parses, and stores NGINX logs and system metrics.

## Status
✅ Implemented

## Files
- `backend/monitoring/log_collector.py` — tails NGINX access log in real-time
- `backend/monitoring/log_parser.py` — parses combined log format into structured dicts
- `backend/monitoring/metrics_collector.py` — CPU, memory, network via psutil
- `backend/monitoring/storage.py` — SQLite persistence layer

## Key Classes
- `LogCollector` — generator-based tail, calls callback per line
- `NginxLogParser` — regex parse → structured dict
- `MetricsCollector` — system stats snapshot
- `LogStorage` — save/query requests table

## Database Table
`requests` — stores every parsed request with attack metadata fields

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with full implementation |
