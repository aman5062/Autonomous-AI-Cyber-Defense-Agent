# Module 08: Vulnerability Scanner

## Purpose
Proactive security assessment — port scanning, service detection, outdated software, SSL/TLS checks, HTTP header analysis via nmap and nikto.

## Status
✅ Implemented

## Files
- `backend/scanning/vulnerability_scanner.py` — nmap + nikto wrapper

## Scan Types
- Quick scan (common ports)
- Full scan (all ports)
- Service version detection
- Vulnerability scripts (nmap NSE)
- SSL/TLS certificate check
- HTTP header analysis

## Output
```json
{
  "open_ports": [...],
  "vulnerabilities": [{"severity": "HIGH", "description": "...", "recommendation": "..."}]
}
```

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with nmap integration and scheduled scanning |
