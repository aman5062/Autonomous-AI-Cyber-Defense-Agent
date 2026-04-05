# Module 07: Security Automation Engine

## Purpose
Automated defense — IP blocking via iptables, rate limiting, fail2ban integration, auto-unblock scheduling, whitelist management, emergency lockdown.

## Status
✅ Implemented

## Files
- `backend/defense/defense_engine.py` — orchestrates defense actions
- `backend/defense/ip_blocker.py` — iptables wrapper
- `backend/defense/rate_limiter.py` — NGINX rate limit config
- `backend/defense/whitelist_manager.py` — safe IP management
- `backend/defense/unblock_scheduler.py` — APScheduler auto-unblock

## Ban Durations
| Attack | Duration |
|--------|----------|
| SQL Injection | 24h |
| Brute Force | 1h |
| Path Traversal | 24h |
| XSS | 6h |
| DDoS | Until review |
| Port Scan | 48h |

## Safety Rules
- Never block 127.0.0.1
- Never block whitelisted IPs
- Dry-run mode available
- All actions logged

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with iptables, scheduler, whitelist |
