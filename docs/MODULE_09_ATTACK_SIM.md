# Module 09: Attack Simulation Engine

## Purpose
Security testing and validation — simulates SQL injection, brute force, path traversal, XSS, DDoS, port scan to verify detection and defense are working.

## Status
✅ Implemented

## Files
- `backend/scanning/attack_simulator.py` — simulation framework

## Simulated Attacks
- SQL Injection variants
- Brute force login
- Path traversal
- XSS injections
- Port scanning
- DDoS (traffic spike)
- Directory enumeration

## Safety
- Only targets configured test environment (testapp container)
- Configurable intensity
- Emergency stop mechanism

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created targeting testapp container only |
