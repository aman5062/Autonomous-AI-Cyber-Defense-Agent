# Module 02: Attack Detection Engine

## Purpose
Rule-based detection of SQL injection, brute force, path traversal, XSS, CSRF, command injection, DDoS, port scan, and bot attacks.

## Status
✅ Implemented

## Files
- `backend/detection/detection_engine.py` — orchestrates all detectors
- `backend/detection/sql_injection.py` — pattern-based SQLi detection
- `backend/detection/brute_force.py` — threshold-based frequency analysis
- `backend/detection/path_traversal.py` — directory traversal patterns
- `backend/detection/xss_detector.py` — XSS pattern matching
- `backend/detection/patterns.py` — centralized attack signatures DB

## Key Classes
- `AttackDetectionEngine` — runs all detectors, returns unified result list
- `SQLInjectionDetector` — regex patterns, severity scoring
- `BruteForceDetector` — sliding window counter per IP
- `PathTraversalDetector` — path pattern + sensitive file matching
- `XSSDetector` — script/event handler patterns

## Output Format
```json
[{"attack_type": "SQL_INJECTION", "severity": "CRITICAL", "confidence": 0.95, "recommended_action": "BLOCK_IP"}]
```

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with full implementation |
