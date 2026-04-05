# Module 03: Anomaly Detection Model
## Purpose
ML-based detection of unknown/novel attack patterns using unsupervised learning on traffic behavior.

## Status
✅ Implemented

## Files
- `backend/detection/anomaly_model.py` — Isolation Forest + One-Class SVM

## Models Used
- Isolation Forest (primary)
- One-Class SVM (secondary)

## Features
- Request frequency per IP
- GET/POST ratio
- Response time distribution
- HTTP status code distribution
- User-Agent entropy
- Payload size
- Time-based features

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with Isolation Forest implementation |
