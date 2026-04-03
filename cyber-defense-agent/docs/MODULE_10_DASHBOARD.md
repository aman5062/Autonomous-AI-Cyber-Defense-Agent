# Module 10: Security Dashboard

## Purpose
Real-time monitoring and control interface — live attack feed, blocked IPs, charts, manual controls, vulnerability scan results, GeoIP map.

## Status
✅ Implemented

## Files
- `dashboard/app.py` — Streamlit main app
- `dashboard/components/attack_feed.py` — live attack component
- `dashboard/components/blocked_ips.py` — blocked IP management
- `dashboard/components/charts.py` — Plotly visualizations
- `dashboard/components/controls.py` — manual defense controls
- `dashboard/utils/data_fetcher.py` — backend API client

## Access
http://localhost:8501

## Features
- Live attack feed (auto-refresh)
- Attack type pie chart
- Timeline line graph
- Blocked IPs table with unblock button
- Manual IP block/unblock
- Emergency lockdown button
- Vulnerability scan results tab
- System health metrics

## Changes Log
| Date | Change |
|------|--------|
| Initial | Module created with full Streamlit dashboard |
