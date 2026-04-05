"""
Live Monitor — real-time attack feed and stats
"""
import sys
sys.path.insert(0, "/app")

import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
import os

st.set_page_config(page_title="Live Monitor", page_icon="📡", layout="wide")

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")

def get(path, params=None):
    try:
        r = requests.get(f"{BACKEND}{path}", params=params, timeout=5)
        return r.json()
    except:
        return None

st.title("📡 Live Attack Monitor")
st.divider()

# ── Controls ──────────────────────────────────────────────────────────────────
col1, col2, col3 = st.columns([1, 1, 2])
with col1:
    limit = st.number_input("Show last N attacks", 5, 100, 20, step=5)
with col2:
    days = st.slider("Stats range (days)", 1, 30, 7)
with col3:
    auto = st.toggle("Auto-refresh every 3s", value=False)

st.divider()

# ── Live Stats ────────────────────────────────────────────────────────────────
stats = get("/api/stats/attacks", {"days": days})
blocked_data = get("/api/defense/blocked-ips")

if stats:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Attacks", stats.get("total_attacks", 0))
    c2.metric("Blocked", stats.get("blocked_count", 0))
    c3.metric("IPs Blocked Now", (blocked_data or {}).get("total", 0))
    by_sev = stats.get("by_severity", {})
    c4.metric("Critical", by_sev.get("CRITICAL", 0))

    # Charts
    col_a, col_b = st.columns(2)

    with col_a:
        by_type = stats.get("by_type", {})
        if by_type:
            fig = px.pie(
                values=list(by_type.values()),
                names=list(by_type.keys()),
                title="Attack Type Distribution",
                color_discrete_sequence=px.colors.qualitative.Bold,
                hole=0.3,
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white", height=300)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No attack data yet — launch some attacks first!")

    with col_b:
        if by_sev:
            colors = {"CRITICAL": "#ff4444", "HIGH": "#ff8800", "MEDIUM": "#ffcc00", "LOW": "#44ff44"}
            fig = go.Figure(go.Bar(
                x=list(by_sev.keys()),
                y=list(by_sev.values()),
                marker_color=[colors.get(k, "#888") for k in by_sev.keys()],
            ))
            fig.update_layout(
                title="Attacks by Severity",
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="white",
                height=300,
            )
            st.plotly_chart(fig, use_container_width=True)

    # Timeline
    timeline = stats.get("timeline", [])
    if timeline:
        df_t = pd.DataFrame(timeline)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_t["date"], y=df_t["count"],
            mode="lines+markers", name="Attacks",
            line={"color": "#ff4444", "width": 2},
            fill="tozeroy", fillcolor="rgba(255,68,68,0.15)",
        ))
        fig.update_layout(
            title="Attack Timeline",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white", height=250,
        )
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# ── Live Attack Feed ──────────────────────────────────────────────────────────
st.subheader("🚨 Recent Attacks")

attacks_data = get("/api/attacks/recent", {"limit": int(limit)})
attacks = (attacks_data or {}).get("attacks", [])

if not attacks:
    st.info("No attacks detected yet. Go to **Launch Attacks** to generate some!")
else:
    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    type_icon = {
        "SQL_INJECTION": "💉", "BRUTE_FORCE": "🔨", "PATH_TRAVERSAL": "📁",
        "XSS": "🕷️", "COMMAND_INJECTION": "⚡", "BOT_SCAN": "🤖",
    }

    for atk in attacks:
        sev = atk.get("severity", "LOW")
        atype = atk.get("attack_type", "UNKNOWN")
        ip = atk.get("ip", "?")
        blocked = atk.get("blocked", False)
        ts = atk.get("timestamp") or atk.get("created_at", "")

        icon = sev_icon.get(sev, "⚪")
        ticon = type_icon.get(atype, "⚠️")
        block_label = "🔒 BLOCKED" if blocked else "👁️ detected"

        with st.expander(f"{icon} {ticon} {atype} | IP: {ip} | {block_label} | {ts}"):
            t1, t2, t3 = st.tabs(["Request Details", "AI Analysis", "Raw JSON"])

            with t1:
                ca, cb = st.columns(2)
                ca.write(f"**Method:** {atk.get('method', '')}")
                ca.write(f"**Status:** {atk.get('status', '')}")
                ca.write(f"**IP:** `{ip}`")
                cb.write(f"**Severity:** {sev}")
                cb.write(f"**Blocked:** {'✅ Yes' if blocked else '❌ No'}")
                cb.write(f"**Attack:** {atype}")
                st.code(atk.get("path", ""), language="text")
                st.caption(f"User-Agent: {atk.get('user_agent', '')}")

            with t2:
                explanation = atk.get("explanation")
                if explanation:
                    st.info(f"**Explanation:** {explanation}")
                    if atk.get("impact"):
                        st.warning(f"**Impact:** {atk['impact']}")
                    mitigation = atk.get("mitigation")
                    if mitigation:
                        st.write("**Mitigation Steps:**")
                        if isinstance(mitigation, list):
                            for step in mitigation:
                                st.write(f"• {step}")
                        else:
                            st.write(mitigation)
                    code_fix = atk.get("code_fix")
                    if code_fix and isinstance(code_fix, dict):
                        if code_fix.get("vulnerable"):
                            st.write("**Vulnerable Code:**")
                            st.code(code_fix["vulnerable"], language="python")
                        if code_fix.get("secure"):
                            st.write("**Secure Fix:**")
                            st.code(code_fix["secure"], language="python")
                else:
                    st.info("AI analysis pending — Ollama may still be loading the model.")

            with t3:
                st.json(atk)

st.divider()

# ── Blocked IPs ───────────────────────────────────────────────────────────────
st.subheader("🚫 Currently Blocked IPs")
blocked_ips = (blocked_data or {}).get("blocked_ips", [])
if blocked_ips:
    df = pd.DataFrame(blocked_ips)
    cols = [c for c in ["ip", "attack_type", "severity", "block_time", "unblock_time", "reason"] if c in df.columns]
    st.dataframe(df[cols], use_container_width=True)
else:
    st.success("No IPs currently blocked.")

if auto:
    time.sleep(3)
    st.rerun()
