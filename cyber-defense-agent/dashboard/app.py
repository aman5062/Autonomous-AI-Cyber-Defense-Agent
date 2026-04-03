"""
Streamlit dashboard – Autonomous AI Cyber Defense Agent
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from dashboard.utils.data_fetcher import (
    add_to_whitelist,
    block_ip,
    emergency_unblock_all,
    fetch_attack_stats,
    fetch_blocked_ips,
    fetch_health,
    fetch_ollama_health,
    fetch_recent_attacks,
    fetch_system_metrics,
    fetch_whitelist,
    set_defense_mode,
    unblock_ip,
)

# ------------------------------------------------------------------
# Page config
# ------------------------------------------------------------------
st.set_page_config(
    page_title="AI Cyber Defense Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------------------------------------------------------
# Styling
# ------------------------------------------------------------------
st.markdown("""
<style>
.metric-card {background: #1e1e2e; border-radius: 10px; padding: 1rem; text-align: center;}
.attack-critical {color: #ff4444; font-weight: bold;}
.attack-high     {color: #ff8800; font-weight: bold;}
.attack-medium   {color: #ffcc00;}
.attack-low      {color: #44ff44;}
.status-active   {color: #00cc44; font-weight: bold;}
.status-blocked  {color: #ff4444;}
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
    }.get(severity, "⚪")


def _attack_badge(attack_type: str) -> str:
    icons = {
        "SQL_INJECTION": "💉",
        "BRUTE_FORCE": "🔨",
        "PATH_TRAVERSAL": "📁",
        "XSS": "🕷️",
        "COMMAND_INJECTION": "⚡",
        "BOT_SCAN": "🤖",
        "DDOS": "🌊",
    }
    return icons.get(attack_type, "⚠️") + " " + attack_type.replace("_", " ")


def _calculate_risk(stats: Optional[Dict]) -> str:
    if not stats:
        return "UNKNOWN"
    total = stats.get("total_attacks", 0)
    critical = stats.get("by_severity", {}).get("CRITICAL", 0)
    if critical > 10 or total > 100:
        return "CRITICAL"
    if critical > 5 or total > 50:
        return "HIGH"
    if total > 10:
        return "MEDIUM"
    return "LOW"


# ------------------------------------------------------------------
# Sidebar
# ------------------------------------------------------------------

def render_sidebar(health: Optional[Dict]):
    with st.sidebar:
        st.title("🛡️ Cyber Defense")
        st.divider()

        if health:
            st.success("✅ Backend Online")
            defense = health.get("defense_mode", {})
            st.write(f"Auto-Block: {'✅' if defense.get('auto_block') else '❌'}")
            st.write(f"Dry-Run: {'🔵' if defense.get('dry_run') else '⚫'}")
        else:
            st.error("❌ Backend Offline")

        st.divider()
        st.write("**Navigation**")
        return st.radio(
            "Section",
            ["🏠 Overview", "🚨 Live Attacks", "🚫 Blocked IPs",
             "📊 Analytics", "⚙️ Controls", "📋 Whitelist"],
            label_visibility="collapsed",
        )


# ------------------------------------------------------------------
# Sections
# ------------------------------------------------------------------

def render_overview(health: Optional[Dict], stats: Optional[Dict]):
    st.title("🛡️ Autonomous AI Cyber Defense Agent")
    st.caption(f"Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    st.divider()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        status = "ACTIVE" if health else "OFFLINE"
        color = "normal" if health else "inverse"
        st.metric("System Status", status)
    with col2:
        risk = _calculate_risk(stats)
        st.metric("Risk Level", risk)
    with col3:
        total = (stats or {}).get("total_attacks", 0)
        st.metric("Attacks (7d)", total)
    with col4:
        blocked = (stats or {}).get("blocked_count", 0)
        st.metric("Blocked (7d)", blocked)

    st.divider()

    # Metrics row
    metrics = fetch_system_metrics()
    if metrics and metrics.get("available"):
        col1, col2, col3 = st.columns(3)
        col1.metric("CPU", f"{metrics['cpu_percent']:.1f}%")
        col2.metric("Memory", f"{metrics['memory_percent']:.1f}%")
        col3.metric("Disk", f"{metrics['disk_percent']:.1f}%")

    # Services status
    if health:
        st.subheader("Service Status")
        services = health.get("services", {})
        cols = st.columns(len(services))
        for i, (svc, status) in enumerate(services.items()):
            icon = "✅" if status in ("connected", "ready", "active") else "⚠️"
            cols[i].metric(svc.title(), f"{icon} {status}")


def render_live_attacks():
    st.subheader("🚨 Live Attack Feed")

    col1, col2 = st.columns([1, 4])
    limit = col1.number_input("Show last N", min_value=5, max_value=100,
                               value=20, step=5)
    auto_refresh = col2.toggle("Auto-refresh (5s)", value=False)

    attacks = fetch_recent_attacks(limit=int(limit))

    if not attacks:
        st.info("No attacks detected yet. System is monitoring...")
        return

    for atk in attacks:
        severity = atk.get("severity", "LOW")
        icon = _severity_color(severity)
        attack_type = atk.get("attack_type", "UNKNOWN")
        ip = atk.get("ip", "N/A")
        ts = atk.get("timestamp") or atk.get("created_at", "")
        blocked = atk.get("blocked", False)

        with st.expander(
            f"{icon} {_attack_badge(attack_type)} | IP: {ip} | "
            f"{'🔒 BLOCKED' if blocked else '👁️ DETECTED'} | {ts}"
        ):
            tab1, tab2, tab3 = st.tabs(["Request", "AI Analysis", "Raw"])

            with tab1:
                col_a, col_b = st.columns(2)
                col_a.write(f"**Method:** {atk.get('method', '')}")
                col_a.write(f"**Status:** {atk.get('status', '')}")
                col_b.write(f"**Severity:** {severity}")
                col_b.write(f"**Blocked:** {'Yes ✅' if blocked else 'No'}")
                st.code(atk.get("path", ""), language="text")
                st.caption(f"User-Agent: {atk.get('user_agent', '')}")

            with tab2:
                explanation = atk.get("explanation")
                if explanation:
                    st.write("**Explanation:**")
                    st.info(explanation)
                    st.write("**Impact:**")
                    st.warning(atk.get("impact", ""))
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
                            st.write("**Secure Code:**")
                            st.code(code_fix["secure"], language="python")
                else:
                    st.info("AI analysis pending or not available.")

            with tab3:
                st.json(atk)

    if auto_refresh:
        time.sleep(5)
        st.rerun()


def render_blocked_ips():
    st.subheader("🚫 Blocked IPs")

    ips = fetch_blocked_ips()

    if not ips:
        st.success("No IPs currently blocked.")
    else:
        df = pd.DataFrame(ips)
        display_cols = [c for c in
                        ["ip", "attack_type", "severity", "block_time",
                         "unblock_time", "status", "reason"]
                        if c in df.columns]
        st.dataframe(df[display_cols], use_container_width=True)

        st.divider()
        st.write("**Unblock an IP**")
        ip_list = [row.get("ip") for row in ips if row.get("ip")]
        if ip_list:
            chosen = st.selectbox("Select IP to unblock", ip_list)
            if st.button("🔓 Unblock Selected IP"):
                if unblock_ip(chosen):
                    st.success(f"IP {chosen} unblocked")
                    st.rerun()
                else:
                    st.error("Unblock failed – check backend logs")


def render_analytics(stats: Optional[Dict]):
    st.subheader("📊 Attack Analytics")

    if not stats or stats.get("total_attacks", 0) == 0:
        st.info("Not enough data yet for analytics.")
        return

    days_range = st.slider("Days range", 1, 30, 7)
    stats = fetch_attack_stats(days=days_range) or stats

    col1, col2 = st.columns(2)

    # Attack type pie
    with col1:
        by_type = stats.get("by_type", {})
        if by_type:
            fig = px.pie(
                values=list(by_type.values()),
                names=list(by_type.keys()),
                title="Attack Type Distribution",
                color_discrete_sequence=px.colors.qualitative.Bold,
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

    # Severity pie
    with col2:
        by_sev = stats.get("by_severity", {})
        if by_sev:
            sev_colors = {
                "CRITICAL": "#ff4444",
                "HIGH": "#ff8800",
                "MEDIUM": "#ffcc00",
                "LOW": "#44ff44",
            }
            colors = [sev_colors.get(k, "#888") for k in by_sev.keys()]
            fig = px.pie(
                values=list(by_sev.values()),
                names=list(by_sev.keys()),
                title="Severity Distribution",
                color_discrete_sequence=colors,
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

    # Timeline
    timeline = stats.get("timeline", [])
    if timeline:
        df = pd.DataFrame(timeline)
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df["date"],
            y=df["count"],
            mode="lines+markers",
            name="Attacks",
            line={"color": "red", "width": 2},
            fill="tozeroy",
            fillcolor="rgba(255,68,68,0.2)",
        ))
        fig.update_layout(
            title="Attacks Over Time",
            xaxis_title="Date",
            yaxis_title="Attack Count",
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
        )
        st.plotly_chart(fig, use_container_width=True)


def render_controls(health: Optional[Dict]):
    st.subheader("⚙️ Defense Controls")

    defense = (health or {}).get("defense_mode", {})
    current_auto = defense.get("auto_block", True)
    current_dry = defense.get("dry_run", False)

    col1, col2 = st.columns(2)
    with col1:
        st.write("**Auto-Block Mode**")
        new_auto = st.toggle("Enable Auto-Block", value=current_auto)
        if new_auto != current_auto:
            result = set_defense_mode(auto_block=new_auto)
            if result:
                st.success("Auto-block updated")
                st.rerun()

    with col2:
        st.write("**Dry-Run Mode**")
        new_dry = st.toggle("Dry-Run (no real blocks)", value=current_dry)
        if new_dry != current_dry:
            result = set_defense_mode(dry_run=new_dry)
            if result:
                st.success("Dry-run mode updated")
                st.rerun()

    st.divider()

    # Manual block
    st.write("**Manual IP Block**")
    col_a, col_b, col_c = st.columns([2, 2, 1])
    manual_ip = col_a.text_input("IP Address", placeholder="e.g. 192.168.1.100")
    manual_reason = col_b.text_input("Reason", placeholder="Manual block")
    manual_dur = col_c.number_input("Duration (s)", value=3600, step=900)

    if st.button("🔒 Block IP Now"):
        if manual_ip:
            if block_ip(manual_ip, manual_reason or "Manual", int(manual_dur)):
                st.success(f"✅ IP {manual_ip} blocked for {manual_dur}s")
            else:
                st.error("Block failed – check backend")
        else:
            st.warning("Please enter an IP address")

    st.divider()

    # Ollama status
    st.write("**AI Analysis Service (Ollama)**")
    ollama = fetch_ollama_health()
    if ollama and ollama.get("available"):
        st.success(f"✅ Ollama online | Models: {', '.join(ollama.get('models', []))}")
        if not ollama.get("model_ready"):
            st.warning(
                f"⚠️ Model {ollama.get('target_model')} not downloaded. "
                "Run: `docker exec cyber_defense_ollama ollama pull llama3.2:3b`"
            )
    else:
        st.warning(
            "⚠️ Ollama not available – using rule-based fallback analysis. "
            "Start Ollama to enable AI analysis."
        )

    st.divider()

    # Emergency unblock
    st.write("**Emergency Controls**")
    st.error("⚠️ These actions affect all blocked IPs!")
    confirm = st.checkbox("I understand the consequences")
    if st.button("🚨 Emergency Unblock ALL IPs", disabled=not confirm):
        if emergency_unblock_all():
            st.success("All IPs unblocked")
            st.rerun()
        else:
            st.error("Emergency unblock failed")


def render_whitelist():
    st.subheader("📋 IP Whitelist (Never Blocked)")

    whitelist = fetch_whitelist()
    if whitelist:
        df = pd.DataFrame({"IP Address": whitelist})
        st.dataframe(df, use_container_width=True)
    else:
        st.info("Whitelist is empty (only localhost is always protected).")

    st.divider()
    st.write("**Add IP to Whitelist**")
    col1, col2 = st.columns(2)
    wl_ip = col1.text_input("IP Address", key="wl_ip")
    wl_reason = col2.text_input("Reason", key="wl_reason")

    if st.button("➕ Add to Whitelist"):
        if wl_ip:
            if add_to_whitelist(wl_ip, wl_reason):
                st.success(f"IP {wl_ip} added to whitelist")
                st.rerun()
            else:
                st.error("Failed to add to whitelist")
        else:
            st.warning("Enter an IP address")


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    health = fetch_health()
    stats = fetch_attack_stats(days=7)

    section = render_sidebar(health)

    if "Overview" in section:
        render_overview(health, stats)
    elif "Live Attacks" in section:
        render_live_attacks()
    elif "Blocked IPs" in section:
        render_blocked_ips()
    elif "Analytics" in section:
        render_analytics(stats)
    elif "Controls" in section:
        render_controls(health)
    elif "Whitelist" in section:
        render_whitelist()


if __name__ == "__main__":
    main()
