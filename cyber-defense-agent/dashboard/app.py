import time
import streamlit as st
import pandas as pd
from dashboard.utils.data_fetcher import (
    fetch_health, fetch_recent_attacks, fetch_blocked_ips,
    fetch_stats, fetch_latest_scan, block_ip, unblock_ip,
    emergency_unblock, set_defense_mode, run_scan, run_simulation,
)
from dashboard.components.charts import (
    attack_distribution_chart, attack_timeline_chart, severity_bar_chart,
)

st.set_page_config(
    page_title="AI Cyber Defense Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("🛡️ Cyber Defense")
    st.divider()

    health = fetch_health()
    services = health.get("services", {})
    st.subheader("System Status")
    for svc, status in services.items():
        icon = "🟢" if status in ("connected", "ready", "active") else "🟡" if status == "dry-run" else "🔴"
        st.write(f"{icon} **{svc}**: {status}")

    st.divider()
    st.subheader("Defense Mode")
    auto_on = st.toggle("Auto-Defense", value=True)
    dry_run = st.toggle("Dry-Run Mode", value=False)
    if st.button("Apply Mode"):
        set_defense_mode(auto_defense=auto_on, dry_run=dry_run)
        st.success("Mode updated")

    st.divider()
    st.subheader("Tools")
    if st.button("🔍 Run Vulnerability Scan"):
        run_scan()
        st.success("Scan started in background")

    st.subheader("Attack Simulator")
    sim_type = st.selectbox("Attack Type", ["all", "sql_injection", "xss", "path_traversal", "brute_force"])
    if st.button("▶ Run Simulation"):
        run_simulation(sim_type)
        st.info(f"Simulation '{sim_type}' started")

    st.divider()
    if st.button("🚨 Emergency Unblock All", type="secondary"):
        if st.session_state.get("confirm_unblock"):
            emergency_unblock()
            st.success("All IPs unblocked")
            st.session_state["confirm_unblock"] = False
        else:
            st.session_state["confirm_unblock"] = True
            st.warning("Click again to confirm")

    days_filter = st.slider("Stats window (days)", 1, 30, 7)
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=False)

# ── Main ──────────────────────────────────────────────────────────────────────
st.title("🛡️ AI Cyber Defense Dashboard")

stats = fetch_stats(days=days_filter)
attacks = fetch_recent_attacks(limit=50)
blocked = fetch_blocked_ips()

# ── Metrics row ───────────────────────────────────────────────────────────────
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Attacks", stats.get("total_attacks", 0), f"Last {days_filter}d")
c2.metric("Blocked", stats.get("blocked_count", 0))
c3.metric("Blocked IPs", len(blocked))
c4.metric("Active Threats", sum(1 for a in attacks if a.get("severity") == "CRITICAL"))

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["Live Feed", "Analytics", "Blocked IPs", "Vulnerability Scan"])

# ── Tab 1: Live Feed ──────────────────────────────────────────────────────────
with tab1:
    st.subheader("🚨 Live Attack Feed")

    SEVERITY_COLOR = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    if not attacks:
        st.info("No attacks detected yet. System is monitoring...")
    else:
        for atk in attacks[:20]:
            icon = SEVERITY_COLOR.get(atk.get("severity", ""), "⚪")
            with st.container(border=True):
                col1, col2, col3, col4 = st.columns([3, 2, 2, 2])
                col1.write(f"{icon} **{atk.get('attack_type', 'UNKNOWN')}**")
                col2.write(f"`{atk.get('ip', '-')}`")
                col3.write(atk.get("severity", "-"))
                col4.write(str(atk.get("created_at", "-"))[:19])

                with st.expander("Details & AI Analysis"):
                    st.write(f"**Path:** `{atk.get('path', '-')}`")
                    st.write(f"**Method:** {atk.get('method', '-')} | **Status:** {atk.get('status', '-')}")
                    st.write(f"**User-Agent:** {atk.get('user_agent', '-')}")
                    st.write(f"**Blocked:** {'Yes' if atk.get('blocked') else 'No'}")

                    if atk.get("explanation"):
                        st.subheader("AI Analysis")
                        st.write(f"**Explanation:** {atk['explanation']}")
                        st.write(f"**Impact:** {atk.get('impact', '-')}")
                        mitigation = atk.get("mitigation", [])
                        if mitigation:
                            st.write("**Mitigation Steps:**")
                            for step in (mitigation if isinstance(mitigation, list) else [mitigation]):
                                st.write(f"  - {step}")
                        code_fix = atk.get("code_fix", {})
                        if isinstance(code_fix, dict) and code_fix.get("secure"):
                            st.write("**Secure Code:**")
                            st.code(code_fix["secure"])

# ── Tab 2: Analytics ──────────────────────────────────────────────────────────
with tab2:
    st.subheader("📊 Attack Analytics")
    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(attack_distribution_chart(stats.get("by_type", {})), use_container_width=True)
    with col2:
        st.plotly_chart(severity_bar_chart(stats.get("by_severity", {})), use_container_width=True)

    st.plotly_chart(attack_timeline_chart(stats.get("timeline", [])), use_container_width=True)

# ── Tab 3: Blocked IPs ────────────────────────────────────────────────────────
with tab3:
    st.subheader("🚫 Blocked IPs")

    col1, col2 = st.columns([3, 1])
    with col1:
        manual_ip = st.text_input("IP to block manually")
        manual_reason = st.text_input("Reason", value="Manual block")
        manual_duration = st.number_input("Duration (seconds)", value=3600, min_value=60)
    with col2:
        st.write("")
        st.write("")
        if st.button("Block IP"):
            if manual_ip:
                result = block_ip(manual_ip, manual_reason, int(manual_duration))
                if result.get("success"):
                    st.success(f"Blocked {manual_ip}")
                    st.rerun()
                else:
                    st.error(result.get("message", "Failed"))
            else:
                st.warning("Enter an IP address")

    st.divider()

    if not blocked:
        st.info("No IPs currently blocked.")
    else:
        df = pd.DataFrame(blocked)
        display_cols = [c for c in ["ip", "attack_type", "severity", "block_time", "unblock_time", "status", "reason"] if c in df.columns]
        st.dataframe(df[display_cols], use_container_width=True)

        ip_to_unblock = st.selectbox("Select IP to unblock", [b["ip"] for b in blocked])
        if st.button("Unblock Selected IP"):
            result = unblock_ip(ip_to_unblock)
            if result.get("success"):
                st.success(f"Unblocked {ip_to_unblock}")
                st.rerun()

# ── Tab 4: Vulnerability Scan ─────────────────────────────────────────────────
with tab4:
    st.subheader("🔍 Vulnerability Scan Results")
    scan = fetch_latest_scan()

    if not scan or scan.get("message"):
        st.info("No scan results yet. Run a scan from the sidebar.")
    else:
        st.write(f"**Scan Time:** {scan.get('scan_time', '-')}")
        st.write(f"**Target:** {scan.get('target', '-')}")

        open_ports = scan.get("open_ports", [])
        if open_ports:
            st.subheader("Open Ports")
            st.dataframe(pd.DataFrame(open_ports), use_container_width=True)

        vulns = scan.get("vulnerabilities", [])
        if vulns:
            st.subheader(f"Vulnerabilities Found ({len(vulns)})")
            for v in vulns:
                sev = v.get("severity", "LOW")
                icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(sev, "⚪")
                with st.container(border=True):
                    st.write(f"{icon} **{sev}** — {v.get('description', '')}")
                    st.write(f"Recommendation: {v.get('recommendation', '')}")
        else:
            st.success("No vulnerabilities found.")

# ── Auto-refresh ──────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(5)
    st.rerun()
