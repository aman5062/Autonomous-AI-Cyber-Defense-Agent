"""
Defense Controls — manage the defense engine
"""
import sys
sys.path.insert(0, "/app")

import streamlit as st
import requests
import os

st.set_page_config(page_title="Defense Controls", page_icon="🛡️", layout="wide")

BACKEND = os.getenv("BACKEND_URL", "http://localhost:8000")

def get(path):
    try:
        r = requests.get(f"{BACKEND}{path}", timeout=5)
        return r.json()
    except:
        return None

def post(path, payload=None):
    try:
        r = requests.post(f"{BACKEND}{path}", json=payload, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

st.title("🛡️ Defense Controls")
st.divider()

health = get("/health")
defense_mode = (health or {}).get("defense_mode", {})

# ── Defense Mode ──────────────────────────────────────────────────────────────
st.subheader("⚙️ Defense Mode")
col1, col2 = st.columns(2)

with col1:
    st.markdown("**Auto-Block Mode**")
    st.caption("Automatically block IPs when attacks are detected")
    current_auto = defense_mode.get("auto_block", True)
    new_auto = st.toggle("Enable Auto-Block", value=current_auto, key="auto_block")
    if new_auto != current_auto:
        result = post("/api/defense/mode", {"auto_block": new_auto})
        if result and not result.get("error"):
            st.success(f"Auto-block {'enabled' if new_auto else 'disabled'}")
            st.rerun()

with col2:
    st.markdown("**Dry-Run Mode**")
    st.caption("Log attacks without actually blocking IPs (safe for testing)")
    current_dry = defense_mode.get("dry_run", False)
    new_dry = st.toggle("Dry-Run (no real blocks)", value=current_dry, key="dry_run")
    if new_dry != current_dry:
        result = post("/api/defense/mode", {"dry_run": new_dry})
        if result and not result.get("error"):
            st.success(f"Dry-run {'enabled' if new_dry else 'disabled'}")
            st.rerun()

st.divider()

# ── Manual Block/Unblock ──────────────────────────────────────────────────────
st.subheader("🔒 Manual IP Management")
col_a, col_b = st.columns(2)

with col_a:
    st.markdown("**Block an IP**")
    manual_ip = st.text_input("IP Address", placeholder="e.g. 1.2.3.4", key="block_ip")
    manual_reason = st.text_input("Reason", value="Manual block", key="block_reason")
    manual_dur = st.selectbox("Duration", [
        ("1 hour", 3600), ("6 hours", 21600), ("24 hours", 86400), ("7 days", 604800)
    ], format_func=lambda x: x[0], key="block_dur")

    if st.button("🔒 Block IP", key="do_block"):
        if manual_ip:
            result = post("/api/defense/block-ip", {
                "ip": manual_ip,
                "reason": manual_reason,
                "duration": manual_dur[1]
            })
            if result and result.get("success"):
                st.success(f"✅ {manual_ip} blocked for {manual_dur[0]}")
            else:
                st.error(f"Failed: {result}")
        else:
            st.warning("Enter an IP address")

with col_b:
    st.markdown("**Unblock an IP**")
    blocked_data = get("/api/defense/blocked-ips")
    blocked_ips = (blocked_data or {}).get("blocked_ips", [])

    if blocked_ips:
        ip_options = [f"{b['ip']} ({b.get('attack_type', '?')})" for b in blocked_ips]
        chosen = st.selectbox("Select IP to unblock", ip_options, key="unblock_select")
        chosen_ip = chosen.split(" ")[0]

        if st.button("🔓 Unblock Selected", key="do_unblock"):
            result = post("/api/defense/unblock-ip", {"ip": chosen_ip})
            if result and result.get("success"):
                st.success(f"✅ {chosen_ip} unblocked")
                st.rerun()
            else:
                st.error("Unblock failed")
    else:
        st.info("No IPs currently blocked")

st.divider()

# ── Blocked IPs Table ─────────────────────────────────────────────────────────
st.subheader(f"🚫 Blocked IPs ({(blocked_data or {}).get('total', 0)} active)")

if blocked_ips:
    import pandas as pd
    df = pd.DataFrame(blocked_ips)
    cols = [c for c in ["ip", "attack_type", "severity", "block_time", "unblock_time", "reason", "blocked_by"] if c in df.columns]
    st.dataframe(df[cols], use_container_width=True)
else:
    st.success("No IPs currently blocked — system is clean.")

st.divider()

# ── Whitelist ─────────────────────────────────────────────────────────────────
st.subheader("✅ IP Whitelist (Never Blocked)")
wl_data = get("/api/whitelist")
whitelist = (wl_data or {}).get("whitelist", [])

col_w1, col_w2 = st.columns(2)
with col_w1:
    if whitelist:
        import pandas as pd
        st.dataframe(pd.DataFrame({"IP": whitelist}), use_container_width=True)
    else:
        st.info("Whitelist is empty")

with col_w2:
    st.markdown("**Add to Whitelist**")
    wl_ip = st.text_input("IP to whitelist", key="wl_ip")
    wl_reason = st.text_input("Reason", key="wl_reason")
    if st.button("➕ Add to Whitelist"):
        if wl_ip:
            result = post("/api/whitelist/add", {"ip": wl_ip, "reason": wl_reason})
            if result and result.get("success"):
                st.success(f"✅ {wl_ip} added to whitelist")
                st.rerun()
        else:
            st.warning("Enter an IP")

st.divider()

# ── AI Analysis Status ────────────────────────────────────────────────────────
st.subheader("🤖 AI Analysis (Ollama)")
ollama = get("/api/analysis/ollama-health")

if ollama and ollama.get("available"):
    st.success(f"✅ Ollama online | Model: {ollama.get('target_model')} | Ready: {ollama.get('model_ready')}")
    if ollama.get("models"):
        st.write(f"Available models: {', '.join(ollama['models'])}")
    if not ollama.get("model_ready"):
        st.warning("⚠️ llama3.2:3b not yet downloaded. Still pulling...")
        st.code("docker logs cyber_defense_ollama_init")
else:
    st.warning("⚠️ Ollama unavailable — using rule-based fallback analysis")

st.divider()

# ── Emergency ─────────────────────────────────────────────────────────────────
st.subheader("🚨 Emergency Controls")
st.error("⚠️ These actions affect ALL blocked IPs immediately!")

confirm = st.checkbox("I understand — unblock ALL IPs")
if st.button("🚨 Emergency Unblock ALL", disabled=not confirm):
    result = post("/api/defense/emergency-unblock")
    if result and result.get("success"):
        st.success("✅ All IPs unblocked")
        st.rerun()
    else:
        st.error("Failed")
