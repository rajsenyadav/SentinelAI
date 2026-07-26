"""
SentinelAI Dashboard — Live Event Stream Component

Continuously streams incoming enterprise access logs in real-time.
Renders live status badges reflecting analyst triage decisions.
Premium white-only theme integration.
"""

import streamlit as st
import pandas as pd


def render_live_stream(df: pd.DataFrame):
    """Render real-time streaming event table with live triage status badges."""
    st.subheader("Live Enterprise Telemetry Log Stream")
    st.caption("Real-time access events streaming through SentinelAI ingestion pipeline.")

    # Select last 20 events sorted by timestamp
    df_sorted = df.sort_values("timestamp", ascending=False).head(20).reset_index(drop=True)

    formatted_rows = []
    for idx, row in df_sorted.iterrows():
        is_anomaly = (row.get("label") == "anomaly")
        curr_status = str(row.get("status", "LIVE_THREAT"))

        if curr_status == "FALSE_POSITIVE":
            status_html = "<span style='background:#f0faf3;color:#2e7d4f;border:1.5px solid rgba(46,125,79,0.25);padding:3px 10px;border-radius:50px;font-weight:700;font-size:0.75rem;'>FALSE POSITIVE</span>"
        elif curr_status == "RESOLVED":
            status_html = "<span style='background:#f0faf3;color:#2e7d4f;border:1.5px solid rgba(46,125,79,0.25);padding:3px 10px;border-radius:50px;font-weight:700;font-size:0.75rem;'>RESOLVED</span>"
        elif curr_status == "UNDER_INVESTIGATION":
            status_html = "<span style='background:#fdf8ee;color:#b8860b;border:1.5px solid rgba(184,134,11,0.3);padding:3px 10px;border-radius:50px;font-weight:700;font-size:0.75rem;'>INVESTIGATING</span>"
        elif is_anomaly:
            status_html = "<span style='background:#fef2f0;color:#c4392a;border:1.5px solid rgba(196,57,42,0.3);padding:3px 10px;border-radius:50px;font-weight:700;font-size:0.75rem;'>ANOMALY</span>"
        else:
            status_html = "<span style='background:#f0faf3;color:#2e7d4f;border:1.5px solid rgba(46,125,79,0.25);padding:3px 10px;border-radius:50px;font-weight:700;font-size:0.75rem;'>NORMAL</span>"
        
        formatted_rows.append({
            "Status": status_html,
            "Timestamp": str(row.get("timestamp"))[:19],
            "Entity ID": row.get("entity_id", "N/A"),
            "Department": row.get("department", "Engineering"),
            "Source IP": row.get("source_ip", "N/A"),
            "Geo Location": row.get("geo_location", "N/A"),
            "Resource": row.get("resource_accessed", "N/A"),
            "Action": row.get("action_type", "login"),
            "Threat Category": str(row.get("attack_type", "normal")).replace("_", " ").title(),
        })

    df_display = pd.DataFrame(formatted_rows)
    st.write(df_display.to_html(escape=False, index=False), unsafe_allow_html=True)
