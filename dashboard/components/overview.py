"""
SentinelAI Dashboard — Overview Component

Displays top-level SOC metric cards and real-time enterprise access log stream.
"""

import streamlit as st
import pandas as pd
from dashboard.components.live_stream import render_live_stream


def render_overview(df: pd.DataFrame):
    """Render high-level KPI cards and integrated live telemetry stream."""
    st.subheader("SOC Command Center — Executive Overview")

    total_events = len(df)
    anomalies = df[df["label"] == "anomaly"]
    normal_events = total_events - len(anomalies)

    # Risk level breakdown
    critical_cnt = len(anomalies[anomalies["attack_type"].isin(["lateral_movement", "low_slow_exfiltration"])])
    high_cnt = len(anomalies[anomalies["attack_type"].isin(["brute_force", "impossible_travel", "credential_stuffing"])])
    active_threats = len(anomalies)

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.metric("Total Events", f"{total_events:,}", delta="100k Baseline")
    with col2:
        st.metric("Normal Events", f"{normal_events:,}", delta=f"{normal_events/total_events*100:.1f}%")
    with col3:
        st.metric("Active Threats", f"{active_threats:,}", delta=f"-{active_threats} Flagged", delta_color="inverse")
    with col4:
        st.metric("High Risk Alerts", f"{high_cnt:,}", delta="Top 5% Budget", delta_color="inverse")
    with col5:
        st.metric("Critical Incidents", f"{critical_cnt:,}", delta="Immediate Action", delta_color="inverse")

    st.markdown("---")

    # Embedded Live Telemetry Stream Section
    render_live_stream(df)
