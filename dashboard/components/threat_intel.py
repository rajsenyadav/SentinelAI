"""
SentinelAI Dashboard — Threat Intelligence Component

Displays categorized threat intelligence table with filters by Attack Type, Department, and Entity.
"""

import streamlit as st
import pandas as pd


def render_threat_intel(df: pd.DataFrame):
    """Render threat intelligence panel."""
    st.subheader("Threat Intelligence & Active Incidents")

    df_anom = df[df["label"] == "anomaly"].copy()
    if len(df_anom) == 0:
        st.info("No active threats detected in dataset.")
        return

    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        selected_attack = st.selectbox(
            "Filter by Attack Type",
            ["All"] + sorted(list(df_anom["attack_type"].unique()))
        )
    with col2:
        selected_dept = st.selectbox(
            "Filter by Department",
            ["All"] + sorted(list(df_anom["department"].unique())) if "department" in df_anom.columns else ["All"]
        )
    with col3:
        selected_entity = st.text_input("Search Entity ID / User")

    # Apply filters
    filtered_df = df_anom.copy()
    if selected_attack != "All":
        filtered_df = filtered_df[filtered_df["attack_type"] == selected_attack]
    if selected_dept != "All" and "department" in filtered_df.columns:
        filtered_df = filtered_df[filtered_df["department"] == selected_dept]
    if selected_entity:
        filtered_df = filtered_df[filtered_df["entity_id"].astype(str).str.contains(selected_entity, case=False)]

    st.write(f"Displaying **{len(filtered_df)}** active security incidents:")

    display_cols = ["event_id", "timestamp", "entity_id", "attack_type", "source_ip", "geo_location", "resource_accessed"]
    available_cols = [c for c in display_cols if c in filtered_df.columns]

    st.dataframe(
        filtered_df[available_cols].rename(columns={
            "event_id": "Event ID",
            "timestamp": "Timestamp",
            "entity_id": "Entity ID",
            "attack_type": "Threat Category",
            "source_ip": "Source IP",
            "geo_location": "Location",
            "resource_accessed": "Resource Targeted"
        }),
        use_container_width=True,
    )
