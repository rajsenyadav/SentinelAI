"""
SentinelAI Dashboard — Geo Map Component

Displays interactive Pydeck / Plotly 3D world map of geographic access logs
and impossible travel flight arcs between consecutive suspicious logins.
"""

import streamlit as st
import pandas as pd
import plotly.express as px


def render_geo_map(df: pd.DataFrame):
    """Render interactive geographic login map."""
    st.subheader("🌍 Global Telemetry & Impossible Travel Map")

    df_map = df[df["geo_lat"].notnull() & df["geo_lon"].notnull()].copy()
    if len(df_map) == 0:
        st.info("No geographic coordinates present in dataset.")
        return

    # Filter anomalies for map highlights
    df_map["Marker_Size"] = df_map["label"].apply(lambda x: 12 if x == "anomaly" else 4)

    fig = px.scatter_geo(
        df_map,
        lat="geo_lat",
        lon="geo_lon",
        color="label",
        hover_name="geo_location",
        hover_data=["entity_id", "attack_type", "source_ip"],
        size="Marker_Size",
        size_max=15,
        color_discrete_map={"normal": "#00f0ff", "anomaly": "#ef4444"},
        projection="natural earth",
        title="Global Access Telemetry Map (Red = Anomaly / Green = Normal)",
    )

    fig.update_geos(
        showcoastlines=True,
        coastlinecolor="rgba(0, 240, 255, 0.4)",
        showland=True,
        landcolor="#0d1322",
        showocean=True,
        oceancolor="#070a13",
        showlakes=False,
    )
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=40, b=0),
        height=500,
    )

    st.plotly_chart(fig, use_container_width=True)
