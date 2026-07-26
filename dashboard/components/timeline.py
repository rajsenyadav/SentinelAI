"""
SentinelAI Dashboard — User Behavior Timeline Component

Displays interactive visual activity timeline scatter charts, full activity log tables,
and step-by-step incident attack storylines with premium white theme.
"""

import streamlit as st
import pandas as pd
import plotly.express as px
from detection.incident_storyline import IncidentStorylineEngine
from dashboard.components.incident_storyline_card import render_incident_storyline_card


def render_timeline(df: pd.DataFrame):
    """Render user behavioral timeline graph, activity history table, and attack storyline."""
    st.subheader("User Behavioral Timeline & Quick Review Console")

    entity_col = "user_id" if "user_id" in df.columns else "entity_id"
    entities = sorted(list(df[entity_col].unique()))
    selected_entity = st.selectbox("Select User / Entity to Trace:", entities, key="timeline_entity_select")

    df_user = df[df[entity_col] == selected_entity].sort_values("timestamp").reset_index(drop=True)

    # 1. Activity History Timeline Graph (Scatter Plot)
    st.markdown(f"#### Activity History Timeline Graph (`{selected_entity}`)")
    fig_scatter = px.scatter(
        df_user,
        x="timestamp",
        y="action_type" if "action_type" in df_user.columns else "resource_accessed",
        color="label",
        size=[12 if l == "anomaly" else 7 for l in df_user["label"]],
        hover_data=[c for c in ["resource_accessed", "source_ip", "geo_location", "attack_type", "status"] if c in df_user.columns],
        color_discrete_map={"normal": "#2e7d4f", "anomaly": "#c4392a"},
        title=f"Activity Chronology Timeline — {selected_entity}",
        labels={"timestamp": "Timestamp", "action_type": "Action", "label": "Security Status"},
    )
    fig_scatter.update_layout(
        template="plotly_white",
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#2c2825"),
        title_font=dict(size=15, color="#2c2825"),
        height=340,
        margin=dict(l=20, r=20, t=40, b=20),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        xaxis=dict(gridcolor="#f0ede8"),
        yaxis=dict(gridcolor="#f0ede8"),
    )
    fig_scatter.update_traces(marker=dict(line=dict(width=1, color="#ffffff")))
    st.plotly_chart(fig_scatter, use_container_width=True)

    st.markdown("---")

    # 2. Activity History Timeline Table (Placed BEFORE Storyline Engine Card)
    st.markdown(f"#### Activity History Log Table ({len(df_user)} events logged)")
    display_cols = ["timestamp", "action_type", "resource_accessed", "source_ip", "geo_location", "label", "attack_type", "status"]
    avail = [c for c in display_cols if c in df_user.columns]
    st.dataframe(df_user[avail], use_container_width=True)

    st.markdown("---")

    # 3. Step-by-Step Incident Attack Storyline Engine Card
    storyline_engine = IncidentStorylineEngine()
    storyline = storyline_engine.build_storyline(df_user, selected_entity)
    render_incident_storyline_card(storyline)
