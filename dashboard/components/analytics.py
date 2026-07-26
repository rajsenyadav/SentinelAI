"""
SentinelAI Dashboard — Attack Analytics Component

Displays interactive Plotly visual analytics charts:
- Attack Category Distribution
- Risk Level Distribution
- Department-wise Threat Breakdown
- Hourly Incident Trend
"""

import streamlit as st
import pandas as pd
import plotly.express as px


def render_analytics(df: pd.DataFrame, theme_mode: str = "Dark Mode"):
    """Render Plotly threat analytics charts."""
    st.subheader("Cyber Attack Analytics & Trend Intelligence")

    plotly_template = "plotly_dark" if theme_mode == "Dark Mode" else "plotly_white"

    df_anom = df[df["label"] == "anomaly"].copy()
    if len(df_anom) == 0:
        st.info("No anomaly data available for charts.")
        return

    col1, col2 = st.columns(2)

    with col1:
        # 1. Attack Category Distribution
        attack_counts = df_anom["attack_type"].value_counts().reset_index()
        attack_counts.columns = ["Attack Type", "Count"]
        attack_counts["Attack Type"] = attack_counts["Attack Type"].str.replace("_", " ").str.title()

        fig1 = px.pie(
            attack_counts,
            names="Attack Type",
            values="Count",
            title="Threat Vector Distribution",
            color_discrete_sequence=["#ef4444", "#f97316", "#f59e0b", "#3b82f6", "#8b5cf6", "#06b6d4"],
            hole=0.4,
        )
        fig1.update_layout(template=plotly_template, paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig1, use_container_width=True)

    with col2:
        # 2. Department-wise Threat Distribution
        if "department" in df_anom.columns:
            dept_counts = df_anom["department"].value_counts().reset_index()
            dept_counts.columns = ["Department", "Threat Count"]

            fig2 = px.bar(
                dept_counts,
                x="Department",
                y="Threat Count",
                title="Department Risk Exposure",
                color="Threat Count",
                color_continuous_scale="Reds",
            )
            fig2.update_layout(template=plotly_template, paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("Department metadata not present in dataset.")

    st.markdown("---")

    # 3. Time Series Threat Trend
    df_anom["hour"] = pd.to_datetime(df_anom["timestamp"]).dt.floor("h")
    trend_df = df_anom.groupby("hour").size().reset_index(name="Incident Count")

    fig3 = px.line(
        trend_df,
        x="hour",
        y="Incident Count",
        title="Hourly Incident Rate Trend (Time-Series)",
        markers=True,
        line_shape="spline",
    )
    fig3.update_traces(line_color="#3b82f6")
    fig3.update_layout(template=plotly_template, paper_bgcolor="rgba(0,0,0,0)", height=350)
    st.plotly_chart(fig3, use_container_width=True)
