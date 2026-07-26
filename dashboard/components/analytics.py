"""
SentinelAI Dashboard — Attack Analytics Component

Displays interactive Plotly visual analytics charts with premium white theme:
- Attack Category Distribution (Donut Chart)
- Department Risk Exposure (Bar Chart)
- Hourly Incident Trend (Spline Chart)
"""

import streamlit as st
import pandas as pd
import plotly.express as px


# Premium white-only color palette — no blue or dark shades
CHART_COLORS = ["#c4392a", "#e06b5e", "#d97706", "#b8860b", "#2e7d4f", "#8b6f47", "#a0522d", "#cc7a6f"]


def render_analytics(df: pd.DataFrame, theme_mode: str = "Light Mode"):
    """Render Plotly threat analytics charts with white-only premium theme."""
    st.subheader("Cyber Attack Analytics & Trend Intelligence")

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
            color_discrete_sequence=CHART_COLORS,
            hole=0.45,
        )
        fig1.update_layout(
            template="plotly_white",
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(family="Inter, sans-serif", color="#2c2825"),
            title_font=dict(size=15, color="#2c2825"),
            legend=dict(font=dict(size=11)),
            margin=dict(t=50, b=20, l=20, r=20),
        )
        fig1.update_traces(
            textfont_size=12,
            marker=dict(line=dict(color="#ffffff", width=2)),
        )
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
                color_continuous_scale=[[0, "#fef2f0"], [0.5, "#e06b5e"], [1, "#c4392a"]],
            )
            fig2.update_layout(
                template="plotly_white",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(family="Inter, sans-serif", color="#2c2825"),
                title_font=dict(size=15, color="#2c2825"),
                margin=dict(t=50, b=20, l=20, r=20),
                coloraxis_showscale=False,
            )
            fig2.update_traces(marker_line_width=0, marker_cornerradius=6)
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
    fig3.update_traces(
        line_color="#c4392a",
        line_width=2.5,
        marker=dict(size=5, color="#c4392a", line=dict(width=1.5, color="#ffffff")),
        fill="tozeroy",
        fillcolor="rgba(196, 57, 42, 0.06)",
    )
    fig3.update_layout(
        template="plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#2c2825"),
        title_font=dict(size=15, color="#2c2825"),
        height=350,
        margin=dict(l=20, r=20, t=50, b=20),
        xaxis=dict(gridcolor="#f0ede8"),
        yaxis=dict(gridcolor="#f0ede8"),
    )
    st.plotly_chart(fig3, use_container_width=True)
