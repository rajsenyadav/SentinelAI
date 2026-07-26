"""
SentinelAI — Enterprise Security Operations Center (SOC) Dashboard

Main Streamlit Application Entry Point.
Incident-Centric UEBA & SOC Decision Support Platform.
Persistent Analyst Feedback & Audit Logging Integration.
Premium White Theme System.
"""

import os
import sys
import streamlit as st
import pandas as pd

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.utils import load_dataset, load_models
from dashboard.components.overview import render_overview
from dashboard.components.threat_intel import render_threat_intel
from dashboard.components.explainability_panel import render_explainability_panel
from dashboard.components.timeline import render_timeline
from dashboard.components.analytics import render_analytics
from dashboard.components.analyst_console import render_analyst_console
from dashboard.components.incident_details import render_incident_details

# Page Config
st.set_page_config(
    page_title="SentinelAI — SOC Security Console",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Load Custom CSS (Premium White Theme)
css_path = os.path.join(PROJECT_ROOT, "dashboard", "styles.css")
if os.path.exists(css_path):
    with open(css_path, encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


def main():
    # Load Data & Models from CSV Single Source of Truth
    df_raw, df_proc = load_dataset()
    detector, classifier, explainer = load_models()

    # Calculate active anomalies directly from persisted CSV dataset
    anomalies = df_proc[df_proc["label"] == "anomaly"]
    total_events = len(df_proc)
    crit = len(anomalies[anomalies["attack_type"].isin(["lateral_movement", "low_slow_exfiltration"])]) if len(anomalies) > 0 else 0
    high = len(anomalies[anomalies["attack_type"].isin(["brute_force", "impossible_travel", "credential_stuffing"])]) if len(anomalies) > 0 else 0

    st.markdown(
        f"""
        <div class="soc-header-banner">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px;">
                <div>
                    <h1>SentinelAI</h1>
                    <p>Enterprise Behavioral Anomaly Detection & Incident-Centric UEBA Platform</p>
                    <div style="margin-top: 8px;">
                        <span class="developer-watermark">Mark 1 Architect & Developer: <b>Raj Sen</b></span>
                    </div>
                </div>
                <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                    <span class="badge-critical">Critical: {crit}</span>
                    <span class="badge-high">High: {high}</span>
                    <span class="badge-low">System: Operational</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Streamlined Top Navigation Bar
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Threat Intelligence",
            "Incident Details",
            "Explainable AI (XAI)",
            "User Behavior Timeline",
            "Analyst Console",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    # Render Selected Page
    if "Overview" in page:
        render_overview(df_proc)
        render_analytics(df_proc, theme_mode="Light Mode")
    elif "Threat Intelligence" in page:
        render_threat_intel(df_proc)
    elif "Incident Details" in page:
        render_incident_details(df_proc)
    elif "Explainable AI" in page:
        render_explainability_panel(df_proc, explainer)
    elif "User Behavior" in page:
        render_timeline(df_proc)
    elif "Analyst Console" in page:
        render_analyst_console(df_proc)

    # Footer Developer Credit
    st.markdown(
        """
        <div class="footer-credit">
            <b>RAJ SEN</b> &nbsp;&middot;&nbsp; MARK 1 SYSTEMS ARCHITECT
        </div>
        """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
