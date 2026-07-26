"""
Behavioral Identity Card Dashboard Component.

Renders an enterprise visual card displaying employee baseline profiles,
deviation percentages, top anomaly drivers, and natural language explanations
using native Streamlit components.
"""

import streamlit as st
from typing import Dict, Any


def render_behavioral_identity_card(evaluation_result: Dict[str, Any]):
    """Render the Behavioral Identity evaluation card in Streamlit using native UI."""
    entity_id = evaluation_result.get("entity_id", "Unknown")
    dev_pct = evaluation_result.get("deviation_percentage", 0.0)
    summary = evaluation_result.get("behavior_summary", "Baseline Normal")
    explanation = evaluation_result.get("human_explanation", "")
    top_deviations = evaluation_result.get("top_deviations", [])
    baseline = evaluation_result.get("historical_baseline", {})

    st.markdown("### Behavioral Identity Engine Profile")
    st.caption(f"Entity Baseline vs Real-Time Access Telemetry Comparison • Target Entity: **{entity_id}** • Behavioral Deviation: **{dev_pct}%**")

    if dev_pct > 50:
        st.error(f"**{summary}**\n\n{explanation}")
    elif dev_pct > 25:
        st.warning(f"**{summary}**\n\n{explanation}")
    else:
        st.info(f"**{summary}**\n\n{explanation}")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Top Anomaly Deviations")
        if not top_deviations:
            st.info("No baseline behavioral deviations detected.")
        else:
            for dev in top_deviations:
                st.markdown(f"- **{dev['factor']}** `[{dev['severity']} ({dev['weight_pct']}%)]`")
                st.markdown(f"  *{dev['detail']}*")

    with col2:
        st.markdown("#### Entity Baseline Profile Parameters")
        st.markdown(f"- **Entity ID:** `{baseline.get('entity_id', entity_id)}` (Dept: **{baseline.get('department', 'N/A')}**)")
        st.markdown(f"- **Normal Hours:** `{baseline.get('working_hours', [8,18])[0]:02d}:00 – {baseline.get('working_hours', [8,18])[1]:02d}:00`")
        st.markdown(f"- **Approved Devices:** `{', '.join(baseline.get('typical_devices', ['Corporate-Desktop']))}`")
        st.markdown(f"- **Approved Countries:** `{', '.join(baseline.get('typical_countries', ['US']))}`")
        st.markdown(f"- **Frequent Resources:** `{', '.join(baseline.get('normal_resources', ['Portal'])[:3])}`")
        st.markdown(f"- **Avg Session Duration:** `{baseline.get('avg_session_duration', 45.0)} mins ({baseline.get('login_frequency', 10.0)} logins/day)`")
