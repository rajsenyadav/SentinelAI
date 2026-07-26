"""
Incident Storyline Component for SentinelAI Dashboard.

Renders an enterprise step-by-step chronological attack timeline using native
Streamlit UI components to guarantee zero raw HTML tag bleeding or string overflow.
"""

import streamlit as st
from typing import Dict, Any


def render_incident_storyline_card(storyline_data: Dict[str, Any]):
    """Render step-by-step chronological attack storyline card in Streamlit using native UI."""
    entity_id = storyline_data.get("entity_id", "Unknown")
    stages = storyline_data.get("storyline_stages", [])
    narrative = storyline_data.get("attack_narrative", "")
    highest_sev = storyline_data.get("highest_severity", "LOW")

    st.markdown("### Chronological Attack Storyline Engine")
    st.caption(f"Entity Sequence Investigation & Evidence Chain Linker • Target: **{entity_id}** • Severity: **{highest_sev}**")

    # Narrative Summary Box
    if highest_sev == "CRITICAL":
        st.error(f"**Narrative Summary:** {narrative}")
    elif highest_sev == "HIGH":
        st.warning(f"**Narrative Summary:** {narrative}")
    else:
        st.info(f"**Narrative Summary:** {narrative}")

    if not stages:
        st.caption("No activity stages to display.")
        return

    st.markdown("##### Step-by-Step Incident Chain:")

    # Highlight anomalous / critical stages first, limit main view to top 10 milestones
    milestones = [s for s in stages if s.get("attack_vector") != "Normal"]
    if not milestones:
        milestones = stages[:10]  # Take first 10 for normal user baseline

    for stage in milestones:
        step_num = stage["step_number"]
        ts = stage["timestamp"]
        title = stage["stage_title"]
        action = stage["action"]
        vector = stage["attack_vector"]
        evidence = stage["evidence_chain"]
        ev_str = " • ".join(evidence) if evidence else "Standard telemetry event"

        with st.container():
            st.markdown(f"**Step {step_num}: {title}** (`{ts}`)")
            st.markdown(f"- **Action:** `{action}` | **Vector:** `{vector}`")
            st.markdown(f"- **Evidence Chain:** {ev_str}")
            st.markdown("---")

    # If there are additional baseline events, place them inside a clean expander
    if len(stages) > len(milestones):
        with st.expander(f"View All {len(stages)} Telemetry History Milestones"):
            for stage in stages[len(milestones):]:
                st.markdown(f"**Step {stage['step_number']}: {stage['stage_title']}** (`{stage['timestamp']}`)")
                st.markdown(f"Action: `{stage['action']}` | Vector: `{stage['attack_vector']}`")
