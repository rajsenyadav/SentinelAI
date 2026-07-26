"""
SentinelAI Dashboard — Analyst Console Component

Allows SOC analysts to:
- Review AI Copilot Investigation Briefs
- Persistently update incident status to CSV
- Attach investigation notes & audit logs
- Export incident reports (JSON / HTML Report)
"""

import json
import streamlit as st
import pandas as pd
from detection.ai_analyst_copilot import AIAnalystCopilot
from dashboard.components.copilot_card import render_copilot_card
from backend.services.incident_persistence import update_incident_status, get_audit_log


def render_analyst_console(df: pd.DataFrame):
    """Render Analyst Triage Console with AI Copilot Assistant."""
    st.subheader("SOC Analyst Triage & Persistent Audit Console")

    df_anom = df[df["label"] == "anomaly"].copy()
    if len(df_anom) == 0:
        st.info("No active security incidents to triage.")
        st.markdown("##### Analyst Actions Audit Log (`analyst_actions.csv`)")
        df_audit = get_audit_log()
        if not df_audit.empty:
            st.dataframe(df_audit.tail(10), use_container_width=True)
        return

    copilot = AIAnalystCopilot()

    # Select incident to triage
    event_ids = list(df_anom["event_id"].values)
    selected_event = st.selectbox("Select Incident to Investigate:", event_ids, key="console_event_select")

    event_data = df_anom[df_anom["event_id"] == selected_event].iloc[0]

    # Generate AI Copilot Brief
    copilot_brief = copilot.generate_investigation_brief(event_data.to_dict())

    # Render AI Copilot Visual Brief Card
    render_copilot_card(copilot_brief)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### Incident Metadata")
        st.write(f"**Event ID:** `{event_data.get('event_id')}`")
        st.write(f"**User / Entity:** `{event_data.get('entity_id')}`")
        st.write(f"**Timestamp:** `{event_data.get('timestamp')}`")
        st.write(f"**Threat Category:** `{event_data.get('attack_type')}`")
        st.write(f"**Current Status:** `{event_data.get('status', 'LIVE_THREAT')}`")

    with col2:
        st.markdown("### Persistent Triage Form")
        status_action = st.radio(
            "Select New Incident Lifecycle Status:",
            ["Confirmed Threat", "False Positive (Close Alert)", "Under Investigation", "Resolved"]
        )

        notes = st.text_area("Analyst Investigation Notes & Evidence:", placeholder="Enter investigation comments here...")

        if st.button("Submit & Persist Analyst Decision"):
            status_map = {
                "Confirmed Threat": "CONFIRMED_THREAT",
                "False Positive (Close Alert)": "FALSE_POSITIVE",
                "Under Investigation": "UNDER_INVESTIGATION",
                "Resolved": "RESOLVED",
            }
            target_status = status_map.get(status_action, "CONFIRMED_THREAT")

            if update_incident_status(selected_event, target_status, remarks=notes):
                st.cache_data.clear()
                st.success(f"Successfully persisted status **{target_status}** to CSV for incident `{selected_event}`!")
                st.rerun()

    st.markdown("---")
    st.subheader("Export Incident Report & AI Copilot Brief")

    report_payload = {
        "event_id": str(event_data.get("event_id")),
        "entity_id": str(event_data.get("entity_id")),
        "timestamp": str(event_data.get("timestamp")),
        "threat_category": str(event_data.get("attack_type")),
        "assessment": status_action,
        "analyst_notes": notes,
        "ai_analyst_copilot_brief": copilot_brief,
    }

    report_str = json.dumps(report_payload, indent=2)

    st.download_button(
        label="Download JSON Incident & Copilot Report",
        data=report_str,
        file_name=f"sentinel_ai_report_{selected_event}.json",
        mime="application/json",
    )

    st.markdown("---")
    st.markdown("##### Audit Log History (`analyst_actions.csv`)")
    df_audit = get_audit_log()
    if not df_audit.empty:
        st.dataframe(df_audit.tail(10), use_container_width=True)
