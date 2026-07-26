"""
SentinelAI Dashboard — Incident Details Page Component

Streamlined 2-Column SOC Investigation Workspace.
Integrates persistent CSV analyst feedback updates and audit logging.
Premium white-only theme with CSS-driven styling.
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any, Optional
from backend.services.incident_service import incident_service
from backend.services.incident_persistence import update_incident_status, get_audit_log


def render_incident_details(df: pd.DataFrame, selected_incident_id: Optional[str] = None):
    """Render streamlined Incident Details investigation workspace with persistent updates."""
    st.subheader("Incident Details Workspace")

    # Filter anomaly records for dropdown selection (exclude FALSE_POSITIVE & RESOLVED)
    df_anom = df[df["label"] == "anomaly"].copy()
    if df_anom.empty:
        st.success("No active security anomalies flagged. All threats resolved or marked benign.")
        
        # Show recent audit actions log table if available
        st.markdown("##### Recent Persistent Analyst Audit Trail Log")
        df_audit = get_audit_log()
        if not df_audit.empty:
            st.dataframe(df_audit.tail(10), use_container_width=True)
        return

    event_ids = list(df_anom["event_id"].values)
    
    default_index = 0
    if selected_incident_id and selected_incident_id in event_ids:
        default_index = event_ids.index(selected_incident_id)

    incident_id_choice = st.selectbox(
        "Select Active Security Incident to Inspect:",
        event_ids,
        index=default_index,
        key="incident_details_select",
    )

    event_row = df_anom[df_anom["event_id"] == incident_id_choice].iloc[0].to_dict()
    incident = incident_service.build_incident_from_event(event_row, df)

    # Current persisted status
    current_status = str(event_row.get("status", "LIVE_THREAT"))

    # Incident Summary Header
    sev = incident["severity"]
    sev_color = "#c4392a" if sev == "CRITICAL" else "#d97706" if sev == "HIGH" else "#b8860b"

    st.markdown(
        f"""
        <div style="background: #ffffff; border: 1px solid #e8e4dd; border-radius: 10px; padding: 18px 22px; margin-bottom: 18px; box-shadow: 0 4px 12px rgba(44,40,37,0.06); border-left: 4px solid {sev_color};">
            <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #f0ede8; padding-bottom: 10px; margin-bottom: 12px;">
                <div>
                    <h2 style="margin: 0; color: #2c2825; font-size: 1.2rem; font-weight: 800; letter-spacing: -0.3px;">{incident['incident_id']} — {incident['attack_type']}</h2>
                    <p style="margin: 3px 0 0 0; color: #6b6560; font-size: 0.85rem; font-weight: 500;">Target User: <b style="color: #2c2825;">{incident['user']}</b> ({incident['department']} • {incident['role']})</p>
                </div>
                <div style="text-align: right;">
                    <span style="background: {sev_color}; color: #ffffff; padding: 6px 14px; border-radius: 50px; font-weight: 800; font-size: 0.9rem; letter-spacing: 0.3px;">
                        {sev} ({incident['risk_score']}/100)
                    </span>
                    <br/><span style="font-size: 0.75rem; color: #9c9690; font-weight: 600; margin-top: 4px; display: inline-block;">Persisted Status: <code style="background: #f5f3ef; color: #c4392a; padding: 2px 8px; border-radius: 4px; border: 1px solid #e8e4dd;">{current_status}</code></span>
                </div>
            </div>
            <div style="display: flex; gap: 24px; font-size: 0.84rem; color: #6b6560; font-weight: 500;">
                <div><b style="color: #2c2825;">Timestamp:</b> <code style="background: #f5f3ef; padding: 2px 6px; border-radius: 4px; border: 1px solid #e8e4dd; color: #2c2825;">{incident['timestamp'][:19]}</code></div>
                <div><b style="color: #2c2825;">Location:</b> <code style="background: #f5f3ef; padding: 2px 6px; border-radius: 4px; border: 1px solid #e8e4dd; color: #2c2825;">{incident['location']}</code></div>
                <div><b style="color: #2c2825;">Device:</b> <code style="background: #f5f3ef; padding: 2px 6px; border-radius: 4px; border: 1px solid #e8e4dd; color: #2c2825;">{incident['device']}</code></div>
                <div><b style="color: #2c2825;">Confidence:</b> <code style="background: #f5f3ef; padding: 2px 6px; border-radius: 4px; border: 1px solid #e8e4dd; color: #2c2825;">{incident['confidence']}%</code></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_left, col_right = st.columns([3, 2])

    # Left Column: Essential Incident Brief & Core Evidence
    with col_left:
        st.markdown("#### Essential Evidence & Impact")
        st.warning(incident['recommendations'].get('business_impact', 'Potential access compromise requiring analyst triage.'))
        
        st.markdown("**Core Evidence Chain:**")
        for ev in incident["evidence"][:4]:
            st.markdown(f"- `{ev}`")

        with st.expander("View Full Incident Attack Storyline & Baseline"):
            st.markdown("##### Attack Sequence Timeline")
            for step in incident["timeline"]:
                st.markdown(f"- **{step.get('timestamp', '09:00')}** — `{step.get('stage_title', 'Event')}` ({step.get('action', 'Access')})")

    # Right Column: Instant Triage Actions & Persistent Feedback
    with col_right:
        st.markdown("#### Persistent Triage Lifecycle Action")

        remarks_input = st.text_area(
            "Analyst Remarks / RCA Notes:",
            placeholder="Enter triage notes or mitigation actions...",
            key=f"notes_{incident_id_choice}",
            height=70,
        )

        # Lifecycle Action Buttons
        b_col1, b_col2 = st.columns(2)

        with b_col1:
            if st.button("Confirm Threat", key=f"btn_ct_{incident_id_choice}"):
                if update_incident_status(incident_id_choice, "CONFIRMED_THREAT", remarks=remarks_input):
                    st.cache_data.clear()
                    st.success("Confirmed Threat persisted to CSV!")
                    st.rerun()

            if st.button("Under Investigation", key=f"btn_ui_{incident_id_choice}"):
                if update_incident_status(incident_id_choice, "UNDER_INVESTIGATION", remarks=remarks_input):
                    st.cache_data.clear()
                    st.warning("Under Investigation persisted to CSV!")
                    st.rerun()

        with b_col2:
            if st.button("False Positive (Close)", key=f"btn_fp_{incident_id_choice}"):
                if update_incident_status(incident_id_choice, "FALSE_POSITIVE", remarks=remarks_input):
                    st.cache_data.clear()
                    st.info("False Positive persisted to CSV! Alert cleared.")
                    st.rerun()

            if st.button("Mark Resolved", key=f"btn_res_{incident_id_choice}"):
                if update_incident_status(incident_id_choice, "RESOLVED", remarks=remarks_input):
                    st.cache_data.clear()
                    st.success("Incident Resolved persisted to CSV!")
                    st.rerun()

    st.markdown("---")

    # Display Audit Log Table below workspace
    st.markdown("##### Audit Log History")
    df_audit = get_audit_log()
    if not df_audit.empty:
        st.dataframe(df_audit.tail(10), use_container_width=True)
