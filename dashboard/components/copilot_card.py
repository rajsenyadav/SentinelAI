"""
AI Analyst Copilot Card Dashboard Component.

Renders an enterprise investigation brief using native Streamlit UI components
to ensure zero raw HTML markup, tags, or unformatted text bleed into the dashboard.
"""

import streamlit as st
from typing import Dict, Any


def render_copilot_card(copilot_brief: Dict[str, Any]):
    """Render the AI Analyst Copilot investigation brief as a clean enterprise SOC report."""
    entity_id = copilot_brief.get("entity_id", "Unknown")
    exec_summary = copilot_brief.get("executive_summary", "")
    why_detected = copilot_brief.get("why_detected", "")
    evidence = copilot_brief.get("supporting_evidence", [])
    risk_exp = copilot_brief.get("risk_score_explanation", "")
    biz_impact = copilot_brief.get("business_impact", "")
    rec_actions = copilot_brief.get("recommended_actions", [])
    mitre = copilot_brief.get("mitre_attack_mapping", {})
    soc_resp = copilot_brief.get("suggested_soc_response", {})
    time_saved = copilot_brief.get("estimated_investigation_time_saved", "")
    confidence = copilot_brief.get("copilot_confidence_pct", 95.0)

    # Top Header Box
    st.markdown("### SentinelAI Analyst Copilot Brief")
    st.caption(f"Target Entity: **{entity_id}** • Confidence: **{confidence}%** • *{time_saved}*")

    st.markdown("---")

    # Executive Summary & Why Detected Sections
    st.markdown("#### Executive Summary")
    st.info(exec_summary)

    st.markdown("#### Why Detected")
    st.warning(why_detected)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### MITRE ATT&CK Mapping")
        st.markdown(f"- **Tactic:** {mitre.get('tactic', 'Initial Access')}")
        st.markdown(f"- **Technique:** `{mitre.get('technique_id', 'T1078')}` — [{mitre.get('technique_name', 'Valid Accounts')}]({mitre.get('url', 'https://attack.mitre.org')})")

        st.markdown("#### Business Impact")
        st.error(biz_impact)

        st.markdown("#### Risk Explanation")
        st.markdown(f"> {risk_exp}")

        st.markdown("#### Supporting Evidence Chain")
        for ev in evidence:
            st.markdown(f"- `{ev}`")

    with col2:
        st.markdown("#### Recommended SOC Containment Steps")
        for act in rec_actions:
            st.markdown(f"- {act}")

        st.markdown("#### Executable Remediation Command (PowerShell)")
        ps_cmd = soc_resp.get("powershell", f"Disable-LocalUser -Name '{entity_id}'")
        st.code(ps_cmd, language="powershell")

        aws_cmd = soc_resp.get("aws_cli", "")
        if aws_cmd:
            st.markdown("#### Cloud Remediation Command (AWS CLI)")
            st.code(aws_cmd, language="bash")
