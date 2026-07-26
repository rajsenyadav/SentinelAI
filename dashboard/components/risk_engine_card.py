"""
Dynamic Enterprise Risk Card Dashboard Component.

Renders a multi-factor risk scorecard visualization displaying factor weights,
normalized score contributions, velocity multipliers, and recommended actions
using native Streamlit components.
"""

import streamlit as st
from typing import Dict, Any


def render_dynamic_risk_card(risk_result: Dict[str, Any]):
    """Render the Dynamic Enterprise Risk card in Streamlit using native UI."""
    score = risk_result.get("composite_risk_score", 0.0)
    tier = risk_result.get("risk_tier", "LOW")
    multiplier = risk_result.get("velocity_multiplier", 1.0)
    explanation = risk_result.get("risk_explanation", "")
    action = risk_result.get("recommended_soc_action", "")
    breakdown = risk_result.get("factor_breakdown", {})

    st.markdown("### Dynamic Multi-Factor Enterprise Risk Engine")
    st.caption(f"Normalized 9-Factor Weighted Risk Scoring • Composite Risk Score: **{score} / 100 [{tier}]** • Velocity Multiplier: **{multiplier}x**")

    if tier == "CRITICAL":
        st.error(f"**Risk Assessment:** {explanation}")
    elif tier == "HIGH":
        st.warning(f"**Risk Assessment:** {explanation}")
    else:
        st.info(f"**Risk Assessment:** {explanation}")

    st.markdown("#### 9-Factor Weighted Risk Breakdown")
    cols = st.columns(3)

    factors_list = list(breakdown.items())
    for idx, (fname, fdata) in enumerate(factors_list):
        c = cols[idx % 3]
        pts = fdata["risk_contribution_pts"]
        weight = fdata["weight_pct"]
        score_norm = fdata["score_norm"]
        clean_name = fname.replace("_", " ").title()

        with c:
            st.metric(label=clean_name, value=f"+{pts} pts", delta=f"Weight: {weight}% | Score: {score_norm}")

    st.markdown(f"**Recommended Automated Action:** `{action}`")
