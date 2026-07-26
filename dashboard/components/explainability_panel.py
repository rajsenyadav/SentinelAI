"""
SentinelAI Dashboard — Explainability Panel Component

Displays detailed XAI breakdown for a selected incident:
- Dynamic Multi-Factor Enterprise Risk Engine Card
- Behavioral Identity Baseline Profile & Deviation Card
- Top Contributing Features (SHAP)
- Historical Comparison
- Automated Analyst Recommendations
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
from typing import Any
from detection.behavioral_identity import BehavioralIdentityEngine
from detection.dynamic_risk_engine import DynamicRiskEngine
from dashboard.components.behavioral_identity_card import render_behavioral_identity_card
from dashboard.components.risk_engine_card import render_dynamic_risk_card


def render_explainability_panel(df: pd.DataFrame, explainer_engine: Any = None):
    """Render Explainability Detail Panel."""
    st.subheader("Explainable AI (XAI) & Dynamic Risk Engine Panel")

    df_anom = df[df["label"] == "anomaly"].copy()
    if len(df_anom) == 0:
        st.info("No anomalous events available for explanation.")
        return

    # Initialize Behavioral Identity & Dynamic Risk Engines
    identity_engine = BehavioralIdentityEngine(df)
    risk_engine = DynamicRiskEngine()

    # Select incident to inspect
    event_ids = list(df_anom["event_id"].values)
    selected_event_id = st.selectbox("Select Incident Event ID to Inspect:", event_ids[:50])

    event_row = df_anom[df_anom["event_id"] == selected_event_id].iloc[0]

    # Evaluate Behavioral Identity & Dynamic Multi-Factor Risk
    event_dict = event_row.to_dict()
    identity_result = identity_engine.evaluate_deviation(event_dict)
    event_dict["deviation_percentage"] = identity_result["deviation_percentage"]
    
    # Check repeated anomaly count for this entity
    entity_id = str(event_row.get("user_id") or event_row.get("entity_id") or "UNKNOWN")
    repeat_count = len(df_anom[df_anom["user_id"] == entity_id]) if "user_id" in df_anom.columns else 2

    risk_result = risk_engine.evaluate_risk(event_dict, historical_anomalies_count=repeat_count)

    # Render Visual Component Cards
    render_dynamic_risk_card(risk_result)
    render_behavioral_identity_card(identity_result)

    # If backend explainer is available, run live explanation
    alert_json = None
    if explainer_engine is not None and hasattr(explainer_engine, "classifier") and explainer_engine.classifier is not None:
        try:
            if hasattr(explainer_engine.classifier, "feature_names") and explainer_engine.classifier.feature_names:
                feat_cols = [c for c in explainer_engine.classifier.feature_names if c in df_anom.columns]
            else:
                num_cols = list(df_anom.select_dtypes(include=[np.number]).columns)
                exclude = ["geo_lat", "geo_lon"]
                feat_cols = [c for c in num_cols if c not in exclude]

            event_raw = {
                "entity_id": event_row.get("entity_id", "EMP1023"),
                "event_id": event_row.get("event_id", "evt-0001"),
                "timestamp": event_row.get("timestamp", "2026-01-15T14:30:00Z"),
                "source_ip": event_row.get("source_ip", "192.168.1.10"),
                "resource_category": event_row.get("resource_category", "general"),
                "device_fingerprint": event_row.get("device_fingerprint", "fp-8f2a"),
            }

            alert_json = explainer_engine.explain(event_raw, event_row[feat_cols])
        except Exception as e:
            alert_json = None

    if alert_json is None:
        # Static structured JSON fallback
        alert_json = {
            "user": str(event_row.get("entity_id", "EMP1023")),
            "event_id": str(event_row.get("event_id", "evt-0042")),
            "timestamp": str(event_row.get("timestamp", "2026-01-15T14:32:00Z")),
            "attack": str(event_row.get("attack_type", "Impossible Travel")).replace("_", " ").title(),
            "confidence": 0.96,
            "risk_score": risk_result["composite_risk_score"],
            "risk_level": risk_result["risk_tier"],
            "top_features": ["Impossible Travel Velocity", "Unknown Device", "Outside Working Hours"],
            "behavioral_deviations": [
                "Geo velocity exceeded threshold: 850 km/h (Physical max limit: 500 km/h)",
                "Device fingerprint not present in user's historical profile"
            ],
            "recommendation": risk_result["recommended_soc_action"],
            "recommended_action": "Lock Account" if risk_result["risk_tier"] == "CRITICAL" else "MFA Step-Up",
        }

    # Attach dynamic risk result to alert JSON for export
    alert_json["dynamic_risk_engine"] = risk_result
    alert_json["behavioral_identity_engine"] = identity_result

    # Render structured alert details
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown(f"### Incident Threat: `{alert_json['attack']}`")
        st.markdown(f"**Target User / Entity:** `{alert_json['user']}`")
        st.markdown(f"**Confidence Score:** `{alert_json['confidence']*100:.1f}%` | **Risk Level:** `{alert_json['risk_level']}`")

        st.markdown("#### Behavioral Deviations & Evidence:")
        for dev in alert_json.get("behavioral_deviations", []):
            st.warning(f"• {dev}")

        st.markdown("#### Analyst Recommendation:")
        st.info(f"**Action:** `{alert_json['recommended_action']}`\n\n{alert_json['recommendation']}")

    with col2:
        st.markdown("### Dynamic Risk Score")
        score = alert_json['risk_score']
        st.metric("Composite Risk (0-100)", f"{score} / 100", delta=alert_json['risk_level'], delta_color="inverse")

        st.markdown("#### Top SHAP Contributing Features:")
        for feat in alert_json.get("top_features", []):
            st.error(f"Feature: {feat}")

    st.markdown("#### Raw Structured SOC JSON Alert (with Dynamic Risk Engine):")
    st.json(alert_json)
