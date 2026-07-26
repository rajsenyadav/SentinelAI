"""
SentinelAI — Main Explainability & Risk Intelligence Engine

Orchestrates detection scores, attack classification, SHAP feature attributions,
behavioral deviation explanations, and SOC analyst recommendations into a single
structured JSON alert payload.
"""

import json
import logging
from typing import Dict, Any, List, Union, Optional, Tuple

import numpy as np
import pandas as pd

from .shap_engine import SHAPExplainer
from .risk_engine import RiskEngine
from .recommendations import RecommendationEngine

logger = logging.getLogger(__name__)


# Human-friendly feature labels
FEATURE_LABEL_MAP = {
    "geo_velocity_kmh": "Impossible Travel Velocity",
    "device_novelty": "Unknown Device",
    "is_off_hours": "Outside Working Hours",
    "failed_auth_count_1h": "Failed Login Burst (1h)",
    "failed_auth_count_24h": "Sustained Auth Failures",
    "unique_entities_per_ip_1h": "Multi-Account IP Spray",
    "resource_novelty": "Unusual Resource Access",
    "category_novelty": "Cross-Department Category Access",
    "bytes_zscore": "Abnormal Data Transfer Volume",
    "bytes_per_second": "High-Speed Data Extraction",
    "suspicious_cmd_flag": "Suspicious Terminal Command",
    "command_diversity": "Automated Recon Command Pattern",
    "resource_sensitivity": "High-Sensitivity Asset Targeted",
    "auth_method_change": "Authentication Method Change",
    "geo_novelty": "New Geographic Location",
    "protocol_novelty": "Unusual Access Protocol",
    "is_weekend": "Weekend Activity",
    "minutes_since_last": "Rapid Login Rate",
}


class ExplainabilityEngine:
    """
    Unified Explainability Engine.
    Combines Anomaly Detector + Attack Classifier + SHAP + Natural Language Evidence.
    """

    def __init__(self, anomaly_detector: Any, attack_classifier: Any):
        self.detector = anomaly_detector
        self.classifier = attack_classifier

        feature_names = self.classifier.feature_names if hasattr(self.classifier, "feature_names") else []
        self.shap_explainer = SHAPExplainer(self.classifier.model, feature_names)

    def explain(
        self,
        event_raw: Dict[str, Any],
        event_features: pd.Series,
    ) -> Dict[str, Any]:
        """
        Generate complete, structured Explainability Alert JSON for a single event.

        Args:
            event_raw: Dictionary of raw event fields (event_id, entity_id, timestamp, etc.)
            event_features: Series or 1-row DataFrame of engineered numerical features

        Returns:
            JSON-serializable dictionary formatted for SOC analysts.
        """
        df_feat = pd.DataFrame([event_features]) if isinstance(event_features, pd.Series) else event_features

        # 1. Anomaly Scoring
        _, anomaly_scores, risk_tiers = self.detector.predict(df_feat)
        anomaly_score = float(anomaly_scores[0])

        # 2. Attack Classification
        attack_types, confidences = self.classifier.predict(df_feat)
        attack_type = str(attack_types[0])
        confidence = float(confidences[0])

        # 3. SHAP Attributions
        top_shap = self.shap_explainer.explain_instance(df_feat, top_k=3)
        top_feature_names = [
            FEATURE_LABEL_MAP.get(feat, feat.replace("_", " ").title())
            for feat, _ in top_shap
        ]

        # 4. Risk Score & Level Calculation
        risk_multiplier = float(df_feat.get("risk_multiplier", pd.Series([0])).iloc[0])
        risk_score, risk_level = RiskEngine.calculate_risk_score(
            anomaly_score=anomaly_score,
            classifier_confidence=confidence,
            risk_multiplier=risk_multiplier,
            attack_type=attack_type,
        )

        # 5. Behavioral Deviations & Evidence Generation
        deviations, evidence = self._generate_evidence(event_raw, df_feat.iloc[0])

        # 6. Recommendation
        rec_info = RecommendationEngine.get_recommendation(attack_type, risk_level)

        # Format attack name
        pretty_attack = attack_type.replace("_", " ").title()
        if pretty_attack == "Low Slow Exfiltration":
            pretty_attack = "Low & Slow Exfiltration"

        # Construct final SOC Alert JSON payload
        alert = {
            "user": str(event_raw.get("entity_id", "UNKNOWN")),
            "event_id": str(event_raw.get("event_id", "N/A")),
            "timestamp": str(event_raw.get("timestamp", "N/A")),
            "attack": pretty_attack,
            "confidence": round(confidence, 2),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "top_features": top_feature_names,
            "behavioral_deviations": deviations,
            "evidence": evidence,
            "recommendation": rec_info["recommendation"],
            "recommended_action": rec_info["action"],
        }

        return alert

    def _generate_evidence(
        self, event_raw: Dict[str, Any], feat: pd.Series
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Generate human-readable behavioral deviation strings and evidence breakdown."""
        deviations = []
        evidence = {}

        # Check Geo Velocity / Travel
        vel = float(feat.get("geo_velocity_kmh", 0))
        if vel > 300:
            deviations.append(f"Geo velocity exceeded threshold: {vel:.0f} km/h (Physical max limit: 500 km/h)")
            evidence["geo_velocity_kmh"] = round(vel, 1)

        # Check Device Novelty
        if feat.get("device_novelty", 0) == 1:
            dev_fp = str(event_raw.get("device_fingerprint", "Unknown"))
            deviations.append(f"Device fingerprint '{dev_fp}' not present in user's historical profile")
            evidence["unrecognized_device"] = dev_fp

        # Check Off-hours
        if feat.get("is_off_hours", 0) == 1:
            hour = event_raw.get("timestamp", "")
            deviations.append(f"Access initiated outside standard operating hours (08:00–19:00)")
            evidence["is_off_hours"] = True

        # Check Auth Failures
        failed_1h = int(feat.get("failed_auth_count_1h", 0))
        if failed_1h > 5:
            deviations.append(f"High authentication failure rate: {failed_1h} failed attempts in past hour")
            evidence["failed_auth_count_1h"] = failed_1h

        # Check IP Spray
        unique_ent_ip = int(feat.get("unique_entities_per_ip_1h", 0))
        if unique_ent_ip > 5:
            ip = str(event_raw.get("source_ip", "Unknown"))
            deviations.append(f"Source IP {ip} attempted logins across {unique_ent_ip} distinct accounts within 1 hour")
            evidence["multi_account_ip_spray"] = unique_ent_ip

        # Check Category / Resource Novelty
        if feat.get("category_novelty", 0) == 1:
            res_cat = str(event_raw.get("resource_category", "Unknown"))
            deviations.append(f"Access requested to uncharacteristic resource category '{res_cat}'")
            evidence["unusual_resource_category"] = res_cat

        # Check Suspicious Command
        if feat.get("suspicious_cmd_flag", 0) == 1:
            cmds = str(event_raw.get("command_sequence", "[]"))
            deviations.append(f"Execution of suspicious administrative/recon command sequence: {cmds}")
            evidence["suspicious_commands"] = cmds

        if not deviations:
            deviations.append("Statistical deviation from standard user historical baseline")

        return deviations, evidence
