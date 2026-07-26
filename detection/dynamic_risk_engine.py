"""
Dynamic Enterprise Risk Engine for SentinelAI.

Calculates multi-factor, weighted, normalized composite risk scores (0–100)
incorporating behavior deviation, model confidence, department/resource sensitivity,
repeated anomaly velocity, time of day, and environmental attributes.
"""

import math
from typing import Dict, Any, List, Optional
import pandas as pd


class DynamicRiskEngine:
    """Computes dynamic, multi-factor enterprise risk scores for security events."""

    # Department Sensitivity Matrix (0.0 - 1.0)
    DEPT_SENSITIVITY = {
        "FINANCE": 0.90,
        "EXECUTIVE": 0.95,
        "HR": 0.85,
        "R_AND_D": 0.85,
        "ENGINEERING": 0.70,
        "IT_ADMIN": 0.90,
        "LEGAL": 0.80,
        "GENERAL": 0.40,
    }

    # Resource Sensitivity Matrix (0.0 - 1.0)
    RESOURCE_SENSITIVITY = {
        "DOMAIN_CONTROLLER": 1.00,
        "PAYROLL_DATABASE": 0.95,
        "SOURCE_CODE_REPOS": 0.85,
        "VPN_GATEWAY": 0.80,
        "CUSTOMER_CRM": 0.75,
        "INTERNAL_WIKI": 0.30,
        "PUBLIC_PORTAL": 0.20,
    }

    # Factor Weights (Sum = 1.0)
    WEIGHTS = {
        "behavior_deviation": 0.20,
        "attack_confidence": 0.15,
        "department_sensitivity": 0.10,
        "resource_sensitivity": 0.15,
        "time_of_day": 0.10,
        "unknown_device": 0.08,
        "unknown_location": 0.07,
        "historical_risk": 0.05,
        "repeated_anomalies": 0.10,
    }

    def __init__(self):
        pass

    def evaluate_risk(self, event: Dict[str, Any], historical_anomalies_count: int = 1) -> Dict[str, Any]:
        """Calculate normalized multi-factor composite risk score (0-100) for an access event."""
        
        # 1. Behavior Deviation Factor (0.0 - 1.0)
        dev_pct = float(event.get("deviation_percentage", 0.0)) / 100.0
        f_behavior = min(1.0, max(0.0, dev_pct))

        # 2. Attack Model Confidence Factor (0.0 - 1.0)
        confidence = float(event.get("confidence", 0.85))
        f_confidence = min(1.0, max(0.0, confidence))

        # 3. Department Sensitivity Factor (0.0 - 1.0)
        dept = str(event.get("department", "GENERAL")).upper()
        f_dept = self.DEPT_SENSITIVITY.get(dept, 0.50)

        # 4. Resource Sensitivity Factor (0.0 - 1.0)
        res = str(event.get("resource_category") or event.get("resource_accessed") or "PUBLIC_PORTAL").upper().replace(" ", "_")
        f_resource = self.RESOURCE_SENSITIVITY.get(res, 0.50)

        # 5. Time of Day / Off-Hours Factor (0.0 - 1.0)
        ts = pd.to_datetime(event.get("timestamp", pd.Timestamp.now()))
        hour = ts.hour
        f_time = 1.0 if (hour < 7 or hour > 19) else 0.2

        # 6. Unknown Device Factor (0.0 - 1.0)
        f_device = 1.0 if event.get("is_unknown_device", False) or event.get("device_id") == "Unknown" else 0.0

        # 7. Unknown Location / Geo-Velocity Factor (0.0 - 1.0)
        f_location = 1.0 if event.get("is_unknown_location", False) or event.get("attack_type") == "impossible_travel" else 0.0

        # 8. Historical Risk Baseline Factor (0.0 - 1.0)
        hist_risk = float(event.get("historical_risk_baseline", 20.0)) / 100.0
        f_hist = min(1.0, max(0.0, hist_risk))

        # 9. Repeated Anomalies Factor (Velocity Multiplier)
        repeat_count = max(1, historical_anomalies_count)
        f_repeat = min(1.0, (repeat_count - 1) / 5.0)  # 0.0 at 1, 1.0 at 6+ events

        # Calculate Weighted Composite Score
        factor_scores = {
            "behavior_deviation": f_behavior,
            "attack_confidence": f_confidence,
            "department_sensitivity": f_dept,
            "resource_sensitivity": f_resource,
            "time_of_day": f_time,
            "unknown_device": f_device,
            "unknown_location": f_location,
            "historical_risk": f_hist,
            "repeated_anomalies": f_repeat,
        }

        weighted_sum = 0.0
        risk_breakdown = {}

        for factor, weight in self.WEIGHTS.items():
            score = factor_scores[factor]
            contribution = score * weight * 100.0
            weighted_sum += score * weight
            risk_breakdown[factor] = {
                "score_norm": round(score, 2),
                "weight_pct": round(weight * 100.0, 1),
                "risk_contribution_pts": round(contribution, 1),
            }

        # Apply Velocity Multiplier for Repeat Anomalies
        velocity_multiplier = 1.0 + (min(repeat_count - 1, 5) * 0.08)  # Up to +40% boost for repeated bursts
        composite_risk_score = round(min(100.0, weighted_sum * 100.0 * velocity_multiplier), 1)

        # Determine Risk Tier
        if composite_risk_score >= 80.0:
            risk_tier = "CRITICAL"
            color = "#dc2626"
            action = "Immediate Automated Account Lockout & Incident Escalate"
        elif composite_risk_score >= 60.0:
            risk_tier = "HIGH"
            color = "#ea580c"
            action = "Require Step-Up Out-of-Band MFA Verification"
        elif composite_risk_score >= 35.0:
            risk_tier = "MEDIUM"
            color = "#d97706"
            action = "Flag for Analyst Triage Queue"
        else:
            risk_tier = "LOW"
            color = "#16a34a"
            action = "Log Telemetry & Continue Monitoring"

        # Generate Natural Language Risk Explanation
        top_factors = sorted(risk_breakdown.items(), key=lambda x: x[1]["risk_contribution_pts"], reverse=True)[:3]
        top_factor_names = [f[0].replace("_", " ").title() for f in top_factors if f[1]["risk_contribution_pts"] > 0]

        explanation = (
            f"Composite Risk Score of {composite_risk_score}/100 [{risk_tier}] calculated via 9-factor dynamic weighting. "
            f"Primary risk drivers: {', '.join(top_factor_names)}. "
            f"Repeat velocity multiplier: {velocity_multiplier:.2f}x ({repeat_count} events in 24h). "
            f"Recommended SOC Action: {action}."
        )

        return {
            "event_id": str(event.get("event_id", "evt-001")),
            "entity_id": str(event.get("user_id") or event.get("entity_id") or "UNKNOWN"),
            "composite_risk_score": composite_risk_score,
            "risk_tier": risk_tier,
            "risk_color": color,
            "velocity_multiplier": round(velocity_multiplier, 2),
            "repeat_anomalies_24h": repeat_count,
            "risk_explanation": explanation,
            "recommended_soc_action": action,
            "factor_breakdown": risk_breakdown,
        }
