"""
SentinelAI — Risk Intelligence Engine

Calculates a continuous Risk Score (0–100) and maps events to Risk Levels:
- Low      (0 – 39)
- Medium   (40 – 69)
- High     (70 – 89)
- Critical (90 – 100)

Risk Score Formula:
    Risk Score = 0.40 * (Anomaly_Prob * 100) + 0.35 * (Classifier_Conf * 100) + 0.25 * (Risk_Multiplier * 16.6)
"""

import logging
from typing import Tuple, Dict, Any

import numpy as np

logger = logging.getLogger(__name__)


class RiskEngine:
    """
    Computes unified enterprise risk scores (0-100) and severity levels.
    """

    @staticmethod
    def calculate_risk_score(
        anomaly_score: float,       # 0.0 to 1.0 from AnomalyDetector
        classifier_confidence: float,# 0.0 to 1.0 from AttackClassifier
        risk_multiplier: float = 0.0, # 0 to 6 compound risk flag count
        attack_type: str = "normal",
    ) -> Tuple[int, str]:
        """
        Calculate composite 0-100 risk score and return (risk_score, risk_level).

        Args:
            anomaly_score: Continuous anomaly probability from Module 4
            classifier_confidence: Classification probability score from Module 5
            risk_multiplier: Compound risk score count (0-6)
            attack_type: Categorized attack type string

        Returns:
            Tuple of:
                - risk_score: Integer between 0 and 100
                - risk_level: String ("Low", "Medium", "High", "Critical")
        """
        # Base raw calculation
        norm_multiplier = min(1.0, risk_multiplier / 6.0)

        raw_score = (
            (0.40 * anomaly_score * 100.0) +
            (0.35 * classifier_confidence * 100.0) +
            (0.25 * norm_multiplier * 100.0)
        )

        # Attack type severe floor adjustments
        critical_attacks = ["lateral_movement", "low_slow_exfiltration", "impossible_travel"]
        high_attacks = ["brute_force", "credential_stuffing", "device_spoofing"]

        if attack_type.lower() in critical_attacks and raw_score > 50:
            raw_score = max(raw_score, 85.0)
        elif attack_type.lower() in high_attacks and raw_score > 40:
            raw_score = max(raw_score, 70.0)

        # Clamp to [0, 100]
        final_score = int(round(np.clip(raw_score, 0, 100)))

        # Map to Risk Level
        if final_score >= 90:
            risk_level = "Critical"
        elif final_score >= 70:
            risk_level = "High"
        elif final_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return final_score, risk_level
