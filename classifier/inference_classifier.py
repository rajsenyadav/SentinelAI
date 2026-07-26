"""
SentinelAI — Attack Classification Inference Engine

Provides structured inference returning JSON objects for SOC integration with:
  - attack_type: Predicted threat class
  - confidence: Multi-class probability score [0.0 - 1.0]
  - severity: Calculated alert priority level (Critical, High, Medium, Low)
  - top_features: Top contributing engineered features for the prediction
"""

import json
import logging
from typing import Dict, Any, List, Union, Optional

import numpy as np
import pandas as pd

from .classifier import AttackClassifier

logger = logging.getLogger(__name__)


# Mapping attack types to baseline risk severities
SEVERITY_MAPPING = {
    "brute_force": "High",
    "credential_stuffing": "High",
    "impossible_travel": "High",
    "lateral_movement": "Critical",
    "low_slow_exfiltration": "Critical",
    "device_spoofing": "Medium",
    "insider_drift": "Medium",
    "normal": "Low",
}


class AttackInferenceEngine:
    """
    Inference Engine for Threat Classification with SOC JSON formatting.
    """

    def __init__(self, classifier: AttackClassifier):
        self.classifier = classifier
        self.top_global_features = self.classifier.get_feature_importances(top_n=5)["Feature"].tolist()

    def predict_event(self, event_features: Union[Dict[str, float], pd.Series, pd.DataFrame]) -> Dict[str, Any]:
        """
        Run inference on a single anomalous event.

        Args:
            event_features: Feature vector for a single event.

        Returns:
            JSON-serializable dictionary matching required format:
            {
                "attack_type": "Brute Force",
                "confidence": 0.96,
                "severity": "High",
                "top_features": ["failed_auth_count_1h", ...]
            }
        """
        if isinstance(event_features, dict):
            df_single = pd.DataFrame([event_features])
        elif isinstance(event_features, pd.Series):
            df_single = pd.DataFrame([event_features.to_dict()])
        else:
            df_single = event_features

        # Ensure correct column ordering
        if self.classifier.feature_names:
            for col in self.classifier.feature_names:
                if col not in df_single.columns:
                    df_single[col] = 0.0
            df_single = df_single[self.classifier.feature_names]

        attack_types, confidences = self.classifier.predict(df_single)
        attack_type = str(attack_types[0])
        confidence = float(confidences[0])

        # Pretty name formatting (e.g. "brute_force" -> "Brute Force")
        pretty_name = attack_type.replace("_", " ").title()
        if pretty_name == "Low Slow Exfiltration":
            pretty_name = "Low & Slow Exfiltration"

        # Determine severity
        severity = SEVERITY_MAPPING.get(attack_type, "High")
        if confidence > 0.90 and severity == "High":
            severity = "Critical"

        # Extract top active features for this specific instance
        top_instance_features = self._get_instance_top_features(df_single.iloc[0])

        result = {
            "attack_type": pretty_name,
            "confidence": round(confidence, 4),
            "severity": severity,
            "top_features": top_instance_features,
        }

        return result

    def predict_batch(self, X: pd.DataFrame) -> List[Dict[str, Any]]:
        """Run batch inference over DataFrame X."""
        results = []
        for idx in range(len(X)):
            results.append(self.predict_event(X.iloc[idx]))
        return results

    def _get_instance_top_features(self, row: pd.Series, top_k: int = 3) -> List[str]:
        """Find the most prominent active features for a single event."""
        # Non-zero or extreme values matching top global features
        candidates = []
        for feat in self.top_global_features:
            val = row.get(feat, 0)
            if abs(val) > 0.01:
                candidates.append(feat)

        if len(candidates) < top_k:
            # fill with remaining top global features
            for feat in self.top_global_features:
                if feat not in candidates:
                    candidates.append(feat)
                if len(candidates) >= top_k:
                    break

        return candidates[:top_k]
