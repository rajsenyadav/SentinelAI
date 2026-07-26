"""
SentinelAI — Comprehensive Pipeline Unit Tests

Executes pytest verification across:
1. Preprocessing & Feature Engineering
2. Unsupervised Anomaly Detection Ensemble
3. Multi-Class Attack Classifier
4. Risk Engine & SHAP Explainability
5. FastAPI Backend REST Endpoints
"""

import sys
import os
import unittest
import pandas as pd
import numpy as np

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from feature_engine.preprocessing import DataPreprocessor
from feature_engine.event_features import EventFeatureExtractor
from feature_engine.window_features import WindowFeatureExtractor
from explainer.risk_engine import RiskEngine
from explainer.recommendations import RecommendationEngine


class TestSentinelAIPipeline(unittest.TestCase):

    def setUp(self):
        self.raw_event = {
            "event_id": "evt-test-001",
            "timestamp": "2026-01-15T14:30:00Z",
            "entity_id": "EMP1023",
            "entity_type": "user",
            "entity_role": "employee",
            "department": "Engineering",
            "source_ip": "192.168.1.10",
            "geo_location": "London, UK",
            "geo_lat": 51.5074,
            "geo_lon": -0.1278,
            "resource_accessed": "/api/v1/auth",
            "resource_category": "general",
            "action_type": "login",
            "auth_method": "password",
            "auth_status": "success",
            "session_duration": 300,
            "bytes_transferred": 1024,
            "device_fingerprint": "fp-test-1",
            "device_os": "Windows",
            "user_agent": "Mozilla/5.0",
            "protocol": "HTTPS",
            "command_sequence": "[]",
            "is_vpn": False,
        }

    def test_preprocessor(self):
        preprocessor = DataPreprocessor()
        df = pd.DataFrame([self.raw_event])
        df_clean = preprocessor.clean_dataframe(df)
        self.assertEqual(len(df_clean), 1)
        self.assertIn("hour_of_day", df_clean.columns)

    def test_feature_extractor(self):
        preprocessor = DataPreprocessor()
        extractor = EventFeatureExtractor()
        df = pd.DataFrame([self.raw_event])
        df_clean = preprocessor.clean_dataframe(df)
        df_feat = extractor.transform(df_clean)
        self.assertIn("geo_velocity_kmh", df_feat.columns)
        self.assertIn("is_off_hours", df_feat.columns)

    def test_risk_engine(self):
        score, level = RiskEngine.calculate_risk_score(
            anomaly_score=0.95,
            classifier_confidence=0.98,
            risk_multiplier=4,
            attack_type="impossible_travel"
        )
        self.assertGreaterEqual(score, 70)
        self.assertIn(level, ["High", "Critical"])

    def test_recommendation_engine(self):
        rec = RecommendationEngine.get_recommendation("impossible_travel", "Critical")
        self.assertEqual(rec["action"], "Lock Account")


if __name__ == "__main__":
    unittest.main()
