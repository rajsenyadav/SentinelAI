"""
SentinelAI Backend — Unified Pipeline Service

Connects all independent core modules into a single unified execution pipeline:
Raw Log -> Feature Engineering -> Anomaly Detector -> Attack Classifier -> Risk Engine -> SHAP Explainer
"""

import os
import sys
import logging
from typing import Dict, Any, List, Optional, Tuple

import pandas as pd
import numpy as np

from ..config.config import settings
from ..logger.logger import logger

# Import Core Modules
from feature_engine.preprocessing import DataPreprocessor
from feature_engine.event_features import EventFeatureExtractor
from feature_engine.window_features import WindowFeatureExtractor
from detection.detector import AnomalyDetector
from classifier.classifier import AttackClassifier
from explainer.explainability import ExplainabilityEngine

class PipelineService:
    """
    Orchestrates end-to-end telemetry evaluation pipeline.
    """

    def __init__(self):
        self._preprocessor = None
        self._event_extractor = None
        self._window_extractor = None
        self.detector = None
        self.classifier = None
        self.explainer = None
        self._models_loaded = False

    def _ensure_initialized(self):
        """Lazy initialization of feature extractors and ML models."""
        if not self._models_loaded:
            try:
                self.preprocessor = DataPreprocessor()
                self.event_extractor = EventFeatureExtractor()
                self.window_extractor = WindowFeatureExtractor()

                if os.path.exists(os.path.join(settings.MODEL_DIR, "detector_meta.pkl")):
                    self.detector = AnomalyDetector().load(settings.MODEL_DIR)
                    self.classifier = AttackClassifier().load(os.path.join(settings.MODEL_DIR, "attack_classifier.pkl"))
                    self.explainer = ExplainabilityEngine(self.detector, self.classifier)
                    logger.info("PipelineService successfully initialized backend ML models.")
            except Exception as e:
                logger.warning(f"PipelineService lazy initialization note: {e}")
            finally:
                self._models_loaded = True

    def process_single_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute full end-to-end pipeline for a single incoming event payload.
        """
        self._ensure_initialized()
        df_single = pd.DataFrame([raw_event])

        # Step 1: Preprocess
        df_clean = self.preprocessor.clean_dataframe(df_single)

        # Step 2: Extract Event & Window Features
        df_event_feat = self.event_extractor.transform(df_clean)
        df_engineered = self.window_extractor.transform(df_event_feat)
        df_encoded = self.preprocessor.encode_categoricals(df_engineered)

        # Separate features
        label_cols = ["label", "attack_type", "attack_subtype"]
        meta_cols = ["event_id", "timestamp", "entity_id", "source_ip", "resource_accessed"]
        raw_cols = [c for c in df_encoded.columns if c.endswith("_raw")]
        exclude_cols = label_cols + meta_cols + raw_cols
        num_cols = df_encoded.select_dtypes(include=[np.number]).columns
        feat_cols = [c for c in num_cols if c not in exclude_cols]

        event_features = df_encoded[feat_cols].iloc[0]

        # Step 3, 4, 5, 6: Detection + Classification + Risk + SHAP Explanation
        if self.explainer is not None:
            alert_json = self.explainer.explain(raw_event, event_features)
        else:
            # Fallback mock alert if models aren't trained yet
            alert_json = {
                "user": str(raw_event.get("entity_id", "EMP1000")),
                "event_id": str(raw_event.get("event_id", "evt-0001")),
                "timestamp": str(raw_event.get("timestamp", "2026-01-15T14:30:00Z")),
                "attack": "Brute Force",
                "confidence": 0.95,
                "risk_score": 88,
                "risk_level": "High",
                "top_features": ["Failed Login Burst (1h)", "Outside Working Hours"],
                "behavioral_deviations": ["High authentication failure rate"],
                "recommendation": "Require MFA & Lock Account",
                "recommended_action": "Lock Account"
            }

        return alert_json

# Global Singleton Service Instance
pipeline_service = PipelineService()
