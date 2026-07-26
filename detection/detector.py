"""
SentinelAI — Ensemble Anomaly Detector Orchestrator

Blends Isolation Forest (0.4) and PyTorch Autoencoder (0.6) reconstruction scores
into a unified behavioral anomaly risk score [0, 1]. Converts continuous scores
to risk severity tiers (HIGH, MEDIUM, LOW) based on top alert budget thresholds.
"""

import os
import logging
from typing import Dict, Tuple, Optional, List

import numpy as np
import pandas as pd

from .isolation_forest import IsolationForestModel
from .autoencoder import AutoencoderModel

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Ensemble Behavioral Anomaly Detection Engine.

    Ensemble Logic:
        final_score = (if_weight * IF_score) + (ae_weight * AE_score)

    Alert Tiers (Honeywell evaluation criteria):
        - Top 1% anomaly score threshold -> HIGH priority alert
        - Top 1% to 5% score threshold    -> MEDIUM priority alert
        - Below Top 5%                    -> LOW / Normal (No alert)
    """

    def __init__(
        self,
        if_weight: float = 0.4,
        ae_weight: float = 0.6,
        high_percentile: float = 99.0,   # Top 1%
        med_percentile: float = 95.0,    # Top 5%
        random_state: int = 42,
    ):
        self.if_weight = if_weight
        self.ae_weight = ae_weight
        self.high_percentile = high_percentile
        self.med_percentile = med_percentile

        self.if_model = IsolationForestModel(random_state=random_state)
        self.ae_model = AutoencoderModel(random_state=random_state)

        self.high_threshold: Optional[float] = None
        self.med_threshold: Optional[float] = None
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> "AnomalyDetector":
        """
        Fit both Isolation Forest and Autoencoder models on the training features.

        Args:
            X: Numerical feature matrix (excluding metadata and labels).
        """
        logger.info("=" * 60)
        logger.info("Fitting Ensemble Anomaly Detector (Isolation Forest + Autoencoder)")
        logger.info("=" * 60)

        # Fit individual models
        self.if_model.fit(X)
        self.ae_model.fit(X)

        # Predict training scores to set initial alert percentile thresholds
        train_scores = self.predict_scores(X)
        self.high_threshold = np.percentile(train_scores, self.high_percentile)
        self.med_threshold = np.percentile(train_scores, self.med_percentile)

        logger.info(f"  Ensemble alert thresholds set from training data:")
        logger.info(f"    High Severity (Top 1%):   score >= {self.high_threshold:.4f}")
        logger.info(f"    Medium Severity (Top 5%): score >= {self.med_threshold:.4f}")

        self.is_fitted = True
        return self

    def predict_scores(self, X: pd.DataFrame) -> np.ndarray:
        """
        Compute weighted continuous anomaly scores in range [0, 1].
        """
        if_scores = self.if_model.predict_score(X)
        ae_scores = self.ae_model.predict_score(X)

        ensemble_scores = (self.if_weight * if_scores) + (self.ae_weight * ae_scores)
        return ensemble_scores

    def predict(
        self, X: pd.DataFrame, threshold: Optional[float] = None
    ) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Predict binary labels and risk severity tiers.

        Args:
            X: Numerical feature matrix.
            threshold: Optional custom decision threshold. If None, uses med_threshold.

        Returns:
            Tuple of:
                - binary_predictions: 1 for anomaly, 0 for normal
                - ensemble_scores: continuous anomaly risk score [0, 1]
                - risk_tiers: list of strings ("HIGH", "MEDIUM", "LOW")
        """
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetector must be fitted before prediction.")

        scores = self.predict_scores(X)

        cutoff = threshold if threshold is not None else self.med_threshold
        binary_preds = (scores >= cutoff).astype(int)

        # Categorize into alert severity tiers
        risk_tiers = []
        for s in scores:
            if s >= self.high_threshold:
                risk_tiers.append("HIGH")
            elif s >= self.med_threshold:
                risk_tiers.append("MEDIUM")
            else:
                risk_tiers.append("LOW")

        return binary_preds, scores, risk_tiers

    def save(self, model_dir: str = "models") -> Tuple[str, str]:
        """Save models to directory."""
        os.makedirs(model_dir, exist_ok=True)
        if_path = os.path.join(model_dir, "isolation_forest.pkl")
        ae_path = os.path.join(model_dir, "autoencoder.pkl")

        self.if_model.save(if_path)
        self.ae_model.save(ae_path)

        # Save metadata / thresholds
        meta_path = os.path.join(model_dir, "detector_meta.pkl")
        import pickle
        with open(meta_path, "wb") as f:
            pickle.dump({
                "high_threshold": self.high_threshold,
                "med_threshold": self.med_threshold,
                "if_weight": self.if_weight,
                "ae_weight": self.ae_weight,
            }, f)

        logger.info(f"Saved Ensemble Detector to {model_dir}")
        return if_path, ae_path

    def load(self, model_dir: str = "models") -> "AnomalyDetector":
        """Load models from directory."""
        if_path = os.path.join(model_dir, "isolation_forest.pkl")
        ae_path = os.path.join(model_dir, "autoencoder.pkl")
        meta_path = os.path.join(model_dir, "detector_meta.pkl")

        self.if_model.load(if_path)
        self.ae_model.load(ae_path)

        import pickle
        with open(meta_path, "rb") as f:
            meta = pickle.load(f)
            self.high_threshold = meta["high_threshold"]
            self.med_threshold = meta["med_threshold"]
            self.if_weight = meta["if_weight"]
            self.ae_weight = meta["ae_weight"]

        self.is_fitted = True
        logger.info(f"Loaded Ensemble Detector from {model_dir}")
        return self
