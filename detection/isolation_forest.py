"""
SentinelAI — Isolation Forest Anomaly Detection Model

Unsupervised tree-based anomaly detector. Isolates anomalies by randomly
selecting a feature and splitting value. Anomalies require fewer splits
to isolate, yielding shorter tree path lengths.
"""

import logging
import pickle
from typing import Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class IsolationForestModel:
    """
    Wrapper around Scikit-Learn IsolationForest for behavioral anomaly scoring.
    Scales features and outputs normalized anomaly scores in range [0, 1].
    """

    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float = 0.03,
        random_state: int = 42,
        n_jobs: int = -1,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.n_jobs = n_jobs

        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=self.n_jobs,
            warm_start=False,
        )
        self.is_fitted = False

    def fit(self, X: pd.DataFrame) -> "IsolationForestModel":
        """
        Fit Isolation Forest model on feature matrix X.

        Args:
            X: Numerical feature matrix.
        """
        logger.info(f"Fitting IsolationForest on {X.shape[0]} rows, {X.shape[1]} features...")
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        logger.info("  IsolationForest fit complete.")
        return self

    def predict_score(self, X: pd.DataFrame) -> np.ndarray:
        """
        Compute continuous anomaly scores in range [0, 1].
        Higher score = higher probability of being anomalous.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before scoring.")

        X_scaled = self.scaler.transform(X)
        # raw score from sklearn: lower means more anomalous
        raw_scores = self.model.score_samples(X_scaled)

        # Invert and normalize to [0, 1] range: higher = more anomalous
        # sklearn score range is roughly [-0.8, 0.2]
        # Invert: -raw_scores
        inverted = -raw_scores
        # Min-max scale to [0, 1]
        min_s = inverted.min()
        max_s = inverted.max()
        if max_s - min_s > 0:
            norm_scores = (inverted - min_s) / (max_s - min_s)
        else:
            norm_scores = np.zeros_like(inverted)

        return norm_scores

    def save(self, filepath: str) -> None:
        """Serialize model to file."""
        with open(filepath, "wb") as f:
            pickle.dump({"scaler": self.scaler, "model": self.model}, f)
        logger.info(f"Saved IsolationForest model to {filepath}")

    def load(self, filepath: str) -> "IsolationForestModel":
        """Load serialized model from file."""
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.scaler = data["scaler"]
            self.model = data["model"]
            self.is_fitted = True
        logger.info(f"Loaded IsolationForest model from {filepath}")
        return self
