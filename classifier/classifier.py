"""
SentinelAI — Attack Classifier Core Implementation

Main AttackClassifier wrapper handling fitting, predictions, probability estimation,
feature importances, and model serialization.
"""

import os
import logging
import pickle
from typing import List, Dict, Tuple, Optional, Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

logger = logging.getLogger(__name__)

# Try XGBoost
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False


class AttackClassifier:
    """
    Multi-Class Attack Type Classifier.
    Categorizes anomalous telemetry events into specific attack types:
    - brute_force
    - impossible_travel
    - credential_stuffing
    - lateral_movement
    - device_spoofing
    - low_slow_exfiltration
    - insider_drift
    """

    def __init__(self, model_type: str = "xgboost", random_state: int = 42):
        self.model_type = model_type
        self.random_state = random_state
        self.label_encoder = LabelEncoder()
        self.feature_names: List[str] = []

        if model_type == "xgboost" and HAS_XGBOOST:
            self.model = xgb.XGBClassifier(
                n_estimators=150,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=random_state,
                n_jobs=-1,
                eval_metric="mlogloss",
            )
        else:
            self.model = RandomForestClassifier(
                n_estimators=150,
                max_depth=15,
                random_state=random_state,
                n_jobs=-1,
            )
        self.is_fitted = False

    def fit(self, X: pd.DataFrame, y_str: np.ndarray) -> "AttackClassifier":
        """
        Fit the classifier on anomalous events feature matrix X and string labels y_str.
        """
        self.feature_names = list(X.columns)

        # Encode string attack types to integer classes
        y_encoded = self.label_encoder.fit_transform(y_str)

        logger.info(f"Fitting AttackClassifier ({self.model_type}) on {X.shape[0]} samples across {len(self.label_encoder.classes_)} classes...")
        self.model.fit(X, y_encoded)
        self.is_fitted = True
        logger.info("  AttackClassifier fit complete.")
        return self

    def predict(self, X: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict attack classes and confidence probabilities.

        Returns:
            Tuple of:
                - string_predictions: array of predicted attack type strings
                - confidence_scores: array of maximum class probability scores
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before calling predict.")

        proba = self.model.predict_proba(X)
        pred_indices = np.argmax(proba, axis=1)
        confidences = np.max(proba, axis=1)

        string_preds = self.label_encoder.inverse_transform(pred_indices)
        return string_preds, confidences

    def get_feature_importances(self, top_n: int = 10) -> pd.DataFrame:
        """
        Extract feature importances sorted descending.
        """
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted to get feature importances.")

        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
        else:
            importances = np.zeros(len(self.feature_names))

        df_imp = pd.DataFrame({
            "Feature": self.feature_names,
            "Importance": importances,
        }).sort_values("Importance", ascending=False).reset_index(drop=True)

        return df_imp.head(top_n)

    def save(self, filepath: str) -> None:
        """Serialize trained model and label encoder to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump({
                "model": self.model,
                "label_encoder": self.label_encoder,
                "feature_names": self.feature_names,
                "model_type": self.model_type,
            }, f)
        logger.info(f"Saved AttackClassifier model to {filepath}")

    def load(self, filepath: str) -> "AttackClassifier":
        """Load serialized model from disk."""
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.model = data["model"]
            self.label_encoder = data["label_encoder"]
            self.feature_names = data["feature_names"]
            self.model_type = data["model_type"]
            self.is_fitted = True
        logger.info(f"Loaded AttackClassifier model from {filepath}")
        return self
