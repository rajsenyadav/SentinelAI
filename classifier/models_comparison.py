"""
SentinelAI — Model Comparison Suite

Compares multiple multi-class classifiers (Random Forest, XGBoost, Extra Trees / Gradient Boosting)
on accuracy, weighted precision, recall, F1, training latency, inference latency,
explainability, and scalability.
"""

import time
import logging
from typing import Dict, Any, List, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

logger = logging.getLogger(__name__)

# Check XGBoost availability
try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    logger.warning("XGBoost package not installed. Falling back to GradientBoostingClassifier.")


class ModelComparator:
    """
    Evaluates and compares multiple classification models on attack data.
    """

    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.models = self._initialize_models()

    def _initialize_models(self) -> Dict[str, Any]:
        models = {
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=self.random_state,
                n_jobs=-1,
            ),
            "Extra Trees": ExtraTreesClassifier(
                n_estimators=100,
                max_depth=15,
                random_state=self.random_state,
                n_jobs=-1,
            ),
        }

        if HAS_XGBOOST:
            models["XGBoost"] = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=self.random_state,
                n_jobs=-1,
                eval_metric="mlogloss",
            )
        else:
            models["Gradient Boosting"] = GradientBoostingClassifier(
                n_estimators=80,
                max_depth=5,
                random_state=self.random_state,
            )

        return models

    def compare(
        self,
        X_train: pd.DataFrame,
        y_train: np.ndarray,
        X_test: pd.DataFrame,
        y_test: np.ndarray,
        class_names: List[str],
    ) -> pd.DataFrame:
        """
        Train and evaluate all candidate models.

        Returns:
            Comparison summary DataFrame.
        """
        logger.info("=" * 60)
        logger.info("Comparing Multi-Class Attack Classification Algorithms")
        logger.info("=" * 60)

        from sklearn.preprocessing import LabelEncoder

        label_encoder = LabelEncoder()
        y_train_enc = label_encoder.fit_transform(y_train)
        y_test_enc = label_encoder.transform(y_test)

        results = []

        for name, model in self.models.items():
            logger.info(f"Training {name}...")

            # Measure training time
            t0 = time.time()
            model.fit(X_train, y_train_enc)
            train_time = time.time() - t0

            # Measure inference time
            t0 = time.time()
            preds_enc = model.predict(X_test)
            inf_time = (time.time() - t0) / len(X_test) * 1000.0  # ms per sample

            # Compute metrics
            acc = accuracy_score(y_test_enc, preds_enc)
            prec = precision_score(y_test_enc, preds_enc, average="weighted", zero_division=0)
            rec = recall_score(y_test_enc, preds_enc, average="weighted", zero_division=0)
            f1 = f1_score(y_test_enc, preds_enc, average="weighted", zero_division=0)

            # Qualities
            explainability = "High (SHAP & Tree Feature Importance)" if "Forest" in name or "Trees" in name or "XGBoost" in name else "Medium"
            scalability = "Excellent (Parallelized CPU/GPU)" if name in ("Random Forest", "XGBoost", "Extra Trees") else "Good"

            res = {
                "Model": name,
                "Accuracy": round(acc, 4),
                "Precision (Weighted)": round(prec, 4),
                "Recall (Weighted)": round(rec, 4),
                "F1 Score (Weighted)": round(f1, 4),
                "Train Time (s)": round(train_time, 3),
                "Inference Time (ms/sample)": round(inf_time, 4),
                "Explainability": explainability,
                "Scalability": scalability,
            }
            results.append(res)
            logger.info(
                f"  {name:20s} -> F1: {f1:.4f} | Acc: {acc:.4f} | Train Time: {train_time:.2f}s | Latency: {inf_time:.3f}ms/sample"
            )

        df_res = pd.DataFrame(results).sort_values("F1 Score (Weighted)", ascending=False).reset_index(drop=True)
        return df_res
