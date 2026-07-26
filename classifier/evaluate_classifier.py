"""
SentinelAI — Attack Classifier Evaluator

Generates classification metrics, per-class evaluation, confusion matrix,
and feature importance breakdown for threat classification.
"""

import logging
from typing import Dict, Any, List

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score

logger = logging.getLogger(__name__)


class ClassifierEvaluator:
    """
    Computes comprehensive evaluation metrics for multi-class attack classification.
    """

    @staticmethod
    def evaluate(
        y_true: np.ndarray,
        y_pred: np.ndarray,
        class_names: List[str],
    ) -> Dict[str, Any]:
        """
        Compute evaluation metrics across all attack classes.
        """
        acc = accuracy_score(y_true, y_pred)
        weighted_f1 = f1_score(y_true, y_pred, average="weighted", zero_division=0)
        macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)

        # Classification report as dict
        clf_dict = classification_report(
            y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0
        )

        # Classification report text
        clf_text = classification_report(
            y_true, y_pred, target_names=class_names, zero_division=0
        )

        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred, labels=class_names)
        cm_df = pd.DataFrame(cm, index=class_names, columns=class_names)

        metrics = {
            "accuracy": float(acc),
            "weighted_f1": float(weighted_f1),
            "macro_f1": float(macro_f1),
            "classification_report_text": clf_text,
            "classification_report_dict": clf_dict,
            "confusion_matrix_df": cm_df,
        }

        return metrics

    @staticmethod
    def print_report(metrics: Dict[str, Any], feature_importances: pd.DataFrame) -> str:
        """Format metrics into a clean CLI string."""
        report = f"""
============================================================
SENTINELAI — ATTACK CLASSIFICATION EVALUATION REPORT
============================================================
Overall Accuracy:       {metrics['accuracy']:.4f}
Weighted F1-Score:      {metrics['weighted_f1']:.4f}
Macro F1-Score:         {metrics['macro_f1']:.4f}

--- PER-CLASS PERFORMANCE ---
{metrics['classification_report_text']}

--- CONFUSION MATRIX ---
{metrics['confusion_matrix_df'].to_string()}

--- TOP FEATURE IMPORTANCES ---
{feature_importances.to_string(index=False)}
============================================================
"""
        return report
