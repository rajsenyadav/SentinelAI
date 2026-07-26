"""
SentinelAI — Anomaly Detector Evaluator

Evaluates performance of behavioral anomaly detection against ground-truth labels.
Computes Precision, Recall, F1, False Positive Rate (FPR), Detection Rate,
Confusion Matrix, PR-AUC, ROC-AUC, and Top-1% Alert Budget performance.
"""

import logging
from typing import Dict, Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score, recall_score, f1_score, confusion_matrix,
    roc_auc_score, precision_recall_curve, auc,
)

logger = logging.getLogger(__name__)


class AnomalyEvaluator:
    """
    Computes complete evaluation metrics for anomaly detection.
    Aligned with Honeywell's evaluation criteria:
        - Detection accuracy on imbalanced labels
        - False positive rate at top-1% budget
        - Multi-threshold evaluation
    """

    @staticmethod
    def evaluate(
        y_true: np.ndarray,
        y_scores: np.ndarray,
        threshold: float = 0.5,
    ) -> Dict[str, Any]:
        """
        Evaluate binary anomaly predictions against ground-truth labels.

        Args:
            y_true: Binary ground truth array (1 for anomaly, 0 for normal)
            y_scores: Continuous anomaly scores in range [0, 1]
            threshold: Score decision threshold

        Returns:
            Dictionary containing all key evaluation metrics.
        """
        y_pred = (y_scores >= threshold).astype(int)

        # Confusion Matrix
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        # Core Metrics
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        # Rates
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0  # Detection Rate

        # AUC Metrics
        try:
            roc_auc = roc_auc_score(y_true, y_scores)
            precisions, recalls, _ = precision_recall_curve(y_true, y_scores)
            pr_auc = auc(recalls, precisions)
        except Exception:
            roc_auc = 0.0
            pr_auc = 0.0

        # Top 1% Alert Budget Metrics
        top1_k = max(1, int(len(y_scores) * 0.01))
        top1_idx = np.argsort(y_scores)[-top1_k:]
        top1_preds = np.zeros_like(y_true)
        top1_preds[top1_idx] = 1

        top1_precision = precision_score(y_true, top1_preds, zero_division=0)
        top1_recall = recall_score(y_true, top1_preds, zero_division=0)

        metrics = {
            "total_samples": len(y_true),
            "actual_anomalies": int(np.sum(y_true)),
            "predicted_anomalies": int(np.sum(y_pred)),
            "confusion_matrix": {
                "TP": int(tp), "FP": int(fp),
                "TN": int(tn), "FN": int(fn)
            },
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "false_positive_rate": float(fpr),
            "detection_rate": float(tpr),
            "roc_auc": float(roc_auc),
            "pr_auc": float(pr_auc),
            "top_1percent_budget": {
                "alerts_triggered": int(top1_k),
                "precision": float(top1_precision),
                "recall": float(top1_recall),
            }
        }

        return metrics

    @staticmethod
    def print_report(metrics: Dict[str, Any]) -> str:
        """Format metrics dictionary into a clean CLI evaluation report string."""
        cm = metrics["confusion_matrix"]
        top1 = metrics["top_1percent_budget"]

        report = f"""
============================================================
SENTINELAI — ANOMALY DETECTION EVALUATION REPORT
============================================================
Total Test Samples:        {metrics['total_samples']:,}
Actual Anomalies:          {metrics['actual_anomalies']:,} ({metrics['actual_anomalies']/metrics['total_samples']*100:.2f}%)
Predicted Anomalies:       {metrics['predicted_anomalies']:,}

--- CONFUSION MATRIX ---
  True Negatives (TN):    {cm['TN']:,}
  False Positives (FP):   {cm['FP']:,}
  False Negatives (FN):   {cm['FN']:,}
  True Positives (TP):    {cm['TP']:,}

--- PERFORMANCE METRICS ---
  Precision:               {metrics['precision']:.4f}
  Recall (Detection Rate): {metrics['recall']:.4f}
  F1-Score:                {metrics['f1_score']:.4f}
  False Positive Rate:     {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)
  ROC-AUC:                 {metrics['roc_auc']:.4f}
  PR-AUC:                  {metrics['pr_auc']:.4f}

--- SOC ALERT BUDGET (Top 1% Highest Risk Events) ---
  Budget Capacity:         {top1['alerts_triggered']:,} alerts
  Top 1% Precision:        {top1['precision']:.4f}
  Top 1% Recall:           {top1['recall']:.4f}
============================================================
"""
        return report
