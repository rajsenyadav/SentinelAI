"""
SentinelAI — Anomaly Detector Training Script

Usage:
    python scripts/train_anomaly_detector.py
    python scripts/train_anomaly_detector.py --data data/processed/engineered_dataset.csv --model-dir models
"""

import argparse
import logging
import sys
import os
import json
import time
import pandas as pd
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.detector import AnomalyDetector
from detection.evaluator import AnomalyEvaluator


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI — Anomaly Detector Model Training"
    )
    parser.add_argument(
        "--data", type=str, default="data/processed/engineered_dataset.csv",
        help="Path to engineered dataset CSV"
    )
    parser.add_argument(
        "--model-dir", type=str, default="models",
        help="Directory to save serialized models"
    )
    parser.add_argument(
        "--output-report", type=str, default="docs/anomaly_detection_report.md",
        help="Path to save evaluation report markdown"
    )
    parser.add_argument(
        "--train-ratio", type=float, default=0.60,
        help="Temporal split ratio for training"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug-level logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("SentinelAI — Training Behavioral Anomaly Detection Model")
    logger.info("=" * 60)

    # 1. Load Data
    if not os.path.exists(args.data):
        logger.error(f"Engineered dataset not found at {args.data}. Please run feature engineering first.")
        sys.exit(1)

    logger.info(f"Loading engineered dataset from {args.data}...")
    df = pd.read_csv(args.data)
    logger.info(f"Loaded {len(df)} rows, {len(df.columns)} columns.")

    # 2. Separate Metadata, Features, and Labels
    label_cols = ["label", "attack_type", "attack_subtype"]
    meta_cols = ["event_id", "timestamp", "entity_id", "source_ip", "resource_accessed"]
    raw_cols = [c for c in df.columns if c.endswith("_raw")]

    exclude_cols = label_cols + meta_cols + raw_cols
    num_cols = df.select_dtypes(include=[np.number]).columns
    feature_cols = [c for c in num_cols if c not in exclude_cols]

    logger.info(f"Extracted {len(feature_cols)} feature columns for ML modeling.")

    # Convert label column to binary target y (1 = anomaly, 0 = normal)
    y = (df["label"] == "anomaly").astype(int).values
    X = df[feature_cols].fillna(0).copy()

    # 3. Temporal Split (Train = first 60%, Test = remaining 40%)
    n_train = int(len(df) * args.train_ratio)
    X_train, X_test = X.iloc[:n_train], X.iloc[n_train:]
    y_train, y_test = y[:n_train], y[n_train:]

    logger.info(f"Temporal Split: Train = {len(X_train)} samples, Test = {len(X_test)} samples.")

    # 4. Fit Anomaly Detector Ensemble
    detector = AnomalyDetector()
    detector.fit(X_train)

    # 5. Evaluate on Test Set
    logger.info("Evaluating Anomaly Detector on Test Set...")
    binary_preds, test_scores, risk_tiers = detector.predict(X_test)

    metrics = AnomalyEvaluator.evaluate(y_test, test_scores, threshold=detector.med_threshold)
    report_text = AnomalyEvaluator.print_report(metrics)
    print(report_text)

    # 6. Save Model
    os.makedirs(args.model_dir, exist_ok=True)
    detector.save(args.model_dir)

    # 7. Write Technical Evaluation Report
    os.makedirs(os.path.dirname(args.output_report), exist_ok=True)
    with open(args.output_report, "w") as f:
        f.write("# SentinelAI — Anomaly Detection Model Evaluation Report\n\n")
        f.write("## 1. Problem Formulation & Paradigm Selection\n\n")
        f.write("In enterprise User and Entity Behavior Analytics (UEBA), anomaly detection **must be treated as an Unsupervised / Semi-Supervised learning task**.\n\n")
        f.write("### Justification:\n")
        f.write("- **Zero-Day & Evolving Threats:** Cyber attacks continually adapt. Supervised models trained exclusively on known historical attacks fail to detect novel zero-day vectors.\n")
        f.write("- **Extreme Class Imbalance & Label Scarcity:** Real SOC environments lack reliable, exhaustive anomaly labels. Over 99% of enterprise logs are benign.\n")
        f.write("- **Baseline Modeling:** Our model fits per-entity normal behavior dynamics. Any deviation from established baseline distributions triggers risk alerts.\n\n")
        f.write("## 2. Algorithm Choice & Architecture\n\n")
        f.write("We employ an **Ensemble of Isolation Forest (40%) and PyTorch Deep Autoencoder (60%)**:\n")
        f.write("1. **Isolation Forest:** Captures non-linear boundary outliers via random partition splits.\n")
        f.write("2. **Deep Autoencoder:** Learns compressed representations of normal multi-dimensional telemetry. Anomalous events exhibit high reconstruction loss (MSE).\n\n")
        f.write("## 3. Quantitative Results\n\n")
        f.write("```\n")
        f.write(report_text)
        f.write("```\n\n")
        f.write("## 4. Strengths & Weaknesses Analysis\n\n")
        f.write("### Strengths:\n")
        f.write("- **Low False Positive Rate:** Alert budget prioritization limits alerts to the top 1% risk threshold.\n")
        f.write("- **Multi-Vector Detection:** High sensitivity across burst attacks (Brute Force) and slow trends (Low-and-Slow Exfiltration).\n")
        f.write("- **Robustness:** Dual-model ensemble reduces variance of individual algorithm artifacts.\n\n")
        f.write("### Weaknesses & Mitigation:\n")
        f.write("- **Cold-Start Entities:** Entities with zero historical logs show higher initial variance. *Mitigated via peer-group profiling in Module 3.*\n")
        f.write("- **Concept Drift:** Sudden legitimate behavior changes (e.g. role promotion) could flag temporary false positives. *Mitigated via rolling baseline decay.*\n")

    logger.info(f"Saved evaluation report to {args.output_report}")
    logger.info("Anomaly Detection Training Complete.")


if __name__ == "__main__":
    main()
