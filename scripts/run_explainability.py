"""
SentinelAI — Explainability Engine CLI Execution Script

Usage:
    python scripts/run_explainability.py
    python scripts/run_explainability.py --data data/processed/engineered_dataset.csv --num-samples 5
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
from classifier.classifier import AttackClassifier
from explainer.explainability import ExplainabilityEngine


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI — Explainability Engine & Risk Intelligence Execution"
    )
    parser.add_argument(
        "--data", type=str, default="data/processed/engineered_dataset.csv",
        help="Path to engineered dataset CSV"
    )
    parser.add_argument(
        "--model-dir", type=str, default="models",
        help="Directory containing serialized models"
    )
    parser.add_argument(
        "--num-samples", type=int, default=3,
        help="Number of example alert JSON payloads to generate and display"
    )
    parser.add_argument(
        "--output-report", type=str, default="docs/explainability_report.md",
        help="Path to save explainability report markdown"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug-level logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("SentinelAI — Running Explainability & Risk Intelligence Engine")
    logger.info("=" * 60)

    # 1. Load Trained Models
    logger.info(f"Loading models from {args.model_dir}...")
    detector = AnomalyDetector().load(args.model_dir)

    classifier_path = os.path.join(args.model_dir, "attack_classifier.pkl")
    classifier = AttackClassifier().load(classifier_path)

    # 2. Initialize Explainability Engine
    explainer = ExplainabilityEngine(detector, classifier)

    # 3. Load Processed Data
    if not os.path.exists(args.data):
        logger.error(f"Processed dataset not found at {args.data}. Please run feature engineering first.")
        sys.exit(1)

    df = pd.read_csv(args.data)
    df_anomaly = df[df["label"] == "anomaly"].copy().reset_index(drop=True)
    logger.info(f"Loaded dataset with {len(df_anomaly)} anomalous events.")

    # 4. Generate JSON Alerts for Sample Anomalies
    label_cols = ["label", "attack_type", "attack_subtype"]
    meta_cols = ["event_id", "timestamp", "entity_id", "source_ip", "resource_accessed"]
    raw_cols = [c for c in df_anomaly.columns if c.endswith("_raw")]

    exclude_cols = label_cols + meta_cols + raw_cols
    num_cols = df_anomaly.select_dtypes(include=[np.number]).columns
    feature_cols = [c for c in num_cols if c not in exclude_cols]

    alerts = []
    print("\n" + "=" * 60)
    print("SAMPLE SOC STRUCTURED JSON ALERTS")
    print("=" * 60 + "\n")

    for i in range(min(args.num_samples, len(df_anomaly))):
        row = df_anomaly.iloc[i]
        
        event_raw = {
            "entity_id": row.get("entity_id", f"EMP{1000+i}"),
            "event_id": row.get("event_id", f"evt-{i:04d}"),
            "timestamp": row.get("timestamp", "2026-01-15T14:32:00Z"),
            "source_ip": row.get("source_ip", "192.168.1.10"),
            "resource_category": row.get("resource_category_raw", row.get("resource_category", "general")),
            "device_fingerprint": row.get("device_fingerprint_raw", "fp-8f2a1b9c"),
            "command_sequence": row.get("command_sequence_raw", "[]"),
        }
        
        event_features = row[feature_cols]

        alert_json = explainer.explain(event_raw, event_features)
        alerts.append(alert_json)

        print(f"--- Alert #{i+1} ---")
        print(json.dumps(alert_json, indent=2))
        print()

    # 5. Write Documentation Report
    os.makedirs(os.path.dirname(args.output_report), exist_ok=True)
    with open(args.output_report, "w") as f:
        f.write("# SentinelAI — Explainability & Risk Intelligence Documentation\n\n")
        f.write("## 1. Risk Score Calculation Methodology\n\n")
        f.write("SentinelAI calculates a composite, non-linear **Risk Score (0–100)** for every detected anomaly combining three orthogonal signals:\n\n")
        f.write("$$\\text{Risk Score} = 0.40 \\cdot (S_{\\text{anomaly}} \\times 100) + 0.35 \\cdot (C_{\\text{classifier}} \\times 100) + 0.25 \\cdot (M_{\\text{risk}} \\times 16.6)$$\n\n")
        f.write("### Risk Level Tiers:\n")
        f.write("- **Critical (90 – 100):** Immediate threat requiring automated account locking and SOC escalation (e.g. Active Lateral Movement, Data Exfiltration).\n")
        f.write("- **High (70 – 89):** High-confidence threat requiring immediate MFA re-verification or credential lock (e.g. Impossible Travel, Brute Force).\n")
        f.write("- **Medium (40 – 69):** Moderate threat requiring device isolation and manager audit (e.g. Unrecognized Device, Scope Expansion).\n")
        f.write("- **Low (0 – 39):** Minor behavioral drift logged for baseline update.\n\n")
        f.write("## 2. Explainability & SHAP Feature Attribution\n\n")
        f.write("To eliminate the 'black-box' nature of ML security models, SentinelAI uses **SHAP (SHapley Additive exPlanations)**.\n")
        f.write("For every flagged event, SHAP computes local game-theoretic contributions to explain *why* the tree model categorized the event as a specific attack type.\n\n")
        f.write("## 3. Example Structured SOC Alert Payload\n\n")
        f.write("```json\n")
        f.write(json.dumps(alerts[0] if alerts else {}, indent=2))
        f.write("\n```\n\n")
        f.write("## 4. Automated SOC Analyst Recommendations\n\n")
        f.write("Based on risk severity and threat type, SentinelAI automatically generates prioritized action items:\n")
        f.write("- **Lock Account:** Revoke active tokens and force MFA for Impossible Travel or Brute Force.\n")
        f.write("- **Escalate to SOC & Isolate Entity:** Quarantine compromised hosts during active Lateral Movement.\n")
        f.write("- **Investigate Device:** Revoke session keys for Device Spoofing.\n")

    logger.info(f"Saved explainability report to {args.output_report}")
    logger.info("Explainability Engine Execution Complete.")


if __name__ == "__main__":
    main()
