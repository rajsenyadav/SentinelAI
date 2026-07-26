"""
SentinelAI Dashboard — Utility & Data Integration Helpers

Loads processed datasets, raw events, trained anomaly detector,
attack classifier, and explainability engine.
"""

import os
import sys
import logging
from typing import Tuple, Dict, Any, Optional

import pandas as pd
import numpy as np
import streamlit as st

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from detection.detector import AnomalyDetector
from classifier.classifier import AttackClassifier
from explainer.explainability import ExplainabilityEngine
from backend.services.incident_persistence import ensure_persistence_schema

logger = logging.getLogger(__name__)


def load_dataset() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Load raw events and engineered dataset directly from CSV file on disk."""
    raw_path = os.path.join(PROJECT_ROOT, "data", "raw", "events.csv")
    proc_path = os.path.join(PROJECT_ROOT, "data", "processed", "engineered_dataset.csv")

    if not os.path.exists(proc_path):
        df_raw, df_proc = _generate_mock_dataset()
        df_proc = ensure_persistence_schema(df_proc)
        os.makedirs(os.path.dirname(proc_path), exist_ok=True)
        df_proc.to_csv(proc_path, index=False)
        return df_proc, df_proc

    df_raw = pd.read_csv(raw_path) if os.path.exists(raw_path) else pd.DataFrame()
    df_proc = pd.read_csv(proc_path)
    df_proc = ensure_persistence_schema(df_proc)

    return df_raw, df_proc


@st.cache_resource
def load_models() -> Tuple[Optional[AnomalyDetector], Optional[AttackClassifier], Optional[ExplainabilityEngine]]:
    """Load backend machine learning models."""
    model_dir = os.path.join(PROJECT_ROOT, "models")
    if not os.path.exists(os.path.join(model_dir, "detector_meta.pkl")):
        return None, None, None

    try:
        detector = AnomalyDetector().load(model_dir)
        classifier = AttackClassifier().load(os.path.join(model_dir, "attack_classifier.pkl"))
        explainer = ExplainabilityEngine(detector, classifier)
        return detector, classifier, explainer
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        return None, None, None


def _generate_mock_dataset() -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Fallback generator for demonstration if data files are missing."""
    n = 1000
    dates = pd.date_range("2026-01-01", periods=n, freq="min")
    entities = [f"EMP{np.random.randint(1000, 1050)}" for _ in range(n)]
    attacks = ["normal"] * 900 + ["brute_force"] * 30 + ["impossible_travel"] * 20 + ["credential_stuffing"] * 25 + ["lateral_movement"] * 25

    df_proc = pd.DataFrame({
        "event_id": [f"evt-{i:05d}" for i in range(n)],
        "timestamp": dates,
        "entity_id": entities,
        "source_ip": ["192.168.1.10"] * n,
        "geo_location": ["London, UK"] * n,
        "geo_lat": [51.5074] * n,
        "geo_lon": [-0.1278] * n,
        "resource_accessed": ["/api/v1/auth"] * n,
        "resource_category": ["general"] * n,
        "department": ["Engineering"] * n,
        "action_type": ["login"] * n,
        "auth_status": ["success"] * n,
        "device_fingerprint": ["fp-992a"] * n,
        "is_off_hours": [0] * n,
        "geo_velocity_kmh": [0.0] * n,
        "failed_auth_count_1h": [0] * n,
        "bytes_transferred": [1024] * n,
        "risk_multiplier": [0] * n,
        "label": ["anomaly" if a != "normal" else "normal" for a in attacks],
        "attack_type": attacks,
        "status": ["LIVE_THREAT" if a != "normal" else "BENIGN" for a in attacks],
        "analyst_feedback": ["" for _ in range(n)],
        "last_updated": ["" for _ in range(n)],
        "updated_by": ["" for _ in range(n)],
    })

    return df_proc, df_proc
