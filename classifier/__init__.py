"""
SentinelAI — Attack Classification Module

Multi-class threat classifier for categorizing detected anomalies into
specific attack types (Brute Force, Impossible Travel, Credential Stuffing,
Lateral Movement, Device Spoofing, Low-and-Slow Exfiltration, Insider Drift).
"""

from .classifier import AttackClassifier
from .models_comparison import ModelComparator
from .inference_classifier import AttackInferenceEngine
from .evaluate_classifier import ClassifierEvaluator

__all__ = [
    "AttackClassifier",
    "ModelComparator",
    "AttackInferenceEngine",
    "ClassifierEvaluator",
]
