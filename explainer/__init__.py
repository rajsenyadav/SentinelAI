"""
SentinelAI — Explainability & Risk Intelligence Module

Combines SHAP feature attributions, continuous risk scoring (0-100),
behavioral deviation analysis, evidence generation, and automated SOC recommendations.
"""

from .explainability import ExplainabilityEngine
from .shap_engine import SHAPExplainer
from .risk_engine import RiskEngine
from .recommendations import RecommendationEngine

__all__ = [
    "ExplainabilityEngine",
    "SHAPExplainer",
    "RiskEngine",
    "RecommendationEngine",
]
