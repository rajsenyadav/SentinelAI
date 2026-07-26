"""
SentinelAI — Feature Engineering Module

Transforms raw enterprise access logs into ML-ready numerical features
for behavioral anomaly detection.
"""

from .preprocessing import DataPreprocessor
from .event_features import EventFeatureExtractor
from .window_features import WindowFeatureExtractor
from .feature_pipeline import FeatureEngineeringPipeline

__all__ = [
    "DataPreprocessor",
    "EventFeatureExtractor",
    "WindowFeatureExtractor",
    "FeatureEngineeringPipeline",
]
