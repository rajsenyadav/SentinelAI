"""
SentinelAI — SHAP Engine

Computes local feature attributions using SHAP (SHapley Additive exPlanations)
to identify which engineered features contributed most to flagging an anomaly
and classifying an attack type.
"""

import logging
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Check SHAP availability
try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False
    logger.warning("SHAP package not installed. Using local gradient feature attribution fallback.")


class SHAPExplainer:
    """
    Computes local feature importance attributions for individual events.
    """

    def __init__(self, model: Any, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.explainer = None

        if HAS_SHAP:
            try:
                # Use TreeExplainer if tree model, else KernelExplainer
                self.explainer = shap.TreeExplainer(self.model)
                logger.info("  Initialized SHAP TreeExplainer.")
            except Exception as e:
                logger.warning(f"  TreeExplainer initialization failed: {e}. Falling back to default attributions.")
                self.explainer = None

    def explain_instance(self, instance_df: pd.DataFrame, top_k: int = 5) -> List[Tuple[str, float]]:
        """
        Compute top feature contributions for a single event instance.

        Returns:
            List of (feature_name, shap_value) sorted by absolute contribution.
        """
        if instance_df.ndim == 1:
            instance_df = pd.DataFrame([instance_df])

        if HAS_SHAP and self.explainer is not None:
            try:
                shap_values = self.explainer.shap_values(instance_df)
                
                # If multi-class, shap_values is a list of arrays (one per class)
                if isinstance(shap_values, list):
                    # Sum absolute SHAP values across classes for overall importance
                    vals = np.mean([np.abs(sv[0]) for sv in shap_values], axis=0)
                elif isinstance(shap_values, np.ndarray):
                    if shap_values.ndim == 3:
                        vals = np.abs(shap_values[0]).mean(axis=1)
                    else:
                        vals = np.abs(shap_values[0])
                else:
                    vals = np.zeros(len(self.feature_names))

                pairs = list(zip(self.feature_names, vals))
                pairs.sort(key=lambda x: abs(x[1]), reverse=True)
                return pairs[:top_k]
            except Exception as e:
                logger.warning(f"  SHAP computation failed: {e}. Using fallback.")

        # Fallback: Instance magnitude * global feature importance
        return self._fallback_instance_explanation(instance_df, top_k)

    def _fallback_instance_explanation(self, instance_df: pd.DataFrame, top_k: int) -> List[Tuple[str, float]]:
        """Instance-level fallback attribution based on feature values & model importances."""
        row = instance_df.iloc[0]
        
        # Get global importances if available
        if hasattr(self.model, "feature_importances_"):
            global_imp = self.model.feature_importances_
        else:
            global_imp = np.ones(len(self.feature_names)) / len(self.feature_names)

        # Scale by feature magnitude
        scores = []
        for idx, feat in enumerate(self.feature_names):
            val = float(row.get(feat, 0.0))
            score = abs(val) * global_imp[idx]
            scores.append((feat, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]
