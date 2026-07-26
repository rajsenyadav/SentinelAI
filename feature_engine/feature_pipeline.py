"""
SentinelAI — Feature Engineering Pipeline Orchestrator

Combines Preprocessing, Per-Event Feature Extraction, Window Aggregations,
and Categorical Encoding into a single unified execution pipeline.
"""

import os
import logging
from typing import Tuple, Optional

import pandas as pd
import numpy as np

from .preprocessing import DataPreprocessor
from .event_features import EventFeatureExtractor
from .window_features import WindowFeatureExtractor

logger = logging.getLogger(__name__)


class FeatureEngineeringPipeline:
    """
    End-to-end Feature Engineering Pipeline for SentinelAI.

    Workflow:
        1. Load & Clean raw events and labels (DataPreprocessor)
        2. Split training data to fit entity baseline profiles
        3. Extract per-event numerical features (EventFeatureExtractor)
        4. Extract rolling window features (WindowFeatureExtractor)
        5. Encode categorical columns (DataPreprocessor)
        6. Export processed ML dataset
    """

    def __init__(self, output_dir: str = "data/processed"):
        self.output_dir = output_dir
        self.preprocessor = DataPreprocessor()
        self.event_extractor = EventFeatureExtractor()
        self.window_extractor = WindowFeatureExtractor()

    def run(
        self,
        events_path: str = "data/raw/events.csv",
        labels_path: str = "data/raw/labels.csv",
        output_filename: str = "engineered_dataset.csv",
        train_ratio: float = 0.60,
    ) -> pd.DataFrame:
        """
        Executes the full feature engineering pipeline.

        Args:
            events_path: Path to raw events CSV
            labels_path: Path to ground-truth labels CSV
            output_filename: Filename for the saved dataset
            train_ratio: Ratio of data used for fitting behavioral baselines

        Returns:
            Fully feature-engineered DataFrame ready for ML models.
        """
        logger.info("=" * 60)
        logger.info("SentinelAI — Feature Engineering Pipeline")
        logger.info("=" * 60)

        # Step 1: Preprocessing & Cleaning
        df = self.preprocessor.load_and_clean(events_path, labels_path)

        # Step 2: Fit entity baselines on the training split to avoid data leakage
        n_train = int(len(df) * train_ratio)
        df_train = df.iloc[:n_train]
        logger.info(f"Fitting behavioral baselines on training split ({n_train} events)...")
        self.event_extractor.build_baselines(df_train)

        # Step 3: Per-Event Feature Extraction
        df = self.event_extractor.transform(df)

        # Step 4: Window Aggregation Features
        df = self.window_extractor.transform(df)

        # Step 5: Encode Categoricals
        df = self.preprocessor.encode_categoricals(df)

        # Step 6: Save Processed Dataset
        os.makedirs(self.output_dir, exist_ok=True)
        output_path = os.path.join(self.output_dir, output_filename)

        # Re-order columns for clarity: metadata -> features -> labels
        df = self._organize_columns(df)
        df.to_csv(output_path, index=False)

        logger.info("=" * 60)
        logger.info("FEATURE ENGINEERING COMPLETE")
        logger.info("=" * 60)
        logger.info(f"  Processed rows:     {len(df)}")
        logger.info(f"  Engineered features:{len(df.columns)}")
        logger.info(f"  Saved to:           {output_path}")

        return df

    def _organize_columns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Organizes DataFrame columns systematically."""
        label_cols = ["label", "attack_type", "attack_subtype"]
        meta_cols = ["event_id", "timestamp", "entity_id", "source_ip", "resource_accessed"]

        # All numerical / encoded feature columns
        feature_cols = [
            col for col in df.columns
            if col not in label_cols and col not in meta_cols and not col.endswith("_raw")
        ]

        raw_meta = [col for col in df.columns if col.endswith("_raw") or col in meta_cols]

        ordered = meta_cols + [c for c in raw_meta if c not in meta_cols] + feature_cols + label_cols
        ordered = [c for c in ordered if c in df.columns]

        return df[ordered]
