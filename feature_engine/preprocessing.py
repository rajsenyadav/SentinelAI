"""
SentinelAI — Data Preprocessing

Handles data loading, cleaning, validation, deduplication, type casting,
and missing-value imputation before feature engineering begins.
"""

import ast
import logging
from typing import Tuple, Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class DataPreprocessor:
    """
    Cleans and validates raw event + label CSVs before feature engineering.

    Responsibilities:
        - Load and merge events + labels
        - Remove duplicates
        - Fix dtypes (timestamp → datetime, booleans, numerics)
        - Handle missing / invalid values
        - Parse command_sequence from string to list
        - Encode categoricals to integer codes
    """

    # Columns expected in events.csv
    EVENT_COLUMNS = [
        "event_id", "timestamp", "entity_id", "entity_type", "entity_role",
        "department", "source_ip", "geo_location", "geo_lat", "geo_lon",
        "resource_accessed", "resource_category", "action_type",
        "auth_method", "auth_status", "session_duration", "bytes_transferred",
        "device_fingerprint", "device_os", "user_agent", "protocol",
        "command_sequence", "is_vpn",
    ]

    LABEL_COLUMNS = ["event_id", "label", "attack_type", "attack_subtype"]

    # Categorical columns to encode
    CATEGORICAL_COLS = [
        "entity_type", "entity_role", "department", "resource_category",
        "action_type", "auth_method", "auth_status", "protocol",
    ]

    def __init__(self):
        self.category_mappings = {}  # col_name -> {value: code}
        self._stats = {
            "rows_loaded": 0,
            "duplicates_removed": 0,
            "missing_filled": 0,
            "invalid_removed": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_and_clean(
        self,
        events_path: str,
        labels_path: str,
    ) -> pd.DataFrame:
        """
        Load, merge, clean, and return a single DataFrame ready for
        feature engineering.

        Returns:
            DataFrame with all event columns + label columns, cleaned.
        """
        logger.info("Loading raw data...")
        events_df = pd.read_csv(events_path)
        labels_df = pd.read_csv(labels_path)

        self._stats["rows_loaded"] = len(events_df)
        logger.info(f"  Loaded {len(events_df)} events, {len(labels_df)} labels")

        # Merge events + labels on event_id
        df = events_df.merge(labels_df, on="event_id", how="left")
        logger.info(f"  Merged: {len(df)} rows")

        # Step 1: Remove exact duplicates
        df = self._remove_duplicates(df)

        # Step 2: Fix data types
        df = self._fix_dtypes(df)

        # Step 3: Handle missing values
        df = self._fill_missing(df)

        # Step 4: Remove invalid records
        df = self._remove_invalid(df)

        # Step 5: Parse command sequences
        df = self._parse_commands(df)

        # Step 6: Sort chronologically
        df = df.sort_values("timestamp").reset_index(drop=True)

        logger.info("Preprocessing complete:")
        for key, val in self._stats.items():
            logger.info(f"  {key}: {val}")
        logger.info(f"  Final row count: {len(df)}")

        return df

    def encode_categoricals(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Encode categorical columns to integer codes.
        Stores mappings in self.category_mappings for inverse transforms.

        Original string columns are preserved as `<col>_raw`.
        Encoded columns replace the original name with suffix `_encoded`.
        """
        df = df.copy()

        for col in self.CATEGORICAL_COLS:
            if col not in df.columns:
                continue

            # Preserve raw values
            df[f"{col}_raw"] = df[col].astype(str)

            # Create integer mapping
            unique_vals = sorted(df[col].dropna().unique())
            mapping = {v: i for i, v in enumerate(unique_vals)}
            self.category_mappings[col] = mapping

            df[f"{col}_encoded"] = df[col].map(mapping).fillna(-1).astype(int)

        logger.info(f"  Encoded {len(self.CATEGORICAL_COLS)} categorical columns")
        return df

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    def _remove_duplicates(self, df: pd.DataFrame) -> pd.DataFrame:
        before = len(df)
        df = df.drop_duplicates(subset=["event_id"], keep="first")
        removed = before - len(df)
        self._stats["duplicates_removed"] = removed
        if removed > 0:
            logger.info(f"  Removed {removed} duplicate events")
        return df

    def _fix_dtypes(self, df: pd.DataFrame) -> pd.DataFrame:
        # Timestamp
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

        # Numerics
        df["session_duration"] = pd.to_numeric(df["session_duration"], errors="coerce")
        df["bytes_transferred"] = pd.to_numeric(df["bytes_transferred"], errors="coerce")
        df["geo_lat"] = pd.to_numeric(df["geo_lat"], errors="coerce")
        df["geo_lon"] = pd.to_numeric(df["geo_lon"], errors="coerce")

        # Boolean
        df["is_vpn"] = df["is_vpn"].astype(bool)

        return df

    def _fill_missing(self, df: pd.DataFrame) -> pd.DataFrame:
        fills = 0

        # Numeric: fill with 0
        for col in ["session_duration", "bytes_transferred"]:
            count = df[col].isna().sum()
            if count > 0:
                df[col] = df[col].fillna(0)
                fills += count

        # Geo coordinates: fill with 0.0 (will be flagged as unknown)
        for col in ["geo_lat", "geo_lon"]:
            count = df[col].isna().sum()
            if count > 0:
                df[col] = df[col].fillna(0.0)
                fills += count

        # String columns: fill with "unknown"
        string_cols = [
            "entity_type", "entity_role", "department", "source_ip",
            "geo_location", "resource_accessed", "resource_category",
            "action_type", "auth_method", "auth_status", "protocol",
            "device_fingerprint", "device_os", "user_agent",
            "command_sequence",
        ]
        for col in string_cols:
            if col in df.columns:
                count = df[col].isna().sum()
                if count > 0:
                    df[col] = df[col].fillna("unknown")
                    fills += count

        # Labels: fill unmatched events as normal
        for col in ["label", "attack_type", "attack_subtype"]:
            if col in df.columns:
                df[col] = df[col].fillna("normal")

        self._stats["missing_filled"] = fills
        return df

    def _remove_invalid(self, df: pd.DataFrame) -> pd.DataFrame:
        before = len(df)

        # Remove rows with null timestamps (could not be parsed)
        df = df.dropna(subset=["timestamp"])

        # Remove rows with invalid coordinates
        df = df[
            (df["geo_lat"].between(-90, 90)) &
            (df["geo_lon"].between(-180, 180))
        ]

        # Remove rows with negative durations/bytes
        df = df[df["session_duration"] >= 0]
        df = df[df["bytes_transferred"] >= 0]

        removed = before - len(df)
        self._stats["invalid_removed"] = removed
        if removed > 0:
            logger.info(f"  Removed {removed} invalid records")

        return df.reset_index(drop=True)

    def _parse_commands(self, df: pd.DataFrame) -> pd.DataFrame:
        """Parse command_sequence from string representation to list."""

        def safe_parse(val):
            if pd.isna(val) or val in ("[]", "unknown", ""):
                return []
            try:
                parsed = ast.literal_eval(str(val))
                return parsed if isinstance(parsed, list) else []
            except (ValueError, SyntaxError):
                return []

        df["command_list"] = df["command_sequence"].apply(safe_parse)
        df["command_count"] = df["command_list"].apply(len)
        return df
