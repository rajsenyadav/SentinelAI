"""
SentinelAI — Rolling Window Aggregations

Computes time-windowed aggregated features per entity and per source IP.
Captures sequential patterns, velocity spikes, and accumulation over time.

Features Computed:
    1. failed_auth_count_1h         — Auth failures for entity in rolling 1-hour window (Brute Force)
    2. failed_auth_count_24h        — Auth failures for entity in rolling 24-hour window (Sustained attack)
    3. unique_resources_1h          — Distinct resources accessed by entity in 1 hour (Lateral Movement)
    4. unique_resources_24h         — Distinct resources accessed by entity in 24 hours (Broad Scanning)
    5. unique_geos_24h             — Distinct locations for entity in 24 hours (Impossible Travel / Multi-IP)
    6. unique_entities_per_ip_1h    — Distinct entities targeted from source_ip in 1 hour (Credential Stuffing)
    7. off_hours_event_count_7d     — Off-hours access events by entity over 7 days (Exfiltration)
    8. bytes_total_24h             — Total bytes transferred by entity in 24 hours (Exfiltration volume)
    9. auth_failure_rate_1h        — Ratio of failed auths to total events in 1 hour (Brute Force / Stuffing)
"""

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


class WindowFeatureExtractor:
    """
    Computes rolling window aggregation features using robust time-series indexing.
    """

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute rolling window features. Assumes df is sorted by timestamp.
        """
        df = df.copy().sort_values("timestamp").reset_index(drop=True)
        logger.info(f"Extracting rolling window features for {len(df)} rows...")

        # 1. Entity-based rolling windows
        df = self._entity_rolling_features(df)

        # 2. IP-based rolling windows (Credential stuffing detection)
        df = self._ip_rolling_features(df)

        logger.info(f"  Window features complete. Columns: {len(df.columns)}")
        return df

    def _entity_rolling_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Rolling window features grouped by entity_id."""

        df["_is_failure"] = (df["auth_status"] == "failure").astype(int)
        df["_is_off_hours"] = df["is_off_hours"].astype(int)

        # Convert timestamp to DatetimeIndex
        ts_dt = pd.to_datetime(df["timestamp"])
        df_indexed = df.copy()
        df_indexed.index = ts_dt

        # 1-hour entity rolling windows
        entity_grp = df_indexed.groupby("entity_id")

        failed_1h = entity_grp["_is_failure"].rolling("1h", closed="left").sum()
        df["failed_auth_count_1h"] = failed_1h.values if len(failed_1h) == len(df) else failed_1h.reset_index(level=0, drop=True).reindex(df_indexed.index).fillna(0).values

        total_1h = entity_grp["_is_failure"].rolling("1h", closed="left").count()
        df["total_events_1h"] = total_1h.values if len(total_1h) == len(df) else total_1h.reset_index(level=0, drop=True).reindex(df_indexed.index).fillna(0).values

        df["failed_auth_count_1h"] = df["failed_auth_count_1h"].fillna(0).astype(int)
        df["total_events_1h"] = df["total_events_1h"].fillna(0).astype(int)

        df["auth_failure_rate_1h"] = (
            df["failed_auth_count_1h"] / df["total_events_1h"].replace(0, 1)
        ).fillna(0.0)

        # 24-hour entity rolling windows
        failed_24h = entity_grp["_is_failure"].rolling("24h", closed="left").sum()
        df["failed_auth_count_24h"] = (failed_24h.values if len(failed_24h) == len(df) else failed_24h.reset_index(level=0, drop=True).reindex(df_indexed.index).fillna(0).values)
        df["failed_auth_count_24h"] = df["failed_auth_count_24h"].fillna(0).astype(int)

        bytes_24h = entity_grp["bytes_transferred"].rolling("24h", closed="left").sum()
        df["bytes_total_24h"] = (bytes_24h.values if len(bytes_24h) == len(df) else bytes_24h.reset_index(level=0, drop=True).reindex(df_indexed.index).fillna(0).values)
        df["bytes_total_24h"] = df["bytes_total_24h"].fillna(0.0).astype(float)

        # 7-day entity rolling window for off-hours accumulation
        off_7d = entity_grp["_is_off_hours"].rolling("7d", closed="left").sum()
        df["off_hours_event_count_7d"] = (off_7d.values if len(off_7d) == len(df) else off_7d.reset_index(level=0, drop=True).reindex(df_indexed.index).fillna(0).values)
        df["off_hours_event_count_7d"] = df["off_hours_event_count_7d"].fillna(0).astype(int)

        # Unique counts (resources, geos) in 1h and 24h windows
        df["unique_resources_1h"] = self._rolling_unique(df, "entity_id", "resource_accessed", "1h")
        df["unique_resources_24h"] = self._rolling_unique(df, "entity_id", "resource_accessed", "24h")
        df["unique_geos_24h"] = self._rolling_unique(df, "entity_id", "geo_location", "24h")

        # Cleanup temp columns
        df.drop(columns=["_is_failure", "_is_off_hours", "total_events_1h"], inplace=True)
        return df

    def _ip_rolling_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Rolling window features grouped by source_ip to catch Credential Stuffing."""
        df["unique_entities_per_ip_1h"] = self._rolling_unique(df, "source_ip", "entity_id", "1h")
        return df

    def _rolling_unique(
        self, df: pd.DataFrame, group_col: str, target_col: str, window: str
    ) -> pd.Series:
        """
        Calculates rolling unique target_col values per group_col over specified window.
        """
        return self._fast_rolling_nunique(df, group_col, target_col, window)

    def _fast_rolling_nunique(
        self, df: pd.DataFrame, group_col: str, target_col: str, window: str
    ) -> pd.Series:
        """Fast vectorized rolling nunique computation using NumPy arrays."""
        window_sec = pd.Timedelta(window).total_seconds()

        # Extract underlying numpy arrays to avoid pandas index KeyError bugs
        ts_datetime = pd.to_datetime(df["timestamp"], utc=True)
        timestamps = (ts_datetime.astype("int64") // 10**9).values
        groups = df[group_col].values
        targets = df[target_col].values

        n_rows = len(df)
        counts = np.ones(n_rows, dtype=int)

        # Per group sliding window calculation
        unique_groups = np.unique(groups)
        for g in unique_groups:
            idx = np.where(groups == g)[0]
            if len(idx) <= 1:
                continue

            g_times = timestamps[idx]
            g_targets = targets[idx]

            left = 0
            for right in range(len(idx)):
                while g_times[right] - g_times[left] > window_sec:
                    left += 1
                counts[idx[right]] = len(set(g_targets[left : right + 1]))

        return pd.Series(counts, index=df.index).astype(int)
