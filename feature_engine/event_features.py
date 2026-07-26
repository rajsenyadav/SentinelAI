"""
SentinelAI — Per-Event Feature Extraction

Computes features derivable from a single event row combined with
entity-level historical baselines. No rolling windows here —
those are in window_features.py.

Feature Categories:
    1. Temporal features (hour, day, off-hours, weekend)
    2. Geo-velocity features (speed between consecutive logins)
    3. Novelty features (new device, new geo, new resource, new protocol)
    4. Statistical deviation features (z-scores against entity baseline)
    5. Compound features (risk multiplier, bytes/second, auth method change)
    6. Command features (command count, suspicious command flag)
    7. Sensitivity features (resource category risk score)
"""

import math
import logging
from typing import Dict, Set

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resource sensitivity scores (higher = more sensitive)
# ---------------------------------------------------------------------------
RESOURCE_SENSITIVITY = {
    "general": 0.1,
    "email": 0.2,
    "code_repo": 0.4,
    "hr_data": 0.7,
    "finance_data": 0.8,
    "admin_panel": 0.9,
    "infra_config": 1.0,
}

# Suspicious command keywords
SUSPICIOUS_KEYWORDS = {
    "mimikatz", "nmap", "whoami", "/etc/shadow", "/etc/passwd",
    "net user", "net localgroup", "powershell -enc", "certutil",
    "wget http", "chmod +x", "id_rsa", ".pem", "reg query",
    "payload", "whoami /priv",
}


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in km."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class EventFeatureExtractor:
    """
    Computes per-event features. Requires building entity baselines first
    from the training portion of the data.

    Usage:
        extractor = EventFeatureExtractor()
        extractor.build_baselines(df_train)
        df = extractor.transform(df)
    """

    def __init__(self):
        # Per-entity baselines (built from training data)
        self.entity_baselines: Dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Baseline building (from training data)
    # ------------------------------------------------------------------

    def build_baselines(self, df: pd.DataFrame) -> None:
        """
        Compute per-entity statistical baselines from historical data.
        These baselines define what "normal" looks like per entity.
        """
        logger.info("Building per-entity baselines...")

        for entity_id, group in df.groupby("entity_id"):
            hours = group["timestamp"].dt.hour
            baseline = {
                # Temporal
                "mean_hour": hours.mean(),
                "std_hour": hours.std() if len(hours) > 1 else 4.0,

                # Session
                "mean_session_duration": group["session_duration"].mean(),
                "std_session_duration": group["session_duration"].std() if len(group) > 1 else 600.0,

                # Bytes
                "mean_bytes": group["bytes_transferred"].mean(),
                "std_bytes": group["bytes_transferred"].std() if len(group) > 1 else 10000.0,

                # Known sets
                "known_geos": set(group["geo_location"].unique()),
                "known_devices": set(group["device_fingerprint"].unique()),
                "known_resources": set(group["resource_accessed"].unique()),
                "known_categories": set(group["resource_category"].unique()),
                "known_protocols": set(group["protocol"].unique()),

                # Most common auth method
                "primary_auth_method": group["auth_method"].mode().iloc[0] if len(group) > 0 else "unknown",

                # Event count (for cold-start detection)
                "event_count": len(group),
            }

            # Ensure std is never 0 (prevents division by zero in z-scores)
            for key in ["std_hour", "std_session_duration", "std_bytes"]:
                if baseline[key] == 0 or pd.isna(baseline[key]):
                    baseline[key] = 1.0

            self.entity_baselines[entity_id] = baseline

        logger.info(f"  Built baselines for {len(self.entity_baselines)} entities")

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Compute all per-event features. Adds new columns to df.
        """
        df = df.copy().reset_index(drop=True)
        logger.info(f"Extracting per-event features for {len(df)} rows...")

        # 1. Temporal features
        df = self._temporal_features(df)

        # 2. Geo-velocity
        df = self._geo_velocity(df)

        # 3. Novelty features
        df = self._novelty_features(df)

        # 4. Z-score deviation features
        df = self._zscore_features(df)

        # 5. Command features
        df = self._command_features(df)

        # 6. Sensitivity features
        df = self._sensitivity_features(df)

        # 7. Compound features
        df = self._compound_features(df)

        logger.info(f"  Per-event features complete. Columns: {len(df.columns)}")
        return df

    # ------------------------------------------------------------------
    # 1. Temporal features
    # ------------------------------------------------------------------

    def _temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        hour_of_day      — Hour (0–23). Off-hours access is a strong anomaly signal.
        day_of_week       — Day (0=Mon, 6=Sun). Weekend access deviates for office roles.
        is_weekend        — 1 if Saturday/Sunday. Binary flag for quick filtering.
        is_off_hours      — 1 if outside 08:00–19:00. Key signal for exfiltration.
        minutes_since_last — Minutes since this entity's previous event. Burst = brute force.
        """
        df["hour_of_day"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        df["is_off_hours"] = ((df["hour_of_day"] < 8) | (df["hour_of_day"] > 19)).astype(int)

        # Minutes since last event for each entity
        df = df.sort_values(["entity_id", "timestamp"])
        df["prev_timestamp"] = df.groupby("entity_id")["timestamp"].shift(1)
        df["minutes_since_last"] = (
            (df["timestamp"] - df["prev_timestamp"]).dt.total_seconds() / 60.0
        )
        df["minutes_since_last"] = df["minutes_since_last"].fillna(-1)  # -1 = first event
        df.drop(columns=["prev_timestamp"], inplace=True)

        return df

    # ------------------------------------------------------------------
    # 2. Geo-velocity
    # ------------------------------------------------------------------

    def _geo_velocity(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        geo_velocity_kmh — Speed (km/h) between consecutive logins for same entity.
                           > 500 km/h indicates impossible travel.
                           Computed as haversine_distance / time_delta_hours.
        """
        df = df.sort_values(["entity_id", "timestamp"])

        df["prev_lat"] = df.groupby("entity_id")["geo_lat"].shift(1)
        df["prev_lon"] = df.groupby("entity_id")["geo_lon"].shift(1)

        # Compute distance only where previous values exist
        mask = df["prev_lat"].notna()

        distances = np.zeros(len(df))
        for idx in df[mask].index:
            distances[idx] = _haversine_km(
                df.loc[idx, "prev_lat"], df.loc[idx, "prev_lon"],
                df.loc[idx, "geo_lat"], df.loc[idx, "geo_lon"],
            )
        df["geo_distance_km"] = distances

        # Time delta in hours
        time_hours = df["minutes_since_last"] / 60.0
        time_hours = time_hours.replace(0, np.nan)  # avoid division by zero

        df["geo_velocity_kmh"] = (df["geo_distance_km"] / time_hours).fillna(0)

        # Cap extreme values
        df["geo_velocity_kmh"] = df["geo_velocity_kmh"].clip(upper=50000)

        df.drop(columns=["prev_lat", "prev_lon"], inplace=True)
        return df

    # ------------------------------------------------------------------
    # 3. Novelty features
    # ------------------------------------------------------------------

    def _novelty_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Novelty = 1 if the entity has never used/visited this value before
        (based on training baselines). Key signal for lateral movement,
        device spoofing, and impossible travel.

        geo_novelty        — New location for this entity
        device_novelty     — Unknown device fingerprint
        resource_novelty   — Never-accessed resource
        category_novelty   — Never-accessed resource category
        protocol_novelty   — Unusual protocol for this entity
        """
        geo_flags = []
        device_flags = []
        resource_flags = []
        category_flags = []
        protocol_flags = []

        for _, row in df.iterrows():
            baseline = self.entity_baselines.get(row["entity_id"])
            if baseline is None:
                # Cold-start entity: everything is novel
                geo_flags.append(1)
                device_flags.append(1)
                resource_flags.append(1)
                category_flags.append(1)
                protocol_flags.append(1)
                continue

            geo_flags.append(int(row["geo_location"] not in baseline["known_geos"]))
            device_flags.append(int(row["device_fingerprint"] not in baseline["known_devices"]))
            resource_flags.append(int(row["resource_accessed"] not in baseline["known_resources"]))
            category_flags.append(int(row["resource_category"] not in baseline["known_categories"]))
            protocol_flags.append(int(row["protocol"] not in baseline["known_protocols"]))

        df["geo_novelty"] = geo_flags
        df["device_novelty"] = device_flags
        df["resource_novelty"] = resource_flags
        df["category_novelty"] = category_flags
        df["protocol_novelty"] = protocol_flags

        return df

    # ------------------------------------------------------------------
    # 4. Z-score deviation features
    # ------------------------------------------------------------------

    def _zscore_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Z-scores measure how far this event deviates from the entity's
        historical baseline. High absolute z-scores = anomalous.

        hour_zscore             — (event_hour - mean_hour) / std_hour
        session_duration_zscore — deviation from typical session length
        bytes_zscore            — deviation from typical transfer size
        """
        hour_z = []
        session_z = []
        bytes_z = []

        for _, row in df.iterrows():
            baseline = self.entity_baselines.get(row["entity_id"])
            if baseline is None:
                # Cold-start: z-score = 0 (no deviation computable)
                hour_z.append(0.0)
                session_z.append(0.0)
                bytes_z.append(0.0)
                continue

            hour_z.append(
                (row["hour_of_day"] - baseline["mean_hour"]) / baseline["std_hour"]
            )
            session_z.append(
                (row["session_duration"] - baseline["mean_session_duration"]) / baseline["std_session_duration"]
            )
            bytes_z.append(
                (row["bytes_transferred"] - baseline["mean_bytes"]) / baseline["std_bytes"]
            )

        df["hour_zscore"] = np.clip(hour_z, -10, 10)
        df["session_duration_zscore"] = np.clip(session_z, -10, 10)
        df["bytes_zscore"] = np.clip(bytes_z, -10, 10)

        return df

    # ------------------------------------------------------------------
    # 5. Command features
    # ------------------------------------------------------------------

    def _command_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        command_count        — Number of commands in the session. High count
                               with unusual commands = lateral movement.
        suspicious_cmd_flag  — 1 if any command matches known recon/exploit patterns.
        command_diversity    — Ratio of unique commands to total. High diversity
                               in short sessions = scanning behavior.
        """
        # command_count was already computed in preprocessing
        if "command_count" not in df.columns:
            df["command_count"] = 0

        susp_flags = []
        diversity = []
        for _, row in df.iterrows():
            cmds = row.get("command_list", [])
            if not isinstance(cmds, list):
                cmds = []

            # Suspicious flag
            cmd_text = " ".join(str(c).lower() for c in cmds)
            is_suspicious = int(any(kw in cmd_text for kw in SUSPICIOUS_KEYWORDS))
            susp_flags.append(is_suspicious)

            # Diversity
            if len(cmds) > 0:
                unique_cmds = len(set(cmds))
                diversity.append(unique_cmds / len(cmds))
            else:
                diversity.append(0.0)

        df["suspicious_cmd_flag"] = susp_flags
        df["command_diversity"] = diversity

        return df

    # ------------------------------------------------------------------
    # 6. Sensitivity features
    # ------------------------------------------------------------------

    def _sensitivity_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        resource_sensitivity — Risk score (0.0–1.0) based on resource category.
                               Higher = more sensitive data accessed.
                               Amplifies risk when combined with other signals.
        auth_failure_flag    — Binary flag: 1 if auth_status == failure.
        """
        df["resource_sensitivity"] = df["resource_category"].map(RESOURCE_SENSITIVITY).fillna(0.3)
        df["auth_failure_flag"] = (df["auth_status"] == "failure").astype(int)

        return df

    # ------------------------------------------------------------------
    # 7. Compound features
    # ------------------------------------------------------------------

    def _compound_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        risk_multiplier     — Sum of novelty + off-hours flags (0–6 scale).
                              Events with multiple simultaneous anomaly signals
                              are far more likely to be true positives.

        bytes_per_second    — bytes_transferred / session_duration.
                              High-speed extraction indicates automated exfiltration.

        auth_method_change  — 1 if current auth method ≠ entity's most common.
                              Credential compromise often involves method downgrade.

        is_cold_start       — 1 if entity has < 10 events in baseline.
                              Cold-start entities need peer-group comparison.
        """
        df["risk_multiplier"] = (
            df["geo_novelty"]
            + df["device_novelty"]
            + df["resource_novelty"]
            + df["category_novelty"]
            + df["protocol_novelty"]
            + df["is_off_hours"]
        )

        # Bytes per second (avoid divide-by-zero)
        safe_duration = df["session_duration"].replace(0, np.nan)
        df["bytes_per_second"] = (df["bytes_transferred"] / safe_duration).fillna(0)
        df["bytes_per_second"] = df["bytes_per_second"].clip(upper=1_000_000)

        # Auth method change
        auth_change = []
        cold_start = []
        for _, row in df.iterrows():
            baseline = self.entity_baselines.get(row["entity_id"])
            if baseline is None:
                auth_change.append(0)
                cold_start.append(1)
                continue
            auth_change.append(int(row["auth_method"] != baseline["primary_auth_method"]))
            cold_start.append(int(baseline["event_count"] < 10))

        df["auth_method_change"] = auth_change
        df["is_cold_start"] = cold_start

        return df
