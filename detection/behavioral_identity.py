"""
Behavioral Identity Engine for SentinelAI.

Constructs baseline behavioral profiles per employee/entity from historical telemetry
and calculates deviation percentages, top anomaly drivers, and human-readable explanations.
Does NOT require retraining existing ML models — consumes existing model & telemetry outputs.
"""

import math
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


class BehavioralIdentityEngine:
    """Computes entity behavioral profiles and calculates deviation metrics during anomalies."""

    def __init__(self, historical_df: Optional[pd.DataFrame] = None):
        self.profiles: Dict[str, Dict[str, Any]] = {}
        if historical_df is not None and not historical_df.empty:
            self.build_profiles(historical_df)

    def build_profiles(self, df: pd.DataFrame) -> Dict[str, Dict[str, Any]]:
        """Build historical baseline profiles for all entities in the dataset."""
        # Ensure timestamp is datetime
        df_copy = df.copy()
        if "timestamp" in df_copy.columns:
            df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"])
            df_copy["hour"] = df_copy["timestamp"].dt.hour

        entity_col = "user_id" if "user_id" in df_copy.columns else "entity_id" if "entity_id" in df_copy.columns else None

        if not entity_col:
            return {}

        grouped = df_copy.groupby(entity_col)

        for entity_id, group in grouped:
            # Calculate working hours range (10th to 90th percentile of hours)
            hours = group["hour"].tolist() if "hour" in group.columns else [9, 17]
            min_hr = int(np.percentile(hours, 10)) if len(hours) > 1 else min(hours, default=8)
            max_hr = int(np.percentile(hours, 90)) if len(hours) > 1 else max(hours, default=18)

            # Login / Action frequency
            total_events = len(group)
            num_days = max(1, (group["timestamp"].max() - group["timestamp"].min()).days) if "timestamp" in group.columns else 1
            login_freq = round(total_events / num_days, 1)

            # Typical devices
            devices = group["device_id"].unique().tolist() if "device_id" in group.columns else ["Corporate-Desktop"]

            # Typical countries
            countries = group["geo_location"].unique().tolist() if "geo_location" in group.columns else ["US"]

            # Normal resources
            resources = group["resource_accessed"].unique().tolist() if "resource_accessed" in group.columns else ["Internal-Portal"]

            # Normal commands / actions
            commands = group["action_type"].unique().tolist() if "action_type" in group.columns else ["read_document"]

            # Department
            department = group["department"].iloc[0] if "department" in group.columns else "Engineering"

            # Average session duration / data volume
            avg_duration = round(float(group["session_duration"].mean()), 1) if "session_duration" in group.columns else 45.0
            avg_bytes = round(float(group["bytes_transferred"].mean()), 1) if "bytes_transferred" in group.columns else 1500.0

            self.profiles[str(entity_id)] = {
                "entity_id": str(entity_id),
                "department": department,
                "working_hours": [min_hr, max_hr],
                "login_frequency": login_freq,
                "typical_devices": set(devices),
                "typical_countries": set(countries),
                "normal_resources": set(resources),
                "normal_commands": set(commands),
                "avg_session_duration": avg_duration,
                "avg_bytes_transferred": avg_bytes,
                "total_historical_events": total_events,
            }

        return self.profiles

    def get_profile(self, entity_id: str) -> Dict[str, Any]:
        """Retrieve baseline profile for an entity, returning defaults if unknown."""
        entity_id_str = str(entity_id)
        if entity_id_str in self.profiles:
            prof = self.profiles[entity_id_str].copy()
            # Convert sets to lists for JSON serialization
            prof["typical_devices"] = list(prof["typical_devices"])
            prof["typical_countries"] = list(prof["typical_countries"])
            prof["normal_resources"] = list(prof["normal_resources"])
            prof["normal_commands"] = list(prof["normal_commands"])
            return prof

        return {
            "entity_id": entity_id_str,
            "department": "Unknown",
            "working_hours": [8, 18],
            "login_frequency": 10.0,
            "typical_devices": ["Corporate-Standard"],
            "typical_countries": ["US"],
            "normal_resources": ["General-App"],
            "normal_commands": ["read"],
            "avg_session_duration": 30.0,
            "avg_bytes_transferred": 1000.0,
            "total_historical_events": 0,
        }

    def evaluate_deviation(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Compare a current access event against historical baseline to compute deviation metrics."""
        entity_id = str(event.get("user_id") or event.get("entity_id") or "UNKNOWN")
        profile = self.get_profile(entity_id)

        top_deviations = []
        risk_contributions = {}
        total_weight = 0.0
        weighted_score = 0.0

        # 1. Working Hours Check (Weight: 20%)
        ts = pd.to_datetime(event.get("timestamp", pd.Timestamp.now()))
        event_hour = ts.hour
        min_hr, max_hr = profile["working_hours"]
        hour_weight = 20.0
        total_weight += hour_weight

        if event_hour < min_hr or event_hour > max_hr:
            hr_diff = min(abs(event_hour - min_hr), abs(event_hour - max_hr))
            dev = min(1.0, hr_diff / 6.0)
            weighted_score += dev * hour_weight
            risk_contributions["off_hours_access"] = round(dev * hour_weight, 1)
            top_deviations.append({
                "factor": "Off-Hours Access",
                "severity": "High" if dev > 0.6 else "Medium",
                "detail": f"Access at {event_hour:02d}:00 outside baseline working hours ({min_hr:02d}:00–{max_hr:02d}:00)",
                "weight_pct": 20.0,
            })
        else:
            risk_contributions["off_hours_access"] = 0.0

        # 2. Country / Geo Check (Weight: 25%)
        geo = str(event.get("geo_location", "US"))
        geo_weight = 25.0
        total_weight += geo_weight

        if geo not in profile["typical_countries"]:
            weighted_score += 1.0 * geo_weight
            risk_contributions["unusual_location"] = round(geo_weight, 1)
            top_deviations.append({
                "factor": "Unusual Geographic Location",
                "severity": "Critical",
                "detail": f"Access from '{geo}' not in typical country list ({', '.join(profile['typical_countries'])})",
                "weight_pct": 25.0,
            })
        else:
            risk_contributions["unusual_location"] = 0.0

        # 3. Device Check (Weight: 15%)
        device = str(event.get("device_id", "Unknown-Device"))
        dev_weight = 15.0
        total_weight += dev_weight

        if device not in profile["typical_devices"]:
            weighted_score += 1.0 * dev_weight
            risk_contributions["unrecognized_device"] = round(dev_weight, 1)
            top_deviations.append({
                "factor": "Unrecognized Device",
                "severity": "Medium",
                "detail": f"Device '{device}' not in baseline approved devices",
                "weight_pct": 15.0,
            })
        else:
            risk_contributions["unrecognized_device"] = 0.0

        # 4. Resource Check (Weight: 20%)
        resource = str(event.get("resource_accessed", "Portal"))
        res_weight = 20.0
        total_weight += res_weight

        if resource not in profile["normal_resources"]:
            weighted_score += 1.0 * res_weight
            risk_contributions["sensitive_resource_access"] = round(res_weight, 1)
            top_deviations.append({
                "factor": "Unusual Resource Access",
                "severity": "High",
                "detail": f"Resource '{resource}' never accessed previously by this user",
                "weight_pct": 20.0,
            })
        else:
            risk_contributions["sensitive_resource_access"] = 0.0

        # 5. Data Transfer Volume / Session Duration Check (Weight: 20%)
        bytes_tx = float(event.get("bytes_transferred", 0.0))
        avg_bytes = profile["avg_bytes_transferred"]
        vol_weight = 20.0
        total_weight += vol_weight

        if bytes_tx > avg_bytes * 3.0:
            ratio = round(bytes_tx / max(1.0, avg_bytes), 1)
            dev = min(1.0, (ratio - 1.0) / 10.0)
            weighted_score += dev * vol_weight
            risk_contributions["abnormal_data_volume"] = round(dev * vol_weight, 1)
            top_deviations.append({
                "factor": "Abnormal Data Volume Exfiltration",
                "severity": "Critical" if ratio > 5.0 else "High",
                "detail": f"Transferred {bytes_tx:,.0f} bytes ({ratio}x higher than baseline mean of {avg_bytes:,.0f} bytes)",
                "weight_pct": 20.0,
            })
        else:
            risk_contributions["abnormal_data_volume"] = 0.0

        # Overall Deviation Percentage
        deviation_pct = round((weighted_score / total_weight) * 100.0, 1) if total_weight > 0 else 0.0

        # Construct Human-Readable Explanation
        if not top_deviations:
            human_explanation = f"Entity '{entity_id}' behavior aligns 100% with historical baseline parameters."
            summary = "Normal Behavioral Alignment"
        else:
            top_factors = [d["factor"] for d in top_deviations]
            human_explanation = (
                f"Entity '{entity_id}' demonstrated a {deviation_pct}% overall behavioral deviation. "
                f"Primary anomaly drivers: {', '.join(top_factors)}. "
                f"Access event flagged for security analyst review."
            )
            summary = f"High Behavioral Shift ({deviation_pct}% Deviation)"

        return {
            "entity_id": entity_id,
            "deviation_percentage": deviation_pct,
            "behavior_summary": summary,
            "top_deviations": top_deviations,
            "risk_contributions": risk_contributions,
            "human_explanation": human_explanation,
            "historical_baseline": profile,
        }
