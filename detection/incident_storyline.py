"""
Enterprise Incident Storyline Engine for SentinelAI.

Chains isolated telemetry access logs and anomaly alerts into a coherent,
chronological attack story per entity (e.g., Off-Hours Login -> New Device -> Sensitive Access -> Data Exfiltration -> Critical Escalation).
"""

from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np


class IncidentStorylineEngine:
    """Builds chronological multi-stage attack storylines from entity event streams."""

    # Threat Stage Mapping
    STAGE_MAP = {
        "login": "Stage 1: Authentication & Entry",
        "failed_login": "Stage 1: Authentication Failure",
        "device_anomaly": "Stage 2: Device Fingerprint Anomaly",
        "impossible_travel": "Stage 2: Geo-Velocity Anomaly",
        "read_document": "Stage 3: Resource Reconnaissance",
        "sensitive_file_access": "Stage 3: Privilege & Resource Access",
        "data_download": "Stage 4: Data Exfiltration Burst",
        "exfiltration": "Stage 4: Data Exfiltration Burst",
        "escalation": "Stage 5: Critical Incident Escalation",
    }

    def __init__(self):
        pass

    def build_storyline(self, entity_df: pd.DataFrame, entity_id: str) -> Dict[str, Any]:
        """Construct a step-by-step chronological attack storyline for an entity."""
        if entity_df.empty:
            return {
                "entity_id": entity_id,
                "storyline_stages": [],
                "attack_narrative": "No activity recorded for entity.",
                "total_stages": 0,
                "max_risk_stage": "None",
            }

        # Sort chronologically
        df_sorted = entity_df.copy()
        if "timestamp" in df_sorted.columns:
            df_sorted["timestamp"] = pd.to_datetime(df_sorted["timestamp"])
            df_sorted = df_sorted.sort_values("timestamp")

        storyline_stages = []
        highest_severity = "LOW"

        for idx, (_, row) in enumerate(df_sorted.iterrows(), start=1):
            action = str(row.get("action_type", "login")).lower()
            attack = str(row.get("attack_type", "normal")).lower()
            is_anomaly = str(row.get("label", "normal")).lower() == "anomaly"
            ts_str = pd.to_datetime(row.get("timestamp")).strftime("%Y-%m-%d %H:%M:%S")

            # Determine stage title
            if attack in self.STAGE_MAP:
                stage_title = self.STAGE_MAP[attack]
            elif action in self.STAGE_MAP:
                stage_title = self.STAGE_MAP[action]
            elif is_anomaly:
                stage_title = f"Stage {min(5, idx)}: Behavioral Anomaly Detected"
            else:
                stage_title = f"Stage {min(5, idx)}: Baseline Telemetry Log"

            # Severity color coding
            if is_anomaly and attack in ["lateral_movement", "low_slow_exfiltration"]:
                severity = "CRITICAL"
                color = "#dc2626"
                highest_severity = "CRITICAL"
            elif is_anomaly:
                severity = "HIGH"
                color = "#ea580c"
                if highest_severity != "CRITICAL":
                    highest_severity = "HIGH"
            else:
                severity = "INFO"
                color = "#2563eb"

            # Construct evidence breakdown
            evidence = []
            if row.get("geo_location"):
                evidence.append(f"Geo Location: {row['geo_location']}")
            if row.get("device_id"):
                evidence.append(f"Device Fingerprint: {row['device_id']}")
            if row.get("resource_accessed"):
                evidence.append(f"Resource Target: {row['resource_accessed']}")
            if row.get("bytes_transferred", 0) > 0:
                evidence.append(f"Data Volume: {row['bytes_transferred']:,.0f} bytes")

            storyline_stages.append({
                "step_number": idx,
                "timestamp": ts_str,
                "stage_title": stage_title,
                "action": action.replace("_", " ").title(),
                "attack_vector": attack.replace("_", " ").title(),
                "severity": severity,
                "color": color,
                "evidence_chain": evidence,
                "event_id": str(row.get("event_id", f"evt-{idx:03d}")),
            })

        # Build natural narrative summary
        if len(storyline_stages) == 1:
            narrative = f"Single event recorded for {entity_id} at {storyline_stages[0]['timestamp']}."
        else:
            first_ts = storyline_stages[0]["timestamp"]
            last_ts = storyline_stages[-1]["timestamp"]
            anomaly_steps = [s for s in storyline_stages if s["severity"] in ["CRITICAL", "HIGH"]]
            
            if anomaly_steps:
                narrative = (
                    f"Incident storyline initiated at {first_ts} with initial entry. "
                    f"Progressed through {len(storyline_stages)} chronological stages, escalating to "
                    f"a {highest_severity} incident at {last_ts}. "
                    f"{len(anomaly_steps)} anomalous stages identified in the chain."
                )
            else:
                narrative = f"Normal user activity trace across {len(storyline_stages)} events between {first_ts} and {last_ts}."

        return {
            "entity_id": entity_id,
            "total_stages": len(storyline_stages),
            "highest_severity": highest_severity,
            "attack_narrative": narrative,
            "storyline_stages": storyline_stages,
        }
