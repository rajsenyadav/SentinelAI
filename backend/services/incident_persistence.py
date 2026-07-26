"""
SentinelAI Persistence Service — Persistent CSV Analyst Feedback & Audit Logging

Manages persistent read/write operations for security incident triage statuses and
maintains a separate `analyst_actions.csv` audit trail log.
"""

import os
import sys
import datetime
import logging
import pandas as pd

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROC_CSV_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "engineered_dataset.csv")
AUDIT_LOG_PATH = os.path.join(PROJECT_ROOT, "data", "processed", "analyst_actions.csv")


def ensure_persistence_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Ensures required persistence fields exist on the DataFrame."""
    if "status" not in df.columns:
        df["status"] = df["label"].apply(lambda l: "LIVE_THREAT" if l == "anomaly" else "BENIGN")
    if "analyst_feedback" not in df.columns:
        df["analyst_feedback"] = ""
    if "last_updated" not in df.columns:
        df["last_updated"] = ""
    if "updated_by" not in df.columns:
        df["updated_by"] = ""

    return df


def update_incident_status(
    incident_id: str,
    new_status: str,
    analyst: str = "Raj Sen (SOC Analyst)",
    remarks: str = "",
) -> bool:
    """
    Persists an incident status update directly to engineered_dataset.csv
    and appends an entry to analyst_actions.csv audit log.
    """
    if not os.path.exists(PROC_CSV_PATH):
        logger.warning(f"CSV file not found at {PROC_CSV_PATH}")
        return False

    try:
        # 1. Read main dataset
        df = pd.read_csv(PROC_CSV_PATH)
        df = ensure_persistence_schema(df)

        match_mask = (df["event_id"] == incident_id)
        if not match_mask.any() and "user_id" in df.columns:
            match_mask = (df["user_id"] == incident_id)

        if not match_mask.any():
            logger.error(f"Incident ID {incident_id} not found in dataset CSV.")
            return False

        previous_status = str(df.loc[match_mask, "status"].values[0])
        now_iso = datetime.datetime.utcnow().isoformat()

        # Update primary dataset columns
        df.loc[match_mask, "status"] = new_status
        if remarks:
            existing_fb = str(df.loc[match_mask, "analyst_feedback"].values[0] or "")
            df.loc[match_mask, "analyst_feedback"] = f"{existing_fb} | {remarks}".strip(" |")
        df.loc[match_mask, "last_updated"] = now_iso
        df.loc[match_mask, "updated_by"] = analyst

        # Reclassify label to normal if False Positive or Resolved
        if new_status in ["FALSE_POSITIVE", "RESOLVED"]:
            df.loc[match_mask, "label"] = "normal"
            df.loc[match_mask, "attack_type"] = "normal"
        elif new_status in ["CONFIRMED_THREAT", "UNDER_INVESTIGATION"]:
            df.loc[match_mask, "label"] = "anomaly"

        # Write updated primary CSV back to disk
        df.to_csv(PROC_CSV_PATH, index=False)

        # 2. Append to audit log (analyst_actions.csv)
        audit_entry = {
            "timestamp": now_iso,
            "incident_id": incident_id,
            "previous_status": previous_status,
            "new_status": new_status,
            "analyst": analyst,
            "remarks": remarks,
        }
        df_audit_new = pd.DataFrame([audit_entry])

        if os.path.exists(AUDIT_LOG_PATH):
            df_audit_new.to_csv(AUDIT_LOG_PATH, mode="a", header=False, index=False)
        else:
            df_audit_new.to_csv(AUDIT_LOG_PATH, mode="w", header=True, index=False)

        logger.info(f"Persisted status update for {incident_id}: {previous_status} -> {new_status}")
        return True

    except Exception as e:
        logger.error(f"Error persisting status update: {str(e)}")
        return False


def get_audit_log() -> pd.DataFrame:
    """Read full analyst_actions.csv audit trail."""
    if os.path.exists(AUDIT_LOG_PATH):
        return pd.read_csv(AUDIT_LOG_PATH)
    return pd.DataFrame(columns=["timestamp", "incident_id", "previous_status", "new_status", "analyst", "remarks"])
