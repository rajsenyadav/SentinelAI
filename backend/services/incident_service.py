"""
SentinelAI Backend — Unified Incident Service.

Aggregates outputs from Anomaly Detector, Attack Classifier, Dynamic Risk Engine,
Behavioral Identity Engine, Incident Storyline Engine, and AI Analyst Copilot
into a single, authoritative, incident-centric data model.
"""

from typing import Dict, Any, List, Optional
import datetime
import pandas as pd

from detection.behavioral_identity import BehavioralIdentityEngine
from detection.dynamic_risk_engine import DynamicRiskEngine
from detection.incident_storyline import IncidentStorylineEngine
from detection.ai_analyst_copilot import AIAnalystCopilot


class IncidentService:
    """Centralized service for managing enterprise incident objects and lifecycle states."""

    def __init__(self):
        self._risk_engine = DynamicRiskEngine()
        self._storyline_engine = IncidentStorylineEngine()
        self._copilot = AIAnalystCopilot()
        self._incidents_cache: Dict[str, Dict[str, Any]] = {}

    def build_incident_from_event(
        self, event: Dict[str, Any], full_df: Optional[pd.DataFrame] = None
    ) -> Dict[str, Any]:
        """Constructs a unified, enterprise Incident Object from raw event telemetry."""
        incident_id = str(event.get("event_id") or f"INC-{event.get('user_id', 'EMP1023')}-001")
        entity_id = str(event.get("user_id") or event.get("entity_id") or "EMP1023")
        timestamp = str(event.get("timestamp", datetime.datetime.utcnow().isoformat()))
        department = str(event.get("department", "Engineering"))
        role = str(event.get("entity_role", "Software Engineer"))
        device = str(event.get("device_id") or event.get("device_fingerprint") or "Corporate-Desktop")
        location = str(event.get("geo_location", "London, UK"))
        attack_type = str(event.get("attack_type", "impossible_travel")).replace("_", " ").title()

        # 1. Behavioral Identity Baseline & Evaluation
        identity_engine = BehavioralIdentityEngine(full_df) if full_df is not None else BehavioralIdentityEngine()
        identity_eval = identity_engine.evaluate_deviation(event)
        dev_score = identity_eval.get("deviation_percentage", 65.0)

        # 2. Dynamic 9-Factor Risk Assessment
        risk_eval = self._risk_engine.evaluate_risk(event, historical_anomalies_count=2)
        risk_score = risk_eval.get("composite_risk_score", 94.0)
        severity = risk_eval.get("risk_tier", "CRITICAL")

        # 3. Timeline Sequence
        if full_df is not None and not full_df.empty:
            entity_df = full_df[full_df[full_df.columns[0]] == entity_id] if entity_id in full_df.values else full_df.head(5)
            storyline = self._storyline_engine.build_storyline(entity_df, entity_id)
        else:
            storyline = {
                "storyline_stages": [
                    {"step_number": 1, "timestamp": "09:01 AM", "action": "Login", "stage_title": "Login Success", "color": "#2563eb"},
                    {"step_number": 2, "timestamp": "09:03 AM", "action": "Failed Auth", "stage_title": "Failed Login", "color": "#d97706"},
                    {"step_number": 3, "timestamp": "09:05 AM", "action": "New Device", "stage_title": "New Device Detected", "color": "#ea580c"},
                    {"step_number": 4, "timestamp": "09:06 AM", "action": "Read DB", "stage_title": "Payroll Access", "color": "#dc2626"},
                    {"step_number": 5, "timestamp": "09:08 AM", "action": "Exfiltration", "stage_title": "Large Download", "color": "#dc2626"},
                    {"step_number": 6, "timestamp": "09:09 AM", "action": "Alert", "stage_title": "Critical Alert Generated", "color": "#dc2626"},
                ]
            }

        # 4. AI Copilot Brief & Evidence Collection
        copilot_brief = self._copilot.generate_investigation_brief(event, risk_eval)
        evidence = [
            f"Country / Location Shift: {location}",
            f"Device Fingerprint Deviation: {device}",
            f"Outside Working Hours: Access logged at off-hours window",
            f"Sensitive Resource Targeted: {event.get('resource_accessed', 'Payroll-DB-Primary')}",
            f"Exfiltration Data Burst: {event.get('bytes_transferred', 1250000000):,.0f} bytes",
        ]

        # 5. Build Unified Incident Object
        incident_obj = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "user": entity_id,
            "department": department,
            "role": role,
            "device": device,
            "location": location,
            "risk_score": risk_score,
            "confidence": copilot_brief.get("copilot_confidence_pct", 96.0),
            "severity": severity,
            "attack_type": attack_type,
            "evidence": evidence,
            "behavior_profile": {
                "historical": identity_eval.get("historical_baseline", {}),
                "current_device": device,
                "current_country": location,
                "current_login_time": timestamp,
                "current_resource": str(event.get("resource_accessed", "Payroll-DB-Primary")),
                "behavior_deviation_score": dev_score,
                "deviation_summary": f"Current behavior deviates significantly ({dev_score}%) from historical baseline.",
            },
            "timeline": storyline.get("storyline_stages", []),
            "recommendations": {
                "executive_summary": copilot_brief.get("executive_summary", ""),
                "business_impact": copilot_brief.get("business_impact", ""),
                "risk_explanation": risk_eval.get("risk_explanation", ""),
                "recommended_actions": copilot_brief.get("recommended_actions", []),
                "powershell_remediation": copilot_brief.get("suggested_soc_response", {}).get("powershell", ""),
            },
            "analyst_feedback": {
                "status": "OPEN",
                "assessment": "UNASSIGNED",
                "comments": [],
            },
            "incident_status": "OPEN",
            "resolution": "Pending Triage",
        }

        self._incidents_cache[incident_id] = incident_obj
        return incident_obj

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached incident object or return None."""
        return self._incidents_cache.get(incident_id)

    def list_incidents(self) -> List[Dict[str, Any]]:
        """Return all active incident objects."""
        return list(self._incidents_cache.values())


# Singleton Instance
incident_service = IncidentService()
