"""
SentinelAI Backend — Users, Entity Timeline & Incident Storyline API Router
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Body
import pandas as pd
from detection.behavioral_identity import BehavioralIdentityEngine
from detection.incident_storyline import IncidentStorylineEngine

router = APIRouter(prefix="/api/v1", tags=["Incident Storyline & Identity Engines"])

_identity_engine = BehavioralIdentityEngine()
_storyline_engine = IncidentStorylineEngine()


@router.get("/users/{user_id}", summary="Get User Baseline Profile & Timeline")
def get_user_profile(user_id: str) -> Dict[str, Any]:
    """Returns entity baseline profile, known devices, and recent telemetry events."""
    profile = _identity_engine.get_profile(user_id)
    return {
        "user_id": user_id,
        "department": profile.get("department", "Engineering"),
        "working_hours": profile.get("working_hours", [8, 18]),
        "login_frequency": profile.get("login_frequency", 10.0),
        "typical_devices": profile.get("typical_devices", ["Corporate-Standard"]),
        "typical_countries": profile.get("typical_countries", ["US"]),
        "normal_resources": profile.get("normal_resources", ["Portal"]),
        "normal_commands": profile.get("normal_commands", ["read"]),
        "avg_session_duration": profile.get("avg_session_duration", 45.0),
        "total_historical_events": profile.get("total_historical_events", 0),
    }


@router.get("/incidents/storyline/{entity_id}", summary="Get Chronological Attack Storyline for Entity")
def get_incident_storyline(entity_id: str) -> Dict[str, Any]:
    """
    Chains isolated telemetry access logs into a chronological 5-stage attack story:
    Login -> Device Anomaly -> Sensitive Resource Access -> Data Exfiltration -> Critical Escalation.
    """
    # Sample mock DataFrame for API demonstration
    mock_events = pd.DataFrame([
        {
            "event_id": "evt-001",
            "timestamp": "2026-01-15T08:15:00Z",
            "user_id": entity_id,
            "action_type": "login",
            "attack_type": "normal",
            "label": "normal",
            "source_ip": "192.168.1.10",
            "geo_location": "London, UK",
            "device_id": "Corporate-MacBook-Pro",
            "resource_accessed": "Internal-Portal",
            "bytes_transferred": 1200,
        },
        {
            "event_id": "evt-002",
            "timestamp": "2026-01-15T08:17:00Z",
            "user_id": entity_id,
            "action_type": "device_anomaly",
            "attack_type": "unrecognized_device",
            "label": "anomaly",
            "source_ip": "192.168.1.10",
            "geo_location": "London, UK",
            "device_id": "Unrecognized-Android-Device",
            "resource_accessed": "Internal-Portal",
            "bytes_transferred": 4500,
        },
        {
            "event_id": "evt-003",
            "timestamp": "2026-01-15T08:22:00Z",
            "user_id": entity_id,
            "action_type": "sensitive_file_access",
            "attack_type": "lateral_movement",
            "label": "anomaly",
            "source_ip": "10.0.4.18",
            "geo_location": "London, UK",
            "device_id": "Unrecognized-Android-Device",
            "resource_accessed": "Payroll-DB-Primary",
            "bytes_transferred": 150000,
        },
        {
            "event_id": "evt-004",
            "timestamp": "2026-01-15T08:25:00Z",
            "user_id": entity_id,
            "action_type": "exfiltration",
            "attack_type": "low_slow_exfiltration",
            "label": "anomaly",
            "source_ip": "10.0.4.18",
            "geo_location": "Tokyo, JP",
            "device_id": "Unrecognized-Android-Device",
            "resource_accessed": "Payroll-DB-Primary",
            "bytes_transferred": 1250000000,
        },
    ])

    storyline = _storyline_engine.build_storyline(mock_events, entity_id)
    return {
        "status": "success",
        "storyline": storyline
    }


@router.post("/behavioral-identity/evaluate", summary="Evaluate Event Deviation Against Behavioral Identity Baseline")
def evaluate_event_behavior(event: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """Consumes access telemetry event and computes behavioral deviation metrics."""
    try:
        result = _identity_engine.evaluate_deviation(event)
        return {
            "status": "success",
            "evaluation": result
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to evaluate behavioral deviation: {str(e)}")
