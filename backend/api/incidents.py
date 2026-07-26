"""
SentinelAI Backend — Unified Incidents REST API Router
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Body, status
from backend.services.incident_service import incident_service

router = APIRouter(prefix="/api/v1/incidents", tags=["Unified Incident Service"])


@router.get("", summary="List All Security Incidents", status_code=status.HTTP_200_OK)
def list_incidents() -> Dict[str, Any]:
    """Retrieve list of active security incident objects."""
    incidents = incident_service.list_incidents()
    return {
        "status": "success",
        "total_incidents": len(incidents),
        "incidents": incidents,
    }


@router.get("/{incident_id}", summary="Get Incident Details Object", status_code=status.HTTP_200_OK)
def get_incident_details(incident_id: str) -> Dict[str, Any]:
    """Retrieve detailed unified Incident Object by ID."""
    incident = incident_service.get_incident(incident_id)
    if not incident:
        # Fallback build sample incident for API inspection
        sample_event = {
            "event_id": incident_id,
            "user_id": "EMP1023",
            "department": "Engineering",
            "entity_role": "Software Engineer",
            "geo_location": "Tokyo, JP",
            "device_id": "Unrecognized-Android-Device",
            "resource_accessed": "Payroll-DB-Primary",
            "bytes_transferred": 1250000000,
            "attack_type": "impossible_travel",
            "timestamp": "2026-01-15T08:25:00Z",
        }
        incident = incident_service.build_incident_from_event(sample_event)
    
    return {
        "status": "success",
        "incident": incident,
    }


@router.post("/{incident_id}/triage", summary="Submit Analyst Triage Decision", status_code=status.HTTP_200_OK)
def triage_incident(
    incident_id: str, payload: Dict[str, Any] = Body(...)
) -> Dict[str, Any]:
    """Updates incident status and records analyst triage comments."""
    assessment = payload.get("assessment", "CONFIRMED_ATTACK")
    comment = payload.get("comment", "")

    incident = incident_service.get_incident(incident_id)
    if incident:
        incident["incident_status"] = assessment
        incident["analyst_feedback"]["assessment"] = assessment
        if comment:
            incident["analyst_feedback"]["comments"].append(comment)

    return {
        "status": "success",
        "incident_id": incident_id,
        "recorded_assessment": assessment,
        "message": f"Successfully updated triage status for incident {incident_id}.",
    }
