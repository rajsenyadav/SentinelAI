"""
SentinelAI Backend — Alerts, Prediction & AI Copilot API Router
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status, Body
from pydantic import BaseModel, Field
import numpy as np

from ..services.pipeline_service import pipeline_service
from detection.ai_analyst_copilot import AIAnalystCopilot

router = APIRouter(prefix="/api/v1", tags=["Alerts & Predictions"])
_copilot_engine = AIAnalystCopilot()


class TelemetryEventRequest(BaseModel):
    event_id: str = Field(default="evt-1001", description="Unique event identifier")
    timestamp: str = Field(default="2026-01-15T14:30:00Z", description="ISO 8601 UTC timestamp")
    entity_id: str = Field(default="EMP1023", description="User / Device / Service ID")
    entity_type: str = Field(default="user", description="user, service_account, or edge_device")
    entity_role: str = Field(default="employee", description="Role profile")
    department: str = Field(default="Engineering", description="Department name")
    source_ip: str = Field(default="192.168.1.50", description="Origin IP address")
    geo_location: str = Field(default="London, UK", description="Geographic location")
    geo_lat: float = Field(default=51.5074, description="Latitude")
    geo_lon: float = Field(default=-0.1278, description="Longitude")
    resource_accessed: str = Field(default="/api/v1/auth", description="Resource target path")
    resource_category: str = Field(default="general", description="Resource category enum")
    action_type: str = Field(default="login", description="Action enum")
    auth_method: str = Field(default="password", description="Authentication method")
    auth_status: str = Field(default="success", description="success or failure")
    session_duration: int = Field(default=300, description="Session length in seconds")
    bytes_transferred: int = Field(default=2048, description="Bytes transferred")
    device_fingerprint: str = Field(default="fp-8f2a1b9c", description="Device hash")
    device_os: str = Field(default="Windows", description="Client OS")
    user_agent: str = Field(default="Mozilla/5.0", description="User agent string")
    protocol: str = Field(default="HTTPS", description="Network protocol")
    command_sequence: str = Field(default="[]", description="Privileged command sequence")
    is_vpn: bool = Field(default=False, description="VPN flag")


@router.post("/predict", summary="Predict Threat & Explain Event", status_code=status.HTTP_200_OK)
def predict_event(event: TelemetryEventRequest) -> Dict[str, Any]:
    """
    Evaluates an incoming raw telemetry access event through the entire AI pipeline:
    Feature Engineering -> Anomaly Detector -> Attack Classifier -> Risk Engine -> SHAP Explainer
    """
    try:
        raw_dict = event.dict()
        result = pipeline_service.process_single_event(raw_dict)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline evaluation failed: {str(e)}")


@router.post("/copilot/investigate", summary="Generate AI Analyst Copilot Investigation Brief", status_code=status.HTTP_200_OK)
def copilot_investigate(event: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
    """
    Consumes telemetry incident data and produces an executive 10-point AI Copilot Brief:
    - Executive Summary & Why Detected
    - MITRE ATT&CK TTP Alignment
    - Business Impact & Supporting Evidence Chain
    - Executable PowerShell / CLI Containment Script
    - Estimated Investigation Time Savings (15-20 mins)
    """
    try:
        brief = _copilot_engine.generate_investigation_brief(event)
        return {
            "status": "success",
            "copilot_brief": brief
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate Copilot brief: {str(e)}")


@router.post("/generate-log", summary="Generate Synthetic Telemetry Event", status_code=status.HTTP_201_CREATED)
def generate_log(attack_type: Optional[str] = Query(default="random")) -> Dict[str, Any]:
    """Triggers creation of a synthetic telemetry log event."""
    mock_event = {
        "event_id": "evt-generated-001",
        "entity_id": "EMP8841",
        "attack_type": attack_type,
        "status": "created"
    }
    return mock_event
