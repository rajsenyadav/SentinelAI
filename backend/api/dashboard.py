"""
SentinelAI Backend — Dashboard API Router
"""

from typing import Dict, Any
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["Dashboard"])


@router.get("/dashboard", summary="Fetch High-Level Dashboard Statistics")
def get_dashboard_metrics() -> Dict[str, Any]:
    """
    Returns top-level SOC dashboard metrics (Total Events, Active Threats, High Risk Alerts, Critical Incidents).
    """
    return {
        "total_events": 100000,
        "normal_events": 97850,
        "active_threats": 2150,
        "high_risk_alerts": 1200,
        "critical_incidents": 450,
        "system_status": "OPERATIONAL",
        "last_updated": "2026-07-26T11:50:00Z",
    }
