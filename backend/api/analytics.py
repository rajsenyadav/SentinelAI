"""
SentinelAI Backend — Cyber Threat Analytics API Router
"""

from typing import Dict, Any
from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["Analytics"])


@router.get("/analytics", summary="Get Threat Vector & Risk Analytics")
def get_analytics() -> Dict[str, Any]:
    """
    Returns threat category distributions, department risk breakdowns, and time-series incident trends.
    """
    return {
        "attack_distribution": {
            "Brute Force": 500,
            "Lateral Movement": 500,
            "Low & Slow Exfiltration": 500,
            "Credential Stuffing": 400,
            "Impossible Travel": 300,
            "Device Spoofing": 300,
        },
        "department_threats": {
            "Engineering": 750,
            "Finance": 420,
            "HR": 310,
            "IT Admin": 670,
        },
        "hourly_trend": [
            {"hour": "00:00", "count": 45},
            {"hour": "04:00", "count": 120},
            {"hour": "08:00", "count": 35},
            {"hour": "12:00", "count": 28},
            {"hour": "16:00", "count": 55},
            {"hour": "20:00", "count": 210},
        ]
    }
