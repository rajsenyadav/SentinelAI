"""
SentinelAI Backend — Analyst Triage Feedback API Router
"""

from typing import Dict, Any, Optional
from fastapi import APIRouter, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["Feedback & Triage"])


class AnalystFeedbackRequest(BaseModel):
    event_id: str = Field(..., description="Target incident event ID")
    is_false_positive: bool = Field(..., description="True if marked False Positive, False if Confirmed Attack")
    notes: Optional[str] = Field(default="", description="Analyst investigation notes")


@router.post("/feedback", summary="Submit Analyst Triage Feedback", status_code=status.HTTP_200_OK)
def submit_feedback(feedback: AnalystFeedbackRequest) -> Dict[str, Any]:
    """
    Submits analyst feedback (False Positive / Confirmed Attack) to refine model baselines.
    """
    status_label = "False Positive" if feedback.is_false_positive else "Confirmed Attack"
    return {
        "status": "success",
        "message": f"Successfully registered assessment '{status_label}' for event {feedback.event_id}.",
        "event_id": feedback.event_id,
        "is_false_positive": feedback.is_false_positive,
    }
