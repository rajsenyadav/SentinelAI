"""
SentinelAI Backend — API Router Aggregator
"""

from fastapi import APIRouter

from .alerts import router as alerts_router
from .dashboard import router as dashboard_router
from .users import router as users_router
from .analytics import router as analytics_router
from .feedback import router as feedback_router
from .incidents import router as incidents_router

api_router = APIRouter()

api_router.include_router(alerts_router)
api_router.include_router(dashboard_router)
api_router.include_router(users_router)
api_router.include_router(analytics_router)
api_router.include_router(feedback_router)
api_router.include_router(incidents_router)
