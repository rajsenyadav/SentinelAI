"""
SentinelAI — Enterprise Behavioral Anomaly Detection & Threat Intelligence Backend API

Main FastAPI Application Entry Point.
Provides automatic OpenAPI Swagger documentation at /docs and ReDoc at /redoc.
"""

import sys
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.config.config import settings
from backend.logger.logger import logger
from backend.middleware.exception_handler import global_exception_handler
from backend.api.routes import api_router

# Create FastAPI App
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Production-Ready Behavioral Anomaly Detection, Threat Intelligence & XAI Engine for Enterprise SOCs.",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Global Exception Handler
app.add_exception_handler(Exception, global_exception_handler)

# Include API Router
app.include_router(api_router)


@app.get("/", tags=["Health Check"])
def root_health_check():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "documentation": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    logger.info(f"Starting {settings.APP_NAME} server on http://{settings.HOST}:{settings.PORT}...")
    uvicorn.run("backend.app:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
