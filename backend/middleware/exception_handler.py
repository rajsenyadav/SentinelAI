"""
SentinelAI Backend — Exception Handling Middleware

Catches unexpected errors gracefully and returns standard JSON error responses.
"""

from fastapi import Request, status
from fastapi.responses import JSONResponse
from ..logger.logger import logger


async def global_exception_handler(request: Request, exc: Exception):
    """Global unhandled exception interceptor."""
    logger.error(f"Unhandled Exception on {request.method} {request.url.path}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred processing your request.",
            "details": str(exc),
            "path": str(request.url.path),
        },
    )
