"""
SentinelAI — FastAPI Backend Server Launch Script

Usage:
    python scripts/run_backend.py
"""

import sys
import os
import uvicorn

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from backend.config.config import settings
from backend.app import app


def main():
    print("=" * 60)
    print(f"SentinelAI — Starting FastAPI Backend Server on http://localhost:{settings.PORT}")
    print(f"Interactive Swagger Docs available at: http://localhost:{settings.PORT}/docs")
    print("=" * 60)

    uvicorn.run(app, host=settings.HOST, port=settings.PORT)


if __name__ == "__main__":
    main()
