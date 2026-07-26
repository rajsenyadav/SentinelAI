"""
SentinelAI — Dashboard Launch Script

Usage:
    python scripts/run_dashboard.py
"""

import os
import sys
import subprocess


def main():
    dashboard_app = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dashboard", "app.py")
    
    print("=" * 60)
    print("SentinelAI — Launching Enterprise SOC Dashboard...")
    print("=" * 60)
    print(f"App Path: {dashboard_app}\n")

    # Try running python -m streamlit
    cmd = [sys.executable, "-m", "streamlit", "run", dashboard_app]
    result = subprocess.run(cmd)

    if result.returncode != 0:
        # Fallback to direct 'streamlit' command on PATH
        try:
            subprocess.run(["streamlit", "run", dashboard_app])
        except Exception:
            print("\n" + "!" * 60)
            print("[ERROR] Streamlit is not installed in your Python environment.")
            print("Please install Streamlit by running:")
            print("    pip install streamlit plotly")
            print("!" * 60)


if __name__ == "__main__":
    main()
