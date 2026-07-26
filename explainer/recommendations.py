"""
SentinelAI — Recommendation Engine

Generates automated, actionable SOC analyst recommendations and next steps
based on attack type, risk level, and evidence.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


# Standardized analyst actions as per prompt requirements:
# - Monitor
# - Require MFA
# - Lock Account
# - Investigate Device
# - Escalate to SOC

ACTION_MAP = {
    "brute_force": {
        "action": "Require MFA & Lock Account",
        "recommendation": "Temporarily lock the targeted account, revoke active tokens, and enforce immediate MFA reset.",
    },
    "credential_stuffing": {
        "action": "Escalate to SOC & Block IP",
        "recommendation": "Block source IP address at firewall perimeter, trigger automated password reset for affected entities, and alert Tier 2 SOC.",
    },
    "impossible_travel": {
        "action": "Lock Account",
        "recommendation": "Temporarily disable the account and require in-person / out-of-band MFA verification.",
    },
    "lateral_movement": {
        "action": "Escalate to SOC & Isolate Entity",
        "recommendation": "Immediately isolate host/entity credentials, revoke privileged API keys, and launch active incident response investigation.",
    },
    "device_spoofing": {
        "action": "Investigate Device",
        "recommendation": "Quarantine suspicious device fingerprint, revoke device session token, and re-verify hardware PKI certificates.",
    },
    "low_slow_exfiltration": {
        "action": "Escalate to SOC",
        "recommendation": "Trigger automated DLP download caps, flag account for active packet capture monitoring, and escalate to CISO threat team.",
    },
    "insider_drift": {
        "action": "Monitor & Audit Access",
        "recommendation": "Notify HR and line manager to verify if recent resource scope expansion is business-sanctioned; monitor for 7 days.",
    },
    "normal": {
        "action": "Monitor",
        "recommendation": "No action required. Maintain baseline logging.",
    },
}


class RecommendationEngine:
    """
    Generates SOC recommendations based on threat assessment.
    """

    @staticmethod
    def get_recommendation(attack_type: str, risk_level: str) -> Dict[str, str]:
        """
        Return action and human-readable recommendation string.
        """
        key = attack_type.lower().replace(" ", "_").replace("&_", "")
        rec_info = ACTION_MAP.get(key, ACTION_MAP["normal"])

        # Override for Low risk
        if risk_level == "Low":
            return {
                "action": "Monitor",
                "recommendation": "Log event for baseline profiling; no immediate action required.",
            }

        return {
            "action": rec_info["action"],
            "recommendation": rec_info["recommendation"],
        }
