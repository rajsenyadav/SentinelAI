"""
SentinelAI — Entity Templates

Defines behavioral profiles for each entity role. Every entity is instantiated
from a template that constrains what "normal" looks like for that role.
"""

import random
import hashlib
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Optional
from datetime import datetime, timedelta

from .schemas import (
    GEO_LOCATIONS, DATACENTER_LOCATIONS, RESOURCES, OPERATING_SYSTEMS,
    USER_AGENTS, AUTH_METHODS, PROTOCOLS, NORMAL_ADMIN_COMMANDS,
)

# ---------------------------------------------------------------------------
# Entity profile dataclass
# ---------------------------------------------------------------------------

@dataclass
class EntityProfile:
    """Fully instantiated behavioral profile for a single entity."""
    entity_id: str
    entity_type: str            # user | service_account | edge_device
    entity_role: str            # employee | developer | hr | finance | admin | service | device
    department: str
    primary_geo: str            # city name key in GEO_LOCATIONS
    secondary_geo: Optional[str]
    work_hours_start: int       # hour (0-23)
    work_hours_end: int         # hour (0-23)
    work_days: List[int]        # 0=Mon ... 6=Sun
    known_devices: List[dict]   # [{"fingerprint": ..., "os": ..., "user_agent": ...}]
    typical_resources: List[str]
    typical_resource_categories: List[str]
    typical_auth_methods: List[str]
    typical_protocols: List[str]
    avg_session_duration: int   # seconds
    session_duration_std: int   # seconds
    avg_bytes_per_session: int
    bytes_std: int
    avg_events_per_day: float
    typical_actions: List[str]
    typical_commands: List[List[str]]
    vpn_probability: float      # probability of using VPN
    onboarding_date: str        # ISO date string
    is_cold_start: bool = False

    def to_dict(self) -> dict:
        """Serialize to a dict for CSV export."""
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "entity_role": self.entity_role,
            "department": self.department,
            "primary_geo": self.primary_geo,
            "secondary_geo": self.secondary_geo or "",
            "work_hours_start": self.work_hours_start,
            "work_hours_end": self.work_hours_end,
            "work_days": str(self.work_days),
            "known_devices": str([d["fingerprint"] for d in self.known_devices]),
            "typical_resources": str(self.typical_resources),
            "typical_auth_method": self.typical_auth_methods[0],
            "avg_session_duration": self.avg_session_duration,
            "avg_bytes_per_session": self.avg_bytes_per_session,
            "onboarding_date": self.onboarding_date,
        }


# ---------------------------------------------------------------------------
# Device fingerprint generator
# ---------------------------------------------------------------------------

def _make_device(os_name: str, rng: random.Random) -> dict:
    """Create a device fingerprint dict."""
    mac_prefix = f"{rng.randint(0,255):02x}:{rng.randint(0,255):02x}:{rng.randint(0,255):02x}"
    raw = f"{os_name}-{mac_prefix}-{rng.randint(1000,9999)}"
    fp = "fp-" + hashlib.md5(raw.encode()).hexdigest()[:8]
    ua = USER_AGENTS.get(os_name, "unknown-agent")
    return {"fingerprint": fp, "os": os_name, "user_agent": ua}


def _make_ip(rng: random.Random, prefix: str = "10") -> str:
    """Generate a plausible internal or semi-random IP."""
    if prefix == "10":
        return f"10.{rng.randint(0,255)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
    return f"192.168.{rng.randint(1,254)}.{rng.randint(1,254)}"


# ---------------------------------------------------------------------------
# Entity factory
# ---------------------------------------------------------------------------

class EntityFactory:
    """
    Creates EntityProfile instances according to the behavioral templates
    defined in the dataset specification.
    """

    def __init__(self, rng: random.Random, start_date: str):
        self.rng = rng
        self.start_date = datetime.fromisoformat(start_date)
        self._counter = 0

    def _next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    def _pick_geos(self, n_primary: int = 1, n_secondary: int = 0,
                   pool: List[str] = None) -> Tuple[str, Optional[str]]:
        pool = pool or list(GEO_LOCATIONS.keys())
        primary = self.rng.choice(pool)
        secondary = None
        if n_secondary > 0:
            remaining = [g for g in pool if g != primary]
            secondary = self.rng.choice(remaining) if remaining else None
        return primary, secondary

    def _onboarding_date(self, cold_start: bool = False, span_days: int = 90) -> str:
        if cold_start:
            # Onboard in the last third of the time span (test period)
            offset = self.rng.randint(int(span_days * 0.7), span_days - 5)
        else:
            # Onboard before the simulation starts (established entity)
            offset = -self.rng.randint(30, 365)
        dt = self.start_date + timedelta(days=offset)
        return dt.strftime("%Y-%m-%d")

    # --- Role-specific factories ---

    def create_employee(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("USR")
        primary, secondary = self._pick_geos(1, 0)
        os_choices = ["Windows 11", "Windows 10"]
        devices = [_make_device(self.rng.choice(os_choices), self.rng)]
        if self.rng.random() < 0.4:
            devices.append(_make_device(self.rng.choice(["Android 14", "iOS 17"]), self.rng))

        resources = (
            self.rng.sample(RESOURCES["email"], min(3, len(RESOURCES["email"])))
            + self.rng.sample(RESOURCES["general"], min(4, len(RESOURCES["general"])))
        )
        return EntityProfile(
            entity_id=eid, entity_type="user", entity_role="employee",
            department="Operations",
            primary_geo=primary, secondary_geo=secondary,
            work_hours_start=9, work_hours_end=18,
            work_days=[0, 1, 2, 3, 4],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["email", "general"],
            typical_auth_methods=["sso", "password"],
            typical_protocols=["HTTPS"],
            avg_session_duration=3600, session_duration_std=1800,
            avg_bytes_per_session=25_000, bytes_std=20_000,
            avg_events_per_day=self.rng.uniform(1, 3),
            typical_actions=["login", "read", "download"],
            typical_commands=[],
            vpn_probability=0.05,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    def create_developer(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("USR")
        primary, secondary = self._pick_geos(1, 1)
        os_pool = ["macOS 14", "macOS 13", "Ubuntu 22.04", "Ubuntu 24.04", "Windows 11"]
        devices = [_make_device(self.rng.choice(os_pool), self.rng)]
        devices.append(_make_device(self.rng.choice(os_pool), self.rng))
        if self.rng.random() < 0.3:
            devices.append(_make_device(self.rng.choice(["Android 14", "iOS 17"]), self.rng))

        resources = (
            self.rng.sample(RESOURCES["code_repo"], min(6, len(RESOURCES["code_repo"])))
            + self.rng.sample(RESOURCES["general"], min(2, len(RESOURCES["general"])))
        )
        return EntityProfile(
            entity_id=eid, entity_type="user", entity_role="developer",
            department="Engineering",
            primary_geo=primary, secondary_geo=secondary,
            work_hours_start=8, work_hours_end=22,
            work_days=[0, 1, 2, 3, 4, 5],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["code_repo", "general"],
            typical_auth_methods=["token", "sso"],
            typical_protocols=["HTTPS", "SSH"],
            avg_session_duration=5400, session_duration_std=3600,
            avg_bytes_per_session=500_000, bytes_std=400_000,
            avg_events_per_day=self.rng.uniform(5, 15),
            typical_actions=["login", "read", "write", "upload", "download"],
            typical_commands=[],
            vpn_probability=0.15,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    def create_hr(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("USR")
        primary, _ = self._pick_geos(1, 0)
        devices = [_make_device(self.rng.choice(["Windows 11", "Windows 10"]), self.rng)]

        resources = self.rng.sample(RESOURCES["hr_data"], min(4, len(RESOURCES["hr_data"])))
        resources += self.rng.sample(RESOURCES["email"], min(2, len(RESOURCES["email"])))
        return EntityProfile(
            entity_id=eid, entity_type="user", entity_role="hr",
            department="Human Resources",
            primary_geo=primary, secondary_geo=None,
            work_hours_start=9, work_hours_end=17,
            work_days=[0, 1, 2, 3, 4],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["hr_data", "email"],
            typical_auth_methods=["sso", "biometric"],
            typical_protocols=["HTTPS"],
            avg_session_duration=2400, session_duration_std=1200,
            avg_bytes_per_session=50_000, bytes_std=40_000,
            avg_events_per_day=self.rng.uniform(2, 5),
            typical_actions=["login", "read", "write"],
            typical_commands=[],
            vpn_probability=0.02,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    def create_finance(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("USR")
        primary, _ = self._pick_geos(1, 0)
        devices = [_make_device("Windows 11", self.rng)]
        if self.rng.random() < 0.3:
            devices.append(_make_device(self.rng.choice(["Android 14", "iOS 17"]), self.rng))

        resources = self.rng.sample(RESOURCES["finance_data"], min(5, len(RESOURCES["finance_data"])))
        resources += self.rng.sample(RESOURCES["email"], min(2, len(RESOURCES["email"])))
        return EntityProfile(
            entity_id=eid, entity_type="user", entity_role="finance",
            department="Finance",
            primary_geo=primary, secondary_geo=None,
            work_hours_start=9, work_hours_end=18,
            work_days=[0, 1, 2, 3, 4],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["finance_data", "email"],
            typical_auth_methods=["password", "certificate"],
            typical_protocols=["HTTPS"],
            avg_session_duration=3000, session_duration_std=1500,
            avg_bytes_per_session=200_000, bytes_std=150_000,
            avg_events_per_day=self.rng.uniform(3, 8),
            typical_actions=["login", "read", "download", "write"],
            typical_commands=[],
            vpn_probability=0.03,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    def create_admin(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("USR")
        primary, secondary = self._pick_geos(1, 1)
        os_pool = ["Ubuntu 22.04", "Ubuntu 24.04", "CentOS 8", "RHEL 9", "Windows 11"]
        devices = [_make_device(os, self.rng) for os in self.rng.sample(os_pool, 3)]
        if self.rng.random() < 0.5:
            devices.append(_make_device(self.rng.choice(["Android 14", "iOS 17"]), self.rng))

        resources = (
            self.rng.sample(RESOURCES["infra_config"], min(6, len(RESOURCES["infra_config"])))
            + self.rng.sample(RESOURCES["admin_panel"], min(4, len(RESOURCES["admin_panel"])))
        )
        return EntityProfile(
            entity_id=eid, entity_type="user", entity_role="admin",
            department="IT Infrastructure",
            primary_geo=primary, secondary_geo=secondary,
            work_hours_start=0, work_hours_end=23,  # variable / on-call
            work_days=[0, 1, 2, 3, 4, 5, 6],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["infra_config", "admin_panel"],
            typical_auth_methods=["certificate", "token"],
            typical_protocols=["SSH", "RDP", "HTTPS", "VPN"],
            avg_session_duration=1800, session_duration_std=2400,
            avg_bytes_per_session=500_000, bytes_std=800_000,
            avg_events_per_day=self.rng.uniform(10, 30),
            typical_actions=["login", "read", "write", "config_change"],
            typical_commands=NORMAL_ADMIN_COMMANDS,
            vpn_probability=0.40,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    def create_service_account(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("SVC")
        primary = self.rng.choice(DATACENTER_LOCATIONS)
        devices = [_make_device(self.rng.choice(["CentOS 8", "RHEL 9", "Ubuntu 22.04"]), self.rng)]

        svc_type = self.rng.choice(["api-monitor", "data-sync", "health-check", "log-collector", "backup-agent"])
        resources = self.rng.sample(
            RESOURCES["infra_config"] + RESOURCES["general"],
            min(3, len(RESOURCES["infra_config"]) + len(RESOURCES["general"]))
        )
        interval_minutes = self.rng.choice([5, 10, 15, 30, 60])
        return EntityProfile(
            entity_id=eid, entity_type="service_account", entity_role="service",
            department="Automated Services",
            primary_geo=primary, secondary_geo=None,
            work_hours_start=0, work_hours_end=23,
            work_days=[0, 1, 2, 3, 4, 5, 6],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["infra_config", "general"],
            typical_auth_methods=["token", "certificate"],
            typical_protocols=self.rng.sample(["HTTPS", "MQTT", "OPC-UA"], 1),
            avg_session_duration=30, session_duration_std=10,
            avg_bytes_per_session=5_000, bytes_std=2_000,
            avg_events_per_day=round(1440 / interval_minutes),
            typical_actions=["login", "read"],
            typical_commands=[],
            vpn_probability=0.0,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    def create_edge_device(self, cold_start: bool = False) -> EntityProfile:
        eid = self._next_id("DEV")
        primary = self.rng.choice(DATACENTER_LOCATIONS[:3])
        devices = [_make_device(self.rng.choice(["CentOS 8", "RHEL 9"]), self.rng)]

        resources = self.rng.sample(RESOURCES["infra_config"], min(2, len(RESOURCES["infra_config"])))
        return EntityProfile(
            entity_id=eid, entity_type="edge_device", entity_role="device",
            department="IoT Operations",
            primary_geo=primary, secondary_geo=None,
            work_hours_start=0, work_hours_end=23,
            work_days=[0, 1, 2, 3, 4, 5, 6],
            known_devices=devices,
            typical_resources=resources,
            typical_resource_categories=["infra_config"],
            typical_auth_methods=["certificate"],
            typical_protocols=self.rng.sample(["MQTT", "OPC-UA", "HTTPS"], 1),
            avg_session_duration=15, session_duration_std=5,
            avg_bytes_per_session=2_000, bytes_std=1_000,
            avg_events_per_day=self.rng.uniform(10, 20),
            typical_actions=["login", "read", "upload"],
            typical_commands=[],
            vpn_probability=0.0,
            onboarding_date=self._onboarding_date(cold_start),
            is_cold_start=cold_start,
        )

    # --- Bulk creation ---

    def create_population(self, config: dict, cold_start_count: int = 0) -> List[EntityProfile]:
        """
        Create the full entity population from a config dict.

        Args:
            config: entity counts per role from data_config.yaml
            cold_start_count: number of entities to mark as cold-start
        """
        creators = {
            "user_employee": self.create_employee,
            "user_developer": self.create_developer,
            "user_hr": self.create_hr,
            "user_finance": self.create_finance,
            "user_admin": self.create_admin,
            "service_account": self.create_service_account,
            "edge_device": self.create_edge_device,
        }

        entities = []
        for role_key, count in config.items():
            creator = creators.get(role_key)
            if not creator:
                continue
            for _ in range(count):
                entities.append(creator(cold_start=False))

        # Designate some user entities as cold-start
        user_entities = [e for e in entities if e.entity_type == "user"]
        if cold_start_count > 0 and user_entities:
            cold_picks = self.rng.sample(
                user_entities, min(cold_start_count, len(user_entities))
            )
            for entity in cold_picks:
                entity.is_cold_start = True
                entity.onboarding_date = self._onboarding_date(cold_start=True)

        self.rng.shuffle(entities)
        return entities
