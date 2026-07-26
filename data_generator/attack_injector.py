"""
SentinelAI — Attack Injector

Generates realistic attack events for each attack type defined in the
dataset specification. Each attack method returns a list of (EventRecord, LabelRecord)
tuples that replace or supplement normal events.
"""

import random
import math
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

from .schemas import (
    EventRecord, LabelRecord, GEO_LOCATIONS, RESOURCES, RESOURCE_CATEGORIES,
    SUSPICIOUS_COMMANDS, AUTH_METHODS, PROTOCOLS, OPERATING_SYSTEMS,
    USER_AGENTS, ACTION_TYPES,
)
from .entity_templates import EntityProfile, _make_ip, _make_device

import logging

logger = logging.getLogger(__name__)


def _evt_id() -> str:
    return f"evt-{uuid.uuid4().hex[:8]}"


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in km between two lat/lon points."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


class AttackInjector:
    """
    Generates attack events for a given entity profile.
    Each public method corresponds to one attack type from the spec.
    """

    def __init__(self, rng: random.Random):
        self.rng = rng

    # ------------------------------------------------------------------
    # 1. Brute Force
    # ------------------------------------------------------------------
    def inject_brute_force(
        self, entity: EntityProfile, base_time: datetime, count: int = 30
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Rapid failed-auth attempts from a single IP targeting one entity.
        Characteristics: 10-100+ failures in < 5 minutes, password-only,
        inter-event time < 10 seconds.
        """
        results = []
        attacker_ip = _make_ip(self.rng, prefix="192.168")
        geo = entity.primary_geo
        lat, lon = GEO_LOCATIONS[geo]
        device = entity.known_devices[0] if entity.known_devices else _make_device("Windows 10", self.rng)

        max_c = max(1, min(count, 80))
        min_c = min(15, max_c)
        count = self.rng.randint(min_c, max_c)
        is_spray = self.rng.random() < 0.3
        subtype = "password_spray" if is_spray else "dictionary_attack"

        for i in range(count):
            ts = base_time + timedelta(seconds=self.rng.uniform(1, 8) * i)
            # Last 1-2 events may succeed (attacker breaks in)
            is_success = (i >= count - 2) and (self.rng.random() < 0.3)

            evt = EventRecord(
                event_id=_evt_id(),
                timestamp=ts.isoformat(),
                entity_id=entity.entity_id,
                entity_type=entity.entity_type,
                entity_role=entity.entity_role,
                department=entity.department,
                source_ip=attacker_ip,
                geo_location=geo,
                geo_lat=round(lat + self.rng.uniform(-0.01, 0.01), 4),
                geo_lon=round(lon + self.rng.uniform(-0.01, 0.01), 4),
                resource_accessed="/auth/login",
                resource_category="general",
                action_type="login",
                auth_method="password",
                auth_status="success" if is_success else "failure",
                session_duration=0 if not is_success else self.rng.randint(10, 120),
                bytes_transferred=0 if not is_success else self.rng.randint(500, 5000),
                device_fingerprint=device["fingerprint"],
                device_os=device["os"],
                user_agent=device["user_agent"],
                protocol="HTTPS",
                command_sequence="[]",
                is_vpn=False,
            )
            lbl = LabelRecord(
                event_id=evt.event_id,
                label="anomaly",
                attack_type="brute_force",
                attack_subtype=subtype,
            )
            results.append((evt, lbl))

        return results

    # ------------------------------------------------------------------
    # 2. Impossible Travel
    # ------------------------------------------------------------------
    def inject_impossible_travel(
        self, entity: EntityProfile, base_time: datetime
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Same entity logs in from geographically distant locations within
        an implausible time gap (< 2 hours, > 500 km/h velocity).
        """
        results = []

        # Pick two distant locations
        all_geos = list(GEO_LOCATIONS.keys())
        geo1 = entity.primary_geo
        # Find a distant geo
        lat1, lon1 = GEO_LOCATIONS[geo1]
        distant_geos = [
            g for g in all_geos
            if _haversine_km(lat1, lon1, *GEO_LOCATIONS[g]) > 2000
        ]
        if not distant_geos:
            distant_geos = [g for g in all_geos if g != geo1]
        geo2 = self.rng.choice(distant_geos)
        lat2, lon2 = GEO_LOCATIONS[geo2]

        dist_km = _haversine_km(lat1, lon1, lat2, lon2)
        # Time gap: ensure velocity > 500 km/h
        max_hours = dist_km / 600.0
        gap_minutes = self.rng.randint(10, max(11, int(max_hours * 60)))

        device1 = entity.known_devices[0] if entity.known_devices else _make_device("Windows 11", self.rng)
        # Second login may use a different device
        use_new_device = self.rng.random() < 0.5
        device2 = _make_device(self.rng.choice(["Windows 10", "macOS 14"]), self.rng) if use_new_device else device1

        for idx, (geo, lat, lon, dev, t_offset) in enumerate([
            (geo1, lat1, lon1, device1, 0),
            (geo2, lat2, lon2, device2, gap_minutes),
        ]):
            ts = base_time + timedelta(minutes=t_offset)
            evt = EventRecord(
                event_id=_evt_id(),
                timestamp=ts.isoformat(),
                entity_id=entity.entity_id,
                entity_type=entity.entity_type,
                entity_role=entity.entity_role,
                department=entity.department,
                source_ip=_make_ip(self.rng),
                geo_location=geo,
                geo_lat=round(lat, 4),
                geo_lon=round(lon, 4),
                resource_accessed=self.rng.choice(entity.typical_resources) if entity.typical_resources else "/portal/dashboard",
                resource_category=self.rng.choice(entity.typical_resource_categories),
                action_type="login",
                auth_method=self.rng.choice(entity.typical_auth_methods),
                auth_status="success",
                session_duration=self.rng.randint(60, 1800),
                bytes_transferred=self.rng.randint(1000, 50000),
                device_fingerprint=dev["fingerprint"],
                device_os=dev["os"],
                user_agent=dev["user_agent"],
                protocol="HTTPS",
                command_sequence="[]",
                is_vpn=bool(idx == 1 and self.rng.random() < 0.4),
            )
            lbl = LabelRecord(
                event_id=evt.event_id,
                label="anomaly",
                attack_type="impossible_travel",
                attack_subtype="geo_velocity_violation",
            )
            results.append((evt, lbl))

        return results

    # ------------------------------------------------------------------
    # 3. Credential Stuffing
    # ------------------------------------------------------------------
    def inject_credential_stuffing(
        self, entities: List[EntityProfile], base_time: datetime, count: int = 50
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Many entity_ids targeted from 1-3 IPs with high failure rate (85-99%).
        Automated, uniform intervals between attempts.
        """
        results = []
        num_ips = self.rng.randint(1, 3)
        attacker_ips = [_make_ip(self.rng, prefix="192.168") for _ in range(num_ips)]
        geo = self.rng.choice(list(GEO_LOCATIONS.keys()))
        lat, lon = GEO_LOCATIONS[geo]

        # Target many distinct entities
        target_count = min(count, len(entities))
        targets = self.rng.sample(entities, target_count)
        device = _make_device("Ubuntu 22.04", self.rng)

        failure_rate = self.rng.uniform(0.85, 0.98)
        interval = self.rng.uniform(0.5, 3.0)  # seconds between attempts

        for i, target in enumerate(targets):
            ts = base_time + timedelta(seconds=interval * i)
            is_fail = self.rng.random() < failure_rate

            evt = EventRecord(
                event_id=_evt_id(),
                timestamp=ts.isoformat(),
                entity_id=target.entity_id,
                entity_type=target.entity_type,
                entity_role=target.entity_role,
                department=target.department,
                source_ip=self.rng.choice(attacker_ips),
                geo_location=geo,
                geo_lat=round(lat + self.rng.uniform(-0.005, 0.005), 4),
                geo_lon=round(lon + self.rng.uniform(-0.005, 0.005), 4),
                resource_accessed="/auth/login",
                resource_category="general",
                action_type="login",
                auth_method="password",
                auth_status="failure" if is_fail else "success",
                session_duration=0 if is_fail else self.rng.randint(5, 60),
                bytes_transferred=0 if is_fail else self.rng.randint(200, 2000),
                device_fingerprint=device["fingerprint"],
                device_os=device["os"],
                user_agent="python-requests/2.31.0",
                protocol="HTTPS",
                command_sequence="[]",
                is_vpn=False,
            )
            lbl = LabelRecord(
                event_id=evt.event_id,
                label="anomaly",
                attack_type="credential_stuffing",
                attack_subtype="automated_credential_test",
            )
            results.append((evt, lbl))

        return results

    # ------------------------------------------------------------------
    # 4. Lateral Movement
    # ------------------------------------------------------------------
    def inject_lateral_movement(
        self, entity: EntityProfile, base_time: datetime, count: int = 15
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Compromised entity accesses unusual breadth of resources it has
        never touched before, including cross-category access and
        suspicious command sequences.
        """
        results = []

        # Pick resources outside the entity's normal categories
        unusual_categories = [
            c for c in RESOURCES.keys()
            if c not in entity.typical_resource_categories
        ]
        novel_resources = []
        for cat in unusual_categories:
            novel_resources.extend(
                [(r, cat) for r in RESOURCES[cat] if r not in entity.typical_resources]
            )
        self.rng.shuffle(novel_resources)
        novel_resources = novel_resources[:count]

        if not novel_resources:
            # fallback: use admin resources
            novel_resources = [(r, "admin_panel") for r in RESOURCES["admin_panel"]]

        device = entity.known_devices[0] if entity.known_devices else _make_device("Windows 11", self.rng)
        geo = entity.primary_geo
        lat, lon = GEO_LOCATIONS[geo]

        suspicious_actions = ["read", "write", "config_change", "privilege_escalation", "download"]

        for i, (resource, category) in enumerate(novel_resources):
            ts = base_time + timedelta(minutes=self.rng.randint(3, 20) * i)
            cmd = self.rng.choice(SUSPICIOUS_COMMANDS) if self.rng.random() < 0.4 else []

            evt = EventRecord(
                event_id=_evt_id(),
                timestamp=ts.isoformat(),
                entity_id=entity.entity_id,
                entity_type=entity.entity_type,
                entity_role=entity.entity_role,
                department=entity.department,
                source_ip=_make_ip(self.rng),
                geo_location=geo,
                geo_lat=round(lat, 4),
                geo_lon=round(lon, 4),
                resource_accessed=resource,
                resource_category=category,
                action_type=self.rng.choice(suspicious_actions),
                auth_method=self.rng.choice(entity.typical_auth_methods),
                auth_status="success",
                session_duration=self.rng.randint(30, 300),
                bytes_transferred=self.rng.randint(5000, 500000),
                device_fingerprint=device["fingerprint"],
                device_os=device["os"],
                user_agent=device["user_agent"],
                protocol=self.rng.choice(["HTTPS", "SSH"]),
                command_sequence=str(cmd),
                is_vpn=False,
            )
            lbl = LabelRecord(
                event_id=evt.event_id,
                label="anomaly",
                attack_type="lateral_movement",
                attack_subtype="cross_category_scanning",
            )
            results.append((evt, lbl))

        return results

    # ------------------------------------------------------------------
    # 5. Device Spoofing
    # ------------------------------------------------------------------
    def inject_device_spoofing(
        self, entity: EntityProfile, base_time: datetime
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Known device_id reappears with a mismatched fingerprint
        (different OS/MAC than entity's history).
        """
        results = []

        if not entity.known_devices:
            return results

        original_device = entity.known_devices[0]

        # Create a spoofed version: same logical device, different OS/fingerprint
        original_os = original_device["os"]
        spoofed_os_pool = [os for os in OPERATING_SYSTEMS if os != original_os]
        # Ensure OS family mismatch (Windows -> Linux, Mac -> Windows, etc.)
        if "Windows" in original_os:
            spoofed_os_pool = [os for os in spoofed_os_pool if "Windows" not in os]
        elif "macOS" in original_os:
            spoofed_os_pool = [os for os in spoofed_os_pool if "macOS" not in os]
        elif "Ubuntu" in original_os or "CentOS" in original_os or "RHEL" in original_os:
            spoofed_os_pool = [os for os in spoofed_os_pool if os not in ("Ubuntu 22.04", "Ubuntu 24.04", "CentOS 8", "RHEL 9")]

        if not spoofed_os_pool:
            spoofed_os_pool = ["Windows 10", "Ubuntu 22.04"]

        spoofed_os = self.rng.choice(spoofed_os_pool)
        spoofed_ua = USER_AGENTS.get(spoofed_os, "unknown-agent")
        # New fingerprint but could try to reuse device concept
        new_mac = f"{self.rng.randint(0,255):02x}:{self.rng.randint(0,255):02x}:{self.rng.randint(0,255):02x}"
        raw = f"{spoofed_os}-{new_mac}-{self.rng.randint(1000,9999)}"
        spoofed_fp = "fp-" + hashlib.md5(raw.encode()).hexdigest()[:8]

        geo = entity.primary_geo
        lat, lon = GEO_LOCATIONS[geo]

        event_count = self.rng.randint(2, 5)
        for i in range(event_count):
            ts = base_time + timedelta(minutes=self.rng.randint(5, 60) * i)
            evt = EventRecord(
                event_id=_evt_id(),
                timestamp=ts.isoformat(),
                entity_id=entity.entity_id,
                entity_type=entity.entity_type,
                entity_role=entity.entity_role,
                department=entity.department,
                source_ip=_make_ip(self.rng),
                geo_location=geo,
                geo_lat=round(lat, 4),
                geo_lon=round(lon, 4),
                resource_accessed=self.rng.choice(entity.typical_resources) if entity.typical_resources else "/portal/dashboard",
                resource_category=self.rng.choice(entity.typical_resource_categories),
                action_type=self.rng.choice(["login", "read", "download"]),
                auth_method=self.rng.choice(entity.typical_auth_methods),
                auth_status="success",
                session_duration=self.rng.randint(60, 3600),
                bytes_transferred=self.rng.randint(1000, 100000),
                device_fingerprint=spoofed_fp,
                device_os=spoofed_os,
                user_agent=spoofed_ua,
                protocol=self.rng.choice(entity.typical_protocols),
                command_sequence="[]",
                is_vpn=self.rng.random() < 0.3,
            )
            lbl = LabelRecord(
                event_id=evt.event_id,
                label="anomaly",
                attack_type="device_spoofing",
                attack_subtype="os_family_mismatch",
            )
            results.append((evt, lbl))

        return results

    # ------------------------------------------------------------------
    # 6. Low-and-Slow Exfiltration
    # ------------------------------------------------------------------
    def inject_low_slow_exfiltration(
        self, entity: EntityProfile, start_time: datetime, days: int = 10
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Off-hours access with gradually increasing byte volumes over
        multiple days. Short sessions targeting sensitive resources.
        """
        results = []
        geo = entity.primary_geo
        lat, lon = GEO_LOCATIONS[geo]
        device = entity.known_devices[0] if entity.known_devices else _make_device("Windows 11", self.rng)

        # Sensitive resources from finance/hr/infra
        sensitive_pools = RESOURCES["finance_data"] + RESOURCES["hr_data"] + RESOURCES["infra_config"]
        sensitive = self.rng.sample(sensitive_pools, min(5, len(sensitive_pools)))

        base_bytes = self.rng.randint(100_000, 300_000)

        for day in range(days):
            # Off-hours: 22:00 - 05:00
            hour = self.rng.choice([22, 23, 0, 1, 2, 3, 4])
            minute = self.rng.randint(0, 59)
            ts = start_time + timedelta(days=day, hours=hour, minutes=minute)

            # Gradually increasing volume
            bytes_today = int(base_bytes * (1 + 0.15 * day) + self.rng.randint(-20000, 20000))
            bytes_today = max(bytes_today, 50_000)

            events_this_night = self.rng.randint(1, 3)
            for j in range(events_this_night):
                ts_j = ts + timedelta(minutes=self.rng.randint(0, 60) * j)
                evt = EventRecord(
                    event_id=_evt_id(),
                    timestamp=ts_j.isoformat(),
                    entity_id=entity.entity_id,
                    entity_type=entity.entity_type,
                    entity_role=entity.entity_role,
                    department=entity.department,
                    source_ip=_make_ip(self.rng),
                    geo_location=geo,
                    geo_lat=round(lat, 4),
                    geo_lon=round(lon, 4),
                    resource_accessed=self.rng.choice(sensitive),
                    resource_category=self.rng.choice(["finance_data", "hr_data", "infra_config"]),
                    action_type=self.rng.choice(["read", "download"]),
                    auth_method=self.rng.choice(entity.typical_auth_methods),
                    auth_status="success",
                    session_duration=self.rng.randint(30, 300),
                    bytes_transferred=bytes_today // events_this_night,
                    device_fingerprint=device["fingerprint"],
                    device_os=device["os"],
                    user_agent=device["user_agent"],
                    protocol="HTTPS",
                    command_sequence="[]",
                    is_vpn=self.rng.random() < 0.2,
                )
                lbl = LabelRecord(
                    event_id=evt.event_id,
                    label="anomaly",
                    attack_type="low_slow_exfiltration",
                    attack_subtype="off_hours_data_transfer",
                )
                results.append((evt, lbl))

        return results

    # ------------------------------------------------------------------
    # 7. Insider Drift (Edge Case)
    # ------------------------------------------------------------------
    def inject_insider_drift(
        self, entity: EntityProfile, start_time: datetime, weeks: int = 4
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """
        Gradual expansion of resource access scope over weeks.
        +1-2 new resources per week, slight off-hours creep,
        introduction of write/download actions.
        """
        results = []
        geo = entity.primary_geo
        lat, lon = GEO_LOCATIONS[geo]
        device = entity.known_devices[0] if entity.known_devices else _make_device("Windows 11", self.rng)

        # Build a pool of adjacent-category resources
        adjacent_categories = [
            c for c in RESOURCES.keys()
            if c not in entity.typical_resource_categories
        ]
        adjacent_resources = []
        for cat in adjacent_categories:
            adjacent_resources.extend([(r, cat) for r in RESOURCES[cat]])
        self.rng.shuffle(adjacent_resources)

        resource_idx = 0
        for week in range(weeks):
            # 1-2 new resources accessed this week
            new_this_week = self.rng.randint(1, 2)
            for _ in range(new_this_week):
                if resource_idx >= len(adjacent_resources):
                    break
                resource, category = adjacent_resources[resource_idx]
                resource_idx += 1

                # Slightly shifting to off-hours over weeks
                hour_shift = week * self.rng.randint(0, 1)
                base_hour = entity.work_hours_end + hour_shift
                if base_hour > 23:
                    base_hour = 23

                events_for_resource = self.rng.randint(2, 5)
                for j in range(events_for_resource):
                    day_offset = week * 7 + self.rng.randint(0, 6)
                    hour = self.rng.randint(max(entity.work_hours_start, base_hour - 2), base_hour)
                    ts = start_time + timedelta(days=day_offset, hours=hour, minutes=self.rng.randint(0, 59))

                    # Gradually introduce more write/download actions
                    if week < 2:
                        action = "read"
                    else:
                        action = self.rng.choice(["read", "read", "write", "download"])

                    evt = EventRecord(
                        event_id=_evt_id(),
                        timestamp=ts.isoformat(),
                        entity_id=entity.entity_id,
                        entity_type=entity.entity_type,
                        entity_role=entity.entity_role,
                        department=entity.department,
                        source_ip=_make_ip(self.rng),
                        geo_location=geo,
                        geo_lat=round(lat, 4),
                        geo_lon=round(lon, 4),
                        resource_accessed=resource,
                        resource_category=category,
                        action_type=action,
                        auth_method=self.rng.choice(entity.typical_auth_methods),
                        auth_status="success",
                        session_duration=self.rng.randint(120, 1800),
                        bytes_transferred=self.rng.randint(5000, 200000),
                        device_fingerprint=device["fingerprint"],
                        device_os=device["os"],
                        user_agent=device["user_agent"],
                        protocol=self.rng.choice(entity.typical_protocols),
                        command_sequence="[]",
                        is_vpn=False,
                    )
                    lbl = LabelRecord(
                        event_id=evt.event_id,
                        label="anomaly",
                        attack_type="insider_drift",
                        attack_subtype="gradual_scope_expansion",
                    )
                    results.append((evt, lbl))

        return results
