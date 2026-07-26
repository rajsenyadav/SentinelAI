"""
SentinelAI — Synthetic Data Generator (Orchestrator)

Coordinates entity creation, normal event generation, attack injection,
validation, and CSV export. This is the main entry point for data generation.
"""

import os
import random
import uuid
import math
import logging
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional

import pandas as pd
import yaml

from .schemas import (
    EventRecord, LabelRecord, GEO_LOCATIONS, RESOURCES,
    validate_event, validate_label,
)
from .entity_templates import EntityFactory, EntityProfile, _make_ip
from .attack_injector import AttackInjector

logger = logging.getLogger(__name__)


class SyntheticDataGenerator:
    """
    Generates a complete synthetic enterprise access log dataset.

    Usage:
        gen = SyntheticDataGenerator("config/data_config.yaml")
        gen.generate()
        gen.export()
    """

    def __init__(self, config_path: str):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.seed = self.config.get("seed", 42)
        self.rng = random.Random(self.seed)

        self.total_events = self.config["dataset"]["total_events"]
        self.time_span_days = self.config["dataset"]["time_span_days"]
        self.start_date = datetime.fromisoformat(self.config["dataset"]["start_date"])
        self.end_date = self.start_date + timedelta(days=self.time_span_days)

        self.anomaly_rate = self.config["attacks"]["anomaly_rate"]
        self.attack_distribution = self.config["attacks"]["distribution"]

        self.output_dir = self.config["output"]["directory"]

        self.entities: List[EntityProfile] = []
        self.events: List[EventRecord] = []
        self.labels: List[LabelRecord] = []

        self._entity_factory = EntityFactory(self.rng, self.config["dataset"]["start_date"])
        self._attack_injector = AttackInjector(self.rng)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> None:
        """Run the full generation pipeline."""
        logger.info("Starting SentinelAI synthetic data generation")
        logger.info(f"  Seed: {self.seed}")
        logger.info(f"  Target events: {self.total_events}")
        logger.info(f"  Time span: {self.time_span_days} days")
        logger.info(f"  Anomaly rate: {self.anomaly_rate * 100:.1f}%")

        # Step 1: Create entity population
        self._create_entities()
        logger.info(f"  Created {len(self.entities)} entities")

        # Step 2: Generate normal events
        self._generate_normal_events()
        logger.info(f"  Generated {len(self.events)} normal events")

        # Step 3: Inject attacks
        self._inject_attacks()
        logger.info(f"  Total events after attack injection: {len(self.events)}")

        # Step 4: Sort chronologically
        self._sort_events()
        logger.info("  Events sorted chronologically")

        # Step 5: Validate
        error_count = self._validate()
        if error_count > 0:
            logger.warning(f"  Validation found {error_count} errors")
        else:
            logger.info("  All records passed validation")

        # Step 6: Summary stats
        self._log_summary()

    def export(self) -> Tuple[str, str, str]:
        """Export generated data to CSV files. Returns paths to the 3 files."""
        os.makedirs(self.output_dir, exist_ok=True)

        events_path = os.path.join(self.output_dir, self.config["output"]["events_file"])
        labels_path = os.path.join(self.output_dir, self.config["output"]["labels_file"])
        profiles_path = os.path.join(self.output_dir, self.config["output"]["profiles_file"])

        # Events
        events_df = pd.DataFrame([e.to_dict() for e in self.events])
        events_df.to_csv(events_path, index=False)
        logger.info(f"  Exported events: {events_path} ({len(events_df)} rows)")

        # Labels
        labels_df = pd.DataFrame([l.to_dict() for l in self.labels])
        labels_df.to_csv(labels_path, index=False)
        logger.info(f"  Exported labels: {labels_path} ({len(labels_df)} rows)")

        # Entity profiles
        profiles_df = pd.DataFrame([e.to_dict() for e in self.entities])
        profiles_df.to_csv(profiles_path, index=False)
        logger.info(f"  Exported profiles: {profiles_path} ({len(profiles_df)} rows)")

        return events_path, labels_path, profiles_path

    # ------------------------------------------------------------------
    # Step 1: Entity population
    # ------------------------------------------------------------------

    def _create_entities(self) -> None:
        cold_start_count = self.config.get("cold_start", {}).get("new_entities_in_test", 0)
        self.entities = self._entity_factory.create_population(
            self.config["entities"],
            cold_start_count=cold_start_count,
        )

    # ------------------------------------------------------------------
    # Step 2: Normal event generation
    # ------------------------------------------------------------------

    def _generate_normal_events(self) -> None:
        """Generate normal behavioral events for all entities."""
        target_normal = int(self.total_events * (1 - self.anomaly_rate))

        # Compute event budget per entity proportional to avg_events_per_day
        total_daily_rate = sum(e.avg_events_per_day for e in self.entities)
        entity_budgets = {}
        for entity in self.entities:
            fraction = entity.avg_events_per_day / total_daily_rate
            budget = int(target_normal * fraction)
            # Cold-start entities only generate events after their onboarding date
            if entity.is_cold_start:
                onboard = datetime.fromisoformat(entity.onboarding_date)
                available_days = max(1, (self.end_date - onboard).days)
                budget = min(budget, int(entity.avg_events_per_day * available_days))
            entity_budgets[entity.entity_id] = max(budget, 10)

        # Adjust to hit target
        allocated = sum(entity_budgets.values())
        if allocated > 0:
            scale = target_normal / allocated
            entity_budgets = {k: max(10, int(v * scale)) for k, v in entity_budgets.items()}

        for entity in self.entities:
            budget = entity_budgets.get(entity.entity_id, 50)
            events = self._generate_entity_events(entity, budget)
            for evt in events:
                self.events.append(evt)
                self.labels.append(LabelRecord(
                    event_id=evt.event_id,
                    label="normal",
                    attack_type="normal",
                    attack_subtype="normal",
                ))

    def _generate_entity_events(self, entity: EntityProfile, count: int) -> List[EventRecord]:
        """Generate normal events for a single entity."""
        events = []

        # Determine active time range for this entity
        if entity.is_cold_start:
            entity_start = datetime.fromisoformat(entity.onboarding_date)
        else:
            entity_start = self.start_date
        entity_end = self.end_date

        active_days = max(1, (entity_end - entity_start).days)

        for _ in range(count):
            # Pick a random day
            day_offset = self.rng.randint(0, active_days - 1)
            day = entity_start + timedelta(days=day_offset)

            # Pick hour based on work schedule
            if entity.entity_type == "service_account":
                # Fixed-interval, 24/7
                hour = self.rng.randint(0, 23)
                minute = self.rng.choice([0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55])
            elif entity.entity_type == "edge_device":
                hour = self.rng.randint(0, 23)
                minute = self.rng.randint(0, 59)
            else:
                # Human: 85% work hours, 15% outside
                if self.rng.random() < 0.85:
                    hour = self.rng.randint(entity.work_hours_start, entity.work_hours_end)
                else:
                    # Off-hours
                    if self.rng.random() < 0.5:
                        hour = self.rng.randint(0, max(0, entity.work_hours_start - 1))
                    else:
                        hour = self.rng.randint(min(23, entity.work_hours_end + 1), 23)
                minute = self.rng.randint(0, 59)

                # Check work days
                if day.weekday() not in entity.work_days:
                    if self.rng.random() > 0.05:  # 95% skip non-work days
                        continue

            second = self.rng.randint(0, 59)
            ts = day.replace(hour=hour, minute=minute, second=second)

            # Geo: 92% primary, 8% secondary
            if entity.secondary_geo and self.rng.random() < 0.08:
                geo = entity.secondary_geo
            else:
                geo = entity.primary_geo
            lat, lon = GEO_LOCATIONS[geo]
            lat += self.rng.uniform(-0.02, 0.02)
            lon += self.rng.uniform(-0.02, 0.02)

            # Device
            device = self.rng.choice(entity.known_devices)

            # Resource
            resource = self.rng.choice(entity.typical_resources) if entity.typical_resources else "/portal/dashboard"
            resource_cat = self.rng.choice(entity.typical_resource_categories)

            # Auth: 97% typical method, 3% occasional alternative
            if self.rng.random() < 0.97:
                auth = self.rng.choice(entity.typical_auth_methods)
            else:
                auth = self.rng.choice(["password", "sso", "token"])

            # Auth status: 97% success for normal events
            auth_status = "success" if self.rng.random() < 0.97 else "failure"

            # Session duration
            duration = max(1, int(self.rng.gauss(
                entity.avg_session_duration, entity.session_duration_std
            )))
            if auth_status == "failure":
                duration = 0

            # Bytes transferred
            bytes_transferred = max(0, int(self.rng.gauss(
                entity.avg_bytes_per_session, entity.bytes_std
            )))
            if auth_status == "failure":
                bytes_transferred = 0

            # Action type
            action = self.rng.choice(entity.typical_actions)

            # Protocol
            protocol = self.rng.choice(entity.typical_protocols)

            # Commands (only for admins, occasionally)
            commands = "[]"
            if entity.entity_role == "admin" and entity.typical_commands and self.rng.random() < 0.3:
                commands = str(self.rng.choice(entity.typical_commands))

            # VPN
            is_vpn = self.rng.random() < entity.vpn_probability

            # Source IP
            source_ip = _make_ip(self.rng)

            evt = EventRecord(
                event_id=f"evt-{uuid.uuid4().hex[:8]}",
                timestamp=ts.isoformat(),
                entity_id=entity.entity_id,
                entity_type=entity.entity_type,
                entity_role=entity.entity_role,
                department=entity.department,
                source_ip=source_ip,
                geo_location=geo,
                geo_lat=round(lat, 4),
                geo_lon=round(lon, 4),
                resource_accessed=resource,
                resource_category=resource_cat,
                action_type=action,
                auth_method=auth,
                auth_status=auth_status,
                session_duration=duration,
                bytes_transferred=bytes_transferred,
                device_fingerprint=device["fingerprint"],
                device_os=device["os"],
                user_agent=device["user_agent"],
                protocol=protocol,
                command_sequence=commands,
                is_vpn=is_vpn,
            )
            events.append(evt)

        return events

    # ------------------------------------------------------------------
    # Step 3: Attack injection
    # ------------------------------------------------------------------

    def _inject_attacks(self) -> None:
        """Inject attack events according to configured distribution."""
        target_anomaly = int(self.total_events * self.anomaly_rate)

        attack_budgets = {}
        for attack_type, fraction in self.attack_distribution.items():
            attack_budgets[attack_type] = int(target_anomaly * fraction)

        # Get user entities for targeting
        user_entities = [e for e in self.entities if e.entity_type == "user"]

        for attack_type, budget in attack_budgets.items():
            generated = 0
            attempts = 0
            max_attempts = budget * 3

            while generated < budget and attempts < max_attempts:
                attempts += 1
                # Pick a random time in the simulation window
                day_offset = self.rng.randint(0, self.time_span_days - 1)
                base_time = self.start_date + timedelta(
                    days=day_offset,
                    hours=self.rng.randint(0, 23),
                    minutes=self.rng.randint(0, 59),
                )

                attack_events = self._generate_attack_batch(
                    attack_type, user_entities, base_time, budget - generated
                )

                for evt, lbl in attack_events:
                    self.events.append(evt)
                    self.labels.append(lbl)
                    generated += 1

            logger.info(f"    {attack_type}: {generated} events injected (target: {budget})")

    def _generate_attack_batch(
        self, attack_type: str, entities: List[EntityProfile],
        base_time: datetime, remaining: int
    ) -> List[Tuple[EventRecord, LabelRecord]]:
        """Generate a single batch of attack events for a given type."""
        target = self.rng.choice(entities) if entities else None
        if not target:
            return []

        if attack_type == "brute_force":
            count = max(1, min(remaining, self.rng.randint(15, 50)))
            return self._attack_injector.inject_brute_force(target, base_time, count)

        elif attack_type == "impossible_travel":
            return self._attack_injector.inject_impossible_travel(target, base_time)

        elif attack_type == "credential_stuffing":
            count = max(1, min(remaining, self.rng.randint(25, 60)))
            return self._attack_injector.inject_credential_stuffing(entities, base_time, count)

        elif attack_type == "lateral_movement":
            count = max(1, min(remaining, self.rng.randint(8, 20)))
            return self._attack_injector.inject_lateral_movement(target, base_time, count)

        elif attack_type == "device_spoofing":
            return self._attack_injector.inject_device_spoofing(target, base_time)

        elif attack_type == "low_slow_exfiltration":
            days = min(14, max(5, remaining // 2))
            return self._attack_injector.inject_low_slow_exfiltration(target, base_time, days)

        elif attack_type == "insider_drift":
            weeks = min(4, max(2, remaining // 6))
            return self._attack_injector.inject_insider_drift(target, base_time, weeks)

        return []

    # ------------------------------------------------------------------
    # Step 4: Sort
    # ------------------------------------------------------------------

    def _sort_events(self) -> None:
        """Sort events and labels chronologically by timestamp."""
        paired = list(zip(self.events, self.labels))
        paired.sort(key=lambda x: x[0].timestamp)
        self.events, self.labels = zip(*paired) if paired else ([], [])
        self.events = list(self.events)
        self.labels = list(self.labels)

    # ------------------------------------------------------------------
    # Step 5: Validation
    # ------------------------------------------------------------------

    def _validate(self) -> int:
        """Validate all generated records. Returns count of errors."""
        total_errors = 0
        for i, (evt, lbl) in enumerate(zip(self.events, self.labels)):
            evt_errors = validate_event(evt)
            lbl_errors = validate_label(lbl)
            if evt_errors or lbl_errors:
                total_errors += 1
                if total_errors <= 10:
                    for err in evt_errors + lbl_errors:
                        logger.warning(f"  Row {i}: {err}")
        return total_errors

    # ------------------------------------------------------------------
    # Step 6: Summary
    # ------------------------------------------------------------------

    def _log_summary(self) -> None:
        """Log dataset summary statistics."""
        total = len(self.events)
        anomalies = sum(1 for l in self.labels if l.label == "anomaly")
        normal = total - anomalies

        logger.info("=" * 60)
        logger.info("DATASET GENERATION COMPLETE")
        logger.info("=" * 60)
        logger.info(f"  Total events:    {total}")
        logger.info(f"  Normal events:   {normal} ({normal/total*100:.1f}%)")
        logger.info(f"  Anomaly events:  {anomalies} ({anomalies/total*100:.1f}%)")
        logger.info(f"  Total entities:  {len(self.entities)}")
        logger.info(f"  Time range:      {self.events[0].timestamp} → {self.events[-1].timestamp}")

        # Per-attack breakdown
        attack_counts: Dict[str, int] = {}
        for lbl in self.labels:
            if lbl.label == "anomaly":
                attack_counts[lbl.attack_type] = attack_counts.get(lbl.attack_type, 0) + 1

        logger.info("  Attack breakdown:")
        for atype, count in sorted(attack_counts.items()):
            logger.info(f"    {atype:30s} {count:6d}  ({count/total*100:.2f}%)")

        # Entity type breakdown
        type_counts: Dict[str, int] = {}
        for e in self.entities:
            key = f"{e.entity_type}/{e.entity_role}"
            type_counts[key] = type_counts.get(key, 0) + 1
        logger.info("  Entity breakdown:")
        for etype, count in sorted(type_counts.items()):
            logger.info(f"    {etype:30s} {count:4d}")

        cold_start = sum(1 for e in self.entities if e.is_cold_start)
        logger.info(f"  Cold-start entities: {cold_start}")
