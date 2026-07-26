"""
SentinelAI — Synthetic Data Generator

Generates realistic enterprise access logs with injected attack patterns
for behavioral anomaly detection research.
"""

from .generator import SyntheticDataGenerator
from .entity_templates import EntityFactory
from .attack_injector import AttackInjector

__all__ = ["SyntheticDataGenerator", "EntityFactory", "AttackInjector"]
