"""
SentinelAI — Data Generation Entry Point

Usage:
    python scripts/generate_data.py
    python scripts/generate_data.py --config config/data_config.yaml
    python scripts/generate_data.py --total-events 50000 --anomaly-rate 0.02
"""

import argparse
import logging
import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data_generator.generator import SyntheticDataGenerator


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI — Synthetic Access Log Generator"
    )
    parser.add_argument(
        "--config", type=str, default="config/data_config.yaml",
        help="Path to YAML configuration file (default: config/data_config.yaml)"
    )
    parser.add_argument(
        "--total-events", type=int, default=None,
        help="Override total event count from config"
    )
    parser.add_argument(
        "--anomaly-rate", type=float, default=None,
        help="Override anomaly rate (0.0 - 1.0) from config"
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Override random seed from config"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug-level logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    logger.info("=" * 60)
    logger.info("SentinelAI — Synthetic Data Generator")
    logger.info("=" * 60)

    # Initialize generator
    gen = SyntheticDataGenerator(args.config)

    # Apply CLI overrides
    if args.total_events is not None:
        gen.total_events = args.total_events
        gen.config["dataset"]["total_events"] = args.total_events
        logger.info(f"  Override: total_events = {args.total_events}")

    if args.anomaly_rate is not None:
        gen.anomaly_rate = args.anomaly_rate
        gen.config["attacks"]["anomaly_rate"] = args.anomaly_rate
        logger.info(f"  Override: anomaly_rate = {args.anomaly_rate}")

    if args.seed is not None:
        gen.seed = args.seed
        gen.rng = __import__("random").Random(args.seed)
        logger.info(f"  Override: seed = {args.seed}")

    # Generate
    start_time = time.time()
    gen.generate()
    gen_time = time.time() - start_time
    logger.info(f"  Generation time: {gen_time:.2f}s")

    # Export
    events_path, labels_path, profiles_path = gen.export()

    logger.info("=" * 60)
    logger.info("Output files:")
    logger.info(f"  Events:   {events_path}")
    logger.info(f"  Labels:   {labels_path}")
    logger.info(f"  Profiles: {profiles_path}")
    logger.info("=" * 60)
    logger.info("Done.")


if __name__ == "__main__":
    main()
