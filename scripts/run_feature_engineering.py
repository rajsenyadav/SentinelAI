"""
SentinelAI — Feature Engineering CLI Execution Script

Usage:
    python scripts/run_feature_engineering.py
    python scripts/run_feature_engineering.py --events data/raw/events.csv --labels data/raw/labels.csv
"""

import argparse
import logging
import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from feature_engine.feature_pipeline import FeatureEngineeringPipeline


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI — Feature Engineering Execution"
    )
    parser.add_argument(
        "--events", type=str, default="data/raw/events.csv",
        help="Path to raw events CSV (default: data/raw/events.csv)"
    )
    parser.add_argument(
        "--labels", type=str, default="data/raw/labels.csv",
        help="Path to ground-truth labels CSV (default: data/raw/labels.csv)"
    )
    parser.add_argument(
        "--output-dir", type=str, default="data/processed",
        help="Output directory for engineered dataset (default: data/processed)"
    )
    parser.add_argument(
        "--output-filename", type=str, default="engineered_dataset.csv",
        help="Output CSV filename (default: engineered_dataset.csv)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable debug-level logging"
    )
    args = parser.parse_args()

    setup_logging(args.verbose)

    pipeline = FeatureEngineeringPipeline(output_dir=args.output_dir)

    start_time = time.time()
    pipeline.run(
        events_path=args.events,
        labels_path=args.labels,
        output_filename=args.output_filename,
    )
    elapsed = time.time() - start_time
    logging.info(f"Execution finished in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
