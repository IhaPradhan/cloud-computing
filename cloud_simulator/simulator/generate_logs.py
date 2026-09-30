
"""
Generate synthetic cloud activity datasets.
Creates normal_logs.csv and attack_logs.csv.
"""

import csv
import random
from pathlib import Path

from cloud_simulator import (
    generate_normal_event,
    generate_attack_event,
    ATTACK_SCENARIOS
)


# Reproducible results for development and testing
random.seed(42)

# Save CSV files in the project's data directory
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

NORMAL_COUNT = 1000
ATTACKS_PER_SCENARIO = 100

FIELDS = [
    "timestamp",
    "event_id",
    "user_id",
    "username",
    "role",
    "source_ip",
    "action",
    "resource_id",
    "resource_type",
    "region",
    "status",
    "bytes_out",
    "mfa",
    "user_agent",
    "scenario",
    "is_attack",
    "mitre_tactic",
    "mitre_technique",
    "mitre_name"
]


def save_csv(events, filename):
    """Write a list of events to a CSV file."""

    filepath = DATA_DIR / filename

    with open(filepath, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(events)

    print(f"Saved {len(events)} records to {filepath}")


def main():
    print("Generating simulated cloud activity logs...")

    # Generate normal activity
    normal_events = [
        generate_normal_event()
        for _ in range(NORMAL_COUNT)
    ]

    # Generate attack activity for every scenario
    attack_events = []

    for scenario_name in ATTACK_SCENARIOS:
        for _ in range(ATTACKS_PER_SCENARIO):
            attack_events.append(
                generate_attack_event(scenario_name)
            )

    # Shuffle events to avoid grouping all scenarios together
    random.shuffle(normal_events)
    random.shuffle(attack_events)

    save_csv(normal_events, "normal_logs.csv")
    save_csv(attack_events, "attack_logs.csv")

    print("\nDataset generation completed.")
    print(f"Normal events: {len(normal_events)}")
    print(f"Attack events: {len(attack_events)}")
    print(f"Total events: {len(normal_events) + len(attack_events)}")


if __name__ == "__main__":
    main()