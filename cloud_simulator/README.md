
# Cloud Security Simulation Module

## Overview

This module simulates a cloud environment and generates
synthetic cloud activity logs for a multi-agent cloud
security monitoring project.

It represents an AWS-style environment without connecting
to an actual AWS account.

## Simulated Resources

- IAM users and roles
- S3 storage bucket
- EC2 web server
- RDS application database
- CloudTrail logging service

## Simulated Attack Scenarios

1. Brute-force login attempts
2. Privilege escalation
3. Unusual bulk data access
4. Cloud logging disabled

Each attack scenario has a corresponding MITRE ATT&CK
mapping for the project's initial threat model.

## Project Structure

- simulator/cloud_simulator.py: users, resources,
  event definitions and event generation
- simulator/generate_logs.py: dataset generation
- data/normal_logs.csv: normal activity records
- data/attack_logs.csv: simulated attack records
- architecture/mitre_mapping.csv: attack mapping
- architecture/system_architecture.md: architecture diagram

## Dataset

The generator creates:
- 1,000 normal activity records
- 400 simulated attack records
- 1,400 total records

The data is synthetic and intended for development,
demonstration and testing.

## How to Run

From the project root:

```bash
python cloud_simulator/simulator/cloud_simulator.py
python cloud_simulator/simulator/generate_logs.py
```

Generated CSV files are saved in the data directory.

## Integration

Member 2 can use the generated CSV files to develop
and evaluate the anomaly detection model.

Member 3 can use the attack scenarios and MITRE mappings
to implement investigation, risk assessment and response.

Member 4 can use the generated logs and agent outputs
to populate the Streamlit dashboard.