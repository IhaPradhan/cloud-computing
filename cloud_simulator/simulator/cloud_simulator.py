
"""
Simulated Cloud Environment
Member 1: Cloud + System Architect

This module defines simulated users, cloud resources,
normal activities, and security attack scenarios.
"""

from datetime import datetime, timezone
import random
import uuid


# -----------------------------
# 1. SIMULATED CLOUD USERS
# -----------------------------

USERS = [
    {
        "user_id": "user_001",
        "username": "admin_alex",
        "role": "CloudAdmin",
        "department": "IT",
        "trusted": True,
        "mfa_enabled": True,
        "normal_ip": "192.168.1.10"
    },
    {
        "user_id": "user_002",
        "username": "dev_sam",
        "role": "Developer",
        "department": "Engineering",
        "trusted": True,
        "mfa_enabled": True,
        "normal_ip": "192.168.1.11"
    },
    {
        "user_id": "user_003",
        "username": "analyst_lee",
        "role": "SecurityAnalyst",
        "department": "Security",
        "trusted": True,
        "mfa_enabled": True,
        "normal_ip": "192.168.1.12"
    },
    {
        "user_id": "user_004",
        "username": "intern_jay",
        "role": "ReadOnly",
        "department": "Engineering",
        "trusted": True,
        "mfa_enabled": False,
        "normal_ip": "192.168.1.13"
    }
]


# -----------------------------
# 2. SIMULATED CLOUD RESOURCES
# -----------------------------

RESOURCES = [
    {
        "resource_id": "s3_customer_data",
        "resource_type": "S3Bucket",
        "sensitivity": "High",
        "region": "ap-south-1"
    },
    {
        "resource_id": "ec2_web_server",
        "resource_type": "EC2Instance",
        "sensitivity": "Medium",
        "region": "ap-south-1"
    },
    {
        "resource_id": "iam_user_database",
        "resource_type": "IAM",
        "sensitivity": "High",
        "region": "ap-south-1"
    },
    {
        "resource_id": "cloudtrail_logs",
        "resource_type": "CloudTrail",
        "sensitivity": "High",
        "region": "ap-south-1"
    },
    {
        "resource_id": "rds_application_db",
        "resource_type": "RDS",
        "sensitivity": "High",
        "region": "ap-south-1"
    }
]


# -----------------------------
# 3. NORMAL CLOUD ACTIVITIES
# -----------------------------

NORMAL_ACTIONS = [
    "ConsoleLogin",
    "GetObject",
    "ListBuckets",
    "DescribeInstances",
    "StartInstance",
    "StopInstance",
    "GetUser",
    "ListUsers",
    "PutObject",
    "DescribeDBInstances"
]


# -----------------------------
# 4. ATTACK SCENARIOS
# -----------------------------

ATTACK_SCENARIOS = {
    "brute_force": {
        "action": "ConsoleLogin",
        "description": "Repeated failed login attempts",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force",
        "status": "Failed",
        "mfa": False,
        "bytes_out": 0
    },

    "privilege_escalation": {
        "action": "AttachAdminPolicy",
        "description": "Attempt to assign administrator privileges",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098",
        "mitre_name": "Account Manipulation",
        "status": "Success",
        "mfa": False,
        "bytes_out": 0
    },

    "data_exfiltration": {
        "action": "GetObject",
        "description": "Unusual bulk access to sensitive data",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1537",
        "mitre_name": "Transfer Data to Cloud Account",
        "status": "Success",
        "mfa": False,
        "bytes_out": 50000000
    },

    "logging_disabled": {
        "action": "StopLogging",
        "description": "Attempt to disable cloud activity logging",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.008",
        "mitre_name": "Disable or Modify Cloud Logs",
        "status": "Success",
        "mfa": False,
        "bytes_out": 0
    }
}


# -----------------------------
# 5. EVENT GENERATION
# -----------------------------

def create_event(
    user,
    resource,
    action,
    status="Success",
    bytes_out=0,
    mfa=True,
    source_ip=None,
    scenario="normal",
    is_attack=0,
    mitre_tactic="None",
    mitre_technique="None",
    mitre_name="None"
):
    """Create one simulated cloud activity event."""

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": str(uuid.uuid4()),
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "source_ip": source_ip or user["normal_ip"],
        "action": action,
        "resource_id": resource["resource_id"],
        "resource_type": resource["resource_type"],
        "region": resource["region"],
        "status": status,
        "bytes_out": bytes_out,
        "mfa": mfa,
        "user_agent": "SimulatedCloudClient/1.0",
        "scenario": scenario,
        "is_attack": is_attack,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "mitre_name": mitre_name
    }


def generate_normal_event():
    """Generate a normal activity by a simulated user."""

    user = random.choice(USERS)
    resource = random.choice(RESOURCES)
    action = random.choice(NORMAL_ACTIONS)

    return create_event(
        user=user,
        resource=resource,
        action=action,
        status="Success",
        bytes_out=random.randint(100, 50000),
        mfa=user["mfa_enabled"],
        scenario="normal",
        is_attack=0
    )


def generate_attack_event(scenario_name):
    """Generate an event representing a simulated attack."""

    if scenario_name not in ATTACK_SCENARIOS:
        raise ValueError(f"Unknown attack scenario: {scenario_name}")

    scenario = ATTACK_SCENARIOS[scenario_name]

    # Use a non-admin user for the simulated attack.
    user = random.choice(USERS[1:])
    resource = random.choice(RESOURCES)

    # Simulated external IP address.
    source_ip = f"203.0.113.{random.randint(1, 254)}"

    return create_event(
        user=user,
        resource=resource,
        action=scenario["action"],
        status=scenario["status"],
        bytes_out=scenario["bytes_out"],
        mfa=scenario["mfa"],
        source_ip=source_ip,
        scenario=scenario_name,
        is_attack=1,
        mitre_tactic=scenario["mitre_tactic"],
        mitre_technique=scenario["mitre_technique"],
        mitre_name=scenario["mitre_name"]
    )


if __name__ == "__main__":
    print("Simulated cloud environment initialized.")
    print(f"Users: {len(USERS)}")
    print(f"Resources: {len(RESOURCES)}")
    print(f"Attack scenarios: {len(ATTACK_SCENARIOS)}")

    print("\nSample normal event:")
    print(generate_normal_event())

    print("\nSample attack event:")
    print(generate_attack_event("brute_force"))