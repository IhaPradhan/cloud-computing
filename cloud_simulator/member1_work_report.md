# Member 1 Work Report

## Cloud Security Simulation — Cloud Infrastructure and System Architecture

**Role:** Member 1 — Cloud + System Architect
**Project:** Multi-Agent Cloud Security Monitoring System

---

## 1. Overview

I was responsible for designing and implementing the simulated cloud environment for the project. The purpose of this module is to generate realistic cloud activity logs containing both normal user activities and simulated security attacks.

The simulator follows an AWS-style cloud environment without requiring an actual AWS account.

## 2. Work Completed

### 2.1 Cloud Environment Simulation

Created a simulated cloud environment containing:

* 4 simulated users with different access roles.
* 5 simulated cloud resources.
* User activity and resource access events.
* Simulated cloud regions and IP addresses.
* Activity timestamps and event IDs.

### 2.2 User and Resource Management

The simulated environment includes users with different access permissions and resources representing cloud services.

The user roles and resources allow the project to simulate legitimate activities as well as suspicious access attempts.

### 2.3 Attack Scenario Generation

Implemented four simulated attack scenarios:

* Brute-force attempts
* Unauthorized access
* Suspicious resource access
* Privilege-related attacks

These scenarios are used to generate attack events for the detection module.

### 2.4 Activity Log Generation

Created Python scripts to generate cloud activity logs.

**Files:**

* `simulator/cloud_simulator.py`
* `simulator/generate_logs.py`

The logs contain fields such as:

* Timestamp
* Event ID
* User ID and username
* User role
* Source IP address
* Action performed
* Resource ID and type
* Region
* Event status
* MFA status
* Attack scenario
* Attack label
* MITRE ATT&CK information

### 2.5 Dataset Creation

Generated two CSV datasets:

* `data/normal_logs.csv` — contains simulated legitimate cloud activity.
* `data/attack_logs.csv` — contains simulated attack activity.

These datasets will be used by the detection and investigation modules developed by other team members.

### 2.6 MITRE ATT&CK Mapping

Created a MITRE mapping file to associate simulated attack scenarios with relevant MITRE ATT&CK tactics and techniques.

**File:** `architecture/mitre_mapping.csv`

The mapping provides a security framework for describing the simulated attacks. The final mappings should be verified against the official MITRE ATT&CK Cloud Matrix.

### 2.7 System Architecture

Created the system architecture documentation and diagram to explain the simulated cloud environment and its role in the overall multi-agent security monitoring system.

**Files:**

* `architecture/system_architecture.md`
* `architecture/mermaid-diagram.png`

## 3. Project Folder Structure

```text
cloud_simulator/
│
├── architecture/
│   ├── mitre_mapping.csv
│   ├── system_architecture.md
│   └── mermaid-diagram.png
│
├── data/
│   ├── normal_logs.csv
│   └── attack_logs.csv
│
├── simulator/
│   ├── cloud_simulator.py
│   └── generate_logs.py
│
├── README.md
└── member1_work_report.md
```

## 4. Technologies Used

* Python
* CSV
* Git and GitHub
* Mermaid for architecture diagrams
* MITRE ATT&CK framework

## 5. Integration with Other Team Members

The module provides the initial data and infrastructure for the remaining project components.

**Member 2 — Detection and ML**

* Uses the generated CSV datasets.
* Performs preprocessing and feature extraction.
* Trains and evaluates the anomaly detection model.

**Member 3 — Agent Intelligence and Security**

* Uses detected events for investigation and risk assessment.
* Implements response logic and the supervisor agent.
* Uses the simulated IAM roles and attack information.

**Member 4 — Dashboard and Documentation**

* Displays generated and detected security events.
* Uses the architecture and dataset documentation.
* Integrates actual results into the final presentation.

## 6. How to Run the Simulator

From the project root directory, run:

```bash
python cloud_simulator/simulator/cloud_simulator.py
```

To generate activity logs, run:

```bash
python cloud_simulator/simulator/generate_logs.py
```

The generated CSV files are stored in the `data` directory.

## 7. Current Status

The initial cloud simulation module has been created and uploaded to GitHub. The simulator has been executed successfully, and its output confirmed the initialization of the simulated users, resources, and attack scenarios.

The generated datasets and architecture documentation provide the foundation for integration with the detection and multi-agent modules.

## 8. Future Improvements

* Expand the number and variety of simulated attack scenarios.
* Improve the realism of cloud activity logs.
* Add additional IAM policies and access-control scenarios.
* Integrate the simulator with the detection and response agents.
* Validate the MITRE ATT&CK mappings against the final attack implementations.

---

**Prepared by:** Member 1 — Cloud + System Architect
**Project:** Multi-Agent Cloud Security Monitoring System
