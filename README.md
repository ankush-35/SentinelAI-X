# SentinelAI-X

## AI-Powered Network Intrusion Detection and Monitoring System

![Python](https://img.shields.io/badge/Python-3.12%2B-blue)
![Pytest](https://img.shields.io/badge/Pytest-tested-brightgreen)
![mypy](https://img.shields.io/badge/mypy-static%20typing-blueviolet)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

SentinelAI-X is a Python-based network intrusion detection and monitoring
system designed for security labs, Final Year Project evaluation, and
portfolio-grade cybersecurity demonstrations. The project monitors network
traffic, parses packet metadata, detects suspicious activity through rules and
anomaly detection, manages security alerts, and exposes dashboard-ready data
for monitoring workflows.

The long-term goal is to provide a practical SOC-style platform that can run
in lab environments, including Cisco-focused network setups, while remaining
cleanly structured, testable, and suitable for future AI/ML enhancements.

## Project Overview

Modern networks generate continuous traffic that can hide scans, unusual
protocol usage, suspicious ports, traffic spikes, and other indicators of
compromise. SentinelAI-X addresses this by building a modular detection
pipeline:

- Discover available network interfaces.
- Capture packets from selected interfaces.
- Parse packet metadata into structured records.
- Evaluate traffic through a rules engine.
- Detect anomalous behavior using detection modules.
- Convert findings into managed alerts.
- Provide dashboard backend and API layers for monitoring.

The project is intentionally split into focused modules so each component can
be tested, extended, and reviewed independently.

## Features

- **Interface Discovery**: Detects and normalizes available network interfaces.
- **Packet Capture**: Captures traffic from selected interfaces using Scapy.
- **Packet Parsing**: Converts raw packet data into structured metadata.
- **Rules Engine**: Applies deterministic security rules to packet metadata.
- **Anomaly Detection**: Identifies suspicious behavior and abnormal traffic patterns.
- **Alert Management**: Creates, deduplicates, aggregates, tracks, and exports alerts.
- **Dashboard Backend**: Provides JSON-serializable dashboard read models.
- **Dashboard API**: Exposes a clean API facade for dashboard consumers.
- **Unit Testing**: Uses focused automated tests for core modules.
- **Static Type Checking**: Supports type-safe development with mypy.

## Project Architecture

```text
+-------------------+
| Network Traffic   |
+---------+---------+
          |
          v
+-------------------+      +----------------------+
| Interface         | ---> | Packet Capture       |
| Discovery         |      | and Collection       |
+---------+---------+      +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Packet Parsing       |
                           | and Metadata Model   |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Rules Engine         |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Anomaly Detection    |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Alert Management     |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Dashboard Backend    |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Dashboard API        |
                           +----------+-----------+
                                      |
                                      v
                           +----------------------+
                           | Future Dashboard UI  |
                           +----------------------+
```

## Folder Structure

```text
SentinelAI-X/
├── backend/                 # Placeholder for future backend service integration
├── dashboard/               # Dashboard backend and API facade modules
├── detection/               # Anomaly detection and alert management logic
├── docs/                    # Project documentation and generated explanations
├── llm-agent/               # Placeholder for future LLM-assisted investigation
├── ml-engine/               # Placeholder for future ML model integration
├── rule-engine/             # Deterministic traffic rules engine
├── sensor/                  # Interface discovery, packet capture, and parsing
├── tests/                   # Unit tests for implemented modules
├── LICENSE                  # MIT license
├── pyproject.toml           # Project metadata and tool configuration
├── requirements.txt         # Runtime dependency list
└── README.md                # Project documentation
```

### Major Folders

- **backend/**: Reserved for future web service or API server integration.
- **dashboard/**: Contains dashboard-facing backend and API layers that expose
  JSON-serializable alert data.
- **detection/**: Contains anomaly detection and alert management components.
- **docs/**: Stores roadmap notes, generated reports, and supporting project
  documentation.
- **llm-agent/**: Reserved for future LLM-based investigation or analyst-assist
  workflows.
- **ml-engine/**: Reserved for future machine learning model training and
  inference components.
- **rule-engine/**: Contains rule-based detection logic for structured packet
  metadata.
- **sensor/**: Contains network interface discovery, packet capture, and packet
  parsing modules.
- **tests/**: Contains automated tests for validating project behavior.

## Technology Stack

- **Python**: Core implementation language.
- **Pytest**: Test runner for automated verification.
- **mypy**: Static type checker for safer Python development.
- **Git**: Version control for local development.
- **GitHub**: Repository hosting, collaboration, and project presentation.
- **Scapy**: Packet capture and network packet inspection dependency.

## Installation

Clone the repository:

```bash
git clone https://github.com/ankush-35/SentinelAI-X.git
cd SentinelAI-X
```

Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install runtime dependencies:

```bash
pip install -r requirements.txt
```

Install development tools:

```bash
pip install pytest mypy
```

## Usage

Run modules and experiments from the project root so package imports resolve
correctly:

```bash
python -m unittest
```

Example dashboard API usage:

```python
from dashboard.dashboard_api import DashboardAPI

api = DashboardAPI()
summary = api.get_summary()
recent_alerts = api.get_recent_alerts(limit=10)

print(summary)
print(recent_alerts)
```

For packet capture workflows, ensure Scapy is installed and the terminal has
the permissions required by the operating system to inspect live network
interfaces.

## Running Tests

Run all tests with pytest:

```bash
pytest -v
```

Run a specific test file:

```bash
pytest -v tests/test_alert_manager.py
```

Run unittest discovery:

```bash
python -m unittest discover
```

## Static Type Checking

Run mypy on the detection package:

```bash
mypy detection
```

Run mypy on additional packages as they mature:

```bash
mypy sensor detection dashboard
```

## Git Branch Strategy

Recommended branch strategy:

- **main**: Stable, presentation-ready project state.
- **feature/** branches: New modules, dashboard work, detection improvements,
  and focused enhancements.
- **fix/** branches: Bug fixes and targeted corrections.
- **docs/** branches: README, documentation, and report updates.

Example workflow:

```bash
git checkout -b feature/dashboard-backend
git add .
git commit -m "Add dashboard backend and API"
git push origin feature/dashboard-backend
```

## Current Project Status

SentinelAI-X is currently in an active development stage with the core
foundation implemented across the sensor, rules, detection, alerting, dashboard,
and test layers.

Current highlights:

- Network interface discovery module implemented.
- Packet capture and packet parsing modules implemented.
- Rules engine implemented with unit tests.
- Anomaly detection module implemented.
- Alert manager implemented with dashboard-oriented analytics.
- Dashboard backend and Dashboard API modules added.
- Unit tests exist for core modules.
- Static typing practices are being applied across production modules.

## Future Work

- **Dashboard UI**: Build a web-based monitoring interface for alert summaries,
  trends, and investigation views.
- **AI/ML Model Integration**: Add trainable models for anomaly scoring and
  threat classification.
- **Real-time Monitoring**: Stream live packet and alert data into dashboard
  components.
- **Cisco Lab Deployment**: Validate the system in a Cisco-style networking lab
  with routers, switches, VLANs, and mirrored traffic.
- **Reporting**: Generate PDF/HTML security reports for alerts, anomalies, and
  monitoring sessions.

## Author

**Ankush**  
Final Year Project: SentinelAI-X  
AI-Powered Network Intrusion Detection and Monitoring System

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.
