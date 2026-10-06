# Honeypot-Driven SOC & Threat Intelligence Pipeline

A defensive cybersecurity portfolio project that demonstrates a simplified Security Operations Center (SOC) workflow using controlled synthetic security events.

## Features

- Synthetic honeypot-style event generation
- Security log parsing and normalization
- SSH brute-force detection
- Port-scan detection
- Repeated authentication-failure detection
- Threat-indicator extraction
- SQLite alert storage
- Streamlit SOC dashboard
- Automated unit tests

## Architecture

```text
Synthetic Security Events
          |
          v
     Security Logs
          |
          v
     Python Parser
          |
          v
 Event Normalization
          |
          v
   Detection Engine
      /     |      \
     v      v       v
Brute    Port     Auth
Force    Scan    Anomaly
      \     |      /
       v    v     v
     Security Alerts
          |
          v
    SQLite Database
          |
          v
     SOC Dashboard
```

## Results

The pipeline successfully generated 22 synthetic security events and produced 4 security alerts:

- 1 High-severity SSH brute-force alert
- 1 Medium-severity port-scan alert
- 2 Medium-severity repeated authentication-failure alerts

The project was validated using automated unit tests for log parsing and brute-force detection.

## Technology Stack

- Python
- SQLite
- Pandas
- Streamlit
- unittest

## Installation

```bash
python -m venv .venv
```

macOS/Linux:
```bash
source .venv/bin/activate
```

Windows:
```bash
.venv\Scripts\activate
```

Install dependencies:
```bash
pip install -r requirements.txt
```

## Run the Pipeline

```bash
python -m src.pipeline
```

The pipeline generates synthetic events, parses and normalizes them, applies detection rules, extracts alerts, and stores the results in `data/processed/`.

## Run Tests

```bash
python -m unittest discover -s tests -v
```

## Launch the SOC Dashboard

```bash
streamlit run dashboard/app.py
```

## Detection Rules

### SSH Brute Force
Triggers when one source IP produces at least 5 failed SSH authentication events.

### Port Scan
Triggers when one source IP contacts at least 8 different destination ports.

### Repeated Authentication Failures
Triggers when at least 3 failed authentication events occur within a 2-minute window.

These are demonstration thresholds for a learning project, not production SOC policies.

## Project Structure

```text
Honeypot_SOC_Threat_Intelligence_Pipeline/
├── dashboard/
│   └── app.py
├── data/
│   ├── raw/
│   └── processed/
├── reports/
│   └── project_summary.md
├── src/
│   ├── __init__.py
│   ├── detector.py
│   ├── generate_sample_logs.py
│   ├── parser.py
│   └── pipeline.py
├── tests/
│   └── test_pipeline.py
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Safety and Scope

All events are synthetic and use documentation/reserved IP ranges. The project does not scan, attack, or interact with real systems.

## Future Improvements

- MITRE ATT&CK technique mapping
- Wazuh or Elastic integration
- Configurable detection rules
- Authentication anomaly scoring
- Webhook/email alerting
- Docker deployment
- Threat-intelligence enrichment
