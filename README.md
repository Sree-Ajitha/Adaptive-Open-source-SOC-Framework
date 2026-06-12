Adaptive SOC Research Framework

An integrated open-source Security Operations Centre (SOC) framework combining Zeek,
Suricata, and Wazuh with a machine learning pipeline for SME-grade threat detection,
automated response, and hypothesis-driven evaluation.

## Overview

This repository contains the research artefacts, ML pipeline code, and custom decoder/rule
definitions, metrics scripts, and configuration supporting my master's research
project submitted to Whitecliffe, School of Information Technology, Aotearoa New Zealand.

The framework provides a modular, layered pipeline for:

- **Sensor layer** -- Suricata (signature-based IDS/IPS) and Zeek (behaviour-based
  network depth inspection) deployed on the monitored client host
- **Host-based detection** -- Wazuh Agent (HIDS) and Filebeat forwarding raw events
  to the Wazuh Manager
- **Aggregation and parsing** -- Wazuh Manager (rule/decoder pipeline) and Filebeat
  (custom OpenSearch ingest pipeline) feeding the Wazuh Indexer
- **Indexing and search** -- Wazuh Indexer (OpenSearch) processing inputs from both
  the Wazuh Manager and the Filebeat parse path
- **Visualisation** -- Wazuh Dashboard with a custom IDS Analysis panel, MITRE ATT&CK
  heatmap, per-tool alert breakdown, and live hypothesis scorecard
- **ML false-positive reduction** -- Random Forest classifier and LSTM autoencoder
  fused inside the `wazuh-ml-integration` service to suppress noise and surface true
  positives
- **Automated response (SOAR)** -- Wazuh Active Response triggered on high-confidence
  ML verdicts, with a custom `soar-watchdog` service providing telemetry to
  `/var/ossec/logs/active-responses.log`
- **Research metrics** -- standalone Python measurement script generating hypothesis
  evaluation data, MTTD/MTTC timings, and chart-ready exports

## Research Hypotheses

| ID | Hypothesis | Target | Outcome |
|---|---|---|---|
| Primary | ML pipeline reduces false positive / alert volume | >= 20% reduction | 36% reduction achieved |
| H1 | Cross-tool correlation detects multi-stage attacks invisible to single sensors | Confirmed | Confirmed |
| H2 | Mean Time to Detect (MTTD) below single-tool baseline | < 5 minutes | Sub-second (approx. 0.0 s) |
| H3 | MITRE ATT&CK technique coverage | >= 80% | 15 techniques mapped (>= 80%) |
| H4 | Detection rate across all attack scenarios | >= 80% | 100% across 35 scenarios |

## Key Results (IT9115 Evaluation Window)

- 38,179 real-time alerts processed across Zeek (21,286), Suricata (6,503), and
  Wazuh native (10,390) sources
- 4,777 correlation rule alerts confirming cross-tool pipeline integration
- 36% false positive volume reduction via dual-model ML pipeline
- MTTD sub-second across all 35 simulated attacks; MTTC 3.0 seconds via SOAR
- 100% detection rate across all 10 attack-scenario categories and 35 individual runs
- Total framework cost NZD$450 (hardware upgrade only), less than 1% of equivalent
  commercial SOC investment

## Architecture

```
Attacker (Kali Linux 2025.3)
        |
        v
Target Client (Ubuntu 24.04 + DVWA)
  +---------------------------------------------+
  | Suricata (signature IDS)                    |
  | Zeek (behaviour / protocol analysis)        |
  | Wazuh Agent (HIDS)      --> Wazuh Manager   |
  | Filebeat (log shipper)  --> Wazuh Manager   |
  +---------------------------------------------+
        |
        v
Wazuh Manager (parse + rule/decoder pipeline)
Filebeat (custom OpenSearch ingest pipeline)
        |
        v
Wazuh Indexer (OpenSearch)
  +---------------------------------------------+
  | wazuh-ml-integration.service                |
  |   Random Forest classifier                  |
  |   LSTM autoencoder                          |
  |   Fusion verdict logic                      |
  +---------------------------------------------+
        |
        v
Wazuh Dashboard
  +---------------------------------------------+
  | Custom IDS Analysis panel                   |
  | MITRE ATT&CK heatmap                        |
  | Per-tool alert breakdown (Zeek/Suricata/    |
  |   Wazuh native)                             |
  | Live hypothesis scorecard                   |
  | Active response telemetry                   |
  +---------------------------------------------+
        |
        v
soar-watchdog.service --> /var/ossec/logs/active-responses.log
metrics_collector.py  --> results.json / chart exports
```

## Requirements

- Python 3.10+
- Wazuh 4.x stack (Manager, Indexer, Dashboard, Agent)
- Suricata 7.x
- Zeek 6.x
- Filebeat 8.x (OpenSearch ingest pipeline)
- VMware Workstation Pro 25H2 (or equivalent hypervisor) for isolated testbed

Python dependencies are listed in `requirements.txt`.

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/Adaptive-Open-source-SOC-Framework.git
cd Adaptive-Open-source-SOC-Framework


```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment variables

Copy the example environment file and populate your Wazuh API credentials and
OpenSearch connection details:

```bash
cp .env.example .env
# Edit .env with your Wazuh Manager host, API user, password, and indexer URL
```

### 4. Deploy the ML integration service

```bash
# Copy the service unit file
sudo cp services/wazuh-ml-integration.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-ml-integration.service

# Copy the SOAR watchdog service
sudo cp services/soar-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soar-watchdog.service
```

### 5. Load custom decoders and rules into Wazuh Manager

```bash
sudo cp rules/custom_soc_rules.xml /var/ossec/etc/rules/
sudo cp decoders/custom_soc_decoders.xml /var/ossec/etc/decoders/
sudo systemctl restart wazuh-manager
```

### 6. Run the metrics collector

```bash
python src/metrics/metrics_collector.py \
    --wazuh-host <manager-ip> \
    --output results/results.json \
    --charts results/charts/
```

### 7. Reproduce ML training (optional)

```bash
python src/ml/train_random_forest.py --data data/training_alerts.csv
python src/ml/train_lstm_autoencoder.py --data data/training_alerts.csv
```

## Project Layout

```
Adaptive-Open-source-SOC-Framework/
├── src/
│   ├── ml/
│   │   ├── train_random_forest.py      # Random Forest classifier training
│   │   ├── train_lstm_autoencoder.py   # LSTM autoencoder training
│   │   ├── ml_integration_service.py   # wazuh-ml-integration runtime
│   │   └── fusion_verdict.py           # Dual-model fusion logic
│   ├── metrics/
│   │   ├── metrics_collector.py        # Hypothesis evaluation and telemetry
│   │   ├── mttd_calculator.py          # Mean Time to Detect analysis
│   │   ├── mttc_calculator.py          # Mean Time to Contain analysis
│   │   └── chart_exporter.py           # Plotly/Matplotlib chart generation
│   ├── soar/
│   │   ├── soar_watchdog.py            # Active response watchdog service
│   │   └── active_response_parser.py   # Log parser for active-responses.log
│   └── dashboard/
│       └── custom_dashboard_import.ndjson  # Wazuh dashboard export
├── rules/
│   └── custom_soc_rules.xml            # Custom Wazuh correlation rules
├── decoders/
│   └── custom_soc_decoders.xml         # Custom Wazuh decoders (Zeek + Suricata)
├── services/
│   ├── wazuh-ml-integration.service    # systemd unit for ML service
│   └── soar-watchdog.service           # systemd unit for watchdog
├── models/
│   ├── rf_classifier.joblib            # Trained Random Forest model artefact
│   └── lstm_autoencoder.keras          # Trained LSTM autoencoder artefact
├── data/
│   └── training_alerts.csv             # Sample labelled alert dataset (anonymised)
├── results/
│   ├── results.json                    # Hypothesis evaluation output
│   └── charts/                         # Generated chart exports
├── config/
│   └── filebeat_opensearch_pipeline.yml  # Filebeat ingest pipeline configuration
├── .env.example
├── requirements.txt
├── CITATION.cff
└── README.md
```
### Process workflow 

<img width="2112" height="1046" alt="Open SOC framework summary" src="https://github.com/user-attachments/assets/1b8961a8-f50f-482d-b7e8-601927849c90" />

## Modules

### ML Pipeline (`src/ml/`)

The dual-model pipeline runs as a persistent service (`wazuh-ml-integration.service`)
that subscribes to the Wazuh Indexer alert stream in real time.

Fusion verdict logic:

| RF verdict | LSTM anomaly score | Final verdict |
|---|---|---|
| Malicious | High (> threshold) | TRUE POSITIVE -- forward |
| Malicious | Low | TRUE POSITIVE -- forward |
| Benign | High | REVIEW -- forward with flag |
| Benign | Low | FALSE POSITIVE -- suppress |

```python
from src.ml.fusion_verdict import fuse_verdicts

verdict = fuse_verdicts(rf_prediction, lstm_score, threshold=0.65)
```

### Metrics Collector (`src/metrics/metrics_collector.py`)

Queries the Wazuh Indexer and computes all hypothesis evaluation metrics, exporting
structured JSON and chart images for the written report.

```python
from src.metrics.metrics_collector import collect_all_metrics

results = collect_all_metrics(
    wazuh_host="192.168.50.10",
    index_pattern="wazuh-alerts-*",
    output_path="results/results.json",
)
```

Metrics produced:

- Alert volume by source (Zeek, Suricata, Wazuh native)
- False positive reduction percentage (Primary Hypothesis)
- Cross-tool correlation hit count (H1)
- MTTD per attack and distribution (H2)
- MITRE ATT&CK technique coverage count and percentage (H3)
- Attack scenario detection rate (H4)
- MTTC per active response event

### SOAR Watchdog (`src/soar/soar_watchdog.py`)

A lightweight daemon installed on the target client that monitors Wazuh Active Response
execution and appends structured telemetry entries to
`/var/ossec/logs/active-responses.log`. Implements a five-state machine:

`IDLE -> TRIGGERED -> EXECUTING -> COMPLETED -> LOGGED`

### Custom Decoders and Rules

All custom Wazuh decoders (normalising Zeek JSON log fields and Suricata EVE JSON) and
correlation rules (cross-tool frequency thresholds, MITRE ATT&CK tagging, ML verdict
integration) are stored in `decoders/` and `rules/` respectively. Each rule includes
`<mitre>` tags for dashboard heatmap rendering.

### Dashboard (`src/dashboard/`)

The `custom_dashboard_import.ndjson` file can be imported directly into the Wazuh
Dashboard to restore the full IDS Analysis panel, including per-tool alert
breakdown, MITRE ATT&CK heatmap, live hypothesis scorecard, and active response
telemetry visualisation.

## Attack Simulation Summary

All simulations were conducted in an isolated VMware Workstation Pro 25H2 environment.
No external networks were involved.

| Phase | Category | Example tools / techniques |
|---|---|---|
| 1 | Reconnaissance | Nmap, Masscan, Nikto |
| 2 | Credential access | Hydra, Medusa, Metasploit |
| 3 | Web application attacks | SQLMap, XSS, DVWA exploit chains |
| 4 | Advanced exploitation | Metasploit modules, reverse shells, privilege escalation |

Target host: Ubuntu 24.04 desktop with DVWA, FTP service, and common ports open by design.
Attacker: Kali Linux 2025.3 virtual machine.

## Ethical Statement

All attack simulations were conducted within a fully isolated VMware testbed environment
using deliberately vulnerable machines. No production systems, real user data, or external
networks were involved. This research complies with Whitecliffe's research ethics
guidelines and Aotearoa New Zealand's Privacy Act 2020.


## Acknowledgements

Built with Wazuh, OpenSearch, Suricata, Zeek, Filebeat, scikit-learn, TensorFlow/Keras,
pandas, NumPy, Plotly, Matplotlib, and the wider open-source security community.

Special acknowledgement to the Wazuh community playbook contributors, whose active
response scripts formed the basis for the SOAR integration tested in this research.

Research supervised by the School of Information Technology, Whitecliffe, Aotearoa
New Zealand.

"Ehara taku toa i te toa takitahi, engari he toa takitini"
"My strength is not that of an individual, but that of the collective"
