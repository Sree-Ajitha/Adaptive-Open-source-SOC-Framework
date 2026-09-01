# Adaptive Open-Source SOC Framework
### Multi-Sensor Detection, ML-Assisted Alert Triage, and Automated Response for Resource-Constrained Environments

> **Status:** Conference paper under review at IEEE ITNAC 2026.
> In accordance with the double-blind review process, author and institutional details are omitted from this README until the review outcome is announced.

---

## Overview

This repository contains the complete implementation, configuration artefacts, evaluation scripts, and result datasets for an open-source Security Operations Centre (SOC) framework designed for small and medium-sized enterprises (SMEs) and other resource-constrained environments.

The framework integrates three complementary open-source security tools into a unified six-layer detection and response architecture:

- **Zeek** — network security monitoring and deep packet inspection
- **Suricata** — signature-based intrusion detection (Emerging Threats Open ruleset)
- **Wazuh** — host-based intrusion detection, SIEM, and automated response

A hybrid machine learning pipeline combining a **Random Forest classifier** (weight α = 0.65) and an **LSTM autoencoder** (weight 1 − α = 0.35) performs real-time alert triage to reduce analyst-visible alert volume while preserving 100% recall of confirmed attack events.

The framework was evaluated in two environments:

| Environment | Description |
|---|---|
| **Experiment 1** | Controlled VMware Attack Replay Sandbox (43 attack scenarios, 6 phases) |
| **Experiment 2** | Live DigitalOcean cloud deployment, Sydney SYD1 (120+ hours, Internet-facing) |

---

## Key Results

| Metric | Value |
|---|---|
| Attack scenario detection rate | 100% (43/43) |
| MITRE ATT&CK techniques confirmed (Experiment 1) | 13 (Phase 1–5) |
| MITRE ATT&CK techniques confirmed (Experiment 2) | 4 (independently observed) |
| Analyst-visible alert reduction | 36.0% at 100% recall |
| Cross-sensor correlation events (Rule 100399) | 3,889 |
| ML pipeline mean end-to-end latency | 2.71 s (P95: 3.46 s) |
| ML triage stage latency | 43 ms (1.6% of total) |
| Mean Time To Containment (MTTC) | 3.0 s (ML classification → UFW rule insertion) |
| Cloud records processed (Experiment 2) | 631,633 across 84 collection cycles |
| Non-FP classification rate (cloud, fusion labels) | 96.5% |
| Total VMware hardware cost | Below NZD 450 (2025 pricing) |

> **Reproducibility note:** The alert totals reported above (38,179 alerts, Experiment 1; 3,889 Rule 100399 firings) are stored constants from a prior extended evaluation session, captured in `Experiement1-VMware_Attack_Replay_Sandbox_results.json`. A live run of the metrics pipeline reflects only the current session. To reproduce the reported figures, execute the full attack-replay session as documented in [Running the Attack Replay](#running-the-attack-replay) before running the metrics scripts.

---

## Repository Structure

```
Adaptive-Open-source-SOC-Framework/
│
├── config/                         # Wazuh custom rules, decoders, and Filebeat config
│   ├── rules/
│   │   └── local_rules.xml         # Custom correlation rules including Rule 100399
│   ├── decoders/
│   │   └── local_decoder.xml       # Custom decoders for Zeek and Suricata log formats
│   └── filebeat/
│       └── filebeat.yml            # Filebeat input configuration
│
├── ml/                             # Machine learning pipeline
│   ├── ml_integration.py           # AUTHORITATIVE runtime: RF + LSTM fusion (α = 0.65/0.35)
│   ├── ml_reclassify.py            # Batch reclassification pipeline (run first)
│   ├── classify_alert.py           # Legacy classifier (non-authoritative; α = 0.6/0.4)
│   └── models/
│       ├── random_forest_model.pkl # Trained RF model (10,000 synthetic records)
│       └── lstm_autoencoder.h5     # Trained LSTM autoencoder (5,000 synthetic sequences)
│
├── metrics/                        # Evaluation and metric collection scripts
│   ├── wazuh_manager_report_v5.py  # Primary metrics pipeline (run after ml_reclassify.py)
│   ├── post_process_reports.py     # Mandatory post-processing step (run after report)
│   ├── alpha_sensitivity.py        # Alpha sweep: 21 uniformly spaced values in [0.0, 1.0]
│   └── Mttd_pipeline_latency.py    # Pipeline latency characterisation
│
├── cloud/                          # DigitalOcean cloud deployment scripts
│   ├── DO_log_pull.sh              # Cron-scheduled SSH log retrieval (5-minute interval)
│   ├── DO_sanitise.py              # Log sanitisation and IP deduplication
│   ├── DO_metric_collector.py      # Cloud metric aggregation
│   └── DO_summary_report.py        # Cloud result summary generation
│
├── attack_scripts/                 # Attack scenario orchestration
│   ├── phase1_reconnaissance/      # Port scanning, vulnerability scanning
│   ├── phase2_credential_access/   # Brute force, password guessing
│   ├── phase3_web_attacks/         # SQL injection, XSS, LFI, RCE, CSRF
│   ├── phase4_exploitation/        # Web shells, XXE
│   ├── phase5_post_exploitation/   # DNS tunnelling, data exfiltration, privilege escalation
│   └── phase6_extension/           # AiTM, network sniffing, password spraying,
│                                   # reverse shells, cron persistence, ICMP tunnelling,
│                                   # account discovery, subnet host discovery
│
├── active_response/                # Wazuh Active Response scripts
│   ├── block-ip.sh                 # UFW/iptables blocking script (Rule 99999)
│   └── watchdog_service/           # Custom watchdog to log active-response events
│
├── results/                        # Evaluation result artefacts
│   ├── Experiement1-VMware_Attack_Replay_Sandbox_results.json
│   ├── experiment2_Cloud_results.json
│   ├── ml_corrected_summary.json   # Cloud ML classification labels (authoritative)
│   ├── cloud_results_mitre.csv     # MITRE ATT&CK technique mapping (cloud)
│   ├── vmware_results_mttd.csv     # Per-scenario detection records (VMware)
│   ├── alpha_sensitivity_results.csv
│   ├── mttd_latency_samples.csv
│   ├── results_mitre.csv
│   ├── results_summary.csv
│   └── results_rq.csv
│
├── honeypot/                       # Cowrie honeypot configuration
│   └── cowrie.cfg                  # Port-forwarding: external 22/23 → internal 2222/2223
│
└── notebooks/                      # Jupyter notebooks for figure generation
    └── figures/                    # Publication figures (300 DPI)
```

---

## Framework Architecture

The framework implements six functional layers:

```
┌──────────────┐    ┌──────────────────────┐    ┌─────────────────┐
│   LAYER 1    │    │       LAYER 2        │    │    LAYER 3      │
│ Sensor Layer │───▶│ Log Transport and    │───▶│  ML Triage      │
│              │    │ Correlation Layer    │    │  Layer          │
│ Zeek (NSM)   │    │                      │    │                 │
│ Suricata(IDS)│    │ Filebeat → Wazuh     │    │ RF classifier   │
│ Wazuh (HIDS) │    │ Custom decoders      │    │ LSTM autoencoder│
│ Cowrie       │    │ Rule 100399          │    │ Fusion: α=0.65  │
│ DVWA         │    │ MITRE enrichment     │    │                 │
└──────────────┘    └──────────────────────┘    └────────┬────────┘
                                                         │
┌──────────────┐    ┌──────────────────────┐    ┌────────▼────────┐
│   LAYER 6    │    │       LAYER 5        │    │    LAYER 4      │
│ Analyst Ops  │◀───│ Visualisation        │◀───│ Active Response │
│              │    │                      │    │ Layer           │
│ Investigation│    │ OpenSearch Dashboards│    │                 │
│ Escalation   │    │ MITRE ATT&CK views   │    │ UFW/iptables    │
│ IR actions   │    │ Alert triage views   │    │ Watchdog logger │
└──────────────┘    └──────────────────────┘    └─────────────────┘
```

**Fusion scoring equation:**

ŷ = α · p_RF + (1 − α) · s_LSTM

| Score range | Classification | Action |
|---|---|---|
| ŷ ≥ 0.65 | `TRUE_POSITIVE` | Automated blocking via Active Response |
| 0.50 ≤ ŷ < 0.65 | `SUSPICIOUS` | Surfaced to analyst review queue (OpenSearch Layer 5) |
| ŷ < 0.50 | `FALSE_POSITIVE` | Suppressed; retained in audit log |

> **Note:** SUSPICIOUS-tier events (17.5% of cloud records) are queued for analyst review and are counted neither as confirmed true positives nor as suppressed false positives. FN = 0 reflects the absence of confirmed attack events below the 0.50 suppression threshold, not an absence of unreviewed Suspicious-tier events.

---
## Process workflow 

<img width="2112" height="1046" alt="Open SOC framework summary" src="https://github.com/user-attachments/assets/1b8961a8-f50f-482d-b7e8-601927849c90" />
---
## Prerequisites

### VMware Testbed (Experiment 1)

| Host | OS | Role |
|---|---|---|
| Wazuh Manager (192.168.50.20) | Ubuntu 24.04, 8 GB RAM | Wazuh Manager, Indexer, OpenSearch, Filebeat, ML service |
| Target Client (192.168.50.40) | Ubuntu 24.04 | Zeek, Suricata, Wazuh Agent, DVWA |
| Attacker (192.168.50.50) | Kali Linux 2025 | Attack orchestration |
| Windows Endpoint (192.168.50.60) | Windows 11 Enterprise | Wazuh Agent, additional monitored host |

**Software dependencies (Wazuh Manager):**

```bash
# Core stack
wazuh-manager >= 4.x
wazuh-indexer >= 4.x
opensearch-dashboards >= 2.x
filebeat >= 8.x

# ML pipeline
python3 >= 3.10
pip install scikit-learn tensorflow numpy pandas
```

**Software dependencies (Target Client):**

```bash
zeek >= 6.x          # Network security monitor
suricata >= 7.x      # IDS with Emerging Threats Open rules
wazuh-agent >= 4.x
```

### DigitalOcean Cloud Deployment (Experiment 2)

```
VM: Ubuntu 24.04, 4 vCPU, 8 GB RAM, SYD1 region
Exposed services: Cowrie (port 22/23), Zeek, Suricata, Apache/DVWA (port 80)
No Wazuh Agent deployed on cloud sensor (preserves unfiltered telemetry)
Log retrieval: outbound SSH from Wazuh Manager via cron-scheduled DO_log_pull.sh
```

---

## Installation and Configuration

### 1. Clone the Repository

```bash
git clone https://github.com/Sree-Ajitha/Adaptive-Open-source-SOC-Framework.git
cd Adaptive-Open-source-SOC-Framework
```

### 2. Deploy Wazuh Custom Rules and Decoders

```bash
# Copy to Wazuh Manager
sudo cp config/rules/local_rules.xml /var/ossec/etc/rules/
sudo cp config/decoders/local_decoder.xml /var/ossec/etc/decoders/

# Restart Wazuh Manager to apply
sudo systemctl restart wazuh-manager
```

**Rule 100399** (cross-sensor correlation) triggers when two or more sensors observe the same source IP within a configurable time window and fires correlated alerts enriched with MITRE ATT&CK mappings.

### 3. Configure Filebeat

```bash
sudo cp config/filebeat/filebeat.yml /etc/filebeat/filebeat.yml
sudo systemctl restart filebeat
```

### 4. Deploy the ML Integration Service

```bash
cd ml/
pip3 install -r requirements.txt

# Start the wazuh-ml integration service
# The service intercepts the Wazuh Manager alert stream
# and performs real-time classification using ml_integration.py
python3 ml_integration.py --alpha 0.65 --daemon
```

> **Important:** `ml_integration.py` is the authoritative runtime. The alpha weight (0.65 RF / 0.35 LSTM) was selected via a 21-point sensitivity sweep; `alpha_sensitivity_results.csv` documents all sweep results.

### 5. Configure Active Response

```bash
# Deploy the blocking script on the target client
sudo cp active_response/block-ip.sh /var/ossec/active-response/bin/
sudo chmod 750 /var/ossec/active-response/bin/block-ip.sh

# Deploy and enable the watchdog service
sudo cp active_response/watchdog_service/wazuh-ar-watchdog.service \
    /etc/systemd/system/
sudo systemctl enable --now wazuh-ar-watchdog.service

# Active response events are logged to:
# /var/ossec/logs/active-responses.log
```

### 6. Configure Cowrie Honeypot (Cloud Deployment)

```bash
# Port-forwarding: external 22/23 → internal 2222/2223
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223

cp honeypot/cowrie.cfg ~/cowrie/etc/cowrie.cfg
```

---

## Running the Attack Replay

Attack scenarios are orchestrated as a Python framework ensuring repeatability across six phases.

```bash
cd attack_scripts/

# Run all phases sequentially (Experiment 1)
python3 run_all_phases.py --target 192.168.50.40 --phases 1-6

# Run individual phases
python3 phase1_reconnaissance/run.py --target 192.168.50.40
python3 phase2_credential_access/run.py --target 192.168.50.40
python3 phase3_web_attacks/run.py --target 192.168.50.40
python3 phase4_exploitation/run.py --target 192.168.50.40
python3 phase5_post_exploitation/run.py --target 192.168.50.40
python3 phase6_extension/run.py --target 192.168.50.40
```

**Phase summary:**

| Phase | Scenarios | Key Techniques |
|---|---|---|
| 1 — Reconnaissance | 5 | T1046, T1595, T1595.002 |
| 2 — Credential Access | 4 | T1110, T1110.001, T1021 |
| 3 — Web Application Attacks | 10 | T1190, T1059, T1059.007, T1083 |
| 4 — Exploitation | 6 | T1505.003, T1190 |
| 5 — Post-Exploitation | 10 | T1048, T1068, T1071.004, T1565.001 |
| 6 — Extension (MITRE breadth) | 8 | T1557.002, T1040, T1110.003, T1059.004, T1053.003, T1087.001, T1572, T1018 |

> **Note:** Phase 6 scenarios are included for MITRE ATT&CK coverage breadth and extend the total to 43 scenarios. Phase 6 alert counts are designated NM (Not Measured) within the Experiment 1 attack window and must not be populated with fabricated values.

---

## Running the Metrics Pipeline

Execute in this exact sequence after completing the attack replay:

```bash
cd metrics/

# Step 1: Reclassify alerts through the ML pipeline
python3 ml_reclassify.py

# Step 2: Generate the evaluation report
python3 wazuh_manager_report_v5.py

# Step 3: Mandatory post-processing (always run last)
python3 post_process_reports.py

# Optional: Alpha sensitivity sweep
python3 alpha_sensitivity.py --sweep 0.0 1.0 0.05

# Optional: Pipeline latency characterisation
python3 Mttd_pipeline_latency.py
```

> **Critical:** `post_process_reports.py` must be run after every execution of `wazuh_manager_report_v5.py`. Skipping this step produces incomplete output artefacts.

---

## Cloud Log Collection (Experiment 2)

```bash
# Cron-scheduled retrieval from Wazuh Manager (every 5 minutes)
cd cloud/
chmod +x DO_log_pull.sh

# Add to Wazuh Manager crontab:
# */5 * * * * /path/to/DO_log_pull.sh >> /home/lab1/DO_logs/pull.log 2>&1

# Post-collection processing
python3 DO_sanitise.py
python3 DO_metric_collector.py
python3 DO_summary_report.py
```

Cloud result artefacts are written to `/home/lab1/DO_logs/` and summarised in `results/experiment2_Cloud_results.json`.

---

## Evaluation Results

All result files are in `results/`. Key files:

| File | Description |
|---|---|
| `Experiement1-VMware_Attack_Replay_Sandbox_results.json` | Full Experiment 1 evaluation constants |
| `experiment2_Cloud_results.json` | Cloud deployment metrics and ML classification outcomes |
| `ml_corrected_summary.json` | Authoritative cloud ML classification labels |
| `cloud_results_mitre.csv` | MITRE ATT&CK mapping for cloud-observed techniques |
| `vmware_results_mttd.csv` | Per-scenario detection records across all 43 scenarios |
| `alpha_sensitivity_results.csv` | 21-point alpha sweep results (α = 0.0 to 1.0, step 0.05) |

**Loading result constants in Python:**

```python
import json

with open('results/Experiement1-VMware_Attack_Replay_Sandbox_results.json') as f:
    vmware = json.load(f)

with open('results/experiment2_Cloud_results.json') as f:
    cloud = json.load(f)

# Prior-evaluation constants (authoritative figures for paper)
total_alerts = 38179          # vmware prior_evaluation_constant
rule_100399_hits = 3889       # cloud prior_evaluation_constant
cloud_ml_records = cloud['ml']['total_processed']   # 631,633
fp_reduction = cloud['ml']['fp_reduction_pct']      # 96.5
```

---

## MITRE ATT&CK Coverage

### Experiment 1 (VMware, Phase 1–5, 13 techniques)

T1046 · T1595 · T1595.002 · T1021 · T1110 · T1110.001 · T1083 · T1190 · T1059 · T1059.007 · T1505.003 · T1068 · T1048

### Experiment 2 (Cloud, independently observed, 4 techniques)

T1078 · T1571 · T1095 · T1040

T1040 was also executed as a Phase 6 controlled scenario; its cloud observation constitutes independent cross-environment corroboration. T1548.003 (5 cloud events, `cloud_results_mitre.csv`) was excluded from the reported technique set due to insufficient evidence of confirmed exploitation; raw events are retained in the artefacts for transparency.

---

## Security and Privacy

- All published evaluation artefacts have been reviewed to remove researcher-identifiable information prior to repository release.
- Attacker IP addresses captured during cloud deployment have been deduplicated and sanitised: the researcher's home IP address and the cloud node's own egress IP address were excluded from analysis before any artefact was committed.
- The Cowrie honeypot operated in a bounded medium-interaction configuration with no lateral-movement risk.
- The DVWA instance was deployed with egress firewall restrictions to prevent exploitation of third-party systems.

---

## Limitations

- The 100% attack-scenario detection rate was achieved under controlled conditions with known attack timing and a clean network baseline; it represents an upper bound rather than a forecast for operational enterprise environments.
- ML models were trained on synthetic datasets approximating CIC-IDS2017/2018 feature distributions. The reported precision figures (64.1% for Experiment 1; 95.7% for Experiment 2) are derived from fusion-label counts rather than independently validated ground-truth labels and should be interpreted as operational characterisations.
- Per-attack MTTD was not independently measured due to a UTC−04:00 / UTC+12:00 clock offset between the attacker and Wazuh Manager hosts; UTC-normalised MTTD measurement is identified as a priority for future work.
- The cloud evaluation was limited to a single 120+-hour deployment window in the DigitalOcean SYD1 region; findings may not generalise to all operational settings.
- The fusion weight (α = 0.65) was calibrated on synthetic data. LSTM retraining on environment-specific traffic baselines is recommended before deployment in materially different environments.

---

## Future Work

- Longer-duration cloud deployments across multiple regions and providers
- UTC-synchronised MTTD measurement in future attack-replay sessions
- LSTM retraining on operational traffic to reduce distribution shift under cloud conditions
- Extension of the attack campaign from 43 to additional scenarios for journal-version differentiation
- Evaluation under realistic background traffic conditions

---
