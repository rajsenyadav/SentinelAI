# SentinelAI — Enterprise UEBA & SOC Incident Intelligence Platform

**An Incident-Centric Behavioral Anomaly Detection, AI Analyst Copilot, and Risk Intelligence Platform for Enterprise Cybersecurity**

---

## System Overview

SentinelAI is an enterprise User & Entity Behavior Analytics (UEBA) platform designed for Tier-1 and Tier-2 Security Operations Center (SOC) analysts. It shifts cybersecurity monitoring from **alert-centric log noise** to **incident-centric entity storytelling** by combining machine learning anomaly ensembles, normalized 9-factor risk scoring, behavioral identity profiling, and automated AI Analyst Copilot briefs.

---

## Key Features & Enterprise Engines

1. **Double Ensemble Anomaly Detector**: Combines statistical Isolation Forest scoring (40%) with PyTorch Deep Bottleneck Autoencoder reconstruction loss (60%).
2. **Behavioral Identity Engine**: Builds dynamic baseline profiles across 6 key entity parameters (working hours, devices, locations, resource categories, session length, login frequency).
3. **Dynamic Multi-Factor Risk Engine**: Calculates a normalized 0–100 composite risk score across 9 weighted factors plus velocity multipliers.
4. **Chronological Attack Storyline Engine**: Groups 24-hour telemetry events by entity to reconstruct step-by-step incident attack chains.
5. **Autonomous AI Analyst Copilot**: Synthesizes 10-point incident briefs with MITRE ATT&CK mappings, estimated investigation time savings (15–20 mins), and 1-click executable PowerShell/AWS CLI containment scripts.
6. **Persistent Triage & Compliance Audit Console**: Persists analyst decisions (*Confirmed Threat*, *False Positive*, *Under Investigation*, *Resolved*) directly to dataset storage and logs audit entries in `analyst_actions.csv`.
7. **Vanilla Light Mode Dashboard**: High-contrast, clean enterprise SOC interface (`#faf8f5`) designed for high visibility and quick decision-making.

---

## Quick Start — Data Generation & App Launch

### 1. Install Dependencies

```bash
cd SentinelAI
pip install -r requirements.txt
```

### 2. Generate Synthetic Dataset

```bash
python scripts/generate_data.py
```

This generates raw event telemetry and behavioral profiles in `data/raw/`.

### 3. Run Feature Engineering & Train ML Pipeline

```bash
python scripts/run_feature_engineering.py
python scripts/train_anomaly_detector.py
python scripts/train_attack_classifier.py
```

### 4. Launch Enterprise SOC Dashboard

Launch the interactive Streamlit Security Operations Center console:

```bash
python scripts/run_dashboard.py
# Or directly:
streamlit run dashboard/app.py
```

- **Local Access**: `http://localhost:8501`

### 5. Launch FastAPI REST API Server

Launch the production FastAPI backend with auto-generated Swagger documentation:

```bash
python scripts/run_backend.py
# Or directly:
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **ReDoc API Spec**: `http://localhost:8000/redoc`

---

## Dashboard Workspaces

- **Overview & Command Center**: Top-level SOC metrics, anomaly counts, risk level breakdowns, and real-time streaming access logs.
- **Threat Intelligence**: Interactive matrix filtering active incidents by Attack Type, Department, and Entity ID.
- **Incident Details Workspace**: 2-column investigation workbench with persistent triage buttons synced directly to storage.
- **Explainable AI (XAI) Panel**: SHAP feature attributions, baseline deviation breakdown, and 9-factor risk score explanations.
- **User Behavior Timeline**: Chronological Plotly scatter plot trace, activity history log table, and attack storyline engine.
- **Analyst Console**: AI Analyst Copilot briefs, time-savings metrics, copyable remediation scripts, and `analyst_actions.csv` audit logs.

---

## Project Directory Structure

```
SentinelAI/
├── config/
│   └── data_config.yaml          # Generation & simulation configuration
├── data_generator/               # Telemetry log & attack vector generator
├── feature_engine/               # Temporal, velocity, novelty & z-score pipeline
├── detection/
│   ├── isolation_forest.py       # Isolation Forest anomaly scoring
│   ├── autoencoder.py            # Deep PyTorch Autoencoder reconstruction loss
│   ├── detector.py               # Double ensemble orchestrator
│   ├── behavioral_identity.py    # 6-parameter entity baseline profile engine
│   ├── dynamic_risk_engine.py    # Normalized 9-factor risk Engine
│   ├── incident_storyline.py     # Chronological attack sequence linker
│   └── ai_analyst_copilot.py     # Autonomous SOC Tier-1/Tier-2 triage assistant
├── classifier/                   # Attack multi-class classifier (XGBoost / RF)
├── explainer/                    # SHAP feature attribution & XAI engine
├── dashboard/
│   ├── app.py                    # Main Streamlit SOC Dashboard Entry Point
│   ├── styles.css                # Vanilla Light Mode Theme CSS
│   ├── utils.py                  # Single-source-of-truth dataset loader
│   └── components/               # Overview, Intel, Details, XAI, Timeline, Console, Cards
├── backend/
│   ├── app.py                    # FastAPI REST API Application Entry Point
│   ├── services/                 # Pipeline & incident persistence services
│   └── api/                      # Routes: predict, copilot, alerts, analytics, feedback
├── scripts/                      # CLI launcher scripts for data, ML, dashboard & backend
├── models/                       # Serialized trained model binaries (.pkl)
├── data/
│   ├── raw/                      # Generated raw CSV logs
│   └── processed/                # Engineered dataset & analyst audit logs
├── docs/                         # System specifications & architecture docs
│   └── SENTINELAI_MASTER_DOCUMENTATION.md # Unified master documentation
├── Dockerfile                    # Containerization configuration
├── docker-compose.yml            # Multi-container orchestration
├── requirements.txt              # Production dependency requirements
├── LICENSE                       # MIT Open Source License
└── README.md                     # Main README file
```

---

## Licensing & Hackathon Credits

* **Project**: Honeywell Campus Connect Hackathon Finalist Project
* **Systems Architect & Developer**: Raj Sen | MARK 1
* **License**: MIT Open Source License
