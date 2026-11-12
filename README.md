# Network Defense Tool — Python Prototype

A local, defensive Windows prototype for packet telemetry, five-tuple flows, detection rules, evidence retention, a FastAPI API, and three simple dashboard pages.

## Project layout

```
network_defense/
  capture/       Scapy capture and packet normalization
  detections/    Port-scan, DNS-burst, outbound-transfer rules
  evidence/      Append-only JSONL evidence store
  api/           FastAPI endpoints and dashboard pages
  testing/       Synthetic lab-only event generators
  flows.py       Directional 5-tuple aggregation
  service.py     Pipeline orchestration
data/            Runtime evidence (ignored by Git)
```

## Windows setup

Install Python 3.11+ and [Npcap](https://npcap.com/) (enable WinPcap-compatible mode). In PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run_lab_demo.py
uvicorn network_defense.api.main:app --reload
```

Open `http://127.0.0.1:8000/` for Overview, `/detections` for Detections, and `/evidence` for Evidence. The JSON API is under `/api/*`.

## Live capture (administrator only)

Create a small runner such as:

```python
from network_defense.capture import start_capture
from network_defense.service import TelemetryService

service = TelemetryService()
start_capture(service.ingest)  # Ctrl+C, then call service.flush() in a finally block
```

Capture only networks and systems you own or are explicitly authorized to monitor. This prototype intentionally stores metadata, not packet payloads.

## Detection rules

- TCP SYN packets to 20 distinct ports from a source within 60 seconds
- 50 DNS queries from a source within 60 seconds
- A completed private-to-public flow at or above 10 MB

Thresholds are constructor options on `DetectionEngine`; tune them for your environment before relying on alerts.

## Safe testing

`run_lab_demo.py` adds in-memory synthetic events and never sends packets, performs a scan, transfers a file, or makes network connections. Use this to verify dashboards and rules. Only conduct active scans or transfer experiments in an isolated lab you own and control.

## Verification

```powershell
pytest -q
```
