from network_defense.capture import start_capture
from network_defense.detections.ml_anomaly import MLAnomalyDetector
from network_defense.service import TelemetryService

service = TelemetryService(ml=MLAnomalyDetector(collect_path="data/baseline_features.csv"))
try:
    start_capture(service.ingest)
finally:
    service.flush()
