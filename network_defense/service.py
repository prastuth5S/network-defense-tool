from __future__ import annotations

from network_defense.detections import DetectionEngine
from network_defense.detections.ml_anomaly import MLAnomalyDetector
from network_defense.evidence import EvidenceStore
from network_defense.flows import FlowAggregator
from network_defense.models import PacketEvent


class TelemetryService:
    def __init__(self, store: EvidenceStore | None = None, detector: DetectionEngine | None = None, ml: MLAnomalyDetector | None = None) -> None:
        self.store, self.detector = store or EvidenceStore(), detector or DetectionEngine()
        self.ml = ml
        self.flows = FlowAggregator(self._handle_flow)

    def ingest(self, event: PacketEvent) -> None:
        self.store.append("packets", event.to_dict())
        self.flows.add(event)
        findings = self.detector.inspect_packet(event)
        if self.ml:
            findings += self.ml.inspect_packet(event)
        for finding in findings: self.store.append("detections", finding.to_dict())

    def _handle_flow(self, flow) -> None:
        self.store.append("flows", flow.to_dict())
        for finding in self.detector.inspect_flow(flow): self.store.append("detections", finding.to_dict())

    def flush(self) -> None:
        self.flows.flush()
