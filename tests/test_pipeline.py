from pathlib import Path

from network_defense.detections import DetectionEngine
from network_defense.evidence import EvidenceStore
from network_defense.service import TelemetryService
from network_defense.testing.lab_events import simulated_dns_burst, simulated_large_outbound_transfer, simulated_port_scan


def test_rules_and_evidence(tmp_path: Path):
    service = TelemetryService(EvidenceStore(tmp_path), DetectionEngine(scan_ports=3, dns_queries=4, outbound_bytes=100))
    for event in simulated_port_scan()[:4] + simulated_dns_burst()[:5] + simulated_large_outbound_transfer():
        service.ingest(event)
    service.flush()
    rules = {item["rule"] for item in service.store.read("detections")}
    assert {"port_scan", "dns_burst", "unusual_outbound_transfer"} <= rules
    assert service.store.read("flows")
