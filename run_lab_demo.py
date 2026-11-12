"""Populate the local dashboard with synthetic, lab-only telemetry."""
from network_defense.service import TelemetryService
from network_defense.testing.lab_events import benign_browsing, simulated_dns_burst, simulated_large_outbound_transfer, simulated_port_scan

service = TelemetryService()
for event in benign_browsing() + simulated_port_scan() + simulated_dns_burst() + simulated_large_outbound_transfer():
    service.ingest(event)
service.flush()
print("Synthetic lab evidence written to data/. Run: uvicorn network_defense.api.main:app --reload")
