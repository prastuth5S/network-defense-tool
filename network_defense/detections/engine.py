from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from datetime import datetime
from uuid import uuid4

from network_defense.models import Detection, FlowRecord, PacketEvent, utc_now


class DetectionEngine:
    def __init__(self, scan_ports: int = 20, dns_queries: int = 50, window_seconds: int = 60, outbound_bytes: int = 10_000_000) -> None:
        self.scan_ports, self.dns_queries, self.window_seconds, self.outbound_bytes = scan_ports, dns_queries, window_seconds, outbound_bytes
        self._scan: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._dns: dict[str, deque[float]] = defaultdict(deque)
        self._cooldowns: dict[tuple[str, str], float] = {}

    @staticmethod
    def _timestamp(event: PacketEvent) -> float:
        return datetime.fromisoformat(event.timestamp).timestamp()

    def _new(self, rule: str, severity: str, summary: str, **evidence: object) -> Detection:
        return Detection(str(uuid4()), utc_now(), rule, severity, summary, dict(evidence))

    def inspect_packet(self, event: PacketEvent) -> list[Detection]:
        now, findings = self._timestamp(event), []
        if event.protocol == "TCP" and event.src_ip and event.dst_port is not None and event.tcp_flags and "S" in event.tcp_flags and "A" not in event.tcp_flags:
            items = self._scan[event.src_ip]
            items.append((now, event.dst_port))
            while items and now - items[0][0] > self.window_seconds: items.popleft()
            ports = {port for _, port in items}
            key = ("port_scan", event.src_ip)
            if len(ports) >= self.scan_ports and now >= self._cooldowns.get(key, 0):
                self._cooldowns[key] = now + self.window_seconds
                findings.append(self._new("port_scan", "medium", "Many distinct TCP SYN destination ports from one source.", source=event.src_ip, distinct_ports=len(ports), window_seconds=self.window_seconds))
        if event.dns_query and event.src_ip:
            items = self._dns[event.src_ip]
            items.append(now)
            while items and now - items[0] > self.window_seconds: items.popleft()
            key = ("dns_burst", event.src_ip)
            if len(items) >= self.dns_queries and now >= self._cooldowns.get(key, 0):
                self._cooldowns[key] = now + self.window_seconds
                findings.append(self._new("dns_burst", "medium", "High DNS-query volume from one source.", source=event.src_ip, query_count=len(items), window_seconds=self.window_seconds))
        return findings

    def inspect_flow(self, flow: FlowRecord) -> list[Detection]:
        try:
            outbound = ipaddress.ip_address(flow.src_ip).is_private and not ipaddress.ip_address(flow.dst_ip).is_private
        except ValueError:
            outbound = False
        if outbound and flow.bytes >= self.outbound_bytes:
            return [self._new("unusual_outbound_transfer", "high", "Large outbound flow to a public address.", flow_id=flow.flow_id, source=flow.src_ip, destination=flow.dst_ip, bytes=flow.bytes, threshold_bytes=self.outbound_bytes)]
        return []
