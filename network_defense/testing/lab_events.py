"""Synthetic telemetry only: no packets are sent and no hosts are contacted."""
from __future__ import annotations

from datetime import timedelta

from network_defense.models import PacketEvent, utc_now


def benign_browsing() -> list[PacketEvent]:
    now = utc_now()
    return [PacketEvent(now, "192.168.56.10", "93.184.216.34", 51000, 443, "TCP", 1200, "PA")]


def simulated_port_scan() -> list[PacketEvent]:
    now = utc_now()
    return [PacketEvent(now, "192.168.56.20", "192.168.56.30", 50000, port, "TCP", 60, "S") for port in range(1, 26)]


def simulated_dns_burst() -> list[PacketEvent]:
    now = utc_now()
    return [PacketEvent(now, "192.168.56.20", "192.168.56.1", 53000 + i, 53, "UDP", 80, dns_query=f"lab-{i}.example.test") for i in range(55)]


def simulated_large_outbound_transfer() -> list[PacketEvent]:
    return [PacketEvent(utc_now(), "192.168.56.10", "8.8.8.8", 50100, 443, "TCP", 11_000_000, "PA")]
