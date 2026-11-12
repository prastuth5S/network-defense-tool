from __future__ import annotations

from collections.abc import Callable

from .normalize import normalize_packet
from network_defense.models import PacketEvent


def start_capture(on_event: Callable[[PacketEvent], None], interface: str | None = None, bpf_filter: str = "ip or ip6") -> None:
    """Run a live local capture. Windows requires Npcap and an elevated terminal."""
    from scapy.all import sniff

    def receive(packet: object) -> None:
        event = normalize_packet(packet)
        if event:
            on_event(event)

    sniff(iface=interface, filter=bpf_filter, prn=receive, store=False)
