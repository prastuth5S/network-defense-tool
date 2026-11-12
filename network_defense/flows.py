from __future__ import annotations

import hashlib
from collections.abc import Callable

from network_defense.models import FlowRecord, PacketEvent


class FlowAggregator:
    """Directional five-tuple flow aggregation; call flush() to persist current flows."""
    def __init__(self, on_flow: Callable[[FlowRecord], None] | None = None) -> None:
        self._active: dict[tuple[str, str, int, int, str], FlowRecord] = {}
        self._on_flow = on_flow

    def add(self, event: PacketEvent) -> FlowRecord | None:
        if not event.src_ip or not event.dst_ip:
            return None
        key = (event.src_ip, event.dst_ip, event.src_port or 0, event.dst_port or 0, event.protocol)
        flow = self._active.get(key)
        if flow is None:
            raw = "|".join(map(str, key)).encode()
            flow = FlowRecord(hashlib.sha256(raw).hexdigest()[:16], event.timestamp, event.timestamp, *key)
            self._active[key] = flow
        flow.last_seen, flow.packets, flow.bytes = event.timestamp, flow.packets + 1, flow.bytes + event.length
        return flow

    def flush(self) -> list[FlowRecord]:
        flows = list(self._active.values())
        self._active.clear()
        if self._on_flow:
            for flow in flows:
                self._on_flow(flow)
        return flows
