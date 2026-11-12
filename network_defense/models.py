from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class PacketEvent:
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str
    length: int
    tcp_flags: str | None = None
    dns_query: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FlowRecord:
    flow_id: str
    first_seen: str
    last_seen: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int = 0
    bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["duration_seconds"] = max(
            0.0,
            (datetime.fromisoformat(self.last_seen) - datetime.fromisoformat(self.first_seen)).total_seconds(),
        )
        return data


@dataclass(frozen=True)
class Detection:
    detection_id: str
    timestamp: str
    rule: str
    severity: str
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
