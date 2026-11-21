"""network_defense/detections/ml_anomaly.py

Per-source sliding-window anomaly detector (Isolation Forest).
Same interface as DetectionEngine.inspect_packet, so it can run alongside it.

Two modes:
  - collect mode: MLAnomalyDetector(collect_path="data/baseline_features.csv")
    logs feature rows during NORMAL traffic (used to train the model).
  - detect mode:  MLAnomalyDetector(model_path="models/anomaly.joblib")
"""
from __future__ import annotations

import csv
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from network_defense.models import Detection, PacketEvent, utc_now

FEATURES = ["packets", "syn_count", "distinct_ports", "distinct_dsts", "dns_queries", "syn_ratio"]


def window_features(items) -> list[float]:
    """items: iterable of (ts, dst_ip, dst_port, is_syn, is_dns). Shared by training and live use."""
    packets = len(items)
    syn = sum(1 for i in items if i[3])
    ports = {i[2] for i in items if i[2] is not None}
    dsts = {i[1] for i in items if i[1]}
    dns = sum(1 for i in items if i[4])
    return [packets, syn, len(ports), len(dsts), dns, syn / packets if packets else 0.0]


class MLAnomalyDetector:
    def __init__(
        self,
        model_path: str | None = None,
        collect_path: str | None = None,
        window_seconds: int = 60,
        min_packets: int = 20,
        score_interval: float = 5.0,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_packets = min_packets
        self.score_interval = score_interval
        self.collect_path = collect_path
        self.model = None
        if model_path:
            import joblib  # imported lazily so collect mode needs no sklearn

            self.model = joblib.load(model_path)
        self._win: dict[str, deque] = defaultdict(deque)
        self._last_scored: dict[str, float] = {}
        self._cooldowns: dict[str, float] = {}

    def inspect_packet(self, event: PacketEvent) -> list[Detection]:
        if not event.src_ip:
            return []
        now = datetime.fromisoformat(event.timestamp).timestamp()
        flags = event.tcp_flags or ""
        item = (
            now,
            getattr(event, "dst_ip", None),
            event.dst_port,
            event.protocol == "TCP" and "S" in flags and "A" not in flags,
            bool(event.dns_query),
        )
        items = self._win[event.src_ip]
        items.append(item)
        while items and now - items[0][0] > self.window_seconds:
            items.popleft()

        # Score at most once per score_interval per source, once the window has enough data.
        if len(items) < self.min_packets or now - self._last_scored.get(event.src_ip, 0) < self.score_interval:
            return []
        self._last_scored[event.src_ip] = now
        feats = window_features(items)

        if self.collect_path:
            self._append_row(feats)
            return []
        if self.model is None:
            return []

        is_anomaly = self.model.predict([feats])[0] == -1
        if is_anomaly and now >= self._cooldowns.get(event.src_ip, 0):
            self._cooldowns[event.src_ip] = now + self.window_seconds
            score = float(self.model.decision_function([feats])[0])
            return [
                Detection(
                    str(uuid4()),
                    utc_now(),
                    "ml_anomaly",
                    "medium",
                    "Traffic pattern from one source deviates from the learned baseline.",
                    {"source": event.src_ip, "anomaly_score": round(score, 4), "window_seconds": self.window_seconds, **dict(zip(FEATURES, feats))},
                )
            ]
        return []

    def _append_row(self, feats: list[float]) -> None:
        path = Path(self.collect_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        new = not path.exists()
        with path.open("a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(FEATURES)
            w.writerow(feats)
