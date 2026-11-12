from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class EvidenceStore:
    """Append-only JSONL evidence storage suitable for a small local prototype."""
    def __init__(self, root: Path = Path("data")) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def append(self, kind: str, record: dict[str, Any]) -> None:
        with (self.root / f"{kind}.jsonl").open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, sort_keys=True) + "\n")

    def read(self, kind: str, limit: int = 100) -> list[dict[str, Any]]:
        path = self.root / f"{kind}.jsonl"
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
        return [json.loads(line) for line in reversed(lines)]
