"""
JSONL data stores — the single source of truth.

Each entity type (hosts, services, urls, params, findings, osint, vulns)
has its own JSONL file. Append-only writes, streaming reads.
"""

import json
from pathlib import Path
from typing import Callable, Any
from .dedupe import DedupeStore


class JsonlStore:
    """
    Append-only JSONL store with built-in deduplication.

    Usage:
        store = JsonlStore(path="data/hosts.jsonl", key_func=lambda r: r["host"])
        store.add({"host": "api.example.com", "source": ["ct"]})
        store.add({"host": "api.example.com", "source": ["brute"]})  # skipped (dedup)
    """

    def __init__(self, path: str | Path, key_func: Callable[[dict], str]):
        self.path = Path(path)
        self.key_func = key_func
        self._dedupe = DedupeStore()
        self._count = 0

        # Load existing entries for dedup continuity (resume support)
        if self.path.exists():
            for record in self.read_all():
                key = self.key_func(record)
                self._dedupe.add(key)
                self._count += 1

    def add(self, record: dict) -> bool:
        """
        Add a record. Returns True if written (new), False if duplicate.
        """
        key = self.key_func(record)
        if not self._dedupe.add(key):
            return False

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

        self._count += 1
        return True

    def add_many(self, records: list[dict]) -> int:
        """Add multiple records, return count of new ones written."""
        written = 0
        for record in records:
            if self.add(record):
                written += 1
        return written

    def read_all(self) -> list[dict]:
        """Read all records from the store."""
        if not self.path.exists():
            return []
        records = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records

    def read_stream(self):
        """Generator that yields records one by one (memory efficient)."""
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    @property
    def count(self) -> int:
        return self._count


class StoreManager:
    """
    Manages all JSONL stores for a run.
    Provides typed access to hosts, services, urls, params, findings, osint, vulns.
    """

    def __init__(self, data_dir: str | Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.hosts = JsonlStore(
            self.data_dir / "hosts.jsonl",
            key_func=lambda r: r.get("host", "").lower(),
        )
        self.services = JsonlStore(
            self.data_dir / "services.jsonl",
            key_func=lambda r: r.get("service", "").lower(),
        )
        self.urls = JsonlStore(
            self.data_dir / "urls.jsonl",
            key_func=lambda r: r.get("url", "").lower(),
        )
        self.params = JsonlStore(
            self.data_dir / "params.jsonl",
            key_func=lambda r: f"{r.get('endpoint', '')}|{r.get('method', 'GET')}".lower(),
        )
        self.findings = JsonlStore(
            self.data_dir / "findings.jsonl",
            key_func=lambda r: f"{r.get('type', '')}|{r.get('asset', '')}".lower(),
        )
        self.osint = JsonlStore(
            self.data_dir / "osint.jsonl",
            key_func=lambda r: f"{r.get('type', '')}|{r.get('value', '')}".lower(),
        )
        self.vulns = JsonlStore(
            self.data_dir / "vulns.jsonl",
            key_func=lambda r: f"{r.get('type', '')}|{r.get('url', '')}|{r.get('param', '')}".lower(),
        )
        self.ai_analysis = JsonlStore(
            self.data_dir / "ai_analysis.jsonl",
            key_func=lambda r: f"{r.get('stage', '')}|{r.get('target', '')}".lower(),
        )

    def summary(self) -> dict:
        """Return counts for all stores."""
        return {
            "hosts": self.hosts.count,
            "services": self.services.count,
            "urls": self.urls.count,
            "params": self.params.count,
            "findings": self.findings.count,
            "osint": self.osint.count,
            "vulns": self.vulns.count,
            "ai_analysis": self.ai_analysis.count,
        }
