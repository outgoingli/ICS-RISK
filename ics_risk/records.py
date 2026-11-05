"""Append-only local evaluation records. This module performs no process IO."""
from __future__ import annotations

import json
from pathlib import Path
import re
import uuid
from datetime import datetime, timezone


class RecordStore:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, record_id):
        if not isinstance(record_id, str) or not re.fullmatch(r"[0-9a-f]{32}", record_id):
            raise ValueError("Invalid record ID")
        path = self.directory / (record_id + ".json")
        if path.is_symlink() or path.resolve().parent != self.directory:
            raise ValueError("Invalid record path")
        return path

    def append(self, request, result, *, backend, bundle_profile=None):
        record_id = uuid.uuid4().hex
        record = {
            "record_id": record_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "backend": backend,
            "bundle_profile": bundle_profile,
            "execution": "assessment_only_no_control_write",
            "request": request,
            "result": result,
        }
        payload = json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False)
        with self._path(record_id).open("x", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        return record

    def get(self, record_id):
        return json.loads(self._path(record_id).read_text(encoding="utf-8"))

    def list(self, limit=50):
        limit = max(1, min(int(limit), 200))
        files = [p for p in self.directory.glob("*.json")
                 if re.fullmatch(r"[0-9a-f]{32}", p.stem) and not p.is_symlink()]
        files.sort(key=lambda p: p.stat().st_mtime_ns, reverse=True)
        rows = []
        for path in files[:limit]:
            try:
                record = self.get(path.stem)
                result = record.get("result", {})
                rows.append({
                    "record_id": record["record_id"],
                    "recorded_at": record["recorded_at"],
                    "backend": record.get("backend"),
                    "bundle_profile": record.get("bundle_profile"),
                    "decision": result.get("decision"),
                    "graph_version": result.get("graph_version"),
                    "complete": result.get("completeness", {}).get("complete", False),
                })
            except (OSError, ValueError, KeyError, TypeError):
                rows.append({"record_id": path.stem, "error": "record_unreadable"})
        return rows
