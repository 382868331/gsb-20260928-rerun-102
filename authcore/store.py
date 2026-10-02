from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager


class Store:
    """Tiny JSON-file persistent store with whole-file locking.

    fcntl.flock on a sidecar lockfile serializes readers and writers both
    across threads and across processes, so two refresh attempts on the same
    credential can never commit two independent rotations. The data is
    atomically replaced on disk and survives a process restart.
    """

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        self.lock_path = self.path + ".lock"
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        with open(self.lock_path, "a"):
            pass
        if not os.path.exists(self.path):
            self._write(
                {
                    "users": {},
                    "sessions": {},
                    "access": {},
                    "refresh": {},
                    "reuse": [],
                    "activity": [],
                    "seq": 0,
                }
            )

    def _read(self) -> dict:
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("activity", [])
        return data

    def _write(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    @contextmanager
    def transaction(self):
        """Yield mutable state under an exclusive lock; commit on success."""
        with open(self.lock_path, encoding="utf-8") as lockf:
            fcntl.flock(lockf, fcntl.LOCK_EX)
            data = self._read()
            try:
                yield data
                self._write(data)
            finally:
                fcntl.flock(lockf, fcntl.LOCK_UN)

    @contextmanager
    def connect(self):
        """Read-only snapshot under a shared lock."""
        with open(self.lock_path, encoding="utf-8") as lockf:
            fcntl.flock(lockf, fcntl.LOCK_SH)
            try:
                yield self._read()
            finally:
                fcntl.flock(lockf, fcntl.LOCK_UN)
