"""Durable JSON store with cross-process advisory locking.

No sqlite is available in the runtime, so state lives in a single JSON file
updated atomically (temp file + fsync + rename) while holding an fcntl lock.
The raw credential material is never part of this file: only SHA-256 digests.
"""

import contextlib
import fcntl
import json
import os
import threading
import time


def _empty_state():
    return {
        "version": 1,
        "users": {},
        "access_tokens": {},
        "refresh_tokens": {},
        "families": {},
        "reuse_records": [],
        "next_record_id": 1,
    }


class FileStore:
    """Lock-protected JSON document. ``mutate`` is the atomic read-modify-write API."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        self._lock_path = self.path + ".lock"
        self._lock_file = open(self._lock_path, "a+")
        self._thread_lock = threading.RLock()

    def _load_locked(self):
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                state = json.load(handle)
        except FileNotFoundError:
            state = _empty_state()
        # Guarantee every section exists (forward compatibility).
        for key, value in _empty_state().items():
            state.setdefault(key, value if not isinstance(value, (dict, list)) else type(value)())
        return state

    @contextlib.contextmanager
    def mutate(self):
        """Yield the state dict; it is persisted iff the block exits cleanly."""
        with self._thread_lock:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX)
            try:
                state = self._load_locked()
                try:
                    yield state
                except BaseException:
                    # Business errors (e.g. reuse detection) may still have
                    # mutated state (family revocation, audit records), so
                    # persist before propagating the exception.
                    self._persist(state)
                    raise
                self._persist(state)
            finally:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)

    @contextlib.contextmanager
    def read(self):
        with self._thread_lock:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_SH)
            try:
                yield self._load_locked()
            finally:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)

    def _persist(self, state):
        tmp_path = f"{self.path}.tmp.{os.getpid()}.{threading.get_ident()}"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(state, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, self.path)
        directory = os.path.dirname(self.path) or "."
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def destroy(self):
        with contextlib.suppress(FileNotFoundError):
            os.remove(self.path)
        with contextlib.suppress(FileNotFoundError):
            os.remove(self._lock_path)


def now():
    return int(time.time())
