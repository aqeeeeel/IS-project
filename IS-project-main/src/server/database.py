from __future__ import annotations

from dataclasses import dataclass, field
from time import time
from typing import Any

from common.types import IdentityTag, MatrixMetadata


class DeviceRecordAlreadyExistsError(ValueError):
    pass


class DeviceRecordNotFoundError(KeyError):
    pass


@dataclass(slots=True)
class DeviceRecord:
    device_id: str
    model_id: str
    identity_tag: IdentityTag
    matrix_set: list[MatrixMetadata]
    model_parameters: dict[str, Any]
    threshold: float
    crp_count: int
    hamming_threshold: float = 0.2
    ecc_repetition: int = 1
    fuzzy_max_distance: int = 0
    auth_state: str = "enrolled"
    failed_auth_attempts: int = 0
    failed_auth_lockout_threshold: int = 5
    lockout_duration_seconds: int = 300
    lockout_until: float | None = None
    query_limit_per_minute: int = 120
    query_window_start: float | None = None
    query_count_in_window: int = 0
    last_authenticated_at: float | None = None
    last_session_id: str | None = None
    last_session_key_b64: str | None = None
    created_at: float = field(default_factory=time)
    updated_at: float = field(default_factory=time)


class DeviceRecordDatabase:
    """Simple in-memory CRUD database for enrolled device records."""

    def __init__(self) -> None:
        self._records: dict[str, DeviceRecord] = {}

    def create(self, record: DeviceRecord) -> DeviceRecord:
        if record.device_id in self._records:
            raise DeviceRecordAlreadyExistsError(f"device_id '{record.device_id}' already exists")
        self._records[record.device_id] = record
        return record

    def get(self, device_id: str) -> DeviceRecord:
        record = self._records.get(device_id)
        if record is None:
            raise DeviceRecordNotFoundError(f"device_id '{device_id}' was not found")
        return record

    def update(self, device_id: str, **changes: Any) -> DeviceRecord:
        current = self.get(device_id)
        for key, value in changes.items():
            if not hasattr(current, key):
                raise ValueError(f"Unknown device record field '{key}'")
            setattr(current, key, value)
        current.updated_at = time()
        return current

    def delete(self, device_id: str) -> None:
        if device_id not in self._records:
            raise DeviceRecordNotFoundError(f"device_id '{device_id}' was not found")
        del self._records[device_id]

    def list_all(self) -> list[DeviceRecord]:
        return sorted(self._records.values(), key=lambda entry: entry.device_id)

    def exists(self, device_id: str) -> bool:
        return device_id in self._records
