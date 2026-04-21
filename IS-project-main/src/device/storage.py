from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from common.serialization import to_primitive
from common.types import IdentityTag, MatrixMetadata


@dataclass(frozen=True, slots=True)
class DeviceProvisioning:
    identity_tag: IdentityTag
    matrix_set: list[MatrixMetadata]


def save_provisioning(provisioning: DeviceProvisioning, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = to_primitive(provisioning)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_provisioning(path: str | Path) -> DeviceProvisioning:
    source = Path(path)
    raw = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise TypeError("Provisioning file must contain a JSON object")

    identity_raw = raw.get("identity_tag")
    matrix_raw = raw.get("matrix_set")
    if not isinstance(identity_raw, dict):
        raise TypeError("identity_tag must be an object")
    if not isinstance(matrix_raw, list):
        raise TypeError("matrix_set must be a list")

    identity_tag = IdentityTag(
        value=str(identity_raw["value"]),
        device_id=str(identity_raw["device_id"]),
        model_id=str(identity_raw["model_id"]),
        enrollment_hash=str(identity_raw["enrollment_hash"]),
        created_at=float(identity_raw.get("created_at", 0.0)),
    )
    matrix_set = [MatrixMetadata(**item) for item in matrix_raw]
    return DeviceProvisioning(identity_tag=identity_tag, matrix_set=matrix_set)
