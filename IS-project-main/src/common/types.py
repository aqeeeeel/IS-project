from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Any, TypeAlias
from uuid import uuid4

ChallengeId: TypeAlias = str
DeviceId: TypeAlias = str
ModelId: TypeAlias = str
NonceValue: TypeAlias = str
IdentityValue: TypeAlias = str
ChecksumValue: TypeAlias = str


class ProtocolMessageType(str, Enum):
    CHALLENGE_REQUEST = "challenge_request"
    CHALLENGE_RESPONSE = "challenge_response"
    PARAMETER_REQUEST = "parameter_request"
    PARAMETER_TRANSFER = "parameter_transfer"
    ATTESTATION = "attestation"
    ACK = "ack"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: ChallengeId
    device_id: DeviceId
    model_id: ModelId
    vector: list[int]
    issued_at: float = field(default_factory=time)
    expires_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Response:
    challenge_id: ChallengeId
    device_id: DeviceId
    response_bits: str
    measured_at: float = field(default_factory=time)
    confidence: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Nonce:
    value: NonceValue
    created_at: float = field(default_factory=time)
    ttl_seconds: int = 60

    def is_expired(self, now: float | None = None) -> bool:
        reference_time = now if now is not None else time()
        return (self.created_at + float(self.ttl_seconds)) < reference_time


@dataclass(frozen=True, slots=True)
class IdentityTag:
    value: IdentityValue
    device_id: DeviceId
    model_id: ModelId
    enrollment_hash: str
    created_at: float = field(default_factory=time)


@dataclass(frozen=True, slots=True)
class MatrixMetadata:
    rows: int
    cols: int
    dtype: str
    order: str = "C"
    checksum: ChecksumValue | None = None
    quantized: bool = False


@dataclass(frozen=True, slots=True)
class ParameterPayload:
    model_id: ModelId
    layer_name: str
    matrix: MatrixMetadata
    encoding: str
    data_b64: str
    chunk_index: int = 0
    chunk_total: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ProtocolMessage:
    message_type: ProtocolMessageType
    sender: str
    receiver: str
    nonce: Nonce
    payload: dict[str, Any]
    message_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float = field(default_factory=time)
    signature_b64: str | None = None
    correlation_id: str | None = None
