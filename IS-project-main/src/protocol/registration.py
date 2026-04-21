from __future__ import annotations

from dataclasses import dataclass

from common.types import IdentityTag, MatrixMetadata
from puf.interface import PUFSimulator


@dataclass(frozen=True, slots=True)
class RegistrationRequest:
    device_id: str
    model_id: str
    simulator: PUFSimulator
    num_crps: int = 2000
    noisy: bool = False
    repetitions: int = 1
    learning_rate: float = 0.1
    epochs: int = 300
    l2_strength: float = 0.0
    matrix_count: int = 4
    data_seed: int | None = None
    split_seed: int | None = None
    matrix_seed: int | None = None
    query_limit_per_minute: int = 120
    failed_auth_lockout_threshold: int = 5
    lockout_duration_seconds: int = 300
    ecc_repetition: int = 1
    fuzzy_max_distance: int = 0


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    device_id: str
    model_id: str
    identity_tag: IdentityTag
    matrix_set: list[MatrixMetadata]
    threshold: float
    validation_accuracy: float
    test_accuracy: float
    crp_count: int
