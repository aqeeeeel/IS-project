from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from uuid import uuid4

from common.types import IdentityTag, MatrixMetadata
from modeling.pipeline import PipelineResult, train_puf_surrogate
from puf.interface import PUFSimulator
from protocol.registration import RegistrationRequest, RegistrationResult

from .database import (
    DeviceRecord,
    DeviceRecordAlreadyExistsError,
    DeviceRecordDatabase,
    DeviceRecordNotFoundError,
)
from .audit import AuditLogger


class DuplicateDeviceEnrollmentError(ValueError):
    pass


class DeviceRecoveryError(LookupError):
    pass


@dataclass(frozen=True, slots=True)
class RecoveryResult:
    device_id: str
    model_id: str
    identity_tag: IdentityTag
    matrix_set: list[MatrixMetadata]


class RegistrationService:
    def __init__(self, database: DeviceRecordDatabase, audit_logger: AuditLogger | None = None) -> None:
        self.database = database
        self.audit_logger = audit_logger

    def _audit(self, event_type: str, outcome: str, **details: object) -> None:
        if self.audit_logger is not None:
            self.audit_logger.record(event_type, outcome, **details)

    def is_duplicate_device(self, device_id: str) -> bool:
        return self.database.exists(device_id)

    def _build_matrix_set(self, model_id: str, *, count: int, seed: int | None = None) -> list[MatrixMetadata]:
        rng = random.Random(seed)
        matrix_set: list[MatrixMetadata] = []
        for idx in range(count):
            rows = rng.choice([4, 8, 16, 32])
            cols = rng.choice([4, 8, 16, 32])
            digest = hashlib.sha256(f"{model_id}:{idx}:{rows}:{cols}".encode("utf-8")).hexdigest()
            matrix_set.append(
                MatrixMetadata(
                    rows=rows,
                    cols=cols,
                    dtype="float32",
                    checksum=digest,
                    quantized=False,
                )
            )
        return matrix_set

    def register(self, request: RegistrationRequest) -> RegistrationResult:
        if self.database.exists(request.device_id):
            self._audit("registration.enroll", "fail", device_id=request.device_id, reason="duplicate")
            raise DuplicateDeviceEnrollmentError(
                f"Device '{request.device_id}' is already enrolled"
            )

        pipeline_result = train_puf_surrogate(
            request.simulator,
            num_samples=request.num_crps,
            data_seed=request.data_seed,
            split_seed=request.split_seed,
            noisy=request.noisy,
            repetitions=request.repetitions,
            learning_rate=request.learning_rate,
            epochs=request.epochs,
            l2_strength=request.l2_strength,
        )

        enrollment_hash = self._enrollment_hash(request, pipeline_result)
        identity_tag = IdentityTag(
            value=str(uuid4()),
            device_id=request.device_id,
            model_id=request.model_id,
            enrollment_hash=enrollment_hash,
        )
        matrix_set = self._build_matrix_set(
            request.model_id,
            count=request.matrix_count,
            seed=request.matrix_seed,
        )

        try:
            self.database.create(
                DeviceRecord(
                    device_id=request.device_id,
                    model_id=request.model_id,
                    identity_tag=identity_tag,
                    matrix_set=matrix_set,
                    model_parameters=pipeline_result.model.to_dict(),
                    threshold=pipeline_result.tuned_threshold.threshold,
                    crp_count=request.num_crps,
                    hamming_threshold=max(0.1, min(0.35, pipeline_result.test_metrics.hamming_ratio + 0.05)),
                    ecc_repetition=max(1, request.ecc_repetition),
                    fuzzy_max_distance=max(0, request.fuzzy_max_distance),
                    failed_auth_lockout_threshold=max(1, request.failed_auth_lockout_threshold),
                    lockout_duration_seconds=max(1, request.lockout_duration_seconds),
                    query_limit_per_minute=max(1, request.query_limit_per_minute),
                )
            )
        except DeviceRecordAlreadyExistsError as exc:
            self._audit("registration.enroll", "fail", device_id=request.device_id, reason="duplicate-db")
            raise DuplicateDeviceEnrollmentError(str(exc)) from exc

        self._audit(
            "registration.enroll",
            "ok",
            device_id=request.device_id,
            model_id=request.model_id,
            crp_count=request.num_crps,
            threshold=pipeline_result.tuned_threshold.threshold,
        )

        return RegistrationResult(
            device_id=request.device_id,
            model_id=request.model_id,
            identity_tag=identity_tag,
            matrix_set=matrix_set,
            threshold=pipeline_result.tuned_threshold.threshold,
            validation_accuracy=pipeline_result.validation_metrics.accuracy,
            test_accuracy=pipeline_result.test_metrics.accuracy,
            crp_count=request.num_crps,
        )

    def recover(self, device_id: str) -> RecoveryResult:
        try:
            record = self.database.get(device_id)
        except DeviceRecordNotFoundError as exc:
            self._audit("registration.recover", "fail", device_id=device_id, reason="unknown-device")
            raise DeviceRecoveryError(f"Cannot recover unknown device '{device_id}'") from exc

        self._audit("registration.recover", "ok", device_id=device_id, model_id=record.model_id)

        return RecoveryResult(
            device_id=record.device_id,
            model_id=record.model_id,
            identity_tag=record.identity_tag,
            matrix_set=record.matrix_set,
        )

    @staticmethod
    def _enrollment_hash(request: RegistrationRequest, result: PipelineResult) -> str:
        material = (
            f"{request.device_id}:{request.model_id}:{request.num_crps}:"
            f"{result.validation_metrics.accuracy:.6f}:{result.test_metrics.accuracy:.6f}:"
            f"{result.tuned_threshold.threshold:.6f}"
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()
