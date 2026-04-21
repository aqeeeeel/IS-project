from __future__ import annotations

from protocol.authentication import AuthenticationChallenge, AuthenticationReply, AuthenticationResult
from protocol.registration import RegistrationRequest, RegistrationResult
from puf.engine import PUFEngine
from common.types import Challenge, Response

from .authentication_service import AuthenticationService
from .audit import AuditLogger
from .database import DeviceRecordDatabase
from .registration_service import RecoveryResult, RegistrationService


class ProtectionServer:
    def __init__(self, model_id: str, challenge_bits: int = 256, *, audit_log_path: str | None = None) -> None:
        self.engine = PUFEngine(model_id=model_id, challenge_bits=challenge_bits)
        self._active: dict[str, Challenge] = {}
        self.device_database = DeviceRecordDatabase()
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self.registration_service = RegistrationService(self.device_database, audit_logger=self.audit_logger)
        self.authentication_service = AuthenticationService(
            database=self.device_database,
            challenge_bits=challenge_bits,
            audit_logger=self.audit_logger,
        )

    def issue_challenge(self, challenge_id: str, device_id: str) -> Challenge:
        challenge = self.engine.generate_challenge(challenge_id=challenge_id, device_id=device_id)
        self._active[challenge.challenge_id] = challenge
        return challenge

    def validate_response(self, response: Response, identity_seed: str, tolerance: float = 0.98) -> bool:
        challenge = self._active.get(response.challenge_id)
        if challenge is None:
            return False

        return self.engine.verify_response(
            challenge=challenge,
            response=response,
            identity_seed=identity_seed,
            tolerance=tolerance,
        )

    def register_device(self, request: RegistrationRequest) -> RegistrationResult:
        return self.registration_service.register(request)

    def recover_device(self, device_id: str) -> RecoveryResult:
        return self.registration_service.recover(device_id)

    def is_duplicate_device(self, device_id: str) -> bool:
        return self.registration_service.is_duplicate_device(device_id)

    def issue_authentication_challenge(
        self,
        *,
        device_id: str,
        timeout_seconds: int = 30,
        response_bit_length: int = 256,
        now: int | None = None,
    ) -> AuthenticationChallenge:
        return self.authentication_service.issue_challenge(
            device_id=device_id,
            model_id=self.engine.model_id,
            timeout_seconds=timeout_seconds,
            response_bit_length=response_bit_length,
            now=now,
        )

    def verify_authentication_reply(
        self,
        reply: AuthenticationReply,
        *,
        now: int | None = None,
    ) -> AuthenticationResult:
        return self.authentication_service.verify_reply(reply, now=now)

    def verify_server_challenge_for_device(
        self,
        challenge: AuthenticationChallenge,
        *,
        now: int | None = None,
    ) -> bool:
        return self.authentication_service.verify_server_token(challenge, now=now)
