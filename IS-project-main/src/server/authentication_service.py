from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass, field
from time import time
from uuid import uuid4

from common.crypto_utils import NonceTracker
from common.fuzzy import build_recovery_profile, recover_noisy_bits
from modeling.metrics import hamming_distance, hamming_ratio
from modeling.logistic import LogisticRegressionPUFModel
from protocol.authentication import (
    AuthenticationChallenge,
    AuthenticationReply,
    AuthenticationResult,
    AuthenticationSession,
    AuthenticationState,
    derive_authentication_session_key,
    build_server_challenge,
    decode_reply_response_bits,
    verify_device_reply_message,
)

from .database import DeviceRecordDatabase, DeviceRecordNotFoundError
from .audit import AuditLogger


class AuthenticationError(ValueError):
    pass


class SessionNotFoundError(LookupError):
    pass


class AuthenticationTimeoutError(AuthenticationError):
    pass


class ReplayDetectedError(AuthenticationError):
    pass


class QueryLimitExceededError(AuthenticationError):
    pass


class DeviceLockoutError(AuthenticationError):
    pass


@dataclass(slots=True)
class AuthenticationService:
    database: DeviceRecordDatabase
    challenge_bits: int
    audit_logger: AuditLogger | None = None
    state: AuthenticationState = field(init=False)
    reply_nonce_tracker: NonceTracker = field(init=False)

    def __post_init__(self) -> None:
        self.state = AuthenticationState(tracker=NonceTracker(ttl_seconds=600))
        self.reply_nonce_tracker = NonceTracker(ttl_seconds=600)

    def _audit(self, event_type: str, outcome: str, **details: object) -> None:
        if self.audit_logger is not None:
            self.audit_logger.record(event_type, outcome, **details)

    def _is_locked_out(self, record, current_time: int) -> bool:
        return record.lockout_until is not None and current_time < int(record.lockout_until)

    def _enforce_query_limit(self, record, current_time: int) -> bool:
        window_start = int(record.query_window_start) if record.query_window_start is not None else None
        if window_start is None or (current_time - window_start) >= 60:
            self.database.update(
                record.device_id,
                query_window_start=float(current_time),
                query_count_in_window=1,
            )
            return True

        if record.query_count_in_window >= record.query_limit_per_minute:
            return False
        self.database.update(
            record.device_id,
            query_count_in_window=record.query_count_in_window + 1,
        )
        return True

    def _challenge_variant(self, challenge_vector: list[int], round_index: int) -> list[int]:
        if not challenge_vector:
            raise ValueError("challenge_vector must not be empty")

        width = len(challenge_vector)
        rotation = round_index % width
        rotated = challenge_vector[rotation:] + challenge_vector[:rotation]
        if ((round_index // width) % 2) == 1:
            return [1 - bit for bit in rotated]
        return rotated

    def issue_challenge(
        self,
        *,
        device_id: str,
        model_id: str,
        timeout_seconds: int = 30,
        response_bit_length: int = 256,
        now: int | None = None,
    ) -> AuthenticationChallenge:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if response_bit_length <= 0:
            raise ValueError("response_bit_length must be positive")

        try:
            record = self.database.get(device_id)
        except DeviceRecordNotFoundError as exc:
            self._audit("auth.issue_challenge", "fail", device_id=device_id, reason="unknown-device")
            raise AuthenticationError(f"Unknown device '{device_id}'") from exc

        current_time = int(now if now is not None else time())
        if self._is_locked_out(record, current_time):
            self._audit(
                "auth.issue_challenge",
                "fail",
                device_id=device_id,
                reason="lockout",
                lockout_until=record.lockout_until,
            )
            raise DeviceLockoutError(f"Device '{device_id}' is temporarily locked out")

        if not self._enforce_query_limit(record, current_time):
            self._audit("auth.issue_challenge", "fail", device_id=device_id, reason="query-limit")
            raise QueryLimitExceededError(f"Device '{device_id}' exceeded query limit")

        session_id = str(uuid4())
        challenge_id = str(uuid4())
        vector = [secrets.randbits(1) for _ in range(self.challenge_bits)]

        challenge = build_server_challenge(
            session_id=session_id,
            device_id=device_id,
            model_id=model_id,
            challenge_id=challenge_id,
            challenge_vector=vector,
            timeout_seconds=timeout_seconds,
            shared_key=record.identity_tag.enrollment_hash.encode("utf-8"),
            response_bit_length=response_bit_length,
            ecc_repetition=max(1, record.ecc_repetition),
            issued_at=current_time,
        )

        self.state.sessions[session_id] = AuthenticationSession(
            session_id=session_id,
            device_id=device_id,
            model_id=model_id,
            challenge_id=challenge_id,
            challenge_vector=vector,
            server_nonce=challenge.server_nonce,
            created_at=current_time,
            expires_at=current_time + timeout_seconds,
            response_bit_length=response_bit_length,
            ecc_repetition=max(1, record.ecc_repetition),
            state="issued",
        )
        self.database.update(device_id, auth_state="challenge-issued", last_session_id=session_id)
        self._audit("auth.issue_challenge", "ok", device_id=device_id, session_id=session_id)
        return challenge

    def _expected_response_bits(
        self,
        *,
        model: LogisticRegressionPUFModel,
        challenge_vector: list[int],
        threshold: float,
        response_bit_length: int,
    ) -> str:
        bits: list[str] = []
        for idx in range(response_bit_length):
            variant = self._challenge_variant(challenge_vector, idx)
            predicted = model.predict([variant], threshold=threshold)[0]
            bits.append(str(predicted))
        return "".join(bits)

    def _abort(self, session: AuthenticationSession, reason: str) -> AuthenticationResult:
        session.state = "aborted"
        session.failure_reason = reason
        record = self.database.get(session.device_id)
        failed_attempts = record.failed_auth_attempts + 1
        lockout_until = record.lockout_until
        if failed_attempts >= record.failed_auth_lockout_threshold:
            lockout_until = time() + float(record.lockout_duration_seconds)
        self.database.update(
            session.device_id,
            auth_state="aborted",
            failed_auth_attempts=failed_attempts,
            lockout_until=lockout_until,
        )
        self._audit(
            "auth.verify_reply",
            "fail",
            device_id=session.device_id,
            session_id=session.session_id,
            reason=reason,
            failed_attempts=failed_attempts,
            lockout_until=lockout_until,
        )
        return AuthenticationResult(
            success=False,
            session_id=session.session_id,
            device_id=session.device_id,
            reason=reason,
        )

    def verify_reply(self, reply: AuthenticationReply, *, now: int | None = None) -> AuthenticationResult:
        session = self.state.sessions.get(reply.session_id)
        if session is None:
            raise SessionNotFoundError(f"Unknown session '{reply.session_id}'")

        current_time = int(now if now is not None else time())
        if session.is_expired(current_time):
            return self._abort(session, "timeout")

        if session.state not in {"issued", "pending"}:
            return self._abort(session, f"invalid-session-state:{session.state}")

        if reply.device_nonce in session.used_device_nonces:
            return self._abort(session, "replay-detected")

        if reply.server_nonce != session.server_nonce:
            return self._abort(session, "server-nonce-mismatch")

        try:
            record = self.database.get(reply.device_id)
        except DeviceRecordNotFoundError:
            return self._abort(session, "unknown-device")

        verified = verify_device_reply_message(
            reply,
            record.identity_tag.enrollment_hash.encode("utf-8"),
            timeout_seconds=max(1, session.expires_at - session.created_at),
            nonce_tracker=self.reply_nonce_tracker,
            now=current_time,
        )
        if not verified:
            return self._abort(session, "device-message-verification-failed")

        session.used_device_nonces.add(reply.device_nonce)

        actual_bits = decode_reply_response_bits(
            reply,
            matrix_set=record.matrix_set,
            expected_bit_length=session.response_bit_length,
            ecc_repetition=max(1, session.ecc_repetition),
        )

        model = LogisticRegressionPUFModel.from_dict(record.model_parameters)
        expected_bits = self._expected_response_bits(
            model=model,
            challenge_vector=session.challenge_vector,
            threshold=record.threshold,
            response_bit_length=session.response_bit_length,
        )

        if record.fuzzy_max_distance > 0:
            recovery_profile = build_recovery_profile(
                expected_bits,
                max_hamming_distance=record.fuzzy_max_distance,
            )
            recovered = recover_noisy_bits(actual_bits, recovery_profile)
            if recovered is None:
                return self._abort(session, "fuzzy-recovery-failed")
            actual_bits = recovered

        distance = hamming_distance(expected_bits, actual_bits)
        ratio = hamming_ratio(expected_bits, actual_bits)
        if ratio > record.hamming_threshold:
            return self._abort(session, "hamming-threshold-failed")

        session_key = derive_authentication_session_key(
            actual_bits,
            session_id=session.session_id,
            server_nonce=session.server_nonce,
            device_nonce=reply.device_nonce,
        )
        session_key_b64 = base64.b64encode(session_key).decode("ascii")

        session.state = "authenticated"
        session.session_key_b64 = session_key_b64
        self.database.update(
            record.device_id,
            auth_state="authenticated",
            failed_auth_attempts=0,
            lockout_until=None,
            last_authenticated_at=current_time,
            last_session_id=session.session_id,
            last_session_key_b64=session_key_b64,
        )
        self._audit(
            "auth.verify_reply",
            "ok",
            device_id=record.device_id,
            session_id=session.session_id,
            hamming_ratio=ratio,
            hamming_distance=distance,
        )
        return AuthenticationResult(
            success=True,
            session_id=session.session_id,
            device_id=record.device_id,
            hamming_distance=distance,
            hamming_ratio=ratio,
            authenticated_at=current_time,
            session_key_b64=session_key_b64,
        )

    def verify_server_token(self, challenge: AuthenticationChallenge, *, now: int | None = None) -> bool:
        try:
            record = self.database.get(challenge.device_id)
        except DeviceRecordNotFoundError:
            return False
        from protocol.authentication import verify_server_challenge

        return verify_server_challenge(
            challenge,
            record.identity_tag.enrollment_hash.encode("utf-8"),
            nonce_tracker=self.state.tracker,
            now=now,
        )
