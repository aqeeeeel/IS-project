from __future__ import annotations

from pathlib import Path

from common.crypto_utils import NonceTracker, derive_session_key, generate_nonce
from common.types import Challenge, Response
from puf.engine import PUFEngine
from protocol.authentication import AuthenticationChallenge, AuthenticationReply, build_device_reply, verify_server_challenge

from .storage import DeviceProvisioning, load_provisioning, save_provisioning


class DeviceAgent:
    def __init__(
        self,
        device_id: str,
        model_id: str,
        identity_seed: str,
        *,
        provisioning_path: str | Path | None = None,
    ) -> None:
        self.device_id = device_id
        self.identity_seed = identity_seed
        self.engine = PUFEngine(model_id=model_id)
        self.provisioning_path = Path(provisioning_path) if provisioning_path is not None else None
        self.provisioning: DeviceProvisioning | None = None
        self._server_nonce_tracker = NonceTracker(ttl_seconds=600)
        self.last_authentication_response_bits: str | None = None
        self.last_authentication_session_key: bytes | None = None

    def answer_challenge(self, challenge: Challenge) -> Response:
        bits = self.engine.derive_response_bits(challenge, self.identity_seed)
        return Response(
            challenge_id=challenge.challenge_id,
            device_id=self.device_id,
            response_bits=bits,
        )

    def apply_provisioning(self, provisioning: DeviceProvisioning, *, persist: bool = True) -> None:
        self.provisioning = provisioning
        if persist and self.provisioning_path is not None:
            save_provisioning(provisioning, self.provisioning_path)

    def load_local_provisioning(self) -> DeviceProvisioning:
        if self.provisioning_path is None:
            raise ValueError("No provisioning_path configured for DeviceAgent")
        provisioning = load_provisioning(self.provisioning_path)
        self.provisioning = provisioning
        return provisioning

    def verify_server_challenge(self, challenge: AuthenticationChallenge, *, now: int | None = None) -> bool:
        if self.provisioning is None:
            raise ValueError("Device provisioning is required before authentication")
        return verify_server_challenge(
            challenge,
            self.provisioning.identity_tag.enrollment_hash.encode("utf-8"),
            nonce_tracker=self._server_nonce_tracker,
            now=now,
        )

    def create_authentication_reply(
        self,
        challenge: AuthenticationChallenge,
        *,
        now: int | None = None,
    ) -> AuthenticationReply:
        if self.provisioning is None:
            raise ValueError("Device provisioning is required before authentication")
        if not self.verify_server_challenge(challenge, now=now):
            raise ValueError("Server challenge verification failed")

        challenge_for_puf = Challenge(
            challenge_id=challenge.challenge_id,
            device_id=self.device_id,
            model_id=challenge.model_id,
            vector=challenge.challenge_vector,
        )
        auth_engine = PUFEngine(
            model_id=challenge.model_id,
            challenge_bits=len(challenge.challenge_vector),
        )
        response_bits = auth_engine.derive_response_bits(challenge_for_puf, self.identity_seed)
        response_bits = response_bits[:challenge.response_bit_length]
        used_device_nonce = generate_nonce()
        self.last_authentication_response_bits = response_bits
        self.last_authentication_session_key = self.derive_authentication_session_key(
            challenge,
            response_bits,
            device_nonce=used_device_nonce,
        )

        return build_device_reply(
            challenge=challenge,
            device_id=self.device_id,
            response_bits=response_bits,
            shared_key=self.provisioning.identity_tag.enrollment_hash.encode("utf-8"),
            matrix_set=self.provisioning.matrix_set,
            timestamp=now,
            device_nonce=used_device_nonce,
        )

    @staticmethod
    def derive_authentication_session_key(
        challenge: AuthenticationChallenge,
        response_bits: str,
        *,
        device_nonce: str,
    ) -> bytes:
        return derive_session_key(
            response_bits.encode("utf-8"),
            challenge.session_id.encode("utf-8"),
            challenge.server_nonce.encode("utf-8"),
            device_nonce.encode("utf-8"),
        )
