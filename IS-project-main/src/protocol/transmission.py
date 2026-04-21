from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from common.crypto_utils import aesgcm_decrypt_optional, aesgcm_encrypt_optional, derive_session_key
from puf.interface import PUFSimulator

from .parameter_decoder import deserialize_parameters
from .parameter_decoder import decode_parameters_from_challenges
from .parameter_encoder import (
    ChallengeSelectionStrategy,
    EncodedParameterPacket,
    encode_parameters_to_challenges,
    serialize_parameters,
)


@dataclass(frozen=True, slots=True)
class ParameterTransmissionEnvelope:
    packet: EncodedParameterPacket
    mode: str = "puf-bitmap"
    hybrid_payload: dict[str, str] | None = None
    session_key_challenges: list[list[int]] | None = None


def derive_puf_session_key(
    simulator: PUFSimulator,
    *,
    seed: bytes,
    key_challenge_count: int,
) -> tuple[bytes, list[list[int]]]:
    import hashlib

    if key_challenge_count <= 0:
        raise ValueError("key_challenge_count must be positive")

    challenges: list[list[int]] = []
    response_bits: list[str] = []
    for idx in range(key_challenge_count):
        digest = hashlib.sha256(seed + idx.to_bytes(4, "big")).digest()
        challenge: list[int] = []
        bit_cursor = 0
        while len(challenge) < simulator.challenge_size:
            byte_index = bit_cursor // 8
            bit_index = 7 - (bit_cursor % 8)
            source = digest[byte_index % len(digest)]
            challenge.append((source >> bit_index) & 1)
            bit_cursor += 1
        challenges.append(challenge)
        bit = simulator.evaluate_stable(challenge, repetitions=7)
        response_bits.append(str(bit))

    key_material = "".join(response_bits).encode("utf-8")
    return derive_session_key(key_material, seed, key_size=32), challenges


def transmit_parameters(
    parameters: Any,
    *,
    server_simulator: PUFSimulator,
    strategy: ChallengeSelectionStrategy = ChallengeSelectionStrategy.ENUMERATION,
    stability_repetitions: int = 5,
    noisy: bool = True,
    selection_seed: int | None = None,
    hybrid_mode: bool = False,
    hybrid_large_payload_threshold: int = 2048,
    session_seed: bytes | None = None,
    key_challenge_count: int = 128,
) -> ParameterTransmissionEnvelope:
    payload_bytes = serialize_parameters(parameters)
    if hybrid_mode and len(payload_bytes) >= hybrid_large_payload_threshold:
        seed = session_seed if session_seed is not None else b"puf-session-seed"
        session_key, challenges = derive_puf_session_key(
            server_simulator,
            seed=seed,
            key_challenge_count=key_challenge_count,
        )
        encrypted = aesgcm_encrypt_optional(payload_bytes, session_key, aad=seed)
        return ParameterTransmissionEnvelope(
            packet=EncodedParameterPacket(
                challenge_size=server_simulator.challenge_size,
                bit_length=0,
                strategy=strategy,
                stability_repetitions=stability_repetitions,
                challenges=[],
            ),
            mode="hybrid-aes-gcm",
            hybrid_payload=encrypted,
            session_key_challenges=challenges,
        )

    packet = encode_parameters_to_challenges(
        parameters,
        simulator=server_simulator,
        strategy=strategy,
        stability_repetitions=stability_repetitions,
        noisy=noisy,
        selection_seed=selection_seed,
    )
    return ParameterTransmissionEnvelope(packet=packet)


def recover_parameters(
    envelope: ParameterTransmissionEnvelope,
    *,
    device_simulator: PUFSimulator,
    noisy: bool = True,
    stability_attempts: int = 3,
    session_seed: bytes | None = None,
) -> Any:
    if envelope.mode == "hybrid-aes-gcm":
        if envelope.hybrid_payload is None or envelope.session_key_challenges is None:
            raise ValueError("Hybrid envelope is missing payload metadata")
        seed = session_seed if session_seed is not None else b"puf-session-seed"
        response_bits = [
            str(device_simulator.evaluate_stable(challenge, repetitions=7))
            for challenge in envelope.session_key_challenges
        ]
        key = derive_session_key("".join(response_bits).encode("utf-8"), seed, key_size=32)
        decrypted = aesgcm_decrypt_optional(envelope.hybrid_payload, key)
        return deserialize_parameters(decrypted)

    return decode_parameters_from_challenges(
        envelope.packet,
        simulator=device_simulator,
        noisy=noisy,
        stability_attempts=stability_attempts,
    )
