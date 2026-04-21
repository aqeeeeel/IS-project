from __future__ import annotations

import pytest

from common.fuzzy import fuzzy_enroll, fuzzy_recover, repetition_decode, repetition_encode
from device.client import DeviceAgent
from device.storage import DeviceProvisioning
from modeling.attack_benchmarks import run_attack_benchmarks
from puf.engine import PUFEngine
from protocol.parameter_encoder import ChallengeSelectionStrategy
from protocol.registration import RegistrationRequest
from protocol.transmission import recover_parameters, transmit_parameters
from server.app import ProtectionServer
from server.authentication_service import DeviceLockoutError, QueryLimitExceededError


def _enroll(server: ProtectionServer, device: DeviceAgent, *, challenge_bits: int = 12) -> None:
    simulator = PUFEngine(model_id=server.engine.model_id, challenge_bits=challenge_bits)._build_simulator(
        device.identity_seed
    )
    registration = server.register_device(
        RegistrationRequest(
            device_id=device.device_id,
            model_id=server.engine.model_id,
            simulator=simulator,
            num_crps=600,
            epochs=130,
            learning_rate=0.18,
            data_seed=5,
            split_seed=9,
        )
    )
    device.apply_provisioning(
        DeviceProvisioning(identity_tag=registration.identity_tag, matrix_set=registration.matrix_set),
        persist=False,
    )


def test_repetition_ecc_and_fuzzy_recovery() -> None:
    reference = "10100110"
    encoded = repetition_encode(reference, 3)
    noisy = list(encoded)
    noisy[2] = "1" if noisy[2] == "0" else "0"
    noisy[11] = "1" if noisy[11] == "0" else "0"
    recovered = repetition_decode("".join(noisy), 3)
    assert recovered == reference

    helper = fuzzy_enroll(reference, max_hamming_distance=2)
    assert fuzzy_recover("10100111", helper) == reference
    assert fuzzy_recover("01011000", helper) is None


def test_query_limit_and_lockout_defense() -> None:
    server = ProtectionServer(model_id="secure-model", challenge_bits=12)
    device = DeviceAgent(device_id="dev-limit", model_id="secure-model", identity_seed="seed-limit")
    _enroll(server, device, challenge_bits=12)

    server.device_database.update(
        device.device_id,
        query_limit_per_minute=1,
        failed_auth_lockout_threshold=1,
        lockout_duration_seconds=120,
    )

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=30,
        response_bit_length=96,
        now=1000,
    )
    reply = device.create_authentication_reply(challenge, now=1001)

    tampered = reply.__class__(
        session_id=reply.session_id,
        device_id=reply.device_id,
        server_nonce=reply.server_nonce,
        device_nonce=reply.device_nonce,
        matrix_id=reply.matrix_id,
        padding_bits=reply.padding_bits,
        encrypted_response_b64=("A" + reply.encrypted_response_b64[1:]),
        device_message=reply.device_message,
    )
    result = server.verify_authentication_reply(tampered, now=1002)
    assert not result.success

    with pytest.raises(DeviceLockoutError):
        server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=30,
            response_bit_length=96,
            now=1003,
        )

    server.device_database.update(device.device_id, lockout_until=None)
    with pytest.raises(QueryLimitExceededError):
        server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=30,
            response_bit_length=96,
            now=1004,
        )


def test_hybrid_transmission_with_puf_session_key() -> None:
    cryptography = pytest.importorskip("cryptography")
    assert cryptography is not None

    seed = "hybrid-seed"
    server_sim = PUFEngine(model_id="m", challenge_bits=14)._build_simulator(seed)
    device_sim = PUFEngine(model_id="m", challenge_bits=14)._build_simulator(seed)

    payload = {"blob": "x" * 5000, "weights": [i for i in range(64)]}
    envelope = transmit_parameters(
        payload,
        server_simulator=server_sim,
        strategy=ChallengeSelectionStrategy.TRAVERSAL,
        hybrid_mode=True,
        hybrid_large_payload_threshold=512,
        session_seed=b"session-demo",
        noisy=False,
    )
    recovered = recover_parameters(
        envelope,
        device_simulator=device_sim,
        noisy=False,
        session_seed=b"session-demo",
    )

    assert envelope.mode == "hybrid-aes-gcm"
    assert recovered == payload


def test_attack_benchmark_outputs_are_measurable() -> None:
    result = run_attack_benchmarks(challenge_bits=12, trials=3)

    assert 0.0 <= result.modeling_attack_accuracy <= 1.0
    assert 0.0 <= result.replay_success_rate <= 1.0
    assert 0.0 <= result.mitm_tamper_detection_rate <= 1.0
    assert 0.0 <= result.brute_force_success_rate <= 1.0
    assert 0.0 <= result.noise_resilience_success_rate <= 1.0
