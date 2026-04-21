from __future__ import annotations

from device.client import DeviceAgent
from device.storage import DeviceProvisioning
from puf.engine import PUFEngine
from protocol.registration import RegistrationRequest
from server.app import ProtectionServer


def _enroll_device(server: ProtectionServer, device: DeviceAgent, *, challenge_bits: int = 16) -> None:
    simulator = PUFEngine(model_id="model-a", challenge_bits=challenge_bits)._build_simulator(device.identity_seed)
    registration = server.register_device(
        RegistrationRequest(
            device_id=device.device_id,
            model_id="model-a",
            simulator=simulator,
            num_crps=900,
            epochs=200,
            learning_rate=0.18,
            data_seed=17,
            split_seed=21,
            matrix_seed=55,
        )
    )
    device.apply_provisioning(
        DeviceProvisioning(
            identity_tag=registration.identity_tag,
            matrix_set=registration.matrix_set,
        ),
        persist=False,
    )


def test_mutual_authentication_success() -> None:
    server = ProtectionServer(model_id="model-a", challenge_bits=16)
    device = DeviceAgent(device_id="dev-auth-ok", model_id="model-a", identity_seed="seed-ok")
    _enroll_device(server, device, challenge_bits=16)

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=40,
        response_bit_length=128,
        now=1_000,
    )
    reply = device.create_authentication_reply(challenge, now=1_005)

    result = server.verify_authentication_reply(reply, now=1_010)
    record = server.device_database.get(device.device_id)

    assert result.success
    assert result.hamming_ratio is not None and result.hamming_ratio <= record.hamming_threshold
    assert record.auth_state == "authenticated"
    assert record.last_session_id == challenge.session_id


def test_server_to_device_verification_and_replay_protection() -> None:
    server = ProtectionServer(model_id="model-a", challenge_bits=12)
    device = DeviceAgent(device_id="dev-replay", model_id="model-a", identity_seed="seed-replay")
    _enroll_device(server, device, challenge_bits=12)

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=20,
        response_bit_length=64,
        now=2_000,
    )

    assert device.verify_server_challenge(challenge, now=2_005)
    assert not device.verify_server_challenge(challenge, now=2_006)


def test_timeout_handling_aborts_session() -> None:
    server = ProtectionServer(model_id="model-a", challenge_bits=10)
    device = DeviceAgent(device_id="dev-timeout", model_id="model-a", identity_seed="seed-timeout")
    _enroll_device(server, device, challenge_bits=10)

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=5,
        response_bit_length=64,
        now=5_000,
    )
    reply = device.create_authentication_reply(challenge, now=5_001)

    result = server.verify_authentication_reply(reply, now=5_020)
    record = server.device_database.get(device.device_id)

    assert not result.success
    assert result.reason == "timeout"
    assert record.auth_state == "aborted"
    assert record.failed_auth_attempts >= 1


def test_failed_integrity_check_aborts_authentication() -> None:
    server = ProtectionServer(model_id="model-a", challenge_bits=14)
    device = DeviceAgent(device_id="dev-fail", model_id="model-a", identity_seed="seed-fail")
    _enroll_device(server, device, challenge_bits=14)

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=20,
        response_bit_length=96,
        now=7_000,
    )
    reply = device.create_authentication_reply(challenge, now=7_002)

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

    result = server.verify_authentication_reply(tampered, now=7_004)
    record = server.device_database.get(device.device_id)

    assert not result.success
    assert result.reason in {"device-message-verification-failed", "hamming-threshold-failed"}
    assert record.auth_state == "aborted"
    assert record.failed_auth_attempts >= 1


def test_replay_same_reply_rejected_after_success() -> None:
    server = ProtectionServer(model_id="model-a", challenge_bits=16)
    device = DeviceAgent(device_id="dev-replay-reply", model_id="model-a", identity_seed="seed-reply")
    _enroll_device(server, device, challenge_bits=16)

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=30,
        response_bit_length=128,
        now=9_000,
    )
    reply = device.create_authentication_reply(challenge, now=9_002)

    first = server.verify_authentication_reply(reply, now=9_003)
    second = server.verify_authentication_reply(reply, now=9_004)

    assert first.success
    assert not second.success
    assert second.reason is not None
