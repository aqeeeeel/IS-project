from __future__ import annotations

import base64
import math
import random
from dataclasses import dataclass

from device.client import DeviceAgent
from device.storage import DeviceProvisioning
from puf.arbiter import ArbiterPUFSimulator
from puf.engine import PUFEngine
from protocol.registration import RegistrationRequest
from server.app import ProtectionServer
from server.authentication_service import DeviceLockoutError, QueryLimitExceededError

from .metrics import accuracy_score
from .pipeline import train_puf_surrogate


@dataclass(frozen=True, slots=True)
class AttackBenchmarkResult:
    modeling_attack_accuracy: float
    replay_success_rate: float
    mitm_tamper_detection_rate: float
    brute_force_success_rate: float
    noise_resilience_success_rate: float
    query_limit_block_rate: float = 0.0
    lockout_activation_rate: float = 0.0
    session_key_consistency_rate: float = 0.0


def _enroll(
    server: ProtectionServer,
    device: DeviceAgent,
    *,
    challenge_bits: int,
    query_limit_per_minute: int = 120,
    failed_auth_lockout_threshold: int = 5,
    lockout_duration_seconds: int = 300,
    ecc_repetition: int = 1,
    fuzzy_max_distance: int = 0,
) -> None:
    simulator = PUFEngine(model_id=server.engine.model_id, challenge_bits=challenge_bits)._build_simulator(
        device.identity_seed
    )
    registration = server.register_device(
        RegistrationRequest(
            device_id=device.device_id,
            model_id=server.engine.model_id,
            simulator=simulator,
            num_crps=700,
            epochs=150,
            learning_rate=0.18,
            data_seed=13,
            split_seed=19,
            matrix_seed=31,
            query_limit_per_minute=query_limit_per_minute,
            failed_auth_lockout_threshold=failed_auth_lockout_threshold,
            lockout_duration_seconds=lockout_duration_seconds,
            ecc_repetition=ecc_repetition,
            fuzzy_max_distance=fuzzy_max_distance,
        )
    )
    device.apply_provisioning(
        DeviceProvisioning(identity_tag=registration.identity_tag, matrix_set=registration.matrix_set),
        persist=False,
    )


def _simulate_replay_and_tamper(*, trials: int, challenge_bits: int) -> tuple[float, float]:
    replay_blocked = 0
    tamper_detected = 0

    for idx in range(trials):
        seed = f"seed-{idx}"
        server = ProtectionServer(model_id="bench-model", challenge_bits=challenge_bits)
        device = DeviceAgent(device_id=f"dev-{idx}", model_id="bench-model", identity_seed=seed)
        _enroll(server, device, challenge_bits=challenge_bits)

        challenge = server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=25,
            response_bit_length=96,
            now=10_000 + idx * 10,
        )
        reply = device.create_authentication_reply(challenge, now=10_001 + idx * 10)
        first = server.verify_authentication_reply(reply, now=10_002 + idx * 10)
        second = server.verify_authentication_reply(reply, now=10_003 + idx * 10)
        if first.success and not second.success:
            replay_blocked += 1

        challenge2 = server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=25,
            response_bit_length=96,
            now=20_000 + idx * 10,
        )
        reply2 = device.create_authentication_reply(challenge2, now=20_001 + idx * 10)
        tampered = reply2.__class__(
            session_id=reply2.session_id,
            device_id=reply2.device_id,
            server_nonce=reply2.server_nonce,
            device_nonce=reply2.device_nonce,
            matrix_id=reply2.matrix_id,
            padding_bits=reply2.padding_bits,
            encrypted_response_b64=("A" + reply2.encrypted_response_b64[1:]),
            device_message=reply2.device_message,
        )
        tampered_result = server.verify_authentication_reply(tampered, now=20_002 + idx * 10)
        if not tampered_result.success:
            tamper_detected += 1

    return replay_blocked / float(trials), tamper_detected / float(trials)


def _simulate_query_limit_block_rate(*, trials: int, challenge_bits: int) -> float:
    blocked = 0
    for idx in range(trials):
        server = ProtectionServer(model_id="query-model", challenge_bits=challenge_bits)
        device = DeviceAgent(device_id=f"query-{idx}", model_id="query-model", identity_seed=f"query-seed-{idx}")
        _enroll(server, device, challenge_bits=challenge_bits, query_limit_per_minute=1)

        server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=25,
            response_bit_length=96,
            now=30_000 + idx * 10,
        )
        try:
            server.issue_authentication_challenge(
                device_id=device.device_id,
                timeout_seconds=25,
                response_bit_length=96,
                now=30_001 + idx * 10,
            )
        except QueryLimitExceededError:
            blocked += 1
    return blocked / float(trials)


def _simulate_lockout_activation_rate(*, trials: int, challenge_bits: int) -> float:
    activated = 0
    for idx in range(trials):
        server = ProtectionServer(model_id="lockout-model", challenge_bits=challenge_bits)
        device = DeviceAgent(device_id=f"lockout-{idx}", model_id="lockout-model", identity_seed=f"lockout-seed-{idx}")
        _enroll(
            server,
            device,
            challenge_bits=challenge_bits,
            failed_auth_lockout_threshold=1,
            lockout_duration_seconds=120,
        )

        challenge = server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=25,
            response_bit_length=96,
            now=40_000 + idx * 10,
        )
        reply = device.create_authentication_reply(challenge, now=40_001 + idx * 10)
        tampered = reply.__class__(
            session_id=reply.session_id,
            device_id=reply.device_id,
            server_nonce=reply.server_nonce,
            device_nonce=reply.device_nonce,
            matrix_id=reply.matrix_id,
            padding_bits=reply.padding_bits,
            encrypted_response_b64=("B" + reply.encrypted_response_b64[1:]),
            device_message=reply.device_message,
        )
        result = server.verify_authentication_reply(tampered, now=40_002 + idx * 10)
        if not result.success:
            try:
                server.issue_authentication_challenge(
                    device_id=device.device_id,
                    timeout_seconds=25,
                    response_bit_length=96,
                    now=40_003 + idx * 10,
                )
            except DeviceLockoutError:
                activated += 1
    return activated / float(trials)


def _simulate_session_key_consistency(*, trials: int, challenge_bits: int) -> float:
    matches = 0
    for idx in range(trials):
        seed = f"session-seed-{idx}"
        server = ProtectionServer(model_id="session-model", challenge_bits=challenge_bits)
        device = DeviceAgent(device_id=f"session-{idx}", model_id="session-model", identity_seed=seed)
        _enroll(server, device, challenge_bits=challenge_bits)

        challenge = server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=25,
            response_bit_length=96,
            now=50_000 + idx * 10,
        )
        reply = device.create_authentication_reply(challenge, now=50_001 + idx * 10)
        result = server.verify_authentication_reply(reply, now=50_002 + idx * 10)
        if not result.success:
            continue
        if result.session_key_b64 is None or device.last_authentication_session_key is None:
            continue
        device_session_key_b64 = base64.b64encode(device.last_authentication_session_key).decode("ascii")
        if device_session_key_b64 == result.session_key_b64:
            matches += 1
    return matches / float(trials)


def _simulate_bruteforce_success_rate(*, bit_length: int, threshold: float, trials: int) -> float:
    allowed_distance = int(math.floor(threshold * bit_length))
    successes = 0
    rng = random.Random(2026)

    for _ in range(trials):
        target = [rng.randint(0, 1) for _ in range(bit_length)]
        guess = [rng.randint(0, 1) for _ in range(bit_length)]
        distance = sum(1 for left, right in zip(target, guess) if left != right)
        if distance <= allowed_distance:
            successes += 1
    return successes / float(trials)


def _simulate_noise_resilience(*, trials: int, challenge_bits: int) -> float:
    successes = 0
    for idx in range(trials):
        seed = f"noise-seed-{idx}"
        server = ProtectionServer(model_id="noise-model", challenge_bits=challenge_bits)
        device = DeviceAgent(device_id=f"noise-{idx}", model_id="noise-model", identity_seed=seed)
        _enroll(server, device, challenge_bits=challenge_bits, ecc_repetition=3, fuzzy_max_distance=12)

        challenge = server.issue_authentication_challenge(
            device_id=device.device_id,
            timeout_seconds=25,
            response_bit_length=96,
            now=60_000 + idx * 10,
        )
        reply = device.create_authentication_reply(challenge, now=60_001 + idx * 10)
        result = server.verify_authentication_reply(reply, now=60_002 + idx * 10)
        if result.success:
            successes += 1

    return successes / float(trials)


def run_attack_benchmarks(*, challenge_bits: int = 16, trials: int = 12) -> AttackBenchmarkResult:
    target = ArbiterPUFSimulator(challenge_size=challenge_bits, seed=404)
    surrogate = train_puf_surrogate(
        target,
        num_samples=900,
        epochs=180,
        learning_rate=0.16,
        data_seed=17,
        split_seed=23,
    )
    model_probs = surrogate.model.predict_proba(surrogate.split.test.challenges)
    model_preds = [1 if value >= surrogate.tuned_threshold.threshold else 0 for value in model_probs]
    modeling_attack_accuracy = accuracy_score(surrogate.split.test.responses, model_preds)

    replay_resilience, tamper_resilience = _simulate_replay_and_tamper(trials=trials, challenge_bits=challenge_bits)
    query_limit_block_rate = _simulate_query_limit_block_rate(trials=trials, challenge_bits=challenge_bits)
    lockout_activation_rate = _simulate_lockout_activation_rate(trials=trials, challenge_bits=challenge_bits)
    session_key_consistency_rate = _simulate_session_key_consistency(trials=trials, challenge_bits=challenge_bits)
    brute_force_success = _simulate_bruteforce_success_rate(
        bit_length=96,
        threshold=0.15,
        trials=trials * 100,
    )
    noise_resilience = _simulate_noise_resilience(trials=trials, challenge_bits=challenge_bits)

    return AttackBenchmarkResult(
        modeling_attack_accuracy=modeling_attack_accuracy,
        replay_success_rate=1.0 - replay_resilience,
        mitm_tamper_detection_rate=tamper_resilience,
        brute_force_success_rate=brute_force_success,
        noise_resilience_success_rate=noise_resilience,
        query_limit_block_rate=query_limit_block_rate,
        lockout_activation_rate=lockout_activation_rate,
        session_key_consistency_rate=session_key_consistency_rate,
    )