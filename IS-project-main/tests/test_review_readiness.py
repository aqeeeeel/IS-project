from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from device.client import DeviceAgent
from device.storage import DeviceProvisioning
from puf.engine import PUFEngine
from protocol.registration import RegistrationRequest
from protocol.transmission import derive_puf_session_key
from server.app import ProtectionServer


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
            query_limit_per_minute=33,
            failed_auth_lockout_threshold=2,
            lockout_duration_seconds=90,
            ecc_repetition=3,
            fuzzy_max_distance=7,
        )
    )
    device.apply_provisioning(
        DeviceProvisioning(identity_tag=registration.identity_tag, matrix_set=registration.matrix_set),
        persist=False,
    )


def test_registration_policy_fields_persist() -> None:
    server = ProtectionServer(model_id="policy-model", challenge_bits=12)
    device = DeviceAgent(device_id="dev-policy", model_id="policy-model", identity_seed="seed-policy")
    _enroll(server, device, challenge_bits=12)

    record = server.device_database.get(device.device_id)
    assert record.query_limit_per_minute == 33
    assert record.failed_auth_lockout_threshold == 2
    assert record.lockout_duration_seconds == 90
    assert record.ecc_repetition == 3
    assert record.fuzzy_max_distance == 7


def test_authentication_emits_session_key_and_audit_log(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "events.jsonl"
    server = ProtectionServer(model_id="audit-model", challenge_bits=12, audit_log_path=str(audit_path))
    device = DeviceAgent(device_id="dev-audit", model_id="audit-model", identity_seed="seed-audit")
    _enroll(server, device, challenge_bits=12)

    challenge = server.issue_authentication_challenge(
        device_id=device.device_id,
        timeout_seconds=20,
        response_bit_length=96,
        now=1_000,
    )
    reply = device.create_authentication_reply(challenge, now=1_001)
    result = server.verify_authentication_reply(reply, now=1_002)

    record = server.device_database.get(device.device_id)
    assert result.success
    assert result.session_key_b64 is not None
    assert record.last_session_key_b64 == result.session_key_b64

    lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
    parsed = [json.loads(line) for line in lines]
    assert any(evt["event_type"] == "auth.verify_reply" and evt["outcome"] == "ok" for evt in parsed)


def test_puf_session_key_derivation_is_deterministic() -> None:
    simulator = PUFEngine(model_id="derive-model", challenge_bits=14)._build_simulator("derive-seed")
    key_a, challenges_a = derive_puf_session_key(simulator, seed=b"seed", key_challenge_count=32)
    key_b, challenges_b = derive_puf_session_key(simulator, seed=b"seed", key_challenge_count=32)

    assert key_a == key_b
    assert challenges_a == challenges_b


def test_run_all_single_command_smoke() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "run_all.py"

    completed = subprocess.run(
        [sys.executable, str(script), "--skip-tests"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "Completed successfully" in completed.stdout


def test_demo_script_run_smoke() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    script = repo_root / "scripts" / "demo_end_to_end.py"

    completed = subprocess.run(
        [sys.executable, str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "End-to-end demo completed successfully" in completed.stdout
