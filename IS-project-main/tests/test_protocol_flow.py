from __future__ import annotations

from device.client import DeviceAgent
from server.app import ProtectionServer


def test_end_to_end_challenge_validation() -> None:
    seed = "device-secret-seed"
    server = ProtectionServer(model_id="model-a")
    device = DeviceAgent(device_id="dev-1", model_id="model-a", identity_seed=seed)

    challenge = server.issue_challenge(challenge_id="c-1", device_id="dev-1")
    response = device.answer_challenge(challenge)

    assert server.validate_response(response, identity_seed=seed)
