from __future__ import annotations

from puf.engine import PUFEngine
from protocol.parameter_encoder import ChallengeSelectionStrategy
from protocol.transmission import recover_parameters, transmit_parameters


def test_end_to_end_parameter_transmission_with_shared_identity() -> None:
    model_id = "model-a"
    identity_seed = "device-identity-seed"

    server_engine = PUFEngine(model_id=model_id, challenge_bits=14)
    device_engine = PUFEngine(model_id=model_id, challenge_bits=14)

    server_simulator = server_engine._build_simulator(identity_seed)
    device_simulator = device_engine._build_simulator(identity_seed)

    parameters = {
        "dense.weight": [0.1, -0.2, 0.3, -0.4],
        "dense.bias": [0.9],
        "version": 3,
    }

    envelope = transmit_parameters(
        parameters,
        server_simulator=server_simulator,
        strategy=ChallengeSelectionStrategy.TRAVERSAL,
        stability_repetitions=5,
        noisy=False,
        selection_seed=123,
    )
    recovered = recover_parameters(
        envelope,
        device_simulator=device_simulator,
        noisy=False,
    )

    assert recovered == parameters
