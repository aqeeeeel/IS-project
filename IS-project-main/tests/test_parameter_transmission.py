from __future__ import annotations

import pytest

from puf.arbiter import ArbiterPUFSimulator
from protocol.parameter_decoder import decode_parameters_from_challenges
from protocol.parameter_encoder import ChallengeSelectionStrategy, encode_parameters_to_challenges
from protocol.transmission import recover_parameters, transmit_parameters


class _AlwaysUnstableSimulator:
    challenge_size = 12

    def evaluate(self, challenge, *, noisy: bool = False):
        return 0

    def evaluate_repeated(self, challenge, repetitions: int, *, noisy: bool = True):
        return [idx % 2 for idx in range(repetitions)]

    def evaluate_stable(self, challenge, repetitions: int = 7):
        return 0

    @staticmethod
    def hamming_distance(left, right):
        return sum(1 for l_bit, r_bit in zip(left, right) if l_bit != r_bit)

    @staticmethod
    def hamming_ratio(left, right):
        return _AlwaysUnstableSimulator.hamming_distance(left, right) / float(len(left))


def _example_parameters() -> dict[str, object]:
    return {
        "layer_1": [0.125, -1.75, 2.5, 4.0],
        "layer_2": [3.1415926535, -0.00001],
        "meta": {"epoch": 7, "name": "demo-model"},
    }


def test_parameter_encoding_recovery_enumeration_exact() -> None:
    parameters = _example_parameters()
    server_sim = ArbiterPUFSimulator(challenge_size=16, seed=77)
    device_sim = ArbiterPUFSimulator(challenge_size=16, seed=77)

    envelope = transmit_parameters(
        parameters,
        server_simulator=server_sim,
        strategy=ChallengeSelectionStrategy.ENUMERATION,
        stability_repetitions=5,
        noisy=False,
    )
    recovered = recover_parameters(envelope, device_simulator=device_sim, noisy=False)

    assert recovered == parameters


def test_parameter_encoding_recovery_traversal_exact() -> None:
    parameters = _example_parameters()
    server_sim = ArbiterPUFSimulator(challenge_size=16, seed=101)
    device_sim = ArbiterPUFSimulator(challenge_size=16, seed=101)

    envelope = transmit_parameters(
        parameters,
        server_simulator=server_sim,
        strategy=ChallengeSelectionStrategy.TRAVERSAL,
        stability_repetitions=5,
        noisy=False,
        selection_seed=99,
    )
    recovered = recover_parameters(envelope, device_simulator=device_sim, noisy=False)

    assert recovered == parameters


def test_stability_check_rejects_unstable_challenges() -> None:
    parameters = {"w": [1.0, -2.0]}
    unstable_sim = _AlwaysUnstableSimulator()

    with pytest.raises(RuntimeError):
        encode_parameters_to_challenges(
            parameters,
            simulator=unstable_sim,
            strategy=ChallengeSelectionStrategy.ENUMERATION,
            stability_repetitions=7,
            noisy=True,
            max_attempts_per_bit=100,
        )


def test_decoder_detects_stability_failure_on_device() -> None:
    parameters = {"v": [0.5, 0.25]}
    stable_server = ArbiterPUFSimulator(challenge_size=12, seed=21)
    noisy_device = ArbiterPUFSimulator(
        challenge_size=12,
        seed=21,
        noise_probability=0.35,
        stability=0.6,
    )

    packet = encode_parameters_to_challenges(
        parameters,
        simulator=stable_server,
        strategy=ChallengeSelectionStrategy.TRAVERSAL,
        stability_repetitions=5,
        noisy=False,
        selection_seed=7,
    )

    with pytest.raises(RuntimeError):
        decode_parameters_from_challenges(
            packet,
            simulator=noisy_device,
            noisy=True,
            stability_attempts=1,
        )
