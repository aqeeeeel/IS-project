from __future__ import annotations

from puf.arbiter import ArbiterPUFSimulator
from puf.ipuf import InterposePUFSimulator
from puf.xor_apuf import XORArbiterPUFSimulator


def test_arbiter_deterministic_mode() -> None:
    challenge = [1, 0, 1, 1, 0, 0, 1, 0]
    simulator = ArbiterPUFSimulator(challenge_size=len(challenge), seed=17)

    first = simulator.evaluate(challenge, noisy=False)
    second = simulator.evaluate(challenge, noisy=False)
    repeated = simulator.evaluate_repeated(challenge, repetitions=8, noisy=False)

    assert first in (0, 1)
    assert first == second
    assert all(bit == first for bit in repeated)


def test_arbiter_noisy_mode_and_hamming_comparison() -> None:
    challenge = [1, 1, 0, 1, 0, 1, 0, 0]
    simulator = ArbiterPUFSimulator(
        challenge_size=len(challenge),
        noise_probability=0.35,
        stability=0.95,
        seed=101,
    )

    noisy_samples = simulator.evaluate_repeated(challenge, repetitions=48, noisy=True)
    deterministic_bit = simulator.evaluate(challenge, noisy=False)

    assert any(bit != deterministic_bit for bit in noisy_samples)
    assert any(bit == deterministic_bit for bit in noisy_samples)

    reference = [deterministic_bit for _ in noisy_samples]
    distance = simulator.hamming_distance(noisy_samples, reference)
    ratio = simulator.hamming_ratio(noisy_samples, reference)

    assert distance > 0
    assert 0.0 < ratio < 1.0


def test_response_reproducibility_for_seeded_noisy_simulator() -> None:
    challenge = [0, 1, 1, 0, 1, 0, 1, 1]
    sim_a = ArbiterPUFSimulator(
        challenge_size=len(challenge),
        noise_probability=0.20,
        stability=0.90,
        seed=999,
    )
    sim_b = ArbiterPUFSimulator(
        challenge_size=len(challenge),
        noise_probability=0.20,
        stability=0.90,
        seed=999,
    )

    samples_a = sim_a.evaluate_repeated(challenge, repetitions=32, noisy=True)
    samples_b = sim_b.evaluate_repeated(challenge, repetitions=32, noisy=True)

    assert samples_a == samples_b


def test_xor_apuf_and_ipuf_share_interface() -> None:
    challenge = [1, 0, 1, 0, 0, 1, 1, 0]

    xor_simulator = XORArbiterPUFSimulator(challenge_size=len(challenge), num_xors=3, seed=12)
    ipuf_simulator = InterposePUFSimulator(challenge_size=len(challenge), seed=34)

    xor_response = xor_simulator.evaluate(challenge, noisy=False)
    ipuf_response = ipuf_simulator.evaluate(challenge, noisy=False)

    assert xor_response in (0, 1)
    assert ipuf_response in (0, 1)

    xor_stable = xor_simulator.evaluate_stable(challenge, repetitions=9)
    ipuf_stable = ipuf_simulator.evaluate_stable(challenge, repetitions=9)

    assert xor_stable in (0, 1)
    assert ipuf_stable in (0, 1)
