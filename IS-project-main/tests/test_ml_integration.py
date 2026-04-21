from __future__ import annotations

from ml.device_harness import DeviceInferenceHarness
from ml.demo_model import (
    create_demo_float_mlp,
    export_parameter_stream,
    load_quantized_model,
    quantize_mlp,
    reconstruct_model_from_stream,
    save_quantized_model,
)
from puf.engine import PUFEngine
from protocol.parameter_encoder import ChallengeSelectionStrategy
from protocol.transmission import recover_parameters, transmit_parameters


def test_quantized_model_save_load_and_reconstruction(tmp_path) -> None:
    quantized = quantize_mlp(create_demo_float_mlp())
    target = tmp_path / "demo_quantized_model.json"

    save_quantized_model(quantized, target)
    loaded = load_quantized_model(target)
    reconstructed = reconstruct_model_from_stream(export_parameter_stream(loaded))

    sample = [0.25, -0.5, 0.75, 0.1]
    assert loaded.forward(sample) == quantized.forward(sample)
    assert reconstructed.forward(sample) == quantized.forward(sample)
    assert reconstructed.predict_class(sample) == quantized.predict_class(sample)


def test_device_harness_prediction_matches_expected_output() -> None:
    quantized = quantize_mlp(create_demo_float_mlp())
    harness = DeviceInferenceHarness.from_decoded_parameter_stream(export_parameter_stream(quantized))

    sample = [0.6, -0.3, 0.2, 0.9]
    logits = harness.logits(sample)
    prediction = harness.predict(sample)

    assert prediction == 0
    assert len(logits) == 2
    assert logits[0] > logits[1]


def test_end_to_end_reconstructed_model_prediction_consistency() -> None:
    identity_seed = "ml-integration-seed"
    challenge_bits = 14

    server_sim = PUFEngine(model_id="model-a", challenge_bits=challenge_bits)._build_simulator(identity_seed)
    device_sim = PUFEngine(model_id="model-a", challenge_bits=challenge_bits)._build_simulator(identity_seed)

    quantized = quantize_mlp(create_demo_float_mlp())
    envelope = transmit_parameters(
        export_parameter_stream(quantized),
        server_simulator=server_sim,
        strategy=ChallengeSelectionStrategy.ENUMERATION,
        stability_repetitions=5,
        noisy=False,
    )
    decoded_stream = recover_parameters(
        envelope,
        device_simulator=device_sim,
        noisy=False,
    )

    recovered_harness = DeviceInferenceHarness.from_decoded_parameter_stream(decoded_stream)
    expected_harness = DeviceInferenceHarness.from_decoded_parameter_stream(export_parameter_stream(quantized))

    sample = [0.1, 0.8, -0.4, 0.2]
    assert recovered_harness.logits(sample) == expected_harness.logits(sample)
    assert recovered_harness.predict(sample) == expected_harness.predict(sample)
