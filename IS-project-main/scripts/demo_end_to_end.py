from __future__ import annotations

from device.client import DeviceAgent
from device.storage import DeviceProvisioning
from ml.device_harness import DeviceInferenceHarness
from ml.demo_model import create_demo_float_mlp, export_parameter_stream, quantize_mlp
from puf.engine import PUFEngine
from protocol.parameter_encoder import ChallengeSelectionStrategy
from protocol.registration import RegistrationRequest
from protocol.transmission import recover_parameters, transmit_parameters
from server.app import ProtectionServer


def run_demo() -> dict[str, object]:
    model_id = "demo-model"
    device_id = "device-demo-1"
    identity_seed = "demo-identity-seed"
    challenge_bits = 14

    server = ProtectionServer(model_id=model_id, challenge_bits=challenge_bits)
    device = DeviceAgent(device_id=device_id, model_id=model_id, identity_seed=identity_seed)

    # Registration
    enrollment_simulator = PUFEngine(model_id=model_id, challenge_bits=challenge_bits)._build_simulator(
        identity_seed
    )
    registration = server.register_device(
        RegistrationRequest(
            device_id=device_id,
            model_id=model_id,
            simulator=enrollment_simulator,
            num_crps=900,
            epochs=180,
            learning_rate=0.18,
            data_seed=11,
            split_seed=19,
            matrix_seed=23,
        )
    )
    device.apply_provisioning(
        DeviceProvisioning(
            identity_tag=registration.identity_tag,
            matrix_set=registration.matrix_set,
        ),
        persist=False,
    )

    # Mutual authentication
    challenge = server.issue_authentication_challenge(
        device_id=device_id,
        timeout_seconds=30,
        response_bit_length=128,
    )
    reply = device.create_authentication_reply(challenge)
    auth_result = server.verify_authentication_reply(reply)
    if not auth_result.success:
        raise RuntimeError(f"Authentication failed: {auth_result.reason}")

    # Build and quantize demo model
    float_model = create_demo_float_mlp()
    quantized_model = quantize_mlp(float_model)
    parameter_stream = export_parameter_stream(quantized_model)

    # Parameter transmission and recovery
    server_transmission_sim = PUFEngine(model_id=model_id, challenge_bits=challenge_bits)._build_simulator(
        identity_seed
    )
    envelope = transmit_parameters(
        parameter_stream,
        server_simulator=server_transmission_sim,
        strategy=ChallengeSelectionStrategy.TRAVERSAL,
        stability_repetitions=5,
        noisy=False,
        selection_seed=101,
    )

    device_transmission_sim = PUFEngine(model_id=model_id, challenge_bits=challenge_bits)._build_simulator(
        identity_seed
    )
    decoded_stream = recover_parameters(
        envelope,
        device_simulator=device_transmission_sim,
        noisy=False,
    )

    # Device-side reconstruction + inference
    harness = DeviceInferenceHarness.from_decoded_parameter_stream(decoded_stream)
    sample = [0.6, -0.3, 0.2, 0.9]
    logits = harness.logits(sample)
    prediction = harness.predict(sample)

    return {
        "registration_device": registration.device_id,
        "auth_session": auth_result.session_id,
        "prediction": prediction,
        "logits": logits,
        "sample": sample,
    }


def main() -> None:
    result = run_demo()
    print("End-to-end demo completed successfully")
    print(f"Device: {result['registration_device']}")
    print(f"Session: {result['auth_session']}")
    print(f"Sample: {result['sample']}")
    print(f"Logits: {result['logits']}")
    print(f"Predicted class: {result['prediction']}")


if __name__ == "__main__":
    main()
