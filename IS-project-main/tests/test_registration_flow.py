from __future__ import annotations

from device.client import DeviceAgent
from device.storage import DeviceProvisioning
from puf.arbiter import ArbiterPUFSimulator
from protocol.registration import RegistrationRequest
from server.app import ProtectionServer
from server.database import DeviceRecord, DeviceRecordDatabase
from server.registration_service import DeviceRecoveryError, DuplicateDeviceEnrollmentError
import pytest


def test_successful_registration_and_recovery_with_local_persistence(tmp_path) -> None:
    simulator = ArbiterPUFSimulator(challenge_size=16, seed=7)
    server = ProtectionServer(model_id="model-a", challenge_bits=16)
    device = DeviceAgent(
        device_id="dev-100",
        model_id="model-a",
        identity_seed="seed-dev-100",
        provisioning_path=tmp_path / "device_provisioning.json",
    )

    result = server.register_device(
        RegistrationRequest(
            device_id=device.device_id,
            model_id="model-a",
            simulator=simulator,
            num_crps=700,
            epochs=140,
            learning_rate=0.2,
            data_seed=13,
            split_seed=21,
            matrix_seed=34,
        )
    )

    assert result.device_id == "dev-100"
    assert result.identity_tag.device_id == "dev-100"
    assert result.identity_tag.model_id == "model-a"
    assert len(result.matrix_set) == 4
    assert result.validation_accuracy >= 0.8

    device.apply_provisioning(
        DeviceProvisioning(
            identity_tag=result.identity_tag,
            matrix_set=result.matrix_set,
        )
    )
    loaded = device.load_local_provisioning()

    assert loaded.identity_tag.value == result.identity_tag.value
    assert loaded.matrix_set[0].checksum == result.matrix_set[0].checksum

    recovered = server.recover_device("dev-100")
    assert recovered.identity_tag.value == result.identity_tag.value
    assert recovered.matrix_set == result.matrix_set


def test_duplicate_device_protection() -> None:
    simulator = ArbiterPUFSimulator(challenge_size=12, seed=17)
    server = ProtectionServer(model_id="model-a", challenge_bits=12)
    request = RegistrationRequest(
        device_id="dev-dup",
        model_id="model-a",
        simulator=simulator,
        num_crps=500,
        epochs=120,
        learning_rate=0.2,
        data_seed=42,
        split_seed=56,
    )

    first = server.register_device(request)
    assert first.device_id == "dev-dup"
    assert server.is_duplicate_device("dev-dup")

    with pytest.raises(DuplicateDeviceEnrollmentError):
        server.register_device(request)


def test_recovery_fails_for_unknown_device() -> None:
    server = ProtectionServer(model_id="model-a", challenge_bits=8)

    with pytest.raises(DeviceRecoveryError):
        server.recover_device("missing-device")


def test_database_crud_operations() -> None:
    database = DeviceRecordDatabase()
    simulator = ArbiterPUFSimulator(challenge_size=8, seed=2)
    server = ProtectionServer(model_id="model-a", challenge_bits=8)
    result = server.register_device(
        RegistrationRequest(
            device_id="dev-db",
            model_id="model-a",
            simulator=simulator,
            num_crps=350,
            epochs=100,
            learning_rate=0.2,
            data_seed=1,
            split_seed=2,
        )
    )

    record = DeviceRecord(
        device_id=result.device_id,
        model_id=result.model_id,
        identity_tag=result.identity_tag,
        matrix_set=result.matrix_set,
        model_parameters={"weights": [1.0]},
        threshold=result.threshold,
        crp_count=result.crp_count,
    )

    database.create(record)
    loaded = database.get("dev-db")
    assert loaded.device_id == "dev-db"

    updated = database.update("dev-db", crp_count=999)
    assert updated.crp_count == 999

    listed = database.list_all()
    assert any(entry.device_id == "dev-db" for entry in listed)

    database.delete("dev-db")
    assert not database.exists("dev-db")
