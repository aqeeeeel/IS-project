from __future__ import annotations

from common.config import load_config
from common.serialization import from_json, to_json
from common.types import (
    MatrixMetadata,
    Nonce,
    ParameterPayload,
    ProtocolMessage,
    ProtocolMessageType,
)


def test_nonce_expiration_logic() -> None:
    nonce = Nonce(value="abc", created_at=1_000.0, ttl_seconds=30)
    assert nonce.is_expired(now=1_031.0)
    assert not nonce.is_expired(now=1_020.0)


def test_protocol_message_round_trip() -> None:
    payload = ParameterPayload(
        model_id="model-a",
        layer_name="dense_1",
        matrix=MatrixMetadata(rows=2, cols=2, dtype="float32"),
        encoding="base64",
        data_b64="AAEC",
    )
    msg = ProtocolMessage(
        message_type=ProtocolMessageType.PARAMETER_TRANSFER,
        sender="server",
        receiver="device",
        nonce=Nonce(value="n-1"),
        payload={"parameter": payload},
    )

    encoded = to_json(msg)
    decoded = from_json(encoded, ProtocolMessage)

    assert decoded.message_type == ProtocolMessageType.PARAMETER_TRANSFER
    assert decoded.payload["parameter"]["layer_name"] == "dense_1"


def test_config_load_with_env_override(monkeypatch) -> None:
    monkeypatch.setenv("PUF_PROTECT_SERVER__PORT", "9090")
    cfg = load_config()
    assert cfg.server.port == 9090
