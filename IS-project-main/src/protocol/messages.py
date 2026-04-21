from __future__ import annotations

from typing import Any

from common.types import Nonce, ProtocolMessage, ProtocolMessageType


def build_message(
    *,
    message_type: ProtocolMessageType,
    sender: str,
    receiver: str,
    nonce: str,
    payload: dict[str, Any],
    ttl_seconds: int = 60,
    correlation_id: str | None = None,
) -> ProtocolMessage:
    return ProtocolMessage(
        message_type=message_type,
        sender=sender,
        receiver=receiver,
        nonce=Nonce(value=nonce, ttl_seconds=ttl_seconds),
        payload=payload,
        correlation_id=correlation_id,
    )
