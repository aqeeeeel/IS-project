from __future__ import annotations

from common.serialization import bytes_to_b64
from common.types import MatrixMetadata, ParameterPayload


def build_parameter_payload(
    *,
    model_id: str,
    layer_name: str,
    matrix: MatrixMetadata,
    encoded_bytes: bytes,
    encoding: str = "base64",
) -> ParameterPayload:
    return ParameterPayload(
        model_id=model_id,
        layer_name=layer_name,
        matrix=matrix,
        encoding=encoding,
        data_b64=bytes_to_b64(encoded_bytes),
    )
