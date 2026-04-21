from __future__ import annotations

from dataclasses import dataclass

from .demo_model import QuantizedMLP, reconstruct_model_from_stream


@dataclass(slots=True)
class DeviceInferenceHarness:
    model: QuantizedMLP

    @classmethod
    def from_decoded_parameter_stream(cls, stream: dict[str, object]) -> "DeviceInferenceHarness":
        return cls(model=reconstruct_model_from_stream(stream))

    def predict(self, features: list[float]) -> int:
        return self.model.predict_class(features)

    def logits(self, features: list[float]) -> list[float]:
        return self.model.forward(features)
