from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FloatMLP:
    input_dim: int
    hidden_dim: int
    output_dim: int
    w1: list[float]
    b1: list[float]
    w2: list[float]
    b2: list[float]


@dataclass(frozen=True, slots=True)
class QuantizedTensor:
    shape: list[int]
    scale: float
    zero_point: int
    values: list[int]
    num_bits: int = 8


@dataclass(frozen=True, slots=True)
class QuantizedMLP:
    input_dim: int
    hidden_dim: int
    output_dim: int
    w1: QuantizedTensor
    b1: QuantizedTensor
    w2: QuantizedTensor
    b2: QuantizedTensor

    def _dequantize(self, tensor: QuantizedTensor) -> list[float]:
        return [(value - tensor.zero_point) * tensor.scale for value in tensor.values]

    def forward(self, features: list[float]) -> list[float]:
        if len(features) != self.input_dim:
            raise ValueError(f"Expected {self.input_dim} features, received {len(features)}")

        w1 = self._dequantize(self.w1)
        b1 = self._dequantize(self.b1)
        w2 = self._dequantize(self.w2)
        b2 = self._dequantize(self.b2)

        hidden: list[float] = []
        for row in range(self.hidden_dim):
            start = row * self.input_dim
            score = sum(weight * value for weight, value in zip(w1[start : start + self.input_dim], features))
            score += b1[row]
            hidden.append(max(0.0, score))

        outputs: list[float] = []
        for row in range(self.output_dim):
            start = row * self.hidden_dim
            score = sum(weight * value for weight, value in zip(w2[start : start + self.hidden_dim], hidden))
            score += b2[row]
            outputs.append(score)
        return outputs

    def predict_class(self, features: list[float]) -> int:
        outputs = self.forward(features)
        return max(range(len(outputs)), key=lambda idx: outputs[idx])

    def to_dict(self) -> dict[str, object]:
        return {
            "format": "quantized_mlp_v1",
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "output_dim": self.output_dim,
            "w1": tensor_to_dict(self.w1),
            "b1": tensor_to_dict(self.b1),
            "w2": tensor_to_dict(self.w2),
            "b2": tensor_to_dict(self.b2),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "QuantizedMLP":
        if payload.get("format") != "quantized_mlp_v1":
            raise ValueError("Unsupported quantized model format")
        return cls(
            input_dim=int(payload["input_dim"]),
            hidden_dim=int(payload["hidden_dim"]),
            output_dim=int(payload["output_dim"]),
            w1=tensor_from_dict(payload["w1"]),
            b1=tensor_from_dict(payload["b1"]),
            w2=tensor_from_dict(payload["w2"]),
            b2=tensor_from_dict(payload["b2"]),
        )


def tensor_to_dict(tensor: QuantizedTensor) -> dict[str, object]:
    return {
        "shape": tensor.shape,
        "scale": tensor.scale,
        "zero_point": tensor.zero_point,
        "values": tensor.values,
        "num_bits": tensor.num_bits,
    }


def tensor_from_dict(payload: object) -> QuantizedTensor:
    if not isinstance(payload, dict):
        raise TypeError("Tensor payload must be a dictionary")
    return QuantizedTensor(
        shape=[int(item) for item in payload["shape"]],
        scale=float(payload["scale"]),
        zero_point=int(payload["zero_point"]),
        values=[int(item) for item in payload["values"]],
        num_bits=int(payload.get("num_bits", 8)),
    )


def create_demo_float_mlp() -> FloatMLP:
    return FloatMLP(
        input_dim=4,
        hidden_dim=4,
        output_dim=2,
        w1=[
            0.7, -0.2, 0.3, 0.1,
            -0.4, 0.8, -0.1, 0.5,
            0.2, 0.2, 0.9, -0.6,
            -0.3, 0.4, 0.1, 0.7,
        ],
        b1=[0.05, -0.1, 0.2, 0.0],
        w2=[
            0.9, -0.4, 0.3, 0.2,
            -0.6, 0.5, -0.2, 0.7,
        ],
        b2=[0.1, -0.05],
    )


def quantize_values(values: list[float], *, num_bits: int = 8) -> QuantizedTensor:
    if not values:
        raise ValueError("values must not be empty")
    if num_bits <= 1:
        raise ValueError("num_bits must be > 1")

    qmax = (2 ** (num_bits - 1)) - 1
    qmin = -qmax - 1
    max_abs = max(abs(value) for value in values)
    scale = 1.0 if max_abs == 0.0 else max_abs / float(qmax)
    quantized = [min(qmax, max(qmin, int(round(value / scale)))) for value in values]
    return QuantizedTensor(shape=[len(values)], scale=scale, zero_point=0, values=quantized, num_bits=num_bits)


def _reshape_tensor(base: QuantizedTensor, shape: list[int]) -> QuantizedTensor:
    return QuantizedTensor(
        shape=shape,
        scale=base.scale,
        zero_point=base.zero_point,
        values=base.values,
        num_bits=base.num_bits,
    )


def quantize_mlp(model: FloatMLP, *, num_bits: int = 8) -> QuantizedMLP:
    w1 = _reshape_tensor(quantize_values(model.w1, num_bits=num_bits), [model.hidden_dim, model.input_dim])
    b1 = _reshape_tensor(quantize_values(model.b1, num_bits=num_bits), [model.hidden_dim])
    w2 = _reshape_tensor(quantize_values(model.w2, num_bits=num_bits), [model.output_dim, model.hidden_dim])
    b2 = _reshape_tensor(quantize_values(model.b2, num_bits=num_bits), [model.output_dim])
    return QuantizedMLP(
        input_dim=model.input_dim,
        hidden_dim=model.hidden_dim,
        output_dim=model.output_dim,
        w1=w1,
        b1=b1,
        w2=w2,
        b2=b2,
    )


def save_quantized_model(model: QuantizedMLP, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(model.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_quantized_model(path: str | Path) -> QuantizedMLP:
    source = Path(path)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise TypeError("Model file must contain a JSON object")
    return QuantizedMLP.from_dict(payload)


def export_parameter_stream(model: QuantizedMLP) -> dict[str, object]:
    return model.to_dict()


def reconstruct_model_from_stream(stream: dict[str, object]) -> QuantizedMLP:
    return QuantizedMLP.from_dict(stream)
