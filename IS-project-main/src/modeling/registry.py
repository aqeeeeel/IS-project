from __future__ import annotations

from dataclasses import dataclass, field

from common.types import MatrixMetadata


@dataclass(slots=True)
class ModelDescriptor:
    model_id: str
    version: str
    owner: str
    matrices: list[MatrixMetadata] = field(default_factory=list)


class ModelRegistry:
    def __init__(self) -> None:
        self._models: dict[str, ModelDescriptor] = {}

    def register(self, descriptor: ModelDescriptor) -> None:
        self._models[descriptor.model_id] = descriptor

    def get(self, model_id: str) -> ModelDescriptor | None:
        return self._models.get(model_id)

    def list_ids(self) -> list[str]:
        return sorted(self._models.keys())
