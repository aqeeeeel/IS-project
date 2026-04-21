from __future__ import annotations

import json
from pathlib import Path

from .logistic import LogisticRegressionPUFModel


def save_model(model: LogisticRegressionPUFModel, path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(model.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def load_model(path: str | Path) -> LogisticRegressionPUFModel:
    source = Path(path)
    data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError("model file content must be a JSON object")
    return LogisticRegressionPUFModel.from_dict(data)
