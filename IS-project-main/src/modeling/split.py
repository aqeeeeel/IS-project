from __future__ import annotations

import random
from dataclasses import dataclass

from .crp import CRPDataset


@dataclass(slots=True)
class DatasetSplit:
    train: CRPDataset
    validation: CRPDataset
    test: CRPDataset


def split_crp_dataset(
    dataset: CRPDataset,
    *,
    train_ratio: float = 0.7,
    validation_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int | None = None,
) -> DatasetSplit:
    if dataset.size < 3:
        raise ValueError("dataset must contain at least 3 samples")

    total = train_ratio + validation_ratio + test_ratio
    if abs(total - 1.0) > 1e-9:
        raise ValueError("train_ratio + validation_ratio + test_ratio must equal 1")

    indices = list(range(dataset.size))
    random.Random(seed).shuffle(indices)

    train_end = int(dataset.size * train_ratio)
    validation_end = train_end + int(dataset.size * validation_ratio)

    # Ensure all partitions receive at least one sample.
    train_end = max(1, min(train_end, dataset.size - 2))
    validation_end = max(train_end + 1, min(validation_end, dataset.size - 1))

    train_idx = indices[:train_end]
    val_idx = indices[train_end:validation_end]
    test_idx = indices[validation_end:]

    def _slice(selected: list[int]) -> CRPDataset:
        return CRPDataset(
            challenges=[dataset.challenges[idx] for idx in selected],
            responses=[dataset.responses[idx] for idx in selected],
        )

    return DatasetSplit(train=_slice(train_idx), validation=_slice(val_idx), test=_slice(test_idx))
