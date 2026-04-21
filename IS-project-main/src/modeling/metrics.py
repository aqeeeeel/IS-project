from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


def accuracy_score(y_true: Sequence[int], y_pred: Sequence[int]) -> float:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have equal length")
    if not y_true:
        raise ValueError("y_true must be non-empty")
    matches = sum(1 for actual, predicted in zip(y_true, y_pred) if actual == predicted)
    return matches / float(len(y_true))


def hamming_distance(left: Sequence[int] | str, right: Sequence[int] | str) -> int:
    if len(left) != len(right):
        raise ValueError("inputs must have equal length")
    return sum(1 for l_bit, r_bit in zip(left, right) if l_bit != r_bit)


def hamming_ratio(left: Sequence[int] | str, right: Sequence[int] | str) -> float:
    if len(left) == 0:
        raise ValueError("inputs must be non-empty")
    return hamming_distance(left, right) / float(len(left))


@dataclass(frozen=True, slots=True)
class ThresholdResult:
    threshold: float
    accuracy: float


def tune_threshold(
    y_true: Sequence[int],
    probabilities: Sequence[float],
    *,
    min_threshold: float = 0.1,
    max_threshold: float = 0.9,
    step: float = 0.01,
) -> ThresholdResult:
    if len(y_true) != len(probabilities):
        raise ValueError("y_true and probabilities must have equal length")
    if not y_true:
        raise ValueError("inputs must be non-empty")
    if step <= 0:
        raise ValueError("step must be positive")

    best_threshold = 0.5
    best_accuracy = -1.0

    threshold = min_threshold
    while threshold <= max_threshold + 1e-12:
        predictions = [1 if value >= threshold else 0 for value in probabilities]
        current_accuracy = accuracy_score(y_true, predictions)
        if current_accuracy > best_accuracy:
            best_accuracy = current_accuracy
            best_threshold = threshold
        threshold += step

    return ThresholdResult(threshold=best_threshold, accuracy=best_accuracy)
