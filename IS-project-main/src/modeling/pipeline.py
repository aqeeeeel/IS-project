from __future__ import annotations

from dataclasses import dataclass

from puf.interface import PUFSimulator

from .crp import collect_crps
from .logistic import LogisticRegressionPUFModel, TrainingHistory
from .metrics import ThresholdResult, accuracy_score, hamming_distance, hamming_ratio, tune_threshold
from .split import DatasetSplit, split_crp_dataset


@dataclass(slots=True)
class EvaluationMetrics:
    accuracy: float
    hamming_distance: int
    hamming_ratio: float


@dataclass(slots=True)
class PipelineResult:
    model: LogisticRegressionPUFModel
    history: TrainingHistory
    split: DatasetSplit
    tuned_threshold: ThresholdResult
    validation_metrics: EvaluationMetrics
    test_metrics: EvaluationMetrics


def _evaluate(labels: list[int], predictions: list[int]) -> EvaluationMetrics:
    return EvaluationMetrics(
        accuracy=accuracy_score(labels, predictions),
        hamming_distance=hamming_distance(labels, predictions),
        hamming_ratio=hamming_ratio(labels, predictions),
    )


def train_puf_surrogate(
    simulator: PUFSimulator,
    *,
    num_samples: int = 2000,
    data_seed: int | None = None,
    split_seed: int | None = None,
    noisy: bool = False,
    repetitions: int = 1,
    learning_rate: float = 0.1,
    epochs: int = 300,
    l2_strength: float = 0.0,
) -> PipelineResult:
    dataset = collect_crps(
        simulator,
        num_samples=num_samples,
        seed=data_seed,
        noisy=noisy,
        repetitions=repetitions,
    )
    split = split_crp_dataset(dataset, seed=split_seed)

    model = LogisticRegressionPUFModel(
        challenge_size=simulator.challenge_size,
        learning_rate=learning_rate,
        epochs=epochs,
        l2_strength=l2_strength,
    )
    history = model.fit(
        split.train.challenges,
        split.train.responses,
        validation_challenges=split.validation.challenges,
        validation_labels=split.validation.responses,
    )

    validation_probabilities = model.predict_proba(split.validation.challenges)
    tuned_threshold = tune_threshold(split.validation.responses, validation_probabilities)

    validation_predictions = model.predict(
        split.validation.challenges,
        threshold=tuned_threshold.threshold,
    )
    test_predictions = model.predict(split.test.challenges, threshold=tuned_threshold.threshold)

    validation_metrics = _evaluate(split.validation.responses, validation_predictions)
    test_metrics = _evaluate(split.test.responses, test_predictions)

    return PipelineResult(
        model=model,
        history=history,
        split=split,
        tuned_threshold=tuned_threshold,
        validation_metrics=validation_metrics,
        test_metrics=test_metrics,
    )
