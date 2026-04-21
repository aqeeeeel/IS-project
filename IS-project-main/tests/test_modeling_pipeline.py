from __future__ import annotations

from modeling.logistic import LogisticRegressionPUFModel
from modeling.metrics import accuracy_score
from modeling.persistence import load_model, save_model
from modeling.pipeline import train_puf_surrogate
from puf.arbiter import ArbiterPUFSimulator


def test_training_convergence() -> None:
    simulator = ArbiterPUFSimulator(challenge_size=16, seed=5)
    result = train_puf_surrogate(
        simulator,
        num_samples=1200,
        data_seed=11,
        split_seed=17,
        epochs=220,
        learning_rate=0.18,
    )

    assert len(result.history.train_loss) == 220
    assert result.history.train_loss[-1] < result.history.train_loss[0]
    assert result.validation_metrics.accuracy >= 0.90


def test_model_persistence_round_trip(tmp_path) -> None:
    simulator = ArbiterPUFSimulator(challenge_size=12, seed=21)
    result = train_puf_surrogate(
        simulator,
        num_samples=800,
        data_seed=33,
        split_seed=44,
        epochs=200,
        learning_rate=0.2,
    )

    model_path = tmp_path / "surrogate_model.json"
    save_model(result.model, model_path)
    loaded = load_model(model_path)

    sample_challenges = result.split.test.challenges[:50]
    original_predictions = result.model.predict(sample_challenges, threshold=result.tuned_threshold.threshold)
    loaded_predictions = loaded.predict(sample_challenges, threshold=result.tuned_threshold.threshold)

    assert original_predictions == loaded_predictions


def test_prediction_accuracy_with_threshold_tuning() -> None:
    simulator = ArbiterPUFSimulator(challenge_size=20, seed=101)
    result = train_puf_surrogate(
        simulator,
        num_samples=1600,
        data_seed=202,
        split_seed=303,
        epochs=260,
        learning_rate=0.16,
    )

    threshold = result.tuned_threshold.threshold
    test_predictions = result.model.predict(result.split.test.challenges, threshold=threshold)
    test_accuracy = accuracy_score(result.split.test.responses, test_predictions)

    assert 0.1 <= threshold <= 0.9
    assert result.tuned_threshold.accuracy >= 0.90
    assert test_accuracy >= 0.88
    assert result.test_metrics.hamming_ratio <= 0.12


def test_loaded_model_keeps_probabilities(tmp_path) -> None:
    model = LogisticRegressionPUFModel(challenge_size=8, learning_rate=0.1, epochs=10)
    model.weights = [0.2 for _ in range(9)]

    target = tmp_path / "manual_model.json"
    save_model(model, target)
    loaded = load_model(target)

    challenges = [[0, 1, 0, 1, 1, 0, 1, 0], [1, 1, 1, 0, 0, 1, 0, 1]]
    assert loaded.predict_proba(challenges) == model.predict_proba(challenges)
