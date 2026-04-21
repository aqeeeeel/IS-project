from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


@dataclass(slots=True)
class TrainingHistory:
    train_loss: list[float]
    validation_loss: list[float]


class LogisticRegressionPUFModel:
    """Binary logistic regression in APUF parity feature space."""

    def __init__(
        self,
        challenge_size: int,
        *,
        learning_rate: float = 0.1,
        epochs: int = 300,
        l2_strength: float = 0.0,
    ) -> None:
        if challenge_size <= 0:
            raise ValueError("challenge_size must be positive")
        if learning_rate <= 0.0:
            raise ValueError("learning_rate must be positive")
        if epochs <= 0:
            raise ValueError("epochs must be positive")
        if l2_strength < 0.0:
            raise ValueError("l2_strength must be >= 0")

        self.challenge_size = challenge_size
        self.learning_rate = learning_rate
        self.epochs = epochs
        self.l2_strength = l2_strength
        self.weights = [0.0 for _ in range(challenge_size + 1)]

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            exponent = math.exp(-value)
            return 1.0 / (1.0 + exponent)
        exponent = math.exp(value)
        return exponent / (1.0 + exponent)

    def _transform_challenge(self, challenge: Sequence[int]) -> list[float]:
        if len(challenge) != self.challenge_size:
            raise ValueError(
                f"challenge length {len(challenge)} does not match expected size {self.challenge_size}"
            )

        signs = [1 if bit == 1 else -1 for bit in challenge]
        phi = [0.0 for _ in range(self.challenge_size + 1)]

        product = 1
        for idx in range(self.challenge_size - 1, -1, -1):
            product *= signs[idx]
            phi[idx] = float(product)

        phi[-1] = 1.0
        return phi

    def _predict_proba_transformed(self, features: Sequence[float]) -> float:
        score = sum(weight * value for weight, value in zip(self.weights, features))
        return self._sigmoid(score)

    def predict_proba(self, challenges: Sequence[Sequence[int]]) -> list[float]:
        return [self._predict_proba_transformed(self._transform_challenge(ch)) for ch in challenges]

    def predict(self, challenges: Sequence[Sequence[int]], *, threshold: float = 0.5) -> list[int]:
        probabilities = self.predict_proba(challenges)
        return [1 if value >= threshold else 0 for value in probabilities]

    def _average_loss(self, challenges: Sequence[Sequence[int]], labels: Sequence[int]) -> float:
        epsilon = 1e-12
        losses: list[float] = []
        for challenge, label in zip(challenges, labels):
            probability = self._predict_proba_transformed(self._transform_challenge(challenge))
            probability = min(max(probability, epsilon), 1.0 - epsilon)
            losses.append(-(label * math.log(probability) + (1 - label) * math.log(1.0 - probability)))

        mean_loss = sum(losses) / float(len(losses))
        l2_penalty = 0.5 * self.l2_strength * sum(weight * weight for weight in self.weights[:-1])
        return mean_loss + l2_penalty

    def fit(
        self,
        challenges: Sequence[Sequence[int]],
        labels: Sequence[int],
        *,
        validation_challenges: Sequence[Sequence[int]] | None = None,
        validation_labels: Sequence[int] | None = None,
    ) -> TrainingHistory:
        if len(challenges) != len(labels):
            raise ValueError("challenges and labels must have equal length")
        if not challenges:
            raise ValueError("training dataset must not be empty")
        if validation_challenges is not None and validation_labels is not None:
            if len(validation_challenges) != len(validation_labels):
                raise ValueError("validation_challenges and validation_labels must have equal length")

        transformed = [self._transform_challenge(challenge) for challenge in challenges]
        train_loss: list[float] = []
        validation_loss: list[float] = []

        sample_count = float(len(challenges))
        for _ in range(self.epochs):
            gradients = [0.0 for _ in self.weights]
            for features, label in zip(transformed, labels):
                prediction = self._predict_proba_transformed(features)
                error = prediction - float(label)
                for idx in range(len(self.weights)):
                    gradients[idx] += error * features[idx]

            for idx in range(len(self.weights)):
                gradients[idx] /= sample_count
                if idx < len(self.weights) - 1:
                    gradients[idx] += self.l2_strength * self.weights[idx]
                self.weights[idx] -= self.learning_rate * gradients[idx]

            train_loss.append(self._average_loss(challenges, labels))
            if validation_challenges is not None and validation_labels is not None:
                validation_loss.append(self._average_loss(validation_challenges, validation_labels))

        return TrainingHistory(train_loss=train_loss, validation_loss=validation_loss)

    def to_dict(self) -> dict[str, float | int | list[float]]:
        return {
            "challenge_size": self.challenge_size,
            "learning_rate": self.learning_rate,
            "epochs": self.epochs,
            "l2_strength": self.l2_strength,
            "weights": self.weights,
        }

    @classmethod
    def from_dict(cls, data: dict[str, float | int | list[float]]) -> "LogisticRegressionPUFModel":
        model = cls(
            challenge_size=int(data["challenge_size"]),
            learning_rate=float(data["learning_rate"]),
            epochs=int(data["epochs"]),
            l2_strength=float(data["l2_strength"]),
        )
        weights = data.get("weights")
        if not isinstance(weights, list):
            raise ValueError("weights must be a list")
        model.weights = [float(weight) for weight in weights]
        return model
