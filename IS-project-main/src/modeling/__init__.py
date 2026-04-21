"""Model metadata and model-protection abstractions."""

from .crp import CRPDataset, collect_crps, generate_random_challenges, query_simulator
from .logistic import LogisticRegressionPUFModel, TrainingHistory
from .metrics import ThresholdResult, accuracy_score, hamming_distance, hamming_ratio, tune_threshold
from .persistence import load_model, save_model
from .pipeline import EvaluationMetrics, PipelineResult, train_puf_surrogate
from .registry import ModelDescriptor, ModelRegistry
from .split import DatasetSplit, split_crp_dataset

__all__ = [
	"CRPDataset",
	"DatasetSplit",
	"EvaluationMetrics",
	"LogisticRegressionPUFModel",
	"ModelDescriptor",
	"ModelRegistry",
	"PipelineResult",
	"ThresholdResult",
	"TrainingHistory",
	"accuracy_score",
	"collect_crps",
	"generate_random_challenges",
	"hamming_distance",
	"hamming_ratio",
	"load_model",
	"query_simulator",
	"save_model",
	"split_crp_dataset",
	"train_puf_surrogate",
	"tune_threshold",
]
