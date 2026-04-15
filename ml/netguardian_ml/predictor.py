from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd

from .config import DEFAULT_ARTIFACT_PATH
from .modeling import BaseModelAdapter, load_model_adapter
from .training import ModelArtifact, load_artifact


@dataclass(slots=True)
class PredictionResult:
    label: str
    probability: float
    probabilities: dict[str, float]
    is_attack: bool


class FlowPredictor:
    def __init__(self, artifact: ModelArtifact) -> None:
        self.artifact = artifact
        self.model: BaseModelAdapter = load_model_adapter(artifact.model_type, artifact.model_payload)

    @classmethod
    def from_path(cls, artifact_path: Path = DEFAULT_ARTIFACT_PATH) -> "FlowPredictor":
        return cls(load_artifact(artifact_path))

    def _normalize_input(self, flow: Mapping[str, Any] | pd.Series | pd.DataFrame) -> pd.DataFrame:
        if isinstance(flow, pd.DataFrame):
            frame = flow.copy()
        elif isinstance(flow, pd.Series):
            frame = flow.to_frame().T
        else:
            frame = pd.DataFrame([dict(flow)])

        for column in self.artifact.feature_columns:
            if column not in frame.columns:
                frame[column] = np.nan

        frame = frame[self.artifact.feature_columns]
        frame = frame.apply(pd.to_numeric, errors="coerce")
        frame = frame.replace([np.inf, -np.inf], np.nan)
        return frame

    def predict(self, flow: Mapping[str, Any] | pd.Series | pd.DataFrame) -> PredictionResult:
        frame = self._normalize_input(flow)
        probabilities = self.model.predict_proba(frame)[0]
        class_index = int(np.argmax(probabilities))
        label = self.artifact.class_names[class_index]

        probability_map = {
            class_name: float(score)
            for class_name, score in zip(self.artifact.class_names, probabilities)
        }

        return PredictionResult(
            label=str(label),
            probability=float(probabilities[class_index]),
            probabilities=probability_map,
            is_attack=str(label).upper() != "BENIGN",
        )

    def predict_dict(self, flow: Mapping[str, Any] | pd.Series | pd.DataFrame) -> dict[str, Any]:
        result = self.predict(flow)
        return {
            "label": result.label,
            "probability": result.probability,
            "probabilities": result.probabilities,
            "is_attack": result.is_attack,
        }
