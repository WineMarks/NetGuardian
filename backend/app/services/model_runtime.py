from __future__ import annotations

import sys
from pathlib import Path
from threading import Lock
from typing import Any

from app.core.config import get_settings
from app.core.exceptions import ModelArtifactError, PredictionError


class ModelRuntime:
    def __init__(self) -> None:
        self._predictor = None
        self._lock = Lock()

    def _load_predictor(self):
        settings = get_settings()
        repo_root = Path(__file__).resolve().parents[3]
        ml_root = repo_root / "ml"

        if str(ml_root) not in sys.path:
            sys.path.insert(0, str(ml_root))

        from netguardian_ml.predictor import FlowPredictor  # pylint: disable=import-outside-toplevel

        artifact_path = Path(settings.model_artifact_path)
        if not artifact_path.exists():
            raise ModelArtifactError(f"Model artifact not found: {artifact_path}")

        return FlowPredictor.from_path(artifact_path)

    def get_predictor(self):
        if self._predictor is None:
            with self._lock:
                if self._predictor is None:
                    self._predictor = self._load_predictor()
        return self._predictor

    def evaluate_feature_coverage(self, features: dict[str, Any]) -> dict[str, float | int]:
        predictor = self.get_predictor()
        required = predictor.artifact.feature_columns
        required_set = set(required)
        known = [key for key in features.keys() if key in required_set]
        total_required = len(required)
        known_count = len(known)
        coverage = (known_count / total_required) if total_required else 0.0
        return {
            "required_feature_count": total_required,
            "known_feature_count": known_count,
            "coverage": coverage,
        }

    def get_required_features(self) -> list[str]:
        predictor = self.get_predictor()
        return list(predictor.artifact.feature_columns)

    def predict(self, features: dict[str, Any]) -> dict[str, Any]:
        if not features:
            raise PredictionError("flow_features is empty")

        predictor = self.get_predictor()
        try:
            return predictor.predict_dict(features)
        except Exception as exc:  # noqa: BLE001
            raise PredictionError(f"Model prediction failed: {exc}") from exc


model_runtime = ModelRuntime()
