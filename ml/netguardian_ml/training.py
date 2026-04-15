from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from .config import DEFAULT_ARTIFACT_PATH, DEFAULT_REPORT_PATH
from .data import load_training_frame, split_features_labels
from .modeling import build_model_adapter


@dataclass(slots=True)
class ModelArtifact:
    model_type: str
    model_payload: dict[str, Any]
    feature_columns: list[str]
    class_names: list[str]
    metrics: dict[str, Any]
    label_counts: dict[str, int]


@dataclass(slots=True)
class TrainingResult:
    artifact_path: Path
    report_path: Path
    metrics: dict[str, Any]
    rows: int
    feature_count: int
    class_count: int


def can_stratify(labels: pd.Series) -> bool:
    counts = labels.value_counts()
    return len(counts) > 1 and int(counts.min()) >= 2


def save_artifact(artifact: ModelArtifact, artifact_path: Path = DEFAULT_ARTIFACT_PATH) -> Path:
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path)
    return artifact_path


def load_artifact(artifact_path: Path = DEFAULT_ARTIFACT_PATH) -> ModelArtifact:
    return joblib.load(artifact_path)


def train_model(
    data_dir: Path,
    *,
    model_type: str = "sklearn",
    imbalance_strategy: str = "none",
    model_config: dict[str, Any] | None = None,
    sample_per_file: int = 30_000,
    test_size: float = 0.2,
    random_state: int = 42,
    artifact_path: Path = DEFAULT_ARTIFACT_PATH,
    report_path: Path = DEFAULT_REPORT_PATH,
) -> TrainingResult:
    frame = load_training_frame(data_dir, sample_per_file=sample_per_file, random_state=random_state)
    features, labels = split_features_labels(frame)

    class_names = sorted(labels.unique().tolist())
    class_to_index = {label: index for index, label in enumerate(class_names)}
    encoded_labels = labels.map(class_to_index).to_numpy(dtype=np.int64)

    stratify = encoded_labels if can_stratify(labels) else None
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        encoded_labels,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )

    model = build_model_adapter(
        model_type,
        random_state=random_state,
        imbalance_strategy=imbalance_strategy,
        model_config=model_config,
    )
    model.fit(x_train, y_train)

    y_prob = model.predict_proba(x_test)
    y_pred = np.argmax(y_prob, axis=1)
    y_score = np.max(y_prob, axis=1)

    report = classification_report(
        y_test,
        y_pred,
        labels=list(range(len(class_names))),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    metrics: dict[str, Any] = {
        "model_type": model_type,
        "imbalance_strategy": imbalance_strategy,
        "model_config": model_config or {},
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision_macro": float(precision_score(y_test, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_test, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_test, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_test, y_pred, average="weighted", zero_division=0)),
        "mean_confidence": float(np.mean(y_score)),
        "classification_report": report,
    }

    label_counts = labels.value_counts().sort_values(ascending=False).to_dict()
    artifact = ModelArtifact(
        model_type=model_type,
        model_payload=model.to_payload(),
        feature_columns=list(features.columns),
        class_names=class_names,
        metrics=metrics,
        label_counts={str(key): int(value) for key, value in label_counts.items()},
    )

    save_artifact(artifact, artifact_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    return TrainingResult(
        artifact_path=artifact_path,
        report_path=report_path,
        metrics=metrics,
        rows=int(len(frame)),
        feature_count=int(features.shape[1]),
        class_count=int(len(class_names)),
    )
