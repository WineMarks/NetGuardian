from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np
import pandas as pd

LABEL_COLUMN = "Label"
CHUNK_SIZE = 50_000

LABEL_REPLACEMENTS = {
    "Web Attack � Brute Force": "Web Attack Brute Force",
    "Web Attack � XSS": "Web Attack XSS",
    "Web Attack � Sql Injection": "Web Attack Sql Injection",
}


def discover_csv_paths(data_dir: Path) -> list[Path]:
    return sorted(path for path in data_dir.glob("*.csv") if path.is_file())


def make_unique_columns(columns: Iterable[object]) -> list[str]:
    counts: dict[str, int] = {}
    unique_columns: list[str] = []
    for raw_column in columns:
        column = str(raw_column).strip()
        count = counts.get(column, 0) + 1
        counts[column] = count
        unique_columns.append(column if count == 1 else f"{column}_{count}")
    return unique_columns


def normalize_label(value: object) -> str:
    label = str(value).strip()
    label = LABEL_REPLACEMENTS.get(label, label)
    label = label.replace("�", "")
    label = " ".join(label.split())
    return label


def standardize_frame(frame: pd.DataFrame) -> pd.DataFrame:
    cleaned = frame.copy()
    cleaned.columns = make_unique_columns(cleaned.columns)
    cleaned = cleaned.rename(columns={column: column.strip() for column in cleaned.columns})
    return cleaned


def coerce_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    numeric = frame.apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    return numeric


def load_csv_sample(
    csv_path: Path,
    sample_per_file: int,
    *,
    random_state: int = 42,
    chunksize: int = CHUNK_SIZE,
) -> pd.DataFrame:
    sampled_chunks: list[pd.DataFrame] = []
    seed = random_state

    for chunk in pd.read_csv(
        csv_path,
        chunksize=chunksize,
        low_memory=False,
        encoding_errors="replace",
    ):
        chunk = standardize_frame(chunk)
        if LABEL_COLUMN not in chunk.columns:
            continue

        labels = chunk[LABEL_COLUMN].map(normalize_label)
        features = chunk.drop(columns=[LABEL_COLUMN])
        features = coerce_feature_frame(features)
        sampled = features.copy()
        sampled[LABEL_COLUMN] = labels

        if sample_per_file and len(sampled) > sample_per_file:
            sampled = sampled.sample(n=sample_per_file, random_state=seed)
            seed += 1

        sampled_chunks.append(sampled)

    if not sampled_chunks:
        return pd.DataFrame()

    frame = pd.concat(sampled_chunks, ignore_index=True)
    if sample_per_file and len(frame) > sample_per_file:
        frame = frame.sample(n=sample_per_file, random_state=random_state)

    frame = frame.dropna(subset=[LABEL_COLUMN]).reset_index(drop=True)
    return frame


def load_training_frame(
    data_dir: Path,
    *,
    sample_per_file: int = 30_000,
    random_state: int = 42,
) -> pd.DataFrame:
    csv_paths = discover_csv_paths(data_dir)
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    frames = [
        load_csv_sample(path, sample_per_file, random_state=random_state + index)
        for index, path in enumerate(csv_paths)
    ]
    frames = [frame for frame in frames if not frame.empty]
    if not frames:
        raise ValueError(f"No usable rows found in {data_dir}")

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.dropna(subset=[LABEL_COLUMN]).reset_index(drop=True)
    return merged


def split_features_labels(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    if LABEL_COLUMN not in frame.columns:
        raise ValueError(f"Missing required label column: {LABEL_COLUMN}")

    features = frame.drop(columns=[LABEL_COLUMN])
    labels = frame[LABEL_COLUMN].astype(str)
    return features, labels
