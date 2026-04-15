from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from netguardian_ml.config import DEFAULT_ARTIFACT_PATH, DEFAULT_REPORT_PATH
from netguardian_ml.training import train_model


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the NetGuardian multi-class flow model")
    parser.add_argument("--data-dir", type=Path, default=Path("MachineLearningCVE"))
    parser.add_argument("--model-type", type=str, default="sklearn", choices=["sklearn", "pytorch", "tabnet"])
    parser.add_argument("--imbalance-strategy", type=str, default="none", choices=["none", "class_weight", "focal"])
    parser.add_argument("--max-epochs", type=int, default=20)
    parser.add_argument("--patience", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=8192)
    parser.add_argument("--virtual-batch-size", type=int, default=1024)
    parser.add_argument("--num-workers", type=int, default=8)
    parser.add_argument("--validation-size", type=float, default=0.1)
    parser.add_argument("--learning-rate", type=float, default=2e-2)
    parser.add_argument("--n-d", type=int, default=8)
    parser.add_argument("--n-a", type=int, default=8)
    parser.add_argument("--n-steps", type=int, default=3)
    parser.add_argument("--gamma", type=float, default=1.3)
    parser.add_argument("--class-weight-power", type=float, default=1.0)
    parser.add_argument("--class-weight-max", type=float, default=None)
    parser.add_argument("--no-progress", action="store_true")
    parser.add_argument("--artifact-path", type=Path, default=DEFAULT_ARTIFACT_PATH)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--sample-per-file", type=int, default=30_000)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_config = {
        "max_epochs": args.max_epochs,
        "patience": args.patience,
        "batch_size": args.batch_size,
        "virtual_batch_size": args.virtual_batch_size,
        "num_workers": args.num_workers,
        "validation_size": args.validation_size,
        "learning_rate": args.learning_rate,
        "n_d": args.n_d,
        "n_a": args.n_a,
        "n_steps": args.n_steps,
        "gamma": args.gamma,
        "class_weight_power": args.class_weight_power,
        "class_weight_max": args.class_weight_max,
        "show_progress": not args.no_progress,
    }

    result = train_model(
        args.data_dir,
        model_type=args.model_type,
        imbalance_strategy=args.imbalance_strategy,
        model_config=model_config,
        sample_per_file=args.sample_per_file,
        test_size=args.test_size,
        random_state=args.random_state,
        artifact_path=args.artifact_path,
        report_path=args.report_path,
    )

    summary = {
        "artifact_path": str(result.artifact_path),
        "report_path": str(result.report_path),
        "rows": result.rows,
        "feature_count": result.feature_count,
        "class_count": result.class_count,
        "metrics": result.metrics,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
