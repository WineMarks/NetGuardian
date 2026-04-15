from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from netguardian_ml.config import DEFAULT_ARTIFACT_PATH
from netguardian_ml.predictor import FlowPredictor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a single NetGuardian flow prediction")
    parser.add_argument("payload", type=Path, help="Path to a JSON file containing a single flow sample")
    parser.add_argument("--artifact-path", type=Path, default=DEFAULT_ARTIFACT_PATH)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = json.loads(args.payload.read_text(encoding="utf-8"))
    predictor = FlowPredictor.from_path(args.artifact_path)
    result = predictor.predict_dict(payload)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
