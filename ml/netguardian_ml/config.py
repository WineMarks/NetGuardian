from pathlib import Path

ML_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ML_ROOT.parent
DATA_DIR = REPO_ROOT / "MachineLearningCVE"
ARTIFACT_DIR = ML_ROOT / "artifacts"
DEFAULT_ARTIFACT_PATH = ARTIFACT_DIR / "netguardian_flow_model.joblib"
DEFAULT_REPORT_PATH = ARTIFACT_DIR / "netguardian_flow_metrics.json"
