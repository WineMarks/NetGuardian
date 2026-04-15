from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ENV_PATH = REPO_ROOT / "backend" / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(BACKEND_ENV_PATH), ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=("settings_",),
    )

    app_name: str = "NetGuardian Backend"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"

    database_url: str = f"sqlite:///{(REPO_ROOT / 'backend' / 'netguardian.db').as_posix()}"

    review_threshold: float = 0.85
    auto_block_threshold: float = 0.90
    auto_block_to_graylist_enabled: bool = True
    auto_block_graylist_minutes: int = 30
    auto_graylist_consecutive_hits: int = 3
    urgent_notify_threshold: float = 0.95
    email_verification_code_ttl_minutes: int = 5
    webhook_timeout_seconds: float = 5.0
    collector_local_ips_csv: str = ""

    notify_smtp_host: str = "smtp.mail.hnust.edu.cn"
    notify_smtp_port: int = 465
    notify_smtp_use_ssl: bool = True
    notify_sender_email: str = "2305010321@mail.hnust.edu.cn"
    notify_sender_password: str | None = None

    deepseek_api_key: str | None = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    deepseek_timeout_seconds: float = 30.0
    deepseek_system_prompt: str = "你是 NetGuardian 网络安全助手。回答要专业、简洁、中文优先，必要时给出处置步骤。"

    min_feature_coverage: float = 0.3
    min_known_feature_count: int = 20
    enable_simulation_endpoint: bool = True

    model_artifact_path: str = str(
        REPO_ROOT / "ml" / "artifacts" / "tabnet_class_weight_full_3090_final_try_20260405.joblib"
    )

    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    auth_secret_key: str = "change-me-in-production"
    access_token_expire_seconds: int = 60 * 60 * 12
    admin_registration_code: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()
