from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import text
from sqlmodel import Session, SQLModel, create_engine

from app.core.config import get_settings

settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    _migrate_sqlite_schema()


def _migrate_sqlite_schema() -> None:
    if not settings.database_url.startswith("sqlite"):
        return

    with engine.begin() as conn:
        user_table = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        ).fetchone()
        if user_table is not None:
            user_columns = conn.execute(text("PRAGMA table_info('user')")).fetchall()
            user_column_names = {str(row[1]) for row in user_columns}

            if "webhook_url" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN webhook_url TEXT"))
            if "webhook_enabled" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN webhook_enabled BOOLEAN DEFAULT 0"))
            if "notify_email" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN notify_email TEXT"))
            if "notify_email_verified" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN notify_email_verified BOOLEAN DEFAULT 0"))
            if "notify_email_pending" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN notify_email_pending TEXT"))
            if "notify_email_code" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN notify_email_code TEXT"))
            if "notify_email_code_expires_at" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN notify_email_code_expires_at DATETIME"))
            if "chat_api_key" not in user_column_names:
                conn.execute(text("ALTER TABLE user ADD COLUMN chat_api_key TEXT"))

            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_webhook_enabled ON user (webhook_enabled)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_notify_email_verified ON user (notify_email_verified)"))
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_user_notify_email_code_expires_at "
                    "ON user (notify_email_code_expires_at)"
                )
            )

        table_row = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='iplistentry'")
        ).fetchone()
        if table_row is None:
            return

        columns = conn.execute(text("PRAGMA table_info('iplistentry')")).fetchall()
        column_names = {str(row[1]) for row in columns}

        if "expires_at" not in column_names:
            conn.execute(text("ALTER TABLE iplistentry ADD COLUMN expires_at DATETIME"))

        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_iplistentry_expires_at ON iplistentry (expires_at)"))


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
