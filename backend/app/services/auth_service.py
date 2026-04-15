from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings
from app.core.exceptions import InvalidInputError, NotFoundError
from app.models.user import User
from app.models.user_repository import UserRepository
from app.services.security import create_access_token, hash_password, verify_password


@dataclass(slots=True)
class AuthResult:
    access_token: str
    token_type: str
    user_id: int
    username: str
    role: str


class AuthService:
    def __init__(self, repository: UserRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings

    def register(self, *, username: str, password: str, role: str, admin_code: str | None) -> User:
        normalized_username = username.strip()
        if len(normalized_username) < 3:
            raise InvalidInputError("username must be at least 3 characters")
        if len(password) < 6:
            raise InvalidInputError("password must be at least 6 characters")

        normalized_role = role.strip().lower()
        if normalized_role not in {"user", "admin"}:
            raise InvalidInputError("role must be either user or admin")

        if normalized_role == "admin":
            if not self.settings.admin_registration_code:
                raise InvalidInputError("admin registration is disabled")
            if admin_code != self.settings.admin_registration_code:
                raise InvalidInputError("invalid admin registration code")

        if self.repository.get_by_username(normalized_username):
            raise InvalidInputError("username already exists")

        user = User(
            username=normalized_username,
            password_hash=hash_password(password),
            role=normalized_role,
            is_active=True,
        )
        return self.repository.create(user)

    def login(self, *, username: str, password: str) -> AuthResult:
        user = self.repository.get_by_username(username.strip())
        if user is None:
            raise NotFoundError("user not found")
        if not user.is_active:
            raise InvalidInputError("user is inactive")
        if not verify_password(password, user.password_hash):
            raise InvalidInputError("invalid password")

        token = create_access_token(
            user_id=int(user.id),
            username=user.username,
            role=user.role,
            settings=self.settings,
        )

        return AuthResult(
            access_token=token,
            token_type="bearer",
            user_id=int(user.id),
            username=user.username,
            role=user.role,
        )

    def get_user(self, user_id: int) -> User:
        user = self.repository.get_by_id(user_id)
        if user is None:
            raise NotFoundError("user not found")
        return user
