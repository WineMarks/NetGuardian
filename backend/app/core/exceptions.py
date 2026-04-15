from __future__ import annotations


class AppError(Exception):
    def __init__(self, *, code: str, message: str, status_code: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class NotFoundError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(code="NOT_FOUND", message=message, status_code=404)


class InvalidStateError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(code="INVALID_STATE", message=message, status_code=409)


class InvalidInputError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(code="INVALID_INPUT", message=message, status_code=400)


class ModelArtifactError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(code="MODEL_ARTIFACT_ERROR", message=message, status_code=500)


class PredictionError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(code="PREDICTION_ERROR", message=message, status_code=500)
