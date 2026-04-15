from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings


@dataclass(slots=True)
class DecisionResult:
    action: str
    status: str
    reason: str


class DecisionService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def evaluate(self, *, is_attack: bool, probability: float) -> DecisionResult:
        if (not is_attack) or probability <= self.settings.review_threshold:
            return DecisionResult(
                action="allow",
                status="done",
                reason="Flow considered benign or confidence is below review threshold.",
            )

        if probability > self.settings.auto_block_threshold:
            return DecisionResult(
                action="auto_block",
                status="blocked",
                reason="Attack confidence exceeds auto block threshold.",
            )

        return DecisionResult(
            action="manual_review",
            status="pending_review",
            reason="Attack confidence is in review range and requires analyst approval.",
        )
