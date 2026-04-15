from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.core.config import Settings
from app.core.exceptions import InvalidInputError, InvalidStateError, NotFoundError
from app.models.repository import TrafficLogRepository
from app.models.traffic_log import TrafficLog
from app.services.decision_service import DecisionResult, DecisionService
from app.services.geo_service import geo_service
from app.services.ip_list_service import IpListService
from app.services.model_runtime import model_runtime
from app.services.notification_service import NotificationService


@dataclass(slots=True)
class AnalyzeInput:
    flow_features: dict[str, Any]
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None


class TrafficService:
    def __init__(
        self,
        repository: TrafficLogRepository,
        settings: Settings,
        ip_list_service: IpListService,
        notification_service: NotificationService | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.decision_service = DecisionService(settings)
        self.ip_list_service = ip_list_service
        self.notification_service = notification_service
        self._suppressed_actions = {"blacklist_drop", "graylist_drop"}

    def _count_recent_high_conf_streak(self, *, source_ip: str, threshold: float, lookback: int) -> int:
        if lookback <= 0:
            return 0
        recent = self.repository.list_recent_by_source(
            source_ip=source_ip,
            limit=max(lookback, 1),
            exclude_actions=self._suppressed_actions,
        )
        streak = 0
        for row in recent:
            if row.is_attack and float(row.probability) > threshold:
                streak += 1
            else:
                break
            if streak >= lookback:
                break
        return streak

    def analyze(self, payload: AnalyzeInput) -> TrafficLog:
        quality = model_runtime.evaluate_feature_coverage(payload.flow_features)
        if quality["known_feature_count"] < self.settings.min_known_feature_count:
            raise InvalidInputError(
                "Insufficient known features for reliable prediction: "
                f"{quality['known_feature_count']}/{quality['required_feature_count']} provided."
            )

        if float(quality["coverage"]) < self.settings.min_feature_coverage:
            raise InvalidInputError(
                "Feature coverage below threshold for reliable prediction: "
                f"{quality['coverage']:.3f} < {self.settings.min_feature_coverage:.3f}."
            )

        prediction = model_runtime.predict(payload.flow_features)
        decision = self.decision_service.evaluate(
            is_attack=bool(prediction["is_attack"]),
            probability=float(prediction["probability"]),
        )

        source_ip, source_port, destination_ip, destination_port = self._normalize_flow_direction(
            source_ip=payload.source_ip,
            source_port=payload.source_port,
            destination_ip=payload.destination_ip,
            destination_port=payload.destination_port,
            is_attack=bool(prediction["is_attack"]),
        )

        ip_hit = self.ip_list_service.check_hit(source_ip)
        if ip_hit.hit:
            if ip_hit.list_type == "blacklist":
                return self.repository.create(
                    TrafficLog(
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        predicted_label=str(prediction["label"]),
                        probability=float(prediction["probability"]),
                        is_attack=bool(prediction["is_attack"]),
                        action="blacklist_drop",
                        status="done",
                        reason=(
                            f"Source IP {source_ip} is in blacklist, blocked directly "
                            f"(黑名单屏蔽)."
                        ),
                        probabilities=dict(prediction["probabilities"]),
                        raw_features={
                            **payload.flow_features,
                            "ip_list_hit": "blacklist",
                            "source_ip": source_ip,
                        },
                    )
                )

            if ip_hit.list_type == "graylist":
                until = ip_hit.expires_at.isoformat() if ip_hit.expires_at else "unknown"
                return self.repository.create(
                    TrafficLog(
                        source_ip=source_ip,
                        source_port=source_port,
                        destination_ip=destination_ip,
                        destination_port=destination_port,
                        predicted_label=str(prediction["label"]),
                        probability=float(prediction["probability"]),
                        is_attack=bool(prediction["is_attack"]),
                        action="graylist_drop",
                        status="done",
                        reason=(
                            f"Source IP {source_ip} is graylisted until {until}, blocked directly "
                            f"(灰名单屏蔽)."
                        ),
                        probabilities=dict(prediction["probabilities"]),
                        raw_features={
                            **payload.flow_features,
                            "ip_list_hit": "graylist",
                            "source_ip": source_ip,
                            "expires_at": until,
                        },
                    )
                )

        auto_graylist_applied = False
        high_conf_attack = bool(prediction["is_attack"]) and float(prediction["probability"]) > self.settings.auto_block_threshold
        required_hits = max(1, int(self.settings.auto_graylist_consecutive_hits))
        consecutive_hits = 0
        if source_ip and high_conf_attack:
            consecutive_hits = 1 + self._count_recent_high_conf_streak(
                source_ip=source_ip,
                threshold=self.settings.auto_block_threshold,
                lookback=required_hits - 1,
            )

        if decision.action == "auto_block" and source_ip and high_conf_attack and consecutive_hits < required_hits:
            decision = DecisionResult(
                action="allow",
                status="done",
                reason=(
                    "High-confidence attack detected but consecutive threshold not reached; "
                    f"temporarily allowed ({consecutive_hits}/{required_hits})."
                ),
            )

        if (
            decision.action == "auto_block"
            and self.settings.auto_block_to_graylist_enabled
            and source_ip
            and high_conf_attack
            and consecutive_hits >= required_hits
        ):
            self.ip_list_service.upsert(
                ip=source_ip,
                list_type="graylist",
                reason="Auto-added by auto_block decision",
                gray_duration_minutes=max(1, int(self.settings.auto_block_graylist_minutes)),
                expires_at=None,
                created_by="system:auto_block",
            )
            auto_graylist_applied = True

        reason_suffix = ""
        if auto_graylist_applied:
            reason_suffix = (
                f" Source IP auto-added to graylist for "
                f"{int(self.settings.auto_block_graylist_minutes)} minutes."
            )
        elif source_ip and high_conf_attack and consecutive_hits > 0 and decision.action == "allow":
            reason_suffix = f" Consecutive high-confidence hits: {consecutive_hits}/{required_hits}."

        log = TrafficLog(
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            predicted_label=str(prediction["label"]),
            probability=float(prediction["probability"]),
            is_attack=bool(prediction["is_attack"]),
            action=decision.action,
            status=decision.status,
            reason=(
                f"{decision.reason} "
                f"Feature coverage={float(quality['coverage']):.3f} "
                f"({quality['known_feature_count']}/{quality['required_feature_count']})."
                f"{reason_suffix}"
            ),
            probabilities=dict(prediction["probabilities"]),
            raw_features=payload.flow_features,
        )
        created = self.repository.create(log)
        if self.notification_service is not None:
            try:
                self.notification_service.notify_urgent_attack(created)
            except Exception:  # noqa: BLE001
                pass
        return created

    def review(
        self,
        log_id: int,
        decision: str,
        notes: str | None = None,
        list_action: str = "none",
        gray_duration_minutes: int | None = None,
        operator: str | None = None,
    ) -> TrafficLog:
        log = self.repository.get_by_id(log_id)
        if log is None:
            raise NotFoundError("Traffic log not found")

        if log.status != "pending_review":
            raise InvalidStateError("Traffic log is not pending review")

        if decision == "block":
            log.action = "manual_block"
            log.status = "blocked"
            log.reason = "Blocked by human analyst review."

            if list_action != "none":
                if not log.source_ip:
                    raise InvalidInputError("Cannot add to list: source_ip is empty")
                self.ip_list_service.upsert(
                    ip=log.source_ip,
                    list_type=list_action,
                    reason=notes,
                    gray_duration_minutes=gray_duration_minutes,
                    expires_at=None,
                    created_by=operator,
                )
                log.reason = f"Blocked by human analyst review and added to {list_action}."
        elif decision == "ignore":
            log.action = "manual_allow"
            log.status = "done"
            log.reason = "Ignored by human analyst review."
        else:
            raise InvalidInputError("Unsupported review decision")

        if decision == "ignore" and list_action != "none":
            raise InvalidInputError("list_action is only allowed when decision=block")

        if notes:
            log.notes = notes

        return self.repository.save(log)

    def list_recent(self, limit: int = 100) -> list[TrafficLog]:
        return self.repository.list_recent(limit=limit)

    def list_filtered(
        self,
        *,
        limit: int = 100,
        status: str | None = None,
        action: str | None = None,
        label: str | None = None,
    ) -> list[TrafficLog]:
        return self.repository.list_filtered(limit=limit, status=status, action=action, label=label)

    def get_summary(self) -> dict[str, int]:
        total = self.repository.count_filtered(exclude_actions=self._suppressed_actions)
        blocked = self.repository.count_filtered(action="auto_block") + self.repository.count_filtered(action="manual_block")
        pending = self.repository.count_filtered(status="pending_review", exclude_actions=self._suppressed_actions)
        allowed = self.repository.count_filtered(action="allow") + self.repository.count_filtered(action="manual_allow")
        attacks = total - self.repository.count_filtered(label="BENIGN", exclude_actions=self._suppressed_actions)
        benign = self.repository.count_filtered(label="BENIGN", exclude_actions=self._suppressed_actions)

        return {
            "total": total,
            "attacks": attacks,
            "benign": benign,
            "blocked": blocked,
            "pending_review": pending,
            "allowed": allowed,
        }

    def get_geo_paths(self, *, minutes: int = 60, limit: int = 300) -> list[dict[str, Any]]:
        since = datetime.utcnow() - timedelta(minutes=max(1, minutes))
        rows = self.repository.list_attack_logs_since(
            since=since,
            limit=limit,
            exclude_actions=self._suppressed_actions,
        )

        target = {
            "ip": "NetGuardian",
            "latitude": 31.2304,
            "longitude": 121.4737,
            "country": "China",
            "city": "Shanghai",
        }

        result: list[dict[str, Any]] = []
        for row in rows:
            src_geo = geo_service.locate_ip(row.source_ip)
            if src_geo is None:
                continue

            result.append(
                {
                    "log_id": int(row.id),
                    "label": row.predicted_label,
                    "severity": float(row.probability),
                    "created_at": row.created_at,
                    "source": {
                        "ip": src_geo.ip,
                        "latitude": src_geo.latitude,
                        "longitude": src_geo.longitude,
                        "country": src_geo.country,
                        "city": src_geo.city,
                    },
                    "target": target,
                }
            )

        return result

    def get_threat_profiles(self, *, minutes: int = 120, limit: int = 20) -> list[dict[str, Any]]:
        since = datetime.utcnow() - timedelta(minutes=max(1, minutes))
        rows = self.repository.list_source_logs_since(
            since=since,
            limit=5000,
            exclude_actions=self._suppressed_actions,
        )

        grouped: dict[str, list[TrafficLog]] = {}
        for row in rows:
            if not row.source_ip:
                continue
            grouped.setdefault(row.source_ip, []).append(row)

        profiles: list[dict[str, Any]] = []
        for source_ip, items in grouped.items():
            items.sort(key=lambda x: x.created_at)
            total = len(items)
            attack = sum(1 for x in items if x.is_attack)
            blocked = sum(1 for x in items if x.action in {"auto_block", "manual_block", "blacklist_drop", "graylist_drop"})
            pending = sum(1 for x in items if x.status == "pending_review")

            label_counter: dict[str, int] = {}
            for x in items:
                label_counter[x.predicted_label] = label_counter.get(x.predicted_label, 0) + 1
            top_labels = [k for k, _ in sorted(label_counter.items(), key=lambda p: p[1], reverse=True)[:3]]

            hit = self.ip_list_service.check_hit(source_ip)
            list_status = hit.list_type if hit.hit else "none"

            if list_status == "blacklist":
                suggestion = "该来源已在黑名单，建议持续观察是否出现地址漂移。"
            elif list_status == "graylist":
                suggestion = "该来源在灰名单中，建议到期后复核行为是否恢复正常。"
            elif pending > 5:
                suggestion = "待审批事件较多，建议合并处置并考虑加入灰名单。"
            elif attack / max(total, 1) > 0.6:
                suggestion = "攻击占比较高，建议优先封禁并进行溯源。"
            else:
                suggestion = "风险可控，建议继续观察。"

            profiles.append(
                {
                    "source_ip": source_ip,
                    "total_hits": total,
                    "attack_hits": attack,
                    "blocked_hits": blocked,
                    "pending_hits": pending,
                    "first_seen": items[0].created_at,
                    "last_seen": items[-1].created_at,
                    "top_labels": top_labels,
                    "list_status": list_status,
                    "suggestion": suggestion,
                }
            )

        profiles.sort(key=lambda x: (x["pending_hits"], x["attack_hits"], x["total_hits"]), reverse=True)
        return profiles[:limit]

    def get_merged_cases(self, *, window_minutes: int = 15, limit: int = 100) -> list[dict[str, Any]]:
        since = datetime.utcnow() - timedelta(minutes=max(1, window_minutes))
        rows = self.repository.list_source_logs_since(since=since, limit=8000)

        grouped: dict[tuple[str, str], list[TrafficLog]] = {}
        for row in rows:
            if row.status != "pending_review":
                continue
            if not row.source_ip:
                continue
            key = (row.source_ip, row.predicted_label)
            grouped.setdefault(key, []).append(row)

        cases: list[dict[str, Any]] = []
        for (source_ip, label), items in grouped.items():
            items.sort(key=lambda x: x.created_at)
            probs = [float(x.probability) for x in items]
            cases.append(
                {
                    "source_ip": source_ip,
                    "predicted_label": label,
                    "case_size": len(items),
                    "first_seen": items[0].created_at,
                    "last_seen": items[-1].created_at,
                    "max_probability": max(probs),
                    "avg_probability": sum(probs) / max(len(probs), 1),
                    "status": "pending_review",
                }
            )

        cases.sort(key=lambda x: (x["case_size"], x["max_probability"]), reverse=True)
        return cases[:limit]

    def review_merged_case(
        self,
        *,
        source_ip: str,
        predicted_label: str,
        window_minutes: int,
        decision: str,
        notes: str | None,
        list_action: str,
        gray_duration_minutes: int | None,
        operator: str | None,
    ) -> dict[str, Any]:
        since = datetime.utcnow() - timedelta(minutes=max(1, window_minutes))
        rows = self.repository.list_pending_by_source_label_since(
            source_ip=source_ip,
            label=predicted_label,
            since=since,
        )
        if not rows:
            raise NotFoundError("No pending logs found for merged case")

        reviewed = 0
        for row in rows:
            self.review(
                log_id=int(row.id),
                decision=decision,
                notes=notes,
                list_action=list_action,
                gray_duration_minutes=gray_duration_minutes,
                operator=operator,
            )
            reviewed += 1

        return {
            "source_ip": source_ip,
            "predicted_label": predicted_label,
            "reviewed": reviewed,
            "decision": decision,
        }

    def simulate_attack(
        self,
        *,
        attack_label: str,
        probability: float,
        source_ip: str | None,
        source_port: int | None,
        destination_ip: str | None,
        destination_port: int | None,
        notes: str | None,
    ) -> TrafficLog:
        if not self.settings.enable_simulation_endpoint:
            raise InvalidInputError("Simulation endpoint is disabled")

        if probability < 0 or probability > 1:
            raise InvalidInputError("probability must be in [0, 1]")

        normalized_label = attack_label.strip() if attack_label else "SyntheticAttack"
        if normalized_label.upper() == "BENIGN":
            raise InvalidInputError("attack_label cannot be BENIGN in simulation mode")

        decision = self.decision_service.evaluate(is_attack=True, probability=float(probability))

        log = TrafficLog(
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            predicted_label=normalized_label,
            probability=float(probability),
            is_attack=True,
            action=decision.action,
            status=decision.status,
            reason=f"{decision.reason} Synthetic simulation bypassed model inference.",
            probabilities={normalized_label: float(probability), "BENIGN": float(max(0.0, 1 - probability))},
            raw_features={"simulation": True, "attack_label": normalized_label},
            notes=notes,
        )
        created = self.repository.create(log)
        if self.notification_service is not None:
            try:
                self.notification_service.notify_urgent_attack(created)
            except Exception:  # noqa: BLE001
                pass
        return created

    def _normalize_flow_direction(
        self,
        *,
        source_ip: str | None,
        source_port: int | None,
        destination_ip: str | None,
        destination_port: int | None,
        is_attack: bool,
    ) -> tuple[str | None, int | None, str | None, int | None]:
        # Keep original direction to avoid false inversion for private-network traffic.
        return source_ip, source_port, destination_ip, destination_port
