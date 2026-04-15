from __future__ import annotations

import random
import smtplib
from dataclasses import dataclass
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from urllib import error, request
import json
import logging
import threading

from app.core.config import Settings
from app.core.exceptions import InvalidInputError
from app.models.traffic_log import TrafficLog
from app.models.user import User
from app.models.user_repository import UserRepository


@dataclass(slots=True)
class NotificationBindingInfo:
    webhook_url: str | None
    webhook_enabled: bool
    notify_email: str | None
    notify_email_verified: bool
    pending_email: str | None
    urgent_threshold: float


class NotificationService:
    def __init__(self, repository: UserRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings

    def get_binding_info(self, user: User) -> NotificationBindingInfo:
        return NotificationBindingInfo(
            webhook_url=user.webhook_url,
            webhook_enabled=bool(user.webhook_enabled and user.webhook_url),
            notify_email=user.notify_email,
            notify_email_verified=bool(user.notify_email_verified and user.notify_email),
            pending_email=user.notify_email_pending,
            urgent_threshold=float(self.settings.urgent_notify_threshold),
        )

    def bind_webhook(self, *, user: User, webhook_url: str | None, enabled: bool) -> User:
        cleaned = (webhook_url or "").strip() or None
        if enabled and not cleaned:
            raise InvalidInputError("启用 webhook 时，地址不能为空")

        user.webhook_url = cleaned
        user.webhook_enabled = bool(enabled and cleaned)
        return self.repository.update(user)

    def send_email_verification_code(self, *, user: User, email: str) -> None:
        target = (email or "").strip().lower()
        if "@" not in target or "." not in target:
            raise InvalidInputError("邮箱格式不正确")

        code = f"{random.randint(0, 999999):06d}"
        expire_at = datetime.utcnow() + timedelta(minutes=max(1, int(self.settings.email_verification_code_ttl_minutes)))

        user.notify_email_pending = target
        user.notify_email_code = code
        user.notify_email_code_expires_at = expire_at
        self.repository.update(user)

        subject = "NetGuardian 邮箱绑定验证码"
        message = (
            "尊敬的用户，您好：\n\n"
            "您正在申请将当前邮箱绑定为 NetGuardian 安全通知接收邮箱。\n"
            f"本次验证码为：{code}。\n"
            f"验证码有效期：{int(self.settings.email_verification_code_ttl_minutes)} 分钟。\n\n"
            "请勿将验证码透露给他人。如非本人操作，请忽略本邮件。\n\n"
            "此致\n"
            "NetGuardian 安全平台"
        )

        thread = threading.Thread(
            target=self._send_email_background,
            kwargs={
                "to_email": target,
                "subject": subject,
                "message": message,
                "reset_user_id": int(user.id),
            },
            daemon=True,
        )
        thread.start()

    def verify_email_code(self, *, user: User, email: str, code: str) -> User:
        target = (email or "").strip().lower()
        input_code = (code or "").strip()

        if not user.notify_email_pending or user.notify_email_pending != target:
            raise InvalidInputError("待验证邮箱不匹配")
        if not user.notify_email_code or user.notify_email_code != input_code:
            raise InvalidInputError("验证码错误")
        if not user.notify_email_code_expires_at or user.notify_email_code_expires_at <= datetime.utcnow():
            raise InvalidInputError("验证码已过期，请重新获取")

        user.notify_email = target
        user.notify_email_verified = True
        user.notify_email_pending = None
        user.notify_email_code = None
        user.notify_email_code_expires_at = None
        return self.repository.update(user)

    def clear_email_binding(self, *, user: User) -> User:
        user.notify_email = None
        user.notify_email_verified = False
        user.notify_email_pending = None
        user.notify_email_code = None
        user.notify_email_code_expires_at = None
        return self.repository.update(user)

    def notify_urgent_attack(self, log: TrafficLog) -> None:
        if not log.is_attack:
            return
        if float(log.probability) < float(self.settings.urgent_notify_threshold):
            return

        users = self.repository.list_active_with_notification_channels()
        if not users:
            return

        title = "NetGuardian 紧急攻击告警"
        plain_text = (
            "【NetGuardian 紧急攻击告警通知】\n\n"
            "系统检测到高风险网络攻击行为，详细信息如下：\n"
            f"告警时间：{log.created_at.isoformat()} UTC\n"
            f"攻击类型：{log.predicted_label}\n"
            f"风险置信度：{log.probability * 100:.2f}%\n"
            f"源地址：{log.source_ip or '-'}\n"
            f"目的地址：{log.destination_ip or '-'}\n"
            f"处置动作：{log.action}\n"
            f"触发原因：{log.reason}\n\n"
            "请尽快登录平台进行复核与处置。"
        )

        for user in users:
            if user.webhook_enabled and user.webhook_url:
                try:
                    self._send_webhook(url=user.webhook_url, title=title, markdown=plain_text)
                except Exception:  # noqa: BLE001
                    pass
            if user.notify_email_verified and user.notify_email:
                subject = f"[NetGuardian] 紧急攻击告警 {log.predicted_label} {log.probability * 100:.1f}%"
                try:
                    self._send_email(to_email=user.notify_email, subject=subject, message=plain_text)
                except Exception:  # noqa: BLE001
                    pass

    def _send_webhook(self, *, url: str, title: str, markdown: str) -> None:
        payload = self._build_webhook_payload(url=url, title=title, markdown=markdown)
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            url=url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=float(self.settings.webhook_timeout_seconds)):
                return
        except Exception:
            return

    @staticmethod
    def _build_webhook_payload(*, url: str, title: str, markdown: str) -> dict:
        lowered = url.lower()
        if "qyapi.weixin.qq.com" in lowered:
            return {"msgtype": "markdown", "markdown": {"content": markdown}}
        if "dingtalk" in lowered:
            return {"msgtype": "markdown", "markdown": {"title": title, "text": markdown}}
        if "feishu" in lowered or "lark" in lowered:
            return {
                "msg_type": "post",
                "content": {"post": {"zh_cn": {"title": title, "content": [[{"tag": "text", "text": markdown}]]}}},
            }
        return {"title": title, "markdown": markdown}

    def _send_email_background(self, *, to_email: str, subject: str, message: str, reset_user_id: int | None = None) -> None:
        try:
            self._send_email(to_email=to_email, subject=subject, message=message)
        except InvalidInputError as exc:
            logging.exception("email sending failed: %s", exc)
            if reset_user_id is not None:
                try:
                    user = self.repository.get_by_id(reset_user_id)
                    if user is not None:
                        user.notify_email_pending = None
                        user.notify_email_code = None
                        user.notify_email_code_expires_at = None
                        self.repository.update(user)
                except Exception:  # noqa: BLE001
                    pass

    def _send_email(self, *, to_email: str, subject: str, message: str) -> None:
        if not self.settings.notify_sender_password:
            raise InvalidInputError("邮件发送配置缺失：notify_sender_password 未设置")

        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self.settings.notify_sender_email
        msg["To"] = to_email

        try:
            if self.settings.notify_smtp_use_ssl:
                with smtplib.SMTP_SSL(
                    self.settings.notify_smtp_host,
                    int(self.settings.notify_smtp_port),
                    timeout=10,
                ) as server:
                    server.login(self.settings.notify_sender_email, self.settings.notify_sender_password)
                    server.sendmail(self.settings.notify_sender_email, [to_email], msg.as_string())
            else:
                with smtplib.SMTP(
                    self.settings.notify_smtp_host,
                    int(self.settings.notify_smtp_port),
                    timeout=10,
                ) as server:
                    server.starttls()
                    server.login(self.settings.notify_sender_email, self.settings.notify_sender_password)
                    server.sendmail(self.settings.notify_sender_email, [to_email], msg.as_string())
        except smtplib.SMTPAuthenticationError as exc:
            raise InvalidInputError("SMTP认证失败，请检查邮箱账号或授权码") from exc
        except (smtplib.SMTPException, OSError) as exc:
            raise InvalidInputError(
                f"SMTP连接失败，请检查 notify_smtp_host/port 配置（当前: {self.settings.notify_smtp_host}:{self.settings.notify_smtp_port}）"
            ) from exc
