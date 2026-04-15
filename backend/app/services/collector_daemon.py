from __future__ import annotations

import csv
import json
import asyncio
import os
import socket
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlmodel import Session

from app.core.config import get_settings
from app.core.database import engine
from app.models.ip_list_repository import IpListRepository
from app.models.repository import TrafficLogRepository
from app.models.user_repository import UserRepository
from app.services.event_bus import event_bus
from app.services.ip_list_service import IpListService
from app.services.notification_service import NotificationService
from app.services.traffic_service import AnalyzeInput, TrafficService


@dataclass(slots=True)
class CollectorConfig:
    csv_file: str | None = None
    csv_dir: str | None = None
    file_glob: str = "*.csv"
    poll_seconds: float = 1.0
    max_retries: int = 3
    enable_cfm_capture: bool = False
    cfm_binary: str = "/home/meta/master_pieces/NetGuardian/CICFlowMeter-4.0/bin/cfm"
    tcpdump_binary: str = "/usr/bin/tcpdump"
    network_interface: str | None = None
    capture_filter: str | None = None
    pcap_dir: str | None = None
    pcap_glob: str = "*.pcap"
    rotate_seconds: int = 30
    cleanup_on_stop: bool = True
    ignore_local_source: bool = False


@dataclass(slots=True)
class CollectorStats:
    started_at: float | None = None
    last_activity_at: float | None = None
    total_rows_seen: int = 0
    mapped_rows: int = 0
    analyze_success: int = 0
    analyze_failed: int = 0
    retries_scheduled: int = 0
    retries_attempted: int = 0
    files_tracked: int = 0
    pcap_tracked: int = 0
    pcap_processed: int = 0
    cfm_runs: int = 0
    cfm_failed: int = 0
    tcpdump_restarts: int = 0
    tcpdump_failed: int = 0
    tcpdump_last_error: str | None = None
    cleanup_deleted_files: int = 0
    outbound_ignored: int = 0
    last_error: str | None = None


@dataclass(slots=True)
class RetryItem:
    payload: dict[str, Any]
    retry_count: int = 0
    next_retry_at: float = field(default_factory=time.time)


class CollectorDaemon:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._config: CollectorConfig | None = None
        self._stats = CollectorStats()
        self._file_cursors: dict[str, int] = {}
        self._required_features: set[str] = set()
        self._retry_queue: deque[RetryItem] = deque()
        self._pcap_processed: set[str] = set()
        self._pcap_size_snapshot: dict[str, int] = {}
        self._tcpdump_process: subprocess.Popen[str] | None = None
        self._local_ips: set[str] = set()
        self._recent_success_timestamps: deque[float] = deque()

    def start(self, config: CollectorConfig) -> None:
        with self._lock:
            if self.is_running:
                raise RuntimeError("collector is already running")

            if not config.csv_file and not config.csv_dir:
                raise RuntimeError("either csv_file or csv_dir must be provided")

            self._config = config
            self._stats = CollectorStats(started_at=time.time())
            self._file_cursors = {}
            self._retry_queue.clear()
            self._pcap_processed.clear()
            self._pcap_size_snapshot.clear()
            self._recent_success_timestamps.clear()
            self._stop_event.clear()
            self._required_features = self._load_required_features()
            self._local_ips = self._detect_local_ips()

            self._thread = threading.Thread(target=self._run_loop, name="collector-daemon", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            if not self.is_running:
                return
            self._stop_event.set()
            thread = self._thread
            cfg = self._config

        if thread is not None:
            thread.join(timeout=5)

        self._stop_tcpdump()

        if cfg and cfg.cleanup_on_stop:
            deleted = self._cleanup_generated_files(cfg)
            with self._lock:
                self._stats.cleanup_deleted_files += deleted

        with self._lock:
            self._thread = None

    def retry_failed(self) -> int:
        with self._lock:
            count = len(self._retry_queue)
            now = time.time()
            for item in self._retry_queue:
                item.next_retry_at = now
            return count

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        self._check_tcpdump_health()

        now = time.time()
        recent_window_seconds = 30.0
        with self._lock:
            cfg = self._config
            stats = self._stats
            queue_size = len(self._retry_queue)
            while self._recent_success_timestamps and self._recent_success_timestamps[0] < now - recent_window_seconds:
                self._recent_success_timestamps.popleft()
            recent_count = len(self._recent_success_timestamps)

        elapsed = max((now - stats.started_at), 1e-6) if stats.started_at else 0.0
        throughput = stats.analyze_success / elapsed if elapsed else 0.0
        throughput_recent = recent_count / recent_window_seconds

        return {
            "running": self.is_running,
            "config": {
                "csv_file": cfg.csv_file if cfg else None,
                "csv_dir": cfg.csv_dir if cfg else None,
                "file_glob": cfg.file_glob if cfg else None,
                "poll_seconds": cfg.poll_seconds if cfg else None,
                "max_retries": cfg.max_retries if cfg else None,
                "enable_cfm_capture": cfg.enable_cfm_capture if cfg else None,
                "cfm_binary": cfg.cfm_binary if cfg else None,
                "tcpdump_binary": cfg.tcpdump_binary if cfg else None,
                "network_interface": cfg.network_interface if cfg else None,
                "capture_filter": cfg.capture_filter if cfg else None,
                "pcap_dir": cfg.pcap_dir if cfg else None,
                "pcap_glob": cfg.pcap_glob if cfg else None,
                "rotate_seconds": cfg.rotate_seconds if cfg else None,
                "cleanup_on_stop": cfg.cleanup_on_stop if cfg else None,
                "ignore_local_source": cfg.ignore_local_source if cfg else None,
            },
            "stats": {
                "started_at": stats.started_at,
                "last_activity_at": stats.last_activity_at,
                "total_rows_seen": stats.total_rows_seen,
                "mapped_rows": stats.mapped_rows,
                "analyze_success": stats.analyze_success,
                "analyze_failed": stats.analyze_failed,
                "retries_scheduled": stats.retries_scheduled,
                "retries_attempted": stats.retries_attempted,
                "retry_queue_size": queue_size,
                "files_tracked": stats.files_tracked,
                "pcap_tracked": stats.pcap_tracked,
                "pcap_processed": stats.pcap_processed,
                "cfm_runs": stats.cfm_runs,
                "cfm_failed": stats.cfm_failed,
                "tcpdump_restarts": stats.tcpdump_restarts,
                "tcpdump_failed": stats.tcpdump_failed,
                "tcpdump_last_error": stats.tcpdump_last_error,
                "cleanup_deleted_files": stats.cleanup_deleted_files,
                "outbound_ignored": stats.outbound_ignored,
                "throughput_rps": round(throughput, 4),
                "throughput_recent_rps": round(throughput_recent, 4),
                "last_error": stats.last_error,
            },
            "capture": {
                "tcpdump_running": self._tcpdump_process is not None and self._tcpdump_process.poll() is None,
                "tcpdump_pid": self._tcpdump_process.pid if self._tcpdump_process and self._tcpdump_process.poll() is None else None,
                "local_ips": sorted(self._local_ips),
            },
        }

    def _detect_local_ips(self) -> set[str]:
        ips: set[str] = {"127.0.0.1"}
        settings = get_settings()

        try:
            _, _, host_ips = socket.gethostbyname_ex(socket.gethostname())
            for ip in host_ips:
                if ip:
                    ips.add(ip)
        except Exception:  # noqa: BLE001
            pass

        try:
            output = subprocess.run(
                ["ip", "-o", "-4", "addr", "show"],
                capture_output=True,
                text=True,
                check=False,
            )
            if output.stdout:
                for line in output.stdout.splitlines():
                    parts = line.split()
                    if "inet" not in parts:
                        continue
                    idx = parts.index("inet")
                    if idx + 1 >= len(parts):
                        continue
                    cidr = parts[idx + 1]
                    ip = cidr.split("/", 1)[0].strip()
                    if ip:
                        ips.add(ip)
        except Exception:  # noqa: BLE001
            pass

        if settings.collector_local_ips_csv:
            for raw in settings.collector_local_ips_csv.split(","):
                value = raw.strip()
                if value:
                    ips.add(value)

        return ips

    def _ensure_dirs(self) -> None:
        assert self._config is not None

        if self._config.csv_dir:
            Path(self._config.csv_dir).expanduser().mkdir(parents=True, exist_ok=True)

        if self._config.pcap_dir:
            Path(self._config.pcap_dir).expanduser().mkdir(parents=True, exist_ok=True)

    def _start_tcpdump_if_needed(self) -> None:
        assert self._config is not None
        if not self._config.enable_cfm_capture:
            return

        if self._tcpdump_process is not None and self._tcpdump_process.poll() is None:
            return

        if not self._config.network_interface:
            raise RuntimeError("network_interface is required when enable_cfm_capture=true")

        if not self._config.pcap_dir:
            raise RuntimeError("pcap_dir is required when enable_cfm_capture=true")

        pcap_pattern = str(Path(self._config.pcap_dir).expanduser() / "capture-%Y%m%d-%H%M%S.pcap")
        cmd = [
            self._config.tcpdump_binary,
            "-i",
            self._config.network_interface,
            "-G",
            str(max(2, int(self._config.rotate_seconds))),
            "-w",
            pcap_pattern,
        ]
        if self._config.capture_filter:
            cmd.extend(self._config.capture_filter.split())

        self._tcpdump_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        with self._lock:
            self._stats.tcpdump_restarts += 1

    def _check_tcpdump_health(self) -> None:
        proc = self._tcpdump_process
        if proc is None:
            return

        code = proc.poll()
        if code is None:
            return

        err_text = ""
        if proc.stderr is not None:
            try:
                err_text = proc.stderr.read().strip()
            except Exception:  # noqa: BLE001
                err_text = ""

        message = f"tcpdump exited with code {code}"
        if err_text:
            message = f"{message}: {err_text}"

        with self._lock:
            self._stats.tcpdump_failed += 1
            self._stats.tcpdump_last_error = message
            self._stats.last_error = message
            self._stats.last_activity_at = time.time()

        self._tcpdump_process = None

    def _stop_tcpdump(self) -> None:
        proc = self._tcpdump_process
        if proc is None:
            return

        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

        self._tcpdump_process = None

    def _cleanup_generated_files(self, cfg: CollectorConfig) -> int:
        deleted = 0

        if cfg.enable_cfm_capture and cfg.pcap_dir:
            pcap_dir = Path(cfg.pcap_dir).expanduser().resolve()
            if pcap_dir.exists():
                for file_path in pcap_dir.glob(cfg.pcap_glob):
                    if file_path.is_file():
                        try:
                            file_path.unlink()
                            deleted += 1
                        except OSError:
                            continue

        if cfg.enable_cfm_capture and cfg.csv_dir:
            csv_dir = Path(cfg.csv_dir).expanduser().resolve()
            if csv_dir.exists():
                for file_path in csv_dir.glob(cfg.file_glob):
                    if file_path.is_file():
                        try:
                            file_path.unlink()
                            deleted += 1
                        except OSError:
                            continue

        return deleted

    def _list_pcap_files(self) -> list[Path]:
        assert self._config is not None
        if not self._config.pcap_dir:
            return []

        pcap_dir = Path(self._config.pcap_dir).expanduser().resolve()
        if not pcap_dir.exists():
            return []

        files = [p for p in pcap_dir.glob(self._config.pcap_glob) if p.is_file()]
        files.sort(key=lambda p: p.stat().st_mtime)
        return files

    def _convert_pcap_to_csv(self, pcap_file: Path) -> None:
        assert self._config is not None
        if not self._config.csv_dir:
            raise RuntimeError("csv_dir is required to run CICFlowMeter conversion")

        cfm_path = Path(self._config.cfm_binary).expanduser().resolve()
        cfm_native_dir = cfm_path.parents[1] / "lib" / "native"

        cmd = [
            self._config.cfm_binary,
            str(pcap_file),
            str(Path(self._config.csv_dir).expanduser().resolve()),
        ]

        env = dict(os.environ)
        existing_cfm_opts = env.get("CFM_OPTS", "").strip()
        java_path_opt = f"-Djava.library.path={cfm_native_dir}"
        env["CFM_OPTS"] = f"{existing_cfm_opts} {java_path_opt}".strip()

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            message = stderr or stdout or "unknown error"
            if "UnsatisfiedLinkError" in message:
                message = (
                    f"{message} | Hint: native library load failed, expected at {cfm_native_dir}. "
                    "Check Java architecture and native library compatibility."
                )
            raise RuntimeError(f"cfm failed({proc.returncode}): {message}")

    def _process_pending_pcaps(self) -> None:
        assert self._config is not None
        if not self._config.enable_cfm_capture:
            return

        pcap_files = self._list_pcap_files()
        tcpdump_running = self._tcpdump_process is not None and self._tcpdump_process.poll() is None
        active_capture = str(pcap_files[-1].resolve()) if tcpdump_running and pcap_files else None
        with self._lock:
            self._stats.pcap_tracked = len(pcap_files)

        now = time.time()
        for pcap_file in pcap_files:
            key = str(pcap_file.resolve())
            if key in self._pcap_processed:
                continue

            # Skip the newest rolling pcap while tcpdump is still running.
            if active_capture and key == active_capture:
                continue

            # Skip empty/tiny capture files that cannot contain a valid pcap header.
            size = pcap_file.stat().st_size
            if size < 24:
                continue

            # Skip very fresh files to avoid reading while tcpdump is still writing.
            if now - pcap_file.stat().st_mtime < 0.3:
                continue

            try:
                self._convert_pcap_to_csv(pcap_file)
                self._pcap_processed.add(key)
                with self._lock:
                    self._stats.cfm_runs += 1
                    self._stats.pcap_processed += 1
                    self._stats.last_activity_at = time.time()
                    self._stats.last_error = None
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self._stats.cfm_failed += 1
                    self._stats.last_error = str(exc)

    def _load_required_features(self) -> set[str]:
        from app.services.model_runtime import model_runtime

        return set(model_runtime.get_required_features())

    def _list_source_files(self) -> list[Path]:
        assert self._config is not None

        files: list[Path] = []
        if self._config.csv_file:
            target = Path(self._config.csv_file).expanduser().resolve()
            files.append(target)

        if self._config.csv_dir:
            folder = Path(self._config.csv_dir).expanduser().resolve()
            if folder.exists():
                files.extend(sorted(folder.glob(self._config.file_glob)))

        dedup = {str(item.resolve()): item.resolve() for item in files if item.exists() and item.is_file()}
        return sorted(dedup.values(), key=lambda p: p.name)

    @staticmethod
    def _to_number(value: str) -> float | int | None:
        raw = (value or "").strip()
        if not raw:
            return None

        lowered = raw.lower()
        if lowered in {"nan", "inf", "-inf"}:
            return None

        try:
            if "." in raw or "e" in lowered:
                return float(raw)
            return int(raw)
        except ValueError:
            return None

    def _row_to_payload(self, row: dict[str, str]) -> dict[str, Any]:
        normalized = {str(k).strip(): v for k, v in row.items()}

        source_ip = normalized.get("Src IP") or normalized.get("Source IP")
        if self._config and self._config.ignore_local_source and source_ip and source_ip in self._local_ips:
            return {
                "flow_features": {},
                "metadata": {
                    "source_ip": source_ip,
                },
                "ignored_outbound": True,
            }

        flow_features: dict[str, Any] = {}
        for key, value in normalized.items():
            if key in self._required_features:
                numeric = self._to_number(value)
                if numeric is not None:
                    flow_features[key] = numeric

        metadata = {
            "source_ip": source_ip,
            "source_port": self._to_number(normalized.get("Src Port", "") or normalized.get("Source Port", "")),
            "destination_ip": normalized.get("Dst IP") or normalized.get("Destination IP"),
            "destination_port": self._to_number(
                normalized.get("Dst Port", "") or normalized.get("Destination Port", "")
            ),
        }

        return {
            "flow_features": flow_features,
            "metadata": metadata,
        }

    def _read_new_rows(self, file_path: Path) -> list[dict[str, str]]:
        key = str(file_path)
        cursor = self._file_cursors.get(key, 0)

        with file_path.open("r", encoding="utf-8", newline="") as fp:
            rows = list(csv.DictReader(fp))

        if cursor > len(rows):
            cursor = 0

        new_rows = rows[cursor:]
        self._file_cursors[key] = len(rows)
        return new_rows

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._stats.last_error = message
            self._stats.last_activity_at = time.time()

    def _submit_payload(self, payload: dict[str, Any]) -> None:
        settings = get_settings()
        with Session(engine) as session:
            repository = TrafficLogRepository(session)
            ip_list_service = IpListService(repository=IpListRepository(session))
            notify_service = NotificationService(repository=UserRepository(session), settings=settings)
            service = TrafficService(
                repository=repository,
                settings=settings,
                ip_list_service=ip_list_service,
                notification_service=notify_service,
            )
            analyze_input = AnalyzeInput(
                flow_features=payload.get("flow_features", {}),
                source_ip=payload.get("metadata", {}).get("source_ip"),
                source_port=payload.get("metadata", {}).get("source_port"),
                destination_ip=payload.get("metadata", {}).get("destination_ip"),
                destination_port=payload.get("metadata", {}).get("destination_port"),
            )
            log = service.analyze(analyze_input)

            event_payload = {
                "id": int(log.id),
                "created_at": log.created_at.isoformat(),
                "source_ip": log.source_ip,
                "source_port": log.source_port,
                "destination_ip": log.destination_ip,
                "destination_port": log.destination_port,
                "predicted_label": log.predicted_label,
                "probability": log.probability,
                "is_attack": log.is_attack,
                "action": log.action,
                "status": log.status,
                "reason": log.reason,
                "probabilities": log.probabilities,
                "notes": log.notes,
            }

            # Run websocket broadcast in this worker thread via a short-lived event loop.
            asyncio.run(event_bus.broadcast("traffic.analyzed", json.loads(json.dumps(event_payload))))

    def _run_loop(self) -> None:
        assert self._config is not None
        self._ensure_dirs()

        while not self._stop_event.is_set():
            processed_any = False
            try:
                now = time.time()

                self._start_tcpdump_if_needed()
                self._check_tcpdump_health()
                self._process_pending_pcaps()

                # Process retry queue first
                while self._retry_queue and self._retry_queue[0].next_retry_at <= now:
                    item = self._retry_queue.popleft()
                    with self._lock:
                        self._stats.retries_attempted += 1
                    try:
                        self._submit_payload(item.payload)
                        processed_any = True
                        with self._lock:
                            self._stats.analyze_success += 1
                            self._stats.last_activity_at = time.time()
                            self._stats.last_error = None
                    except Exception as exc:  # noqa: BLE001
                        if item.retry_count + 1 <= self._config.max_retries:
                            item.retry_count += 1
                            item.next_retry_at = time.time() + min(2**item.retry_count, 15)
                            self._retry_queue.append(item)
                            with self._lock:
                                self._stats.retries_scheduled += 1
                        with self._lock:
                            self._stats.analyze_failed += 1
                            self._stats.last_error = str(exc)

                files = self._list_source_files()
                with self._lock:
                    self._stats.files_tracked = len(files)

                for file_path in files:
                    rows = self._read_new_rows(file_path)
                    if not rows:
                        continue

                    with self._lock:
                        self._stats.total_rows_seen += len(rows)

                    for row in rows:
                        payload = self._row_to_payload(row)
                        if payload.get("ignored_outbound"):
                            with self._lock:
                                self._stats.outbound_ignored += 1
                            continue

                        if not payload["flow_features"]:
                            continue

                        with self._lock:
                            self._stats.mapped_rows += 1

                        try:
                            self._submit_payload(payload)
                            processed_any = True
                            with self._lock:
                                self._stats.analyze_success += 1
                                self._recent_success_timestamps.append(time.time())
                                self._stats.last_activity_at = time.time()
                                self._stats.last_error = None
                        except Exception as exc:  # noqa: BLE001
                            with self._lock:
                                self._stats.analyze_failed += 1
                                self._stats.last_error = str(exc)
                            if self._config.max_retries > 0:
                                self._retry_queue.append(RetryItem(payload=payload, retry_count=0))
                                with self._lock:
                                    self._stats.retries_scheduled += 1

            except Exception as exc:  # noqa: BLE001
                self._record_error(str(exc))

            if processed_any:
                sleep_seconds = 0.05
            else:
                sleep_seconds = self._config.poll_seconds
                if self._config.enable_cfm_capture:
                    sleep_seconds = min(sleep_seconds, 2.0)

            time.sleep(sleep_seconds)


collector_daemon = CollectorDaemon()
