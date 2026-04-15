from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bridge CICFlowMeter CSV rows to NetGuardian analyze API")
    parser.add_argument("--csv", help="Path to one CICFlowMeter output CSV")
    parser.add_argument("--csv-dir", help="Directory containing rolling CICFlowMeter CSV files")
    parser.add_argument("--glob", default="*.csv", help="Glob pattern for --csv-dir mode")
    parser.add_argument("--api-base", default="http://127.0.0.1:8000/api/v1", help="NetGuardian API base URL")
    parser.add_argument("--token", required=True, help="Bearer token from /auth/login")
    parser.add_argument("--poll-seconds", type=float, default=1.0, help="Polling interval for new rows")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retries for failed analyze requests")
    parser.add_argument("--dry-run", action="store_true", help="Print payload without sending")
    args = parser.parse_args()

    if not args.csv and not args.csv_dir:
        parser.error("--csv or --csv-dir is required")
    return args


def _request_json(method: str, url: str, token: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None
    headers = {
        "Authorization": f"Bearer {token}",
    }

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url=url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            data = response.read().decode("utf-8")
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc


def fetch_required_features(api_base: str, token: str) -> list[str]:
    url = f"{api_base.rstrip('/')}/traffic/required-features"
    data = _request_json("GET", url, token)
    return [str(item) for item in data.get("features", [])]


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


def row_to_payload(row: dict[str, str], required_features: set[str]) -> dict[str, Any]:
    normalized = {str(k).strip(): v for k, v in row.items()}

    flow_features: dict[str, Any] = {}
    for key, value in normalized.items():
        if key in required_features:
            numeric = _to_number(value)
            if numeric is not None:
                flow_features[key] = numeric

    metadata = {
        "source_ip": normalized.get("Src IP") or normalized.get("Source IP"),
        "source_port": _to_number(normalized.get("Src Port", "") or normalized.get("Source Port", "")),
        "destination_ip": normalized.get("Dst IP") or normalized.get("Destination IP"),
        "destination_port": _to_number(
            normalized.get("Dst Port", "") or normalized.get("Destination Port", "")
        ),
    }

    return {
        "flow_features": flow_features,
        "metadata": metadata,
    }


def iter_new_rows(csv_path: Path, start_index: int) -> tuple[list[dict[str, str]], int]:
    if not csv_path.exists():
        return [], start_index

    with csv_path.open("r", encoding="utf-8", newline="") as fp:
        reader = csv.DictReader(fp)
        rows = list(reader)

    if start_index > len(rows):
        start_index = 0

    if start_index >= len(rows):
        return [], len(rows)

    new_rows = rows[start_index:]
    return new_rows, len(rows)


def resolve_source_files(*, csv_file: Path | None, csv_dir: Path | None, glob_pattern: str) -> list[Path]:
    files: list[Path] = []
    if csv_file is not None:
        files.append(csv_file)
    if csv_dir is not None and csv_dir.exists():
        files.extend(sorted(csv_dir.glob(glob_pattern)))

    dedup = {str(item.resolve()): item.resolve() for item in files if item.exists() and item.is_file()}
    return sorted(dedup.values(), key=lambda p: p.name)


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv).expanduser().resolve() if args.csv else None
    csv_dir = Path(args.csv_dir).expanduser().resolve() if args.csv_dir else None

    required = fetch_required_features(args.api_base, args.token)
    required_set = set(required)
    print(f"Loaded required features: {len(required)}")

    cursors: dict[str, int] = {}
    retry_queue: deque[dict[str, Any]] = deque()

    while True:
        now = time.time()

        while retry_queue and retry_queue[0]["next_retry_at"] <= now:
            item = retry_queue.popleft()
            payload = item["payload"]
            attempt = int(item["attempt"])
            try:
                result = _request_json(
                    "POST",
                    f"{args.api_base.rstrip('/')}/traffic/analyze",
                    args.token,
                    payload,
                )
                print(
                    f"retry-ok label={result.get('predicted_label')} prob={result.get('probability')} "
                    f"status={result.get('status')}"
                )
            except Exception as exc:  # noqa: BLE001
                if attempt < args.max_retries:
                    next_attempt = attempt + 1
                    retry_queue.append(
                        {
                            "payload": payload,
                            "attempt": next_attempt,
                            "next_retry_at": time.time() + min(2**next_attempt, 15),
                        }
                    )
                print(f"retry-failed attempt={attempt} error={exc}")

        for source in resolve_source_files(csv_file=csv_path, csv_dir=csv_dir, glob_pattern=args.glob):
            key = str(source)
            rows, next_cursor = iter_new_rows(source, cursors.get(key, 0))
            cursors[key] = next_cursor

            for row in rows:
                payload = row_to_payload(row, required_set)
                known_count = len(payload["flow_features"])
                if known_count == 0:
                    continue

                if args.dry_run:
                    print(json.dumps(payload, ensure_ascii=True))
                    continue

                try:
                    result = _request_json(
                        "POST",
                        f"{args.api_base.rstrip('/')}/traffic/analyze",
                        args.token,
                        payload,
                    )
                    print(
                        f"analyzed file={source.name} label={result.get('predicted_label')} "
                        f"prob={result.get('probability')} status={result.get('status')} known_features={known_count}"
                    )
                except Exception as exc:  # noqa: BLE001
                    if args.max_retries > 0:
                        retry_queue.append(
                            {
                                "payload": payload,
                                "attempt": 1,
                                "next_retry_at": time.time() + 1,
                            }
                        )
                    print(f"analyze-failed file={source.name} error={exc}")

        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()
