"""The scan records CSPM keeps in Redis, and how long it keeps them (#591).

A scan has three records, all with the same retention,
``CSPM_REPORT_RETENTION_DAYS`` (90 by default):

``scan:{id}:metadata``
    Who started the scan, for which account, and its status. Written when
    the scan starts and again when it completes or fails, each time with the
    full retention.

``cspm:team:{team}:scan_index``
    A sorted set of the team's scan ids, scored by the time each scan's
    metadata expires. Every write of the metadata writes the same expiry
    here, so an entry never outlives its scan and never expires before it.
    Expired entries are pruned on every read and write, and the key itself
    expires with its last entry.

``scan:{id}:report``
    The report of a completed scan, written by the worker. The compliance
    summary and findings, the dashboard summary and
    ``GET /api/v1/scans/{id}/report`` read reports from here and from
    nowhere else.

Reports used to be read from the Celery result backend, where Celery's
default ``result_expires`` dropped them after a day while the metadata and
the index lived on for 30 days. Batch scans wrote no metadata at all.

Reports are stored as zlib-compressed JSON, base64-encoded so the
``decode_responses`` client can read them. A report takes about 720 bytes
per check result as JSON and about a tenth of that stored; see the README
for the memory this needs at a given retention.

Every function takes the Redis client as an argument, so the API and the
worker share them with their own clients.
"""

import base64
import binascii
import json
import logging
import time
import zlib
from typing import Any, Dict, Iterator, Optional

from .config import settings

logger = logging.getLogger(__name__)

SECONDS_PER_DAY = 86400

# Scan states that are final. The worker writes "completed" and "failed";
# DELETE /api/v1/scans/{id} writes "cancelled".
FINAL_STATUSES = ("completed", "failed", "cancelled")


def _now() -> float:
    """The current time; tests replace it to move the clock."""
    return time.time()


def retention_seconds() -> int:
    """The retention as a whole number of seconds (SETEX rejects a float)."""
    return int(settings.cspm_report_retention_days) * SECONDS_PER_DAY


def metadata_key(scan_id: str) -> str:
    return f"scan:{scan_id}:metadata"


def report_key(scan_id: str) -> str:
    return f"scan:{scan_id}:report"


def credentials_key(scan_id: str) -> str:
    """Where a queued scan's encrypted credentials wait for a worker.

    Written by the API with a five-minute expiry and deleted by the worker
    that takes the scan, or by the API when the scan is cancelled first.
    """
    return f"scan:{scan_id}:creds"


def team_index_key(team_id: str) -> str:
    return f"cspm:team:{team_id}:scan_index"


def legacy_team_index_key(team_id: str) -> str:
    """The plain set releases before #591 indexed scans in.

    It is read, never written: it expires on its own 30 days after the last
    scan the previous release started, and its entries whose metadata has
    expired are skipped.
    """
    return f"cspm:team:{team_id}:scans"


def _index_scan(redis, team_id: str, scan_id: str, expires_at: float) -> None:
    key = team_index_key(team_id)
    redis.zadd(key, {scan_id: expires_at})
    redis.zremrangebyscore(key, "-inf", _now())
    # The key lives as long as its longest-lived entry. Taking the highest
    # score, rather than now + retention, keeps entries written under a
    # longer retention reachable after the retention is lowered.
    newest = redis.zrange(key, -1, -1, withscores=True)
    if newest:
        redis.expireat(key, int(newest[0][1]) + 1)


def save_metadata(redis, metadata: Dict[str, Any]) -> None:
    """Write a scan's metadata and its team index entry, with one expiry.

    The only function that writes scan metadata: single scans, batch scans,
    cancellation, completion and failure all go through it.
    """
    ttl = retention_seconds()
    expires_at = _now() + ttl
    redis.setex(metadata_key(metadata["scan_id"]), ttl, json.dumps(metadata))
    _index_scan(redis, metadata["team_id"], metadata["scan_id"], expires_at)


def forget_scan(redis, scan_id: str, team_id: str) -> None:
    """Remove every record of a scan that was never queued (#778).

    Its credentials first, then its metadata and its entry in the team's
    index: all that exists of a scan before a worker takes it. A scan that
    was queued is never forgotten; it ends as completed, failed or
    cancelled.
    """
    redis.delete(credentials_key(scan_id), metadata_key(scan_id))
    redis.zrem(team_index_key(team_id), scan_id)


def load_metadata(redis, scan_id: str) -> Optional[Dict[str, Any]]:
    raw = redis.get(metadata_key(scan_id))
    if not raw:
        return None
    try:
        metadata = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return metadata if isinstance(metadata, dict) else None


def team_scan_metadata(redis, team_id: str) -> Iterator[Dict[str, Any]]:
    """Yield the metadata of the team's scans that are still retained.

    Prunes expired index entries first. An entry whose metadata is gone or
    belongs to another team is skipped.
    """
    key = team_index_key(team_id)
    now = _now()
    redis.zremrangebyscore(key, "-inf", now)
    scan_ids = set(redis.zrangebyscore(key, now, "+inf"))
    scan_ids.update(redis.smembers(legacy_team_index_key(team_id)))
    for scan_id in sorted(scan_ids):
        metadata = load_metadata(redis, scan_id)
        if metadata and metadata.get("team_id") == team_id:
            yield metadata


def encode_report(report: Dict[str, Any]) -> str:
    payload = zlib.compress(json.dumps(report).encode("utf-8"), 6)
    return base64.b64encode(payload).decode("ascii")


def decode_report(blob: str) -> Optional[Dict[str, Any]]:
    try:
        report = json.loads(zlib.decompress(base64.b64decode(blob)))
    except (binascii.Error, zlib.error, ValueError, TypeError):
        return None
    return report if isinstance(report, dict) else None


def load_report(redis, scan_id: str) -> Optional[Dict[str, Any]]:
    """The stored report of a completed scan, or None.

    Its ``scan_id`` is the scan's. The reports stored before #766 carry an
    id the runner made up for each of them; the key a report is stored
    under is what says whose it is.
    """
    blob = redis.get(report_key(scan_id))
    if not blob:
        return None
    report = decode_report(blob)
    if report is None:
        logger.warning("Stored report of scan %s could not be decoded", scan_id)
        return None
    report["scan_id"] = scan_id
    return report


def complete_scan(
    redis, scan_id: str, report: Dict[str, Any], completed_at: str
) -> bool:
    """Store a completed scan's report and mark its metadata completed.

    The report is written first, so a reader that sees "completed" finds it.
    Returns False, and stores nothing, when the scan's metadata is gone: the
    report could not be attributed to a team.
    """
    metadata = load_metadata(redis, scan_id)
    if metadata is None:
        logger.warning("Scan %s completed but has no metadata; report dropped", scan_id)
        return False
    redis.setex(report_key(scan_id), retention_seconds(), encode_report(report))
    metadata["status"] = "completed"
    metadata["completed_at"] = completed_at
    save_metadata(redis, metadata)
    return True


def fail_scan(redis, scan_id: str, failed_at: str) -> None:
    """Mark a scan that is still in progress as failed."""
    metadata = load_metadata(redis, scan_id)
    if metadata is None or metadata.get("status") in FINAL_STATUSES:
        return
    metadata["status"] = "failed"
    metadata["failed_at"] = failed_at
    save_metadata(redis, metadata)


def cancel_scan(redis, scan_id: str, cancelled_at: str) -> bool:
    """Mark a scan that is still in progress as cancelled.

    Returns True when it did. A scan that is gone, or that already has a
    final status, is left exactly as it is and the answer is False: a
    completed scan stays completed, with its completion time and its
    report. DELETE /api/v1/scans/{id} used to write "cancelled" over
    whatever the scan's status was (#766).

    The metadata is read again here, not taken from the caller, so a scan
    the worker finished while the caller was revoking its task is not
    overwritten with what the caller read before.
    """
    metadata = load_metadata(redis, scan_id)
    if metadata is None or metadata.get("status") in FINAL_STATUSES:
        return False
    metadata["status"] = "cancelled"
    metadata["cancelled_at"] = cancelled_at
    save_metadata(redis, metadata)
    return True
