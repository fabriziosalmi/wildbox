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

from redis.exceptions import WatchError

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


def _tidy_index(redis, team_id: str) -> None:
    """Prune the team's expired index entries and set the key's own expiry."""
    key = team_index_key(team_id)
    redis.zremrangebyscore(key, "-inf", _now())
    # The key lives as long as its longest-lived entry. Taking the highest
    # score, rather than now + retention, keeps entries written under a
    # longer retention reachable after the retention is lowered.
    newest = redis.zrange(key, -1, -1, withscores=True)
    if newest:
        redis.expireat(key, int(newest[0][1]) + 1)


def _index_scan(redis, team_id: str, scan_id: str, expires_at: float) -> None:
    redis.zadd(team_index_key(team_id), {scan_id: expires_at})
    _tidy_index(redis, team_id)


def save_metadata(redis, metadata: Dict[str, Any]) -> None:
    """Write a new scan's metadata and its team index entry, with one expiry.

    For the scan's first record, which nothing else writes yet. Its end
    (completed, failed, cancelled) is written by _end_scan, which reads and
    writes in one transaction.
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


def _decode_metadata(raw) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    try:
        metadata = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return metadata if isinstance(metadata, dict) else None


def load_metadata(redis, scan_id: str) -> Optional[Dict[str, Any]]:
    return _decode_metadata(redis.get(metadata_key(scan_id)))


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


def _end_scan(
    redis,
    scan_id: str,
    status: str,
    time_field: str,
    at: str,
    report: Optional[Dict[str, Any]] = None,
    reason: Optional[str] = None,
) -> Optional[str]:
    """Give a scan in progress its final status, in one transaction (#778).

    Returns None when it did. Otherwise nothing is written and the answer
    says why: the final status the scan already has, or "missing" when its
    metadata is gone.

    The API cancels a scan and the worker completes or fails it, from two
    processes. Each used to read the metadata, decide, and write it back in
    separate commands, so the two could decide on the same reading: a
    cancellation and a completion that crossed left a scan recorded as
    cancelled with a report stored and counted in the team's figures, or
    one answered as cancelled that then read completed. complete_scan did
    not look at the status at all, and wrote over a cancellation.

    The metadata key is watched from before it is read to the EXEC that
    writes it: when anything wrote it in between, Redis runs none of the
    queued commands, and the scan is read and decided on again. That second
    reading finds the other writer's final status, so the loop ends: a
    scan's metadata is written once at its start and once at its end.

    The report of a completed scan, the metadata and the team index entry
    are written by that one EXEC: a reader that finds "completed" finds
    the report, and a scan that ends otherwise never has one.
    """
    key = metadata_key(scan_id)
    with redis.pipeline() as pipe:
        while True:
            try:
                pipe.watch(key)
                metadata = _decode_metadata(pipe.get(key))
                if metadata is None:
                    return "missing"
                if metadata.get("status") in FINAL_STATUSES:
                    return metadata["status"]
                metadata["status"] = status
                metadata[time_field] = at
                if reason is not None:
                    metadata["failure_reason"] = reason
                ttl = retention_seconds()
                pipe.multi()
                if report is not None:
                    pipe.setex(report_key(scan_id), ttl, encode_report(report))
                pipe.setex(key, ttl, json.dumps(metadata))
                pipe.zadd(team_index_key(metadata["team_id"]), {scan_id: _now() + ttl})
                pipe.execute()
                break
            except WatchError:
                continue
    _tidy_index(redis, metadata["team_id"])
    return None


def complete_scan(
    redis, scan_id: str, report: Dict[str, Any], completed_at: str
) -> bool:
    """Store a scan's report and mark it completed, if it is still in progress.

    Returns True when it did. Returns False, and stores nothing, when the
    scan's metadata is gone (the report could not be attributed to a team)
    or when the scan already has a final status: a scan cancelled while it
    ran stays cancelled, and has no report.
    """
    refused = _end_scan(redis, scan_id, "completed", "completed_at", completed_at, report)
    if refused == "missing":
        logger.warning("Scan %s completed but has no metadata; report dropped", scan_id)
    elif refused is not None:
        logger.info(
            "Scan %s completed but is already %s; report dropped", scan_id, refused
        )
    return refused is None


# Why a scan failed, when the worker knows a reason that is not in the
# task's own error: kept in the scan's metadata as ``failure_reason``.
#
# The scan ran to its end and the store did not take its report (#788).
REPORT_NOT_STORED = "report_not_stored"


def fail_scan(
    redis, scan_id: str, failed_at: str, reason: Optional[str] = None
) -> None:
    """Mark a scan that is still in progress as failed, with ``reason`` in
    its metadata (``failure_reason``) when there is one to keep."""
    _end_scan(redis, scan_id, "failed", "failed_at", failed_at, reason=reason)


def cancel_scan(redis, scan_id: str, cancelled_at: str) -> bool:
    """Mark a scan that is still in progress as cancelled.

    Returns True when it did. A scan that is gone, or that already has a
    final status, is left exactly as it is and the answer is False: a
    completed scan stays completed, with its completion time and its
    report. DELETE /api/v1/scans/{id} used to write "cancelled" over
    whatever the scan's status was (#766).

    The status is read here, in the transaction that writes it, not taken
    from the caller: a scan the worker finished while the caller was
    revoking its task is not overwritten with what the caller read before.
    """
    return _end_scan(redis, scan_id, "cancelled", "cancelled_at", cancelled_at) is None
