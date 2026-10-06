"""What a collector may log, and store, about a request that failed (#755).

A feed is fetched with a URL and, often, a key: in a header, in the query
string, or in the path itself (URLVoid's is ``/1000/<key>/host/<domain>``).
The text of an HTTP client's error ends with the URL it could not fetch, so
logging it, or storing it as the run's error, wrote the key into the log and
into ``collection_runs.error_message`` and ``sources.last_error``.

``host_of`` names a URL by its host; ``describe_error`` says what failed
without the text: the status an HTTP error came with, the class otherwise.
"""

from typing import Any
from urllib.parse import urlsplit

NO_HOST = "(no host)"


def host_of(url: Any) -> str:
    """The host of a URL, and its port if it names one; nothing else."""
    try:
        parts = urlsplit(str(url or ""))
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return NO_HOST
    if not host:
        return NO_HOST
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def describe_error(error: BaseException) -> str:
    """``ClientResponseError (HTTP 404)`` or ``ClientConnectorError``.

    The class, and the HTTP status when the error has one: enough to tell a
    feed that is gone from one that refuses the key, and nothing that was
    part of the request.
    """
    name = type(error).__name__
    status = getattr(error, "status", None)
    if isinstance(status, int) and not isinstance(status, bool) and status > 0:
        return f"{name} (HTTP {status})"
    return name
