"""
Observability wiring shared by every Wildbox service.

Provides three things a service gets by calling ``install_observability(app, ...)``:

1. **Correlation.** A ``X-Request-ID`` is taken from the inbound header (the
   gateway sets it) or generated, put on ``request.state.request_id``, echoed on
   the response, and made available to the logging and error layers. Previously
   only the tools service minted an id, and it never crossed a boundary.

2. **Metrics.** Request count and latency by method, path template and status,
   exposed in Prometheus exposition format at ``/metrics``. Domain counters are
   available for services to increment (see ``outcome_counter``).

3. **Tracing (optional).** If ``open_security_shared.tracing`` and its
   OpenTelemetry dependencies are installed, tracing is initialised; otherwise
   this is a no-op and the service still starts.

prometheus_client is an optional dependency: if it is absent the middleware
degrades to correlation only, so a service cannot fail to boot because of it.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Optional

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-ID"

try:  # pragma: no cover - exercised by presence/absence of the dependency
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    PROMETHEUS_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain"

_REGISTRY = None
_HTTP_REQUESTS = None
_HTTP_LATENCY = None
_OUTCOME_COUNTERS: dict = {}


def _init_metrics(service_name: str):
    """Create the process-wide collectors once."""
    global _REGISTRY, _HTTP_REQUESTS, _HTTP_LATENCY
    if not PROMETHEUS_AVAILABLE or _REGISTRY is not None:
        return
    _REGISTRY = CollectorRegistry()
    _HTTP_REQUESTS = Counter(
        "wildbox_http_requests_total",
        "HTTP requests handled, by method, route template and status.",
        ["service", "method", "path", "status"],
        registry=_REGISTRY,
    )
    _HTTP_LATENCY = Histogram(
        "wildbox_http_request_duration_seconds",
        "HTTP request duration in seconds.",
        ["service", "method", "path"],
        registry=_REGISTRY,
    )


def outcome_counter(name: str, documentation: str, labelnames: tuple = ("outcome",)):
    """
    Return (and lazily create) a domain counter for a business outcome.

    Use this for the things an operator alerts on -- tool executions, collection
    runs, scans -- rather than only for HTTP status codes::

        outcome_counter("wildbox_tool_executions_total",
                        "Tool executions by outcome.").labels(outcome="completed").inc()
    """
    if not PROMETHEUS_AVAILABLE:
        return _NullMetric()
    _init_metrics("shared")
    if name not in _OUTCOME_COUNTERS:
        _OUTCOME_COUNTERS[name] = Counter(
            name, documentation, list(labelnames), registry=_REGISTRY
        )
    return _OUTCOME_COUNTERS[name]


class _NullMetric:
    """No-op stand-in so call sites need no conditionals."""

    def labels(self, *args, **kwargs):
        return self

    def inc(self, *args, **kwargs):
        return None

    def observe(self, *args, **kwargs):
        return None


def _route_template(request: Request) -> str:
    """Path template (not the concrete path) to keep metric cardinality bounded."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if path:
        return path
    return "unmatched"


API_VERSION_HEADER = "X-API-Version"
SERVICE_HEADER = "X-Wildbox-Service"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Correlation id in, metrics and version out."""

    def __init__(self, app, service_name: str, service_version: str = "unknown"):
        super().__init__(app)
        self.service_name = service_name
        self.service_version = service_version

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get(REQUEST_ID_HEADER) or str(uuid.uuid4())
        request.state.request_id = request_id

        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            response.headers[REQUEST_ID_HEADER] = request_id
            # Every response says which contract answered it. Nothing used to
            # carry a version: the path said /v1 and no service validated it, and
            # the version a caller could observe from the OpenAPI document
            # disagreed with the one the root endpoint reported (WILDBO-API-04).
            response.headers[API_VERSION_HEADER] = self.service_version
            response.headers[SERVICE_HEADER] = self.service_name
            return response
        finally:
            duration = time.perf_counter() - start
            if PROMETHEUS_AVAILABLE and _HTTP_REQUESTS is not None:
                path = _route_template(request)
                try:
                    _HTTP_REQUESTS.labels(
                        service=self.service_name,
                        method=request.method,
                        path=path,
                        status=str(status_code),
                    ).inc()
                    _HTTP_LATENCY.labels(
                        service=self.service_name, method=request.method, path=path
                    ).observe(duration)
                except (
                    Exception
                ):  # pragma: no cover - metrics must never break a request
                    logger.debug("metric emission failed", exc_info=True)


def metrics_response() -> Response:
    """Prometheus exposition format, for a service's /metrics route."""
    if not PROMETHEUS_AVAILABLE or _REGISTRY is None:
        return Response(
            content="# prometheus_client is not installed in this service\n",
            media_type="text/plain",
            status_code=501,
        )
    return Response(content=generate_latest(_REGISTRY), media_type=CONTENT_TYPE_LATEST)


def install_observability(
    app: FastAPI,
    service_name: str,
    service_version: str = "unknown",
    enable_tracing: bool = True,
    metrics_path: Optional[str] = "/metrics",
) -> None:
    """
    Install correlation, metrics and (optionally) tracing on a FastAPI app.

    Call once, from the application module, next to install_error_handlers.
    """
    _init_metrics(service_name)
    app.add_middleware(
        ObservabilityMiddleware,
        service_name=service_name,
        service_version=service_version,
    )

    if metrics_path:

        async def _metrics_endpoint() -> Response:
            return metrics_response()

        app.add_api_route(
            metrics_path,
            _metrics_endpoint,
            methods=["GET"],
            include_in_schema=False,
            name="prometheus_metrics",
        )

    if enable_tracing:
        try:
            from open_security_shared.tracing import (  # noqa: WPS433
                setup_wildbox_service_tracing,
            )

            setup_wildbox_service_tracing(service_name=service_name, app=app)
            logger.info("Tracing initialised for %s", service_name)
        except ImportError:
            logger.info(
                "Tracing not initialised for %s: OpenTelemetry extras not installed "
                "(pip install 'open-security-shared[observability]')",
                service_name,
            )
        except Exception:  # pragma: no cover - tracing must never block startup
            logger.warning("Tracing setup failed for %s", service_name, exc_info=True)
