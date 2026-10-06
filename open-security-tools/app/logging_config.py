"""Logging configuration for the application."""

import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict
from app.config import settings
from open_security_shared.log_safety import quiet_http_client_loggers

# The fields of a record that reach the log, by name. A field is added to a
# record with ``logger.info(..., extra={...})``; it is written only if it is
# named here, so what a line can carry is decided in one reviewed place and
# not at each call (#755). The names say what a request was, never what it
# held: no ``input``, no ``body``, no ``headers``, no ``url`` with its query,
# no exception text. tests/unit/test_no_input_values_in_logs.py fails if a
# name that holds a request's content is added.
LOGGED_FIELDS = (
    "request_id",
    "tool",
    "tool_name",
    "user_id",
    "team_id",
    "input_fields",
    "task_id",
    "execution_id",
    "method",
    "path",
    "client_ip",
    "user_agent",
    "status",
    "status_code",
    "duration",
    "timeout",
    "active_executions",
    "lost_starts",
    "reason",
    "error_type",
)


class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # The record's own fields. This read ``record.extra``, which logging
        # never sets (``extra={...}`` becomes attributes of the record), so
        # no field was ever written: not the request id, not the tool.
        for name in LOGGED_FIELDS:
            value = getattr(record, name, None)
            if value is not None:
                log_entry[name] = value

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False, default=str)


def configure_logging() -> None:
    """Configure application logging with JSON formatting."""

    # Create JSON formatter
    formatter = JSONFormatter()

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper()),
        handlers=[console_handler],
        format="%(message)s"
    )

    # Set specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    # httpx logs "HTTP Request: GET https://target/path?query" at INFO: for a
    # tool that address is the caller's input, credentials in the URL
    # included. The HTTP client libraries say warnings and errors only,
    # whatever LOG_LEVEL is (#755).
    quiet_http_client_loggers()


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the specified name."""
    return logging.getLogger(name)
