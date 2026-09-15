"""Structured logging with cross-process correlation.

One scan crosses three processes: the scheduler enqueues it, a worker claims and
executes it, the API later serves what it found. What ties those together is the
*job*, not any one process's lifetime -- so every line emitted while a job is in
flight carries its id, the image reference and the digest actually scanned.

Those fields come from a context variable rather than from call signatures. The
alternative is threading a logger through ``_execute`` -> ``persist`` ->
``queue``, which makes every function in the path know about logging in order to
preserve one identifier; correlation is ambient to the work, so it is stored that
way.

JSON is the default because the fields exist to be filtered on -- ``job_id == 41``
reconstructs a scan's whole lifecycle -- and a collector should not have to parse
prose to do it. ``SCANNER_LOG_FORMAT=text`` gives the human-readable form for
tailing ``docker compose logs``.
"""
from __future__ import annotations

import json
import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, TextIO

from app.config import Settings, get_settings

_context: ContextVar[dict[str, Any] | None] = ContextVar("log_context", default=None)


def _current() -> dict[str, Any]:
    return _context.get() or {}


#: Attributes every LogRecord already carries. Anything outside this set was passed
#: by a caller as ``extra=`` and belongs in the payload, which is what lets
#: ``log.info("...", extra={"digest": d})`` work without registering a field first.
#: Derived from a throwaway record rather than hard-coded, so a new attribute in a
#: future Python does not start leaking into every log line.
_RESERVED = frozenset(
    logging.LogRecord("", 0, "", 0, "", None, None).__dict__
) | {"asctime", "message", "taskName", "context"}


@contextmanager
def bound(**fields: Any) -> Iterator[None]:
    """Attach ``fields`` to every log line emitted inside this block."""
    token = _context.set({**_current(), **fields})
    try:
        yield
    finally:
        _context.reset(token)


def bind(**fields: Any) -> None:
    """Attach ``fields`` for the rest of the current context.

    For facts discovered partway through a block that is already ``bound`` -- the
    digest is only known after the registry answers, but the lines after that should
    carry it. The enclosing ``bound`` is what removes them again.
    """
    _context.set({**_current(), **fields})


def context() -> dict[str, Any]:
    """The currently bound fields. For handlers that report an error out-of-band."""
    return _current()


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.context = _current()
        return True


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str) -> None:
        super().__init__()
        self.service = service

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "service": self.service,
            "logger": record.name,
            "msg": record.getMessage(),
            **getattr(record, "context", {}),
            **{k: v for k, v in record.__dict__.items() if k not in _RESERVED},
        }
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        # default=str so that a datetime or an Enum in a bound field degrades to a
        # readable string instead of taking down the logging call that reports the
        # failure it was describing.
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """The same fields, laid out for a human."""

    def __init__(self, service: str) -> None:
        super().__init__(f"%(asctime)s %(levelname)s {service}/%(name)s %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        fields = {
            **getattr(record, "context", {}),
            **{k: v for k, v in record.__dict__.items() if k not in _RESERVED},
        }
        if fields:
            line += " " + " ".join(f"{k}={v}" for k, v in fields.items())
        return line


def make_handler(
    service: str, settings: Settings, stream: TextIO | None = None
) -> logging.Handler:
    """A handler in the configured format, writing to ``stream`` (default stdout)."""
    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.addFilter(_ContextFilter())
    handler.setFormatter(
        JsonFormatter(service) if settings.log_format == "json" else TextFormatter(service)
    )
    return handler


def configure(service: str, settings: Settings | None = None) -> None:
    """Install the root handler for a process. Call once, at startup."""
    settings = settings or get_settings()
    handler = make_handler(service, settings)

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(settings.log_level.upper())

    # Uvicorn installs its own handlers with propagate=False, which would put plain
    # text beside our JSON on the same stream. Its access log is dropped outright:
    # the request middleware emits the same line with the request id attached.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = name != "uvicorn.access"

    # httpx logs every request at INFO, and resolving one digest costs three of them
    # (401, token, 200) because tokens are not cached -- three lines per image per
    # cycle, or 3000 at the scale this is designed for, none of them decisions this
    # system made. Failures still surface at WARNING. Suppressed only above DEBUG, so
    # SCANNER_LOG_LEVEL=DEBUG still shows the whole registry conversation -- which is
    # the one time it is worth reading.
    if root.level > logging.DEBUG:
        logging.getLogger("httpx").setLevel(logging.WARNING)
