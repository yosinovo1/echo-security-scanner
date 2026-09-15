"""Request correlation and the API's error boundary.

The rest of this system treats failure as a queryable row -- ``scan_run`` exists so
that a failed scan leaves evidence rather than a log line. The API had no equivalent:
an unhandled exception in a route produced a bare 500 with nothing tying it to the
request that caused it. These two pieces close that, and they are deliberately the
*only* cross-cutting API machinery: everything else a request needs is an explicit
dependency in ``deps.py``.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse

from app.obs.logging import bound

log = logging.getLogger("api")

#: Honoured on the way in, echoed on the way out. A proxy or a caller that already
#: has a correlation id keeps it, so the id spans more than this process.
REQUEST_ID_HEADER = "X-Request-ID"


async def request_context(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Bind a request id, emit one access line, and time the request."""
    request_id = request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex[:16]
    request.state.request_id = request_id
    started = time.perf_counter()

    def elapsed_ms() -> float:
        return round((time.perf_counter() - started) * 1000, 1)

    with bound(request_id=request_id):
        try:
            response = await call_next(request)
        except Exception:
            # Logged here rather than in the handler below: this is the only place
            # the method, path, duration and request id are all in scope together.
            log.exception(
                "request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration_ms": elapsed_ms(),
                },
            )
            raise

        response.headers[REQUEST_ID_HEADER] = request_id
        # The container healthcheck hits /health every 15 seconds; at INFO it would
        # be most of the log. Errors there still surface, because the level below
        # only applies to a response that succeeded.
        level = logging.DEBUG if request.url.path == "/health" else logging.INFO
        if response.status_code >= 500:
            level = logging.ERROR
        log.log(
            level,
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": elapsed_ms(),
            },
        )
        return response


async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:
    """Return the request id instead of a stack trace.

    The trace is already in the log under this id, so a caller reporting "it broke"
    hands over the one token that finds it -- without the response body describing
    the query that failed.
    """
    request_id = getattr(request.state, "request_id", None)
    return JSONResponse(
        status_code=500,
        content={"detail": "internal server error", "request_id": request_id},
        headers={REQUEST_ID_HEADER: request_id} if request_id else None,
    )
