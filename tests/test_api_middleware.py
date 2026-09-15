"""Request correlation and the API's error boundary.

Driven against a throwaway app rather than the real one: the behaviour under test is
the middleware, and the only way to exercise the boundary is a route that raises,
which the real API deliberately does not have. No database.
"""
from __future__ import annotations

import io
import json
import logging

import httpx
import pytest
from fastapi import FastAPI

from app.api.middleware import REQUEST_ID_HEADER, request_context, unhandled_error
from app.config import Settings
from app.obs.logging import make_handler


@pytest.fixture
def app() -> FastAPI:
    app = FastAPI()
    app.middleware("http")(request_context)
    app.add_exception_handler(Exception, unhandled_error)

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    @app.get("/boom")
    async def boom():
        raise RuntimeError("the database went away")

    return app


@pytest.fixture
async def client(app):
    # raise_app_exceptions=False because Starlette re-raises after its error handler
    # has produced the response -- so the 500 the caller actually receives is only
    # observable with the re-raise suppressed. Uvicorn does the same thing in
    # production: it logs the re-raise and sends the response we built.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as http:
        yield http


@pytest.fixture
def json_logs():
    """The middleware's own log lines, parsed.

    Into a buffer rather than through ``capsys``: a StreamHandler binds its stream at
    construction, and pytest swaps stdout between the setup and call phases, so a
    handler built in a fixture writes into the phase the test can no longer read.
    """
    buffer = io.StringIO()
    root = logging.getLogger()
    saved, level = root.handlers[:], root.level
    root.handlers = [make_handler("api", Settings(log_format="json", log_level="INFO"), buffer)]
    root.setLevel(logging.INFO)

    def emitted() -> list[dict]:
        return [
            payload
            for line in buffer.getvalue().splitlines()
            if line and (payload := json.loads(line))["logger"] == "api"
        ]

    yield emitted
    root.handlers, root.level = saved, level


class TestRequestId:
    async def test_is_generated_and_echoed_when_the_caller_sends_none(self, client):
        response = await client.get("/ok")
        assert response.headers[REQUEST_ID_HEADER]

    async def test_a_caller_supplied_id_is_preserved(self, client):
        # So the id spans more than this process: a proxy or an upstream service that
        # already has one keeps it, and both logs join on the same value.
        response = await client.get("/ok", headers={REQUEST_ID_HEADER: "abc-123"})
        assert response.headers[REQUEST_ID_HEADER] == "abc-123"

    async def test_two_requests_do_not_share_an_id(self, client):
        first = (await client.get("/ok")).headers[REQUEST_ID_HEADER]
        second = (await client.get("/ok")).headers[REQUEST_ID_HEADER]
        assert first != second


class TestAccessLog:
    async def test_one_line_per_request_with_method_path_status_and_timing(
        self, client, json_logs
    ):
        await client.get("/ok", headers={REQUEST_ID_HEADER: "abc-123"})
        line = json_logs()[-1]
        assert line["msg"] == "request"
        assert (line["method"], line["path"], line["status"]) == ("GET", "/ok", 200)
        assert line["request_id"] == "abc-123"
        assert line["duration_ms"] >= 0

    async def test_health_is_logged_below_info(self, client, json_logs, app):
        # The container healthcheck polls /health every 15 seconds; at INFO it would
        # be most of the log.
        @app.get("/health")
        async def health():
            return {"status": "ok"}

        await client.get("/health")
        assert json_logs() == []


class TestErrorBoundary:
    async def test_an_unhandled_exception_becomes_a_500_naming_the_request_id(self, client):
        response = await client.get("/boom", headers={REQUEST_ID_HEADER: "abc-123"})
        assert response.status_code == 500
        assert response.json() == {"detail": "internal server error", "request_id": "abc-123"}
        assert response.headers[REQUEST_ID_HEADER] == "abc-123"

    async def test_the_response_body_does_not_leak_the_cause(self, client):
        # The trace belongs in the log, under the id the caller can quote back.
        assert "database went away" not in (await client.get("/boom")).text

    async def test_the_failure_is_logged_with_its_traceback_and_the_request_id(
        self, client, json_logs
    ):
        await client.get("/boom", headers={REQUEST_ID_HEADER: "abc-123"})
        failure = next(line for line in json_logs() if line["msg"] == "request failed")
        assert failure["request_id"] == "abc-123"
        assert failure["path"] == "/boom"
        assert "RuntimeError: the database went away" in failure["error"]
