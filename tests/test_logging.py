"""Structured logging: what ends up in a line, and what must not leak between them.

No database. The interesting behaviour is entirely in the formatter and the context
variable -- specifically that a bound field survives a nested call and is gone again
afterwards, because correlation that leaks across jobs is worse than no correlation:
it attributes one scan's failure to the next image in the loop.
"""
from __future__ import annotations

import json
import logging
import sys

import pytest

from app.config import Settings
from app.obs.logging import JsonFormatter, TextFormatter, bind, bound, configure, context


def _record(msg: str = "hello", **extra) -> logging.LogRecord:
    record = logging.LogRecord("test", logging.INFO, __file__, 1, msg, None, None)
    record.__dict__.update(extra)
    record.context = context()
    return record


def _emitted(**extra) -> dict:
    return json.loads(JsonFormatter("worker").format(_record(**extra)))


class TestJsonFormat:
    def test_carries_the_service_and_message(self):
        payload = _emitted()
        assert payload["service"] == "worker"
        assert payload["msg"] == "hello"
        assert payload["level"] == "INFO"
        assert payload["ts"].endswith("+00:00")

    def test_extra_fields_become_top_level_keys(self):
        # The point of the format: `duration_ms > 5000` is a filter, not a regex over
        # a sentence.
        assert _emitted(duration_ms=4210, findings=17)["duration_ms"] == 4210

    def test_record_internals_do_not_leak_into_the_payload(self):
        payload = _emitted()
        assert "args" not in payload
        assert "context" not in payload
        assert "stack_info" not in payload

    def test_unserialisable_values_degrade_instead_of_raising(self):
        # A log call is often the last thing standing in a failure path; it must not
        # be the thing that raises.
        class Opaque:
            def __repr__(self) -> str:
                return "<opaque>"

        assert _emitted(thing=Opaque())["thing"] == "<opaque>"

    def test_exceptions_are_rendered_into_the_line(self):
        try:
            raise ValueError("boom")
        except ValueError:
            record = _record("failed")
            record.exc_info = sys.exc_info()
        payload = json.loads(JsonFormatter("worker").format(record))
        assert "ValueError: boom" in payload["error"]


class TestBinding:
    def test_bound_fields_appear_on_every_line_inside_the_block(self):
        with bound(job_id=41, image="nginx:1.19"):
            payload = _emitted()
        assert payload["job_id"] == 41
        assert payload["image"] == "nginx:1.19"

    def test_fields_do_not_survive_the_block(self):
        # The invariant that matters: one job's id must never appear on the next
        # job's lines, or the log attributes a failure to the wrong image.
        with bound(job_id=41):
            pass
        assert "job_id" not in _emitted()

    def test_nested_binds_accumulate_and_unwind_to_the_outer_scope(self):
        with bound(job_id=41):
            with bound(digest="sha256:abc"):
                assert context() == {"job_id": 41, "digest": "sha256:abc"}
            assert context() == {"job_id": 41}

    def test_bind_adds_a_field_discovered_partway_through(self):
        # The worker's case: the digest is only known once the registry answers, but
        # every line after that should carry it.
        with bound(job_id=41):
            bind(digest="sha256:abc")
            assert _emitted()["digest"] == "sha256:abc"
        assert context() == {}

    def test_an_explicit_extra_wins_over_a_bound_field_of_the_same_name(self):
        with bound(image="nginx:1.19"):
            assert _emitted(image="redis:6.0")["image"] == "redis:6.0"


class TestTextFormat:
    def test_appends_bound_fields_for_a_human(self):
        with bound(job_id=41):
            line = TextFormatter("worker").format(_record(duration_ms=12))
        assert "worker/test hello" in line
        assert "job_id=41" in line
        assert "duration_ms=12" in line


@pytest.fixture
def restore_root_logging():
    """configure() replaces the root handler; leave the rest of the suite as found."""
    root = logging.getLogger()
    saved, level = root.handlers[:], root.level
    yield
    root.handlers, root.level = saved, level


class TestConfigure:
    def test_installs_exactly_one_handler_and_is_idempotent(
        self, capsys, restore_root_logging
    ):
        settings = Settings(log_format="json", log_level="INFO")
        configure("worker", settings)
        configure("worker", settings)

        root = logging.getLogger()
        assert len(root.handlers) == 1

        logging.getLogger("worker").info("up", extra={"replica": 2})
        payload = json.loads(capsys.readouterr().out.strip())
        assert payload["service"] == "worker" and payload["replica"] == 2

    def test_text_format_is_selectable(self, capsys, restore_root_logging):
        configure("scheduler", Settings(log_format="text", log_level="INFO"))
        logging.getLogger("scheduler").info("tick")
        assert "scheduler/scheduler tick" in capsys.readouterr().out
