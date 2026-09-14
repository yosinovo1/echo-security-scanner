"""Registry client behaviour: reference parsing, digest resolution, and throttling.

Throttling is the interesting half. There is no local model of a registry's rate
limit any more, so correctness here *is* the backpressure story: a 429 has to be
distinguishable from a failure, and the registry's own ``Retry-After`` has to survive
intact all the way to ``queue.defer``.

The HTTP boundary is driven with ``httpx.MockTransport`` rather than a live registry,
so these run offline and deterministically.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from app.registry import digest as registry
from app.registry.digest import (
    DOCKER_HUB_HOST,
    ImageNotFound,
    ImageReference,
    RateLimited,
    parse_reference,
    parse_retry_after,
    resolve_digest,
)

DIGEST = "sha256:" + "ab" * 32
REF = ImageReference(host="registry.test", repository="library/nginx", tag="1.19")


@pytest.fixture
def registry_responds(monkeypatch):
    """Point the module's httpx.Client at a handler instead of the network."""

    real_client = httpx.Client  # captured before patching, or factory recurses

    def install(handler):
        def factory(**kwargs):
            kwargs.pop("transport", None)
            return real_client(transport=httpx.MockTransport(handler), **kwargs)

        monkeypatch.setattr(registry.httpx, "Client", factory)

    return install


class TestReferenceParsing:
    def test_single_component_name_lives_under_library(self):
        ref = parse_reference("nginx", "1.19")
        assert ref.host == DOCKER_HUB_HOST
        assert ref.repository == "library/nginx"
        assert ref.tag == "1.19"

    def test_two_component_docker_hub_name_is_left_alone(self):
        ref = parse_reference("bitnami/redis", "6.0")
        assert ref.host == DOCKER_HUB_HOST
        assert ref.repository == "bitnami/redis"

    @pytest.mark.parametrize(
        "name,host,repository",
        [
            ("ghcr.io/acme/api", "ghcr.io", "acme/api"),
            ("registry.example.com/team/app", "registry.example.com", "team/app"),
            ("localhost/dev", "localhost", "dev"),
            ("localhost:5000/dev", "localhost:5000", "dev"),
        ],
    )
    def test_leading_component_is_a_host_only_when_it_looks_like_one(
        self, name, host, repository
    ):
        ref = parse_reference(name, "latest")
        assert (ref.host, ref.repository) == (host, repository)


class TestRetryAfter:
    """RFC 9110 allows two forms, and registries send both."""

    def test_delta_seconds(self):
        assert parse_retry_after("120") == 120

    def test_http_date_becomes_a_delay_from_now(self):
        when = datetime.now(UTC) + timedelta(seconds=120)
        parsed = parse_retry_after(format_datetime(when, usegmt=True))
        assert parsed is not None and 110 <= parsed <= 125

    def test_date_already_in_the_past_is_clamped_to_zero(self):
        when = datetime.now(UTC) - timedelta(hours=1)
        assert parse_retry_after(format_datetime(when, usegmt=True)) == 0

    def test_absent_header_is_no_answer_rather_than_zero(self):
        # None means "the registry did not say"; the worker then picks its own
        # fallback. Zero would mean "retry immediately", which is the opposite.
        assert parse_retry_after(None) is None

    def test_junk_is_no_answer(self):
        assert parse_retry_after("soon") is None


class TestDigestResolution:
    def test_returns_the_content_digest(self, registry_responds):
        registry_responds(
            lambda request: httpx.Response(200, headers={"Docker-Content-Digest": DIGEST})
        )
        assert resolve_digest(REF) == DIGEST

    def test_missing_header_on_head_falls_back_to_get(self, registry_responds):
        def handler(request):
            if request.method == "HEAD":
                return httpx.Response(200)
            return httpx.Response(200, headers={"Docker-Content-Digest": DIGEST})

        registry_responds(handler)
        assert resolve_digest(REF) == DIGEST

    def test_bearer_challenge_is_followed(self, registry_responds):
        seen = {}

        def handler(request):
            if "auth" in str(request.url):
                return httpx.Response(200, json={"token": "t0ken"})
            if "Authorization" not in request.headers:
                return httpx.Response(
                    401,
                    headers={
                        "WWW-Authenticate": 'Bearer realm="https://auth.test/token",'
                        'service="registry.test"'
                    },
                )
            seen["auth"] = request.headers["Authorization"]
            return httpx.Response(200, headers={"Docker-Content-Digest": DIGEST})

        registry_responds(handler)
        assert resolve_digest(REF) == DIGEST
        assert seen["auth"] == "Bearer t0ken"

    def test_unknown_reference_is_permanent(self, registry_responds):
        registry_responds(lambda request: httpx.Response(404))
        with pytest.raises(ImageNotFound):
            resolve_digest(REF)


class TestThrottling:
    """A 429 is backpressure, and must arrive as something other than an error."""

    def test_429_raises_rate_limited_carrying_retry_after(self, registry_responds):
        registry_responds(
            lambda request: httpx.Response(429, headers={"Retry-After": "300"})
        )
        with pytest.raises(RateLimited) as excinfo:
            resolve_digest(REF)
        assert excinfo.value.retry_after == 300

    def test_429_without_retry_after_leaves_the_delay_to_the_caller(
        self, registry_responds
    ):
        registry_responds(lambda request: httpx.Response(429))
        with pytest.raises(RateLimited) as excinfo:
            resolve_digest(REF)
        assert excinfo.value.retry_after is None

    def test_throttling_the_token_endpoint_is_also_backpressure(self, registry_responds):
        # Docker Hub rate-limits auth separately, and a failure here previously looked
        # like a generic auth error -- which would burn a retry instead of deferring.
        def handler(request):
            if "auth" in str(request.url):
                return httpx.Response(429, headers={"Retry-After": "60"})
            return httpx.Response(
                401, headers={"WWW-Authenticate": 'Bearer realm="https://auth.test/token"'}
            )

        registry_responds(handler)
        with pytest.raises(RateLimited) as excinfo:
            resolve_digest(REF)
        assert excinfo.value.retry_after == 60

    def test_rate_limited_is_a_registry_error_so_nothing_escapes_the_worker(self):
        # The worker catches RateLimited before RegistryError; this guarantees that an
        # ordering mistake degrades to "retried" rather than "crashed the loop".
        assert issubclass(RateLimited, registry.RegistryError)
