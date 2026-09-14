"""Runtime configuration, sourced from SCANNER_* environment variables."""
from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANNER_", env_file=".env", extra="ignore")

    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = "scanner"
    postgres_password: str = "scanner"
    postgres_db: str = "scanner"

    # Scheduling. The brief's 15 minutes is the default; per-image overrides live in
    # image.scan_interval_seconds.
    default_scan_interval_seconds: int = 900
    scheduler_tick_seconds: int = 10

    # Worker.
    worker_poll_seconds: int = 5
    #: Must exceed trivy_timeout_seconds: a lease that expires while the scan is
    #: still running gets reaped and re-claimed, so two workers would scan the same
    #: image at once. Enforced below.
    lease_seconds: int = 1200
    max_attempts: int = 5
    backoff_base_seconds: int = 30
    backoff_max_seconds: int = 3600

    # Trivy.
    trivy_bin: str = "trivy"
    #: Each worker's OWN scratch cache (layer/artifact metadata). Must be writable
    #: and must NOT be shared between workers: it is itself a bolt database, so
    #: sharing it reintroduces exactly the contention client mode exists to avoid.
    trivy_cache_dir: str = "/trivy-cache"
    #: Read-only mount of the trivy-server cache, used only to read
    #: db/metadata.json for the vulnerability DB version.
    trivy_db_dir: str = "/trivy-db"
    trivy_timeout_seconds: int = 900
    #: When set, workers scan via a shared Trivy server instead of opening the
    #: vulnerability database themselves. Required for more than one worker: the
    #: database is a single bbolt file, and concurrent openers serialise badly
    #: (measured: 6s uncontended vs 116s with two workers on one cache).
    trivy_server_url: str | None = None

    # There is deliberately no local registry rate limit. Registries publish their
    # own throttling via 429 + Retry-After, and that signal is authoritative where a
    # compiled-in ceiling is a guess that goes stale. See the README.

    # API pagination. The default is chosen so that an unparameterised request against
    # the brief's 10 images behaves exactly as the brief describes.
    page_size_default: int = 100
    page_size_max: int = 1000

    @model_validator(mode="after")
    def _lease_outlives_a_scan(self) -> Settings:
        if self.lease_seconds <= self.trivy_timeout_seconds:
            raise ValueError(
                f"lease_seconds ({self.lease_seconds}) must exceed "
                f"trivy_timeout_seconds ({self.trivy_timeout_seconds}), otherwise a "
                "slow scan loses its lease mid-flight and a second worker starts the "
                "same scan."
            )
        return self

    @property
    def _dsn_tail(self) -> str:
        return (
            f"{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def sync_dsn(self) -> str:
        """Worker / scheduler / Alembic."""
        return f"postgresql+psycopg://{self._dsn_tail}"

    @property
    def async_dsn(self) -> str:
        """API."""
        return f"postgresql+asyncpg://{self._dsn_tail}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
