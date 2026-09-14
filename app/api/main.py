"""FastAPI application.

Read-only against Postgres. This image does not contain Trivy: scanning lives in the
worker, so the API has no heavy dependency and no scan load competing with requests.
"""
from __future__ import annotations

from fastapi import FastAPI

from app.api.routes import cves, health, images

app = FastAPI(
    title="Container Security Scanner",
    version="1.0.0",
    description=(
        "Query CVE findings produced by periodic Trivy scans of container images.\n\n"
        "Severity is reported per finding, because vendors rate the same CVE "
        "differently across distributions; `max_severity` on a CVE is a rollup "
        "across every scanned image."
    ),
)

app.include_router(health.router)
app.include_router(images.router)
app.include_router(cves.router)
