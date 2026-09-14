"""Deterministic spread for first scans.

Random jitter re-rolls on every restart, which lets the herd re-converge. Hashing
the image id gives each image a fixed offset in the interval, so the load stays
spread for the life of the deployment.
"""
from __future__ import annotations

import hashlib


def jitter_offset(image_id: int, interval_seconds: int) -> int:
    """A stable offset in ``[0, interval_seconds)`` for this image."""
    if interval_seconds <= 0:
        return 0
    digest = hashlib.sha256(str(image_id).encode()).digest()
    return int.from_bytes(digest[:8], "big") % interval_seconds
