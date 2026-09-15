"""Seed the image set from the brief.

Idempotent: safe to run on every start. Images added by hand are left alone, and
re-running never resets a per-image interval.
"""
from __future__ import annotations

import logging

from sqlalchemy.dialects.postgresql import insert

from app.db.session import sync_session
from app.domain.models import Image
from app.obs.logging import configure

log = logging.getLogger("seed")

BRIEF_IMAGES: tuple[tuple[str, str], ...] = (
    ("nginx", "1.19"),
    ("postgres", "12"),
    ("redis", "6.0"),
    ("node", "14-alpine"),
    ("python", "3.8-slim"),
    ("alpine", "3.12"),
    ("ubuntu", "20.04"),
    ("mysql", "8.0"),
    ("mongo", "4.4"),
    ("httpd", "2.4"),
)


def seed() -> int:
    with sync_session() as session:
        result = session.execute(
            insert(Image)
            .values([{"name": name, "tag": tag} for name, tag in BRIEF_IMAGES])
            .on_conflict_do_nothing(constraint="uq_image_name_tag")
            .returning(Image.id)
        )
        added = len(result.scalars().all())
        session.commit()
    return added


def main() -> None:
    configure("seed")
    added = seed()
    log.info("seed complete: %d image(s) added, %d in the brief", added, len(BRIEF_IMAGES))


if __name__ == "__main__":
    main()
