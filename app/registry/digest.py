"""Resolve an image reference to the digest of the bytes it currently points at.

This is a manifest ``HEAD``, not a layer pull, which is what makes the skip
invariant cheap: one small request tells us whether a full scan could possibly
produce a different answer.

It still costs a token against the registry budget, because registries count
manifest requests toward their pull limits.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

DOCKER_HUB_HOST = "registry-1.docker.io"

_MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
    )
)

_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


class RegistryError(RuntimeError):
    """Transient registry problem: worth retrying."""


class ImageNotFound(RegistryError):
    """The reference does not exist. Retrying will not help."""


@dataclass(frozen=True, slots=True)
class ImageReference:
    host: str
    repository: str
    tag: str

    @property
    def budget_key(self) -> str:
        """Token buckets are per registry host, since that is what rate-limits us."""
        return self.host


def parse_reference(name: str, tag: str) -> ImageReference:
    """Split ``name`` into a registry host and repository path.

    A leading component is a host only if it looks like one (contains a dot or a
    port, or is localhost); otherwise the whole thing is a Docker Hub repository,
    and a single-component name lives under ``library/``.
    """
    head, _, rest = name.partition("/")
    if rest and ("." in head or ":" in head or head == "localhost"):
        return ImageReference(host=head, repository=rest, tag=tag)
    repository = name if "/" in name else f"library/{name}"
    return ImageReference(host=DOCKER_HUB_HOST, repository=repository, tag=tag)


def _parse_challenge(header: str) -> dict[str, str]:
    return dict(_CHALLENGE.findall(header))


def _fetch_token(client: httpx.Client, challenge: dict[str, str]) -> str | None:
    realm = challenge.get("realm")
    if not realm:
        return None
    params = {k: v for k, v in challenge.items() if k in ("service", "scope") and v}
    response = client.get(realm, params=params)
    if response.status_code != 200:
        raise RegistryError(f"auth failed at {realm}: HTTP {response.status_code}")
    payload = response.json()
    return payload.get("token") or payload.get("access_token")


def resolve_digest(reference: ImageReference, *, timeout: float = 30.0) -> str:
    """Return the ``Docker-Content-Digest`` for the reference.

    Follows the standard bearer-token challenge, so this works against Docker Hub
    and any other v2 registry without special-casing.
    """
    url = f"https://{reference.host}/v2/{reference.repository}/manifests/{reference.tag}"
    headers = {"Accept": _MANIFEST_ACCEPT}

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.head(url, headers=headers)

            if response.status_code == 401:
                challenge = _parse_challenge(response.headers.get("WWW-Authenticate", ""))
                token = _fetch_token(client, challenge)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    response = client.head(url, headers=headers)

            if response.status_code == 404:
                raise ImageNotFound(f"{reference.repository}:{reference.tag} not found")
            if response.status_code != 200:
                raise RegistryError(
                    f"manifest HEAD returned HTTP {response.status_code} "
                    f"for {reference.repository}:{reference.tag}"
                )

            digest = response.headers.get("Docker-Content-Digest")
            if not digest:
                # Some registries omit the header on HEAD; fall back to a GET, whose
                # body we discard.
                response = client.get(url, headers=headers)
                digest = response.headers.get("Docker-Content-Digest")
            if not digest:
                raise RegistryError("registry did not return Docker-Content-Digest")
            return digest
    except httpx.HTTPError as exc:
        raise RegistryError(f"registry request failed: {exc}") from exc
