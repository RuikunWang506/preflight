"""Which GitHub repo built a package, according to its registry.

A package's `repository` field is whatever its publisher typed, so anyone can claim a
famous repo. Provenance is different: when a package is published from GitHub Actions
with trusted publishing, npm (its provenance statement) and PyPI (PEP 740 attestations)
record the repo whose workflow built it, and check that record when the package is
published. lookfirst reads what the registry recorded; it doesn't re-verify signatures.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any
from urllib.parse import quote

import httpx

from lookfirst.core.http import fetch
from lookfirst.targets.packages import normalize_source_repo

_NPM_HOSTS = frozenset({"registry.npmjs.org"})
_NPM_ATTESTATIONS = "https://registry.npmjs.org/-/npm/v1/attestations/"
_PYPI_HOSTS = frozenset({"pypi.org"})
_SLSA_V1 = "https://slsa.dev/provenance/v1"
_MAX_BYTES = 1024 * 1024


def _github_repo(value: object) -> str | None:
    repo = normalize_source_repo(value) if isinstance(value, str) else None
    return repo if repo and "/" in repo and "://" not in repo else None


def npm_built_from(client: httpx.Client, manifest: dict[str, Any]) -> str | None:
    """The `owner/repo` npm's provenance names for this version, or None if it has none."""
    dist = manifest.get("dist")
    attestations = dist.get("attestations") if isinstance(dist, dict) else None
    url = attestations.get("url") if isinstance(attestations, dict) else None
    if not isinstance(url, str) or not url.startswith(_NPM_ATTESTATIONS):
        return None
    result = fetch(
        client,
        url,
        allowed_hosts=_NPM_HOSTS,
        what="npm's provenance record",
        headers={"Accept": "application/json"},
        max_bytes=_MAX_BYTES,
    )
    if result.status != 200:
        return None
    try:
        for item in result.json().get("attestations", []):
            if item.get("predicateType") != _SLSA_V1:
                continue
            payload = json.loads(base64.b64decode(item["bundle"]["dsseEnvelope"]["payload"]))
            workflow = payload["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
            return _github_repo(workflow.get("repository"))
    except (AttributeError, KeyError, TypeError, ValueError, binascii.Error):
        return None
    return None


def pypi_built_from(client: httpx.Client, name: str, version: str, filename: str) -> str | None:
    """The `owner/repo` PyPI's attestations name for this file, or None if it has none."""
    url = (
        f"https://pypi.org/integrity/{quote(name, safe='')}/{quote(version, safe='')}"
        f"/{quote(filename, safe='')}/provenance"
    )
    result = fetch(
        client,
        url,
        allowed_hosts=_PYPI_HOSTS,
        what="PyPI's provenance record",
        headers={"Accept": "application/vnd.pypi.integrity.v1+json"},
        max_bytes=_MAX_BYTES,
    )
    if result.status != 200:
        return None
    try:
        for bundle in result.json().get("attestation_bundles", []):
            publisher = bundle.get("publisher") or {}
            if publisher.get("kind") == "GitHub":
                return _github_repo(f"https://github.com/{publisher.get('repository')}")
    except (AttributeError, TypeError, ValueError):
        return None
    return None
