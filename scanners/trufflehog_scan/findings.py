"""Normalise raw TruffleHog JSONL results into WhiteHat's finding shape.

Two jobs, both of which fail silently when wrong:

1. **Source metadata.** ``SourceMetadata.Data`` is a single-key object whose key
   names the source (``Github``, ``Docker``, ``S3``, ...) and whose value has a
   different shape per source. The old extractor understood three keys and
   returned all-empty strings for the rest — which produced ``asset=""``, dropped
   the ``HAS_FINDING`` edge, and collapsed every dedup key to the same string so
   all but one finding vanished. Unknown keys now degrade *visibly*
   (``asset="unknown:<Key>"``) instead.

2. **Validation status.** ``Verified: false`` means two very different things —
   "the owning API said this credential is dead" and "we never asked" — and a
   pentest report must not merge them. The mapping below is the single place
   TruffleHog's ``Verified``/``VerificationError`` and our own
   ``skipVerification`` switch converge into the vocabulary the existing
   ``:Secret`` nodes and ``ValidationChip`` already use.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Validation status (6.5a Directive 1)
# ---------------------------------------------------------------------------

#: Confirmed live by the owning API. The only status that means "act now".
VALIDATED = "validated"
#: Verification ran and the API said the credential is not live.
UNVALIDATED = "unvalidated"
#: The verify call itself errored — NOT proof the credential is dead.
VERIFY_ERROR = "verify_error"
#: Verification was switched off for the whole scan. Never checked.
UNVERIFIED = "unverified"

VALIDATION_STATUSES = (VALIDATED, UNVALIDATED, VERIFY_ERROR, UNVERIFIED)


def validation_status(result: dict, verification_enabled: bool = True) -> str:
    """Map one raw TruffleHog result to a WhiteHat validation status.

    ``verification_enabled`` is the scan-level switch (Appendix C). When it is
    off, nothing was checked, so every finding is ``unverified`` regardless of
    the ``Verified`` field's value.
    """
    if not verification_enabled:
        return UNVERIFIED
    if result.get("Verified"):
        return VALIDATED
    if result.get("VerificationError"):
        return VERIFY_ERROR
    return UNVALIDATED


# ---------------------------------------------------------------------------
# Source metadata (6.8)
# ---------------------------------------------------------------------------

#: Findings from an image's build history carry this synthetic path instead of a
#: real file, because the secret is in a RUN/ENV directive, not in a layer.
IMAGE_HISTORY_PREFIX = "image-metadata:history:"

KIND_SECRET = "secret"
KIND_IMAGE_HISTORY = "image_history"


class _Spec:
    """How to read one source's metadata block.

    ``asset`` / ``location`` are ordered candidate key lists (TruffleHog is not
    consistent about capitalisation across sources); the first non-empty wins.
    """

    __slots__ = ("asset", "location", "extra")

    def __init__(self, asset: tuple[str, ...], location: tuple[str, ...],
                 extra: tuple[str, ...] = ()):
        self.asset = asset
        self.location = location
        self.extra = extra


#: Keyed by the lowercased metadata key so a capitalisation change upstream
#: (Huggingface vs HuggingFace) does not silently drop a whole source.
_META_SPECS: dict[str, _Spec] = {
    "github": _Spec(("repository", "link"), ("file", "path"), ("commit", "email", "visibility", "timestamp", "line", "link")),
    "git": _Spec(("repository", "link"), ("file", "path"), ("commit", "email", "timestamp", "line", "link")),
    "gitlab": _Spec(("repository", "link", "project"), ("file", "path"), ("commit", "email", "timestamp", "line", "link")),
    "docker": _Spec(("Image", "image"), ("File", "file"), ("Tag", "tag", "Layer", "layer")),
    "huggingface": _Spec(("repository", "repo", "model", "link"), ("file", "path"), ("commit", "revision", "link", "timestamp")),
    "s3": _Spec(("bucket",), ("file", "key", "path"), ("link", "email", "timestamp")),
    "gcs": _Spec(("bucket",), ("filename", "file", "object", "path"), ("link", "email", "createdAt", "acl")),
    "filesystem": _Spec(("directory", "root"), ("file", "path"), ("line",)),
    "jenkins": _Spec(("jenkins_url", "url"), ("project_name", "job", "build_number"), ("build_number", "link")),
    "elasticsearch": _Spec(("node", "cluster", "index"), ("index", "document_id"), ("document_id", "timestamp")),
    "postman": _Spec(("workspace_name", "workspace_uuid", "workspace"), ("collection_name", "request_name", "collection"), ("environment", "link", "collection_id")),
    "circleci": _Spec(("vcs_type", "project", "link"), ("build_number", "step", "job_name"), ("link", "build_number")),
    "travisci": _Spec(("repository", "link"), ("username", "job", "build"), ("link",)),
}

#: Source id -> the ``SourceMetadata.Data`` key TruffleHog emits for it. NOT the
#: identity map: ``github-experimental`` is a GitHub source and reports under
#: ``Github``, so a per-source-id lookup table would leave it unreadable.
SOURCE_META_KEYS: dict[str, str] = {
    "git": "git",
    "github": "github",
    "github_experimental": "github",
    "gitlab": "gitlab",
    "docker": "docker",
    "huggingface": "huggingface",
    "s3": "s3",
    "gcs": "gcs",
    "filesystem": "filesystem",
    "jenkins": "jenkins",
    "elasticsearch": "elasticsearch",
    "postman": "postman",
    "circleci": "circleci",
    "travisci": "travisci",
}


def _first(meta: dict, keys: tuple[str, ...]) -> str:
    """First non-empty value among `keys`, matched case-INSENSITIVELY.

    TruffleHog is not consistent about capitalisation across sources, and it
    differs from its own Go struct fields: 3.96.0 emits lowercase
    `image`/`file`/`layer` for Docker where the upstream fields are
    `Image`/`File`/`Layer` (verified against the pinned binary). An exact-match
    lookup that guesses wrong yields an EMPTY asset — which drops the graph edge
    and collapses every dedup key for that source, with no error. Ignoring case
    makes the whole table immune to that, including for the sources that cannot
    be exercised without live credentials.
    """
    if not meta:
        return ""
    lowered = {str(k).lower(): v for k, v in meta.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, "", 0):
            return str(value)
    return ""


def _get(meta: dict, key: str) -> str:
    """One metadata field, case-insensitively."""
    return _first(meta, (key,))


def extract_source_meta(result: dict, on_unknown=None) -> dict:
    """Pull asset / location / extra out of a raw result.

    ``on_unknown`` is called with the unrecognised metadata key so the runner can
    log a warning; the finding is still kept, with ``asset="unknown:<Key>"``, so a
    TruffleHog release that adds a source degrades visibly instead of discarding
    data.
    """
    data = (result.get("SourceMetadata") or {}).get("Data") or {}
    if not isinstance(data, dict):
        return _empty_meta()

    for raw_key, meta in data.items():
        if not isinstance(meta, dict):
            continue
        spec = _META_SPECS.get(str(raw_key).lower())
        if spec is None:
            if on_unknown:
                on_unknown(raw_key)
            return {
                "asset": f"unknown:{raw_key}",
                "location": _first(meta, ("file", "path", "link")),
                "commit": "",
                "line": _int(_get(meta, "line")),
                "link": _get(meta, "link"),
                "email": _get(meta, "email"),
                "timestamp": _get(meta, "timestamp"),
                "meta_key": str(raw_key),
                "extra": {k: v for k, v in meta.items() if isinstance(v, (str, int, float, bool))},
            }

        location = _first(meta, spec.location)
        # Same case-insensitive treatment for the extras, keyed by the name the
        # spec declares so downstream display stays predictable.
        lowered = {str(k).lower(): v for k, v in meta.items()}
        extra = {k: lowered[k.lower()] for k in spec.extra
                 if lowered.get(k.lower()) not in (None, "", 0)}
        return {
            "asset": _first(meta, spec.asset),
            "location": location,
            "commit": _get(meta, "commit"),
            "line": _int(_get(meta, "line")),
            "link": _get(meta, "link"),
            "email": _get(meta, "email"),
            "timestamp": _get(meta, "timestamp"),
            "meta_key": str(raw_key),
            "extra": extra,
        }

    return _empty_meta()


def _empty_meta() -> dict:
    return {
        "asset": "", "location": "", "commit": "", "line": 0, "link": "",
        "email": "", "timestamp": "", "meta_key": "", "extra": {},
    }


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def finding_kind(location: str) -> str:
    """Secrets baked into a Dockerfile arrive with a synthetic history path, not a
    real file. Labelling them lets the UI say "baked into the image build" rather
    than showing a path that does not exist in the filesystem."""
    return KIND_IMAGE_HISTORY if str(location or "").startswith(IMAGE_HISTORY_PREFIX) else KIND_SECRET


#: The github sources report `repository` in TWO shapes for the same repo: a
#: clone URL for a finding in a file, and a bare `owner/repo` for one in an issue
#: or PR comment. Both are the same asset, so passing them through verbatim built
#: two MultiscannerRepository nodes for one repository - which split that repo's
#: findings across two nodes and inflated assets_scanned by one per repo whose
#: comments were scanned.
_GITHUB_SOURCES = ("github", "github_experimental")


def _github_clone_url(asset: str, link: str) -> str:
    """Canonicalise a github asset to the clone-URL form file findings use.

    The host comes from the finding's own ``link`` rather than a hardcoded
    github.com: a GitHub Enterprise repository would otherwise be renamed to a
    github.com one, silently merging two different hosts' repos of the same name.
    """
    asset = (asset or "").strip()
    # Already a URL (a file finding, or a gist, which is gist.github.com).
    if not asset or "://" in asset:
        return asset
    host = urlsplit(link).netloc if link else ""
    slug = asset.strip("/")
    if slug.endswith(".git"):
        slug = slug[:-4]
    return f"https://{host or 'github.com'}/{slug}.git"


def asset_name(source_id: str, meta: dict, config: Optional[dict] = None) -> str:
    """The human identifier for the asset node.

    Docker appends the tag so two tags of the same image stay distinguishable
    (TruffleHog reports Image and Tag separately, and each tag can hold different
    secrets). GitHub collapses its two spellings of a repository into one.
    """
    asset = meta.get("asset") or ""
    if source_id in _GITHUB_SOURCES and asset:
        return _github_clone_url(asset, str(meta.get("link") or ""))
    if source_id == "docker" and asset:
        tag = meta.get("extra", {}).get("Tag") or meta.get("extra", {}).get("tag")
        if tag and ":" not in asset.split("/")[-1] and "@" not in asset:
            return f"{asset}:{tag}"
    return asset


def digest(*parts: str) -> str:
    """Stable 12-hex-char identity digest.

    Replaces the builtin ``hash()`` the old ids used: ``hash()`` on ``str`` is
    randomised per process via PYTHONHASHSEED (unpinned in the scanner
    Dockerfile), so the same repository got a different node id on every run. The
    blanket pre-clear used to hide that; with source-scoped clearing it would
    surface as duplicated and orphaned nodes. Identity only, not security, so a
    truncated sha1 is fine — what matters is that it is stable across processes.
    """
    return hashlib.sha1("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:12]


def dedup_key(source_id: str, asset: str, location: str, line, detector_name: str) -> str:
    """Source-scoped dedup key.

    Without the source prefix, an identical secret found by two different sources
    collapses into one finding and the second source's context is lost.
    """
    return f"{source_id}:{asset}:{location}:{line}:{detector_name}"


def normalise(result: dict, source_id: str, verification_enabled: bool = True,
              on_unknown=None, default_asset: str = "") -> dict:
    """Raw TruffleHog result -> the finding dict written to the output JSON.

    ``default_asset`` is the run's target descriptor, used whenever the metadata
    block carries no asset identifier of its own — which is the normal case for
    ``filesystem`` (its metadata is just ``file`` + ``line``). An empty ``asset``
    is never acceptable: it drops the ``HAS_ASSET``/``HAS_FINDING`` edge and
    collapses every dedup key for the source to one string, so all findings but
    one silently vanish.

    ``repository`` and ``file`` are kept as aliases of ``asset`` and ``location``
    for one release so existing report queries keep matching (6.5).
    """
    meta = extract_source_meta(result, on_unknown=on_unknown)
    asset = asset_name(source_id, meta) or str(default_asset or "") or f"{source_id}:target"
    location = meta["location"]
    status = validation_status(result, verification_enabled)

    extra = dict(meta.get("extra") or {})
    detector_extra = result.get("ExtraData") or {}
    if isinstance(detector_extra, dict):
        extra.update(detector_extra)

    return {
        "source": source_id,
        "detector_name": result.get("DetectorName", "Unknown"),
        "detector_description": result.get("DetectorDescription", ""),
        "verified": bool(result.get("Verified", False)),
        "validation_status": status,
        "verification_error": str(result.get("VerificationError") or ""),
        "finding_kind": finding_kind(location),
        "redacted": result.get("Redacted", ""),
        "asset": asset,
        "location": location,
        # Deprecated aliases, kept for one release (6.5).
        "repository": asset,
        "file": location,
        "commit": meta["commit"],
        "line": meta["line"] or _int(result.get("Line")),
        "link": meta["link"],
        "email": meta["email"],
        "timestamp": meta["timestamp"],
        "extra_data": json.dumps(extra, default=str),
    }
