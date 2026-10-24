"""Read-only preimage-hash patch planning for PUBLIC synthetic fixtures.

No file is ever written. This is a demonstrator, not an updater or
authorization to apply patches. Callers must use a separately reviewed
atomic writer, revalidate hashes immediately before writes, and maintain
independent backups and rollback procedures.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat

_SCOPE = "PUBLIC_SYNTHETIC_ONLY"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{i}" for prefix in ("COM", "LPT") for i in range(1, 10)
}


class PatchPlanError(ValueError):
    """Patch manifest, input or preimage failed closed."""


@dataclass(frozen=True)
class PlannedReplacement:
    relative_path: str
    preimage_sha256: str
    replacement_sha256: str
    replacement_bytes: int


@dataclass(frozen=True)
class ReadOnlyPatchPlan:
    scope: str
    replacements: tuple[PlannedReplacement, ...]


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PatchPlanError("Duplicate JSON object key")
        result[key] = value
    return result


def parse_manifest(text: str) -> dict:
    """Parse JSON without silently accepting duplicate object keys."""
    if not isinstance(text, str) or len(text) > 128 * 1024:
        raise PatchPlanError("Invalid manifest text")
    try:
        obj = json.loads(text, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError) as exc:
        raise PatchPlanError("Invalid or ambiguous manifest JSON") from exc
    if not isinstance(obj, dict):
        raise PatchPlanError("Manifest must be a JSON object")
    return obj


def _checked_path(value: object) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 240 or "\\" in value or ":" in value:
        raise PatchPlanError("Invalid relative path")
    parts = value.split("/")
    if len(parts) < 2 or len(parts) > 8 or parts[0] != "synthetic_workspace":
        raise PatchPlanError("Only synthetic_workspace paths are allowed")
    for part in parts:
        if (
            not _COMPONENT.fullmatch(part)
            or ".." in part
            or part.endswith(".")
            or part.split(".")[0].upper() in _RESERVED
        ):
            raise PatchPlanError("Unsafe relative path component")
    return tuple(parts)


def _sha(value: object) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise PatchPlanError("Expected lowercase SHA-256 hex digest")
    return value


def plan_replacements(
    root: Path,
    manifest: dict,
    payloads: dict[str, bytes],
    *,
    max_files: int = 64,
    max_file_bytes: int = 4 * 1024 * 1024,
    max_total_bytes: int = 16 * 1024 * 1024,
) -> ReadOnlyPatchPlan:
    """Validate synthetic replacements and existing preimages; make NO writes.

    This is intentionally replace-only: missing files, additions and deletions
    fail closed. It is subject to TOCTOU and is NOT a write-time authorization.
    """
    if min(max_files, max_file_bytes, max_total_bytes) <= 0:
        raise PatchPlanError("Invalid limits")
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version", "scope", "replacements"
    }:
        raise PatchPlanError("Unexpected manifest schema")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise PatchPlanError("Unsupported schema version")
    if manifest["scope"] != _SCOPE:
        raise PatchPlanError("Only public synthetic manifests allowed")
    replacements = manifest["replacements"]
    if not isinstance(replacements, list) or not replacements or len(replacements) > max_files:
        raise PatchPlanError("Invalid replacement count")
    if not isinstance(payloads, dict):
        raise PatchPlanError("Payloads must be a path-to-bytes dictionary")
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        raise PatchPlanError("Storage root missing or symlinked")
    base = base.resolve(strict=True)
    seen: set[str] = set()
    total = 0
    planned: list[PlannedReplacement] = []
    for entry in replacements:
        if not isinstance(entry, dict) or set(entry) != {
            "path", "preimage_sha256", "replacement_sha256"
        }:
            raise PatchPlanError("Unexpected replacement schema")
        path = entry["path"]
        parts = _checked_path(path)
        key = path.casefold()
        if key in seen:
            raise PatchPlanError("Duplicate or case-colliding path")
        seen.add(key)
        before = _sha(entry["preimage_sha256"])
        after = _sha(entry["replacement_sha256"])
        replacement = payloads.get(path)
        if not isinstance(replacement, bytes) or len(replacement) > max_file_bytes:
            raise PatchPlanError("Missing or oversized replacement payload")
        total += len(replacement)
        if total > max_total_bytes:
            raise PatchPlanError("Total replacement size limit exceeded")
        if hashlib.sha256(replacement).hexdigest() != after:
            raise PatchPlanError("Replacement payload digest mismatch")
        candidate = base
        for part in parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise PatchPlanError("Symlinked path component prohibited")
        if not candidate.is_file() or not candidate.resolve(strict=True).is_relative_to(base):
            raise PatchPlanError("Missing, non-file or escaping preimage")
        metadata = candidate.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_file_bytes:
            raise PatchPlanError("Invalid or oversized preimage")
        current = candidate.read_bytes()
        if len(current) > max_file_bytes or hashlib.sha256(current).hexdigest() != before:
            raise PatchPlanError("Preimage hash mismatch")
        planned.append(PlannedReplacement(path, before, after, len(replacement)))
    if set(payloads) != {p.relative_path for p in planned}:
        raise PatchPlanError("Unexpected or missing replacement payload")
    return ReadOnlyPatchPlan(_SCOPE, tuple(planned))
