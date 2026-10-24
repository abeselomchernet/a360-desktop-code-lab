"""Strict identifier and archive-path validation for local synthetic application data."""
from __future__ import annotations

import re
import stat
from pathlib import Path, PurePosixPath
from zipfile import ZipInfo

_ALLOWED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{index}" for prefix in ("COM", "LPT") for index in range(1, 10)
}


def validate_identifier(value: str) -> str:
    if (
        not isinstance(value, str)
        or not _ALLOWED_ID.fullmatch(value)
        or ".." in value
        or value.endswith(".")
        or value.split(".")[0].upper() in _RESERVED
    ):
        raise ValueError("Invalid record identifier")
    return value


def checked_record_path(base: Path, *components: str) -> Path:
    parts = [validate_identifier(part) for part in components]
    root = base.resolve()
    path = base.joinpath(*parts).resolve()
    if not path.is_relative_to(root):
        raise ValueError("Record path escapes storage root")
    return path


def checked_archive_target(data_dir: Path, item: ZipInfo) -> Path:
    """Reject absolute, traversal, symlink and non-data entries."""
    name = item.filename
    if not name or name.startswith(("/", "\\")) or "\\" in name or ":" in name:
        raise ValueError("Unsafe archive member path")
    parts = PurePosixPath(name).parts
    if not parts or any(part in (".", "..") for part in parts):
        raise ValueError("Unsafe archive member path")
    if parts[0] not in {"annotations", "synthetic_inputs"} or len(parts) < 2:
        raise ValueError("Archive member outside allowed data folders")
    if len(parts) > 8 or any(not part or part.startswith(".") for part in parts):
        raise ValueError("Unsafe archive directory component")
    if stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK:
        raise ValueError("Archive symlink entries are prohibited")
    root = data_dir.resolve()
    destination = data_dir.joinpath(*parts).resolve()
    if not destination.is_relative_to(root):
        raise ValueError("Archive member escapes storage root")
    return destination
