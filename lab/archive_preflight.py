"""Read-only ZIP metadata preflight for synthetic local data bundles.

This does not extract files. Callers must separately verify content hashes and
use race-resistant extraction; checking a path is not a write authorization.
"""
from __future__ import annotations

import stat
from pathlib import Path
from zipfile import ZipFile

from .security_paths import checked_archive_target

_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}
_FORBIDDEN = set('<>:"\\|?*')


def _validate_member_name(name: str) -> None:
    if not name or name.endswith("/") or name.startswith(("/", "\\")):
        raise ValueError("Only relative file entries are permitted")
    components = name.split("/")
    if len(components) < 2 or len(components) > 8:
        raise ValueError("Invalid archive member depth")
    for component in components:
        if (
            not component
            or component in (".", "..")
            or component.endswith((".", " "))
            or any(char in _FORBIDDEN or ord(char) < 32 for char in component)
            or component.split(".")[0].upper() in _WINDOWS_RESERVED
        ):
            raise ValueError("Unsafe Windows archive member name")


def _reject_ambiguous_raw_names(archive: ZipFile, infos: list) -> None:
    """Inspect raw central-directory names before ZipInfo can normalize them.

    On Windows, Python's ZipInfo normalizes backslashes to slashes when it
    constructs member names. Validation of info.filename alone therefore
    cannot distinguish an unsafe raw backslash from a canonical ZIP slash.
    """
    stream = archive.fp
    start = getattr(archive, "start_dir", None)
    if stream is None or not isinstance(start, int):
        raise ValueError("Cannot inspect raw ZIP member names")
    original_position = stream.tell()
    try:
        stream.seek(start)
        for _ in infos:
            header = stream.read(46)
            if len(header) != 46 or header[:4] != b"PK\x01\x02":
                raise ValueError("Invalid ZIP central-directory header")
            name_length = int.from_bytes(header[28:30], "little")
            extra_length = int.from_bytes(header[30:32], "little")
            comment_length = int.from_bytes(header[32:34], "little")
            raw_name = stream.read(name_length)
            if (
                len(raw_name) != name_length
                or b"\\" in raw_name
                or b"\x00" in raw_name
            ):
                raise ValueError("Ambiguous raw ZIP member name")
            stream.seek(extra_length + comment_length, 1)
    finally:
        stream.seek(original_position)


def preflight_archive(
    archive: ZipFile,
    destination_root: Path,
    *,
    max_files: int = 128,
    max_file_bytes: int = 16 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
    max_ratio: int = 1000,
) -> tuple[Path, ...]:
    """Validate metadata and return planned targets; never write or extract.

    Fail closed for traversal, Windows device names, case collisions, special
    files, excess file counts, advertised decompressed size and compression
    ratios. ZIP CRC and content digest checks remain extraction-time duties.
    """
    if min(max_files, max_file_bytes, max_total_bytes, max_ratio) <= 0:
        raise ValueError("Limits must be positive")
    infos = archive.infolist()
    if not infos or len(infos) > max_files:
        raise ValueError("Archive file-count limit exceeded")
    _reject_ambiguous_raw_names(archive, infos)
    total = 0
    paths: list[Path] = []
    keys: set[str] = set()
    for info in infos:
        _validate_member_name(info.filename)
        mode = stat.S_IFMT(info.external_attr >> 16)
        if mode not in (0, stat.S_IFREG):
            raise ValueError("Nonregular archive entry")
        if info.file_size < 0 or info.compress_size < 0:
            raise ValueError("Invalid archive size")
        if info.file_size > max_file_bytes:
            raise ValueError("Archive member exceeds size limit")
        total += info.file_size
        if total > max_total_bytes:
            raise ValueError("Archive exceeds total size limit")
        if info.file_size and (
            info.compress_size == 0 or info.file_size > info.compress_size * max_ratio
        ):
            raise ValueError("Archive compression ratio exceeds limit")
        target = checked_archive_target(destination_root, info)
        key = str(target).casefold()
        if key in keys:
            raise ValueError("Archive has duplicate or case-colliding paths")
        keys.add(key)
        paths.append(target)

    # A file cannot simultaneously be a parent directory of another file.
    for key in keys:
        parent = str(Path(key).parent)
        while parent != key:
            if parent in keys:
                raise ValueError("Archive contains file/directory path collision")
            next_parent = str(Path(parent).parent)
            if next_parent == parent:
                break
            parent = next_parent
    return tuple(paths)
