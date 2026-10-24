"""Only synthetic filesystem fixtures; independent of private programme data."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from zipfile import ZipInfo

from lab.security_paths import (
    checked_archive_target,
    checked_record_path,
    validate_identifier,
)


class TestStorageBoundaries(unittest.TestCase):
    def test_safe_identifiers(self):
        for value in ("gate", "G01_test", "F05", "a-b_c.1"):
            with self.subTest(value=value):
                self.assertEqual(validate_identifier(value), value)

    def test_unsafe_identifiers(self):
        for value in ("../secret", "..", ".hidden", "a/b", "a\\b", "CON", "com1.txt", "x" * 81, "", "x..y", "x."):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_identifier(value)

    def test_safe_path_is_under_base(self):
        with TemporaryDirectory() as directory:
            base = Path(directory) / "records"
            target = checked_record_path(base, "notes", "demo.json")
            self.assertTrue(target.is_relative_to(base.resolve()))

    def test_archive_entries_outside_data_rejected(self):
        with TemporaryDirectory() as directory:
            for name in ("../../private", "annotations/../../escape.txt", "/absolute.txt", "C:/data", "backups/old.zip", "annotations/..\\escape", "annotations/.hidden/demo.json"):
                with self.subTest(name=name):
                    with self.assertRaises(ValueError):
                        checked_archive_target(Path(directory), ZipInfo(name))

    def test_safe_archive_entry(self):
        with TemporaryDirectory() as directory:
            path = checked_archive_target(Path(directory), ZipInfo("annotations/gate/G01.json"))
            self.assertEqual(path, Path(directory, "annotations", "gate", "G01.json").resolve())

    def test_archive_symlink_rejected(self):
        with TemporaryDirectory() as directory:
            item = ZipInfo("annotations/gate/demo.json")
            item.external_attr = (0o120777 << 16)
            with self.assertRaises(ValueError):
                checked_archive_target(Path(directory), item)


if __name__ == "__main__":
    unittest.main()
