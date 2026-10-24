"""Synthetic negative tests for metadata-only archive preflight."""
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import stat
import unittest
import warnings
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED, ZIP_STORED

from lab.archive_preflight import preflight_archive


def make_archive(entries, compression=ZIP_STORED):
    stream = BytesIO()
    with ZipFile(stream, "w", compression=compression) as archive:
        for name, content in entries:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(name, content)
    stream.seek(0)
    return stream


class ArchivePreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def preflight(self, entries, **kwargs):
        with ZipFile(make_archive(entries)) as archive:
            return preflight_archive(archive, self.root, **kwargs)

    def test_accepts_valid_synthetic_entries(self):
        targets = self.preflight([
            ("annotations/note.json", "{}"),
            ("synthetic_inputs/sample.json", "[]"),
        ])
        self.assertEqual(len(targets), 2)
        self.assertTrue(all(path.is_relative_to(self.root.resolve()) for path in targets))

    def test_rejects_traversal_and_absolute_names(self):
        for name in ("annotations/../escape", "/annotations/file", "annotations/./file"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.preflight([(name, "x")])

    def test_rejects_windows_reserved_names(self):
        for name in ("annotations/CON.txt", "annotations/LPT1", "annotations/aux.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.preflight([(name, "x")])

    def test_rejects_windows_illegal_names(self):
        for name in ("annotations/a?.json", "annotations/has space .", "annotations/a//b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.preflight([(name, "x")])

    def test_rejects_raw_backslash_name_on_all_platforms(self):
        # ZipInfo normalizes a backslash during creation on Windows, so
        # mutate the raw local + central ZIP headers instead.
        stream = make_archive([("annotations/a/b", "x")])
        data = stream.getvalue()
        original = b"annotations/a/b"
        self.assertEqual(data.count(original), 2)
        data = data.replace(original, b"annotations/a\\b")
        with ZipFile(BytesIO(data)) as archive, self.assertRaises(ValueError):
            preflight_archive(archive, self.root)

    def test_rejects_raw_null_name_on_all_platforms(self):
        stream = make_archive([("annotations/a/b", "x")])
        data = stream.getvalue()
        original = b"annotations/a/b"
        self.assertEqual(data.count(original), 2)
        data = data.replace(original, b"annotations/a\x00b")
        with ZipFile(BytesIO(data)) as archive, self.assertRaises(ValueError):
            preflight_archive(archive, self.root)

    def test_rejects_exact_duplicate_names(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/a.json", "a"), ("annotations/a.json", "b")])

    def test_rejects_case_collisions(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/A.json", "a"), ("annotations/a.json", "b")])

    def test_rejects_file_as_parent_of_another_file(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/item", "a"), ("annotations/item/child", "b")])

    def test_rejects_wrong_root(self):
        with self.assertRaises(ValueError):
            self.preflight([("private/data.json", "x")])

    def test_rejects_directory_entry(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/folder/", "")])

    def test_rejects_symlink(self):
        stream = BytesIO()
        with ZipFile(stream, "w") as archive:
            item = ZipInfo("annotations/link")
            item.create_system = 3
            item.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(item, "target")
        stream.seek(0)
        with ZipFile(stream) as archive, self.assertRaises(ValueError):
            preflight_archive(archive, self.root)

    def test_rejects_file_count_limit(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/a", "a"), ("annotations/b", "b")], max_files=1)

    def test_rejects_total_size_limit(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/a", "abc"), ("annotations/b", "def")], max_total_bytes=5)

    def test_rejects_per_file_limit(self):
        with self.assertRaises(ValueError):
            self.preflight([("annotations/a", "abcdef")], max_file_bytes=5)

    def test_rejects_high_compression_ratio(self):
        with ZipFile(make_archive([("annotations/bomb", "A" * 10000)], ZIP_DEFLATED)) as archive:
            with self.assertRaises(ValueError):
                preflight_archive(archive, self.root, max_ratio=10)

    def test_rejects_empty_archive(self):
        with ZipFile(make_archive([])) as archive, self.assertRaises(ValueError):
            preflight_archive(archive, self.root)

    def test_rejects_invalid_limits(self):
        with ZipFile(make_archive([("annotations/a", "a")])) as archive:
            with self.assertRaises(ValueError):
                preflight_archive(archive, self.root, max_files=0)


if __name__ == "__main__":
    unittest.main()
