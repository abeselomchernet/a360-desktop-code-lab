"""Read-only patch planner regression tests: synthetic files only."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from lab.patch_plan import PatchPlanError, parse_manifest, plan_replacements


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ReadOnlyPatchPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.dir = self.root / "synthetic_workspace"
        self.dir.mkdir()
        self.path = self.dir / "sample.json"
        self.before = b'{"status":"old"}'
        self.after = b'{"status":"new"}'
        self.path.write_bytes(self.before)
        self.name = "synthetic_workspace/sample.json"
        self.manifest = {
            "schema_version": 1,
            "scope": "PUBLIC_SYNTHETIC_ONLY",
            "replacements": [{
                "path": self.name,
                "preimage_sha256": sha(self.before),
                "replacement_sha256": sha(self.after),
            }],
        }
        self.payloads = {self.name: self.after}

    def plan(self, **kwargs):
        return plan_replacements(self.root, self.manifest, self.payloads, **kwargs)

    def test_valid_plan_is_read_only(self):
        plan = self.plan()
        self.assertEqual(plan.scope, "PUBLIC_SYNTHETIC_ONLY")
        self.assertEqual(plan.replacements[0].replacement_bytes, len(self.after))
        self.assertEqual(self.path.read_bytes(), self.before)

    def test_rejects_changed_preimage(self):
        self.path.write_bytes(b"changed after manifest")
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_wrong_preimage_hash(self):
        self.manifest["replacements"][0]["preimage_sha256"] = "0" * 64
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_tampered_replacement(self):
        self.payloads[self.name] = b"tampered"
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_wrong_replacement_hash(self):
        self.manifest["replacements"][0]["replacement_sha256"] = "f" * 64
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_traversal_absolute_and_windows_names(self):
        for path in (
            "../private", "/tmp/escape", "synthetic_workspace/../escape",
            "synthetic_workspace/a\\b", "synthetic_workspace/CON.txt",
            "synthetic_workspace/a//b", "synthetic_workspace/a.",
            "synthetic_workspace/.hidden", "synthetic_workspace/C:/x",
        ):
            with self.subTest(path=path):
                self.manifest["replacements"][0]["path"] = path
                with self.assertRaises(PatchPlanError):
                    self.plan()

    def test_rejects_unapproved_scope(self):
        self.manifest["scope"] = "PRIVATE_PRODUCTION"
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_extra_manifest_fields(self):
        self.manifest["apply"] = True
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_missing_preimage(self):
        self.path.unlink()
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_case_colliding_paths(self):
        entry = dict(self.manifest["replacements"][0])
        entry["path"] = "synthetic_workspace/SAMPLE.json"
        self.manifest["replacements"].append(entry)
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_extra_payload(self):
        self.payloads["synthetic_workspace/extra.json"] = b"x"
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_missing_payload(self):
        self.payloads.clear()
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_file_size_limit(self):
        with self.assertRaises(PatchPlanError):
            self.plan(max_file_bytes=2)

    def test_rejects_total_size_limit(self):
        with self.assertRaises(PatchPlanError):
            self.plan(max_total_bytes=2)

    def test_rejects_zero_limits(self):
        with self.assertRaises(PatchPlanError):
            self.plan(max_files=0)

    def test_rejects_boolean_schema_version(self):
        self.manifest["schema_version"] = True
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_empty_replacements(self):
        self.manifest["replacements"] = []
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_uppercase_digest(self):
        self.manifest["replacements"][0]["preimage_sha256"] = "A" * 64
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_symlinked_preimage(self):
        target = self.dir / "real.json"
        target.write_bytes(self.before)
        self.path.unlink()
        try:
            self.path.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Host does not allow symlink creation")
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_symlinked_directory(self):
        real = self.root / "real"
        real.mkdir()
        (real / "sample.json").write_bytes(self.before)
        self.path.unlink()
        self.dir.rmdir()
        try:
            self.dir.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Host does not allow symlink creation")
        with self.assertRaises(PatchPlanError):
            self.plan()

    def test_rejects_duplicate_json_keys(self):
        text = '{"schema_version":1,"scope":"PUBLIC_SYNTHETIC_ONLY","scope":"BAD","replacements":[]}'
        with self.assertRaises(PatchPlanError):
            parse_manifest(text)

    def test_accepts_unambiguous_json(self):
        parsed = parse_manifest(json.dumps(self.manifest))
        self.assertEqual(parsed["scope"], "PUBLIC_SYNTHETIC_ONLY")

    def test_rejects_non_object_json(self):
        with self.assertRaises(PatchPlanError):
            parse_manifest("[]")

    def test_rejects_malformed_json(self):
        with self.assertRaises(PatchPlanError):
            parse_manifest("{invalid")


if __name__ == "__main__":
    unittest.main()
