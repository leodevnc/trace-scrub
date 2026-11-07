import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from trace_scrub.core import (
    FILES, MASK, MAX_FILE, MAX_LINE, Invalid, Transformer, decode, encode,
    export, parse_records, validate_policy, verify,
)


ROOT = Path(__file__).resolve().parents[1]


class TraceScrubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.jsonl"
        self.policy_path = self.root / "policy.json"
        self.source.write_bytes((ROOT / "examples/traces.jsonl").read_bytes())
        self.policy_path.write_bytes((ROOT / "examples/policy.json").read_bytes())
        self.policy = decode(self.policy_path.read_bytes())
        self.rows = parse_records(self.source.read_bytes())
        self.output = self.root / "bundle"

    def cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "trace_scrub", *map(str, arguments)],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )

    def publish(self):
        return export(self.source, self.policy_path, self.output)

    def save_rows(self, rows):
        self.source.write_bytes(b"".join(encode(row) for row in rows))

    def rehash(self):
        manifest = {"format_version": 1, "files": {
            name: hashlib.sha256((self.output / name).read_bytes()).hexdigest()
            for name in FILES - {"manifest.json"}
        }}
        (self.output / "manifest.json").write_bytes(encode(manifest))

    def test_end_to_end_cli_in_separate_processes(self):
        original = self.source.read_bytes()
        result = self.cli("export", self.source, "--policy", self.policy_path, "--out", self.output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"exported": True, "records": 3})
        # Verification is a fresh process: no in-memory alias state is required.
        checked = self.cli("verify", self.output, "--source", self.source, "--policy", self.policy_path)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertTrue(json.loads(checked.stdout)["source_verified"])
        self.assertTrue(json.loads(checked.stdout)["policy_verified"])
        self.assertEqual(original, self.source.read_bytes())
        self.assertIn("내 회의", original.decode())
        rows = parse_records((self.output / "records.jsonl").read_bytes())
        self.assertEqual([row["run_id"] for row in rows], ["run-0001", "run-0001", "run-0002"])
        self.assertEqual(rows[1]["calls"], [{"name": "search_docs", "result": MASK}])
        self.assertEqual(rows[1]["duration_ms"], 145)
        bundle = b"".join(path.read_bytes() for path in self.output.iterdir())
        self.assertNotIn(b"SYNTHETIC_", bundle)
        self.assertNotIn(b"synthetic-account", bundle)
        self.assertNotIn(hashlib.sha256(original).hexdigest().encode(), bundle)
        report = decode((self.output / "report.json").read_bytes())
        self.assertEqual(report["alias_groups"], {"run": 2})
        self.assertEqual(report["actions"]["mask"], 5)
        self.assertEqual(report["actions"]["drop"], 3)

    def test_output_is_deterministic_and_aliases_reset_each_export(self):
        self.publish()
        second = self.root / "second"
        export(self.source, self.policy_path, second)
        for name in FILES:
            self.assertEqual((self.output / name).read_bytes(), (second / name).read_bytes())

    def test_late_unknown_field_fails_before_creating_output_without_echo(self):
        self.rows[-1]["SYNTHETIC_PRIVATE_KEY"] = "SYNTHETIC_PRIVATE_VALUE"
        self.save_rows(self.rows)
        result = self.cli("export", self.source, "--policy", self.policy_path, "--out", self.output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("record 3", result.stderr)
        self.assertNotIn("SYNTHETIC", result.stderr + result.stdout)
        self.assertFalse(self.output.exists())

    def test_nested_unknown_field_is_rejected(self):
        self.rows[1]["calls"][0]["extra"] = "private"
        self.save_rows(self.rows)
        with self.assertRaisesRegex(Invalid, "unknown input"):
            self.publish()
        self.assertFalse(self.output.exists())

    def test_mask_and_drop_replace_entire_subtrees(self):
        self.rows[0]["prompt"] = {"new-private-field": ["private", None]}
        self.rows[0]["debug"] = {"unknown-schema": [1, 2]}
        self.save_rows(self.rows)
        self.publish()
        output = parse_records((self.output / "records.jsonl").read_bytes())[0]
        self.assertEqual(output["prompt"], MASK)
        self.assertNotIn("debug", output)

    def test_bad_input_types_ranges_and_missing_required_fields(self):
        for key, value in [("kind", "private"), ("duration_ms", True),
                           ("duration_ms", -1), ("duration_ms", 600001),
                           ("calls", {}), ("run_id", ""), ("run_id", 17)]:
            with self.subTest(key=key, value=value):
                row = copy.deepcopy(self.rows[0])
                row[key] = value
                with self.assertRaises(Invalid):
                    Transformer(self.policy).transform([row])
        row = copy.deepcopy(self.rows[0])
        del row["kind"]
        with self.assertRaisesRegex(Invalid, "required"):
            Transformer(self.policy).transform([row])

    def test_array_bound_and_boolean_rule(self):
        self.rows[0]["calls"] = [self.rows[1]["calls"][0]] * 21
        with self.assertRaises(Invalid):
            Transformer(self.policy).transform(self.rows)
        policy = {"action": "object", "fields": {"ok": {"action": "boolean"}}, "required": ["ok"]}
        self.assertEqual(Transformer(policy).transform([{"ok": False}]), [{"ok": False}])
        with self.assertRaises(Invalid):
            Transformer(policy).transform([{"ok": 0}])

    def test_namespaced_aliases_preserve_equality_not_source_identity(self):
        policy = {"action": "object", "fields": {
            "a": {"action": "alias", "namespace": "run"},
            "b": {"action": "alias", "namespace": "run"},
            "c": {"action": "alias", "namespace": "user"},
        }, "required": []}
        result = Transformer(policy).transform([{"a": "same", "b": "same", "c": "same"}])
        self.assertEqual(result, [{"a": "run-0001", "b": "run-0001", "c": "user-0001"}])

    def test_policy_rejects_unbounded_or_ambiguous_rules(self):
        rules = [
            {"action": "keep"}, {"action": "mask", "unexpected": True},
            {"action": "alias", "namespace": "../private"},
            {"action": "enum", "values": ["a", "a"]},
            {"action": "enum", "values": []},
            {"action": "number", "min": True, "max": 10},
            {"action": "number", "min": 10, "max": 0},
            {"action": "number", "min": 0, "max": float("inf")},
            {"action": "array", "items": {"action": "drop"}, "max_items": 1},
            {"action": "array", "items": {"action": "mask"}, "max_items": True},
            {"action": "object", "fields": {}, "required": ["missing"]},
        ]
        for rule in rules:
            with self.subTest(rule=rule), self.assertRaises(Invalid):
                validate_policy({"action": "object", "fields": {"x": rule}, "required": []})
        with self.assertRaises(Invalid):
            validate_policy({"action": "drop"})

    def test_policy_size_depth_and_node_limits(self):
        large = {"action": "object", "fields": {str(i): {"action": "mask"} for i in range(256)}, "required": []}
        with self.assertRaises(Invalid):
            validate_policy(large)
        nested = {"action": "mask"}
        for _ in range(14):
            nested = {"action": "object", "fields": {"x": nested}, "required": []}
        with self.assertRaises(Invalid):
            validate_policy(nested)
        self.policy_path.write_bytes(b" " * 65537)
        with self.assertRaises(Invalid):
            self.publish()
        self.assertFalse(self.output.exists())

    def test_large_integer_bounds_do_not_crash_float_conversion(self):
        policy = {"action": "object", "fields": {
            "n": {"action": "number", "min": 0, "max": 10 ** 400}}, "required": ["n"]}
        decoded = decode(encode(policy))
        self.assertEqual(Transformer(decoded).transform([{"n": 10 ** 399}]), [{"n": 10 ** 399}])

    def test_malformed_json_unicode_and_nonfinite_numbers(self):
        invalid = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                   b'{"x":1e999}', b'{"x":"\\ud800"}', b'{"x":"\xff"}',
                   '{"x":1}'.encode("utf-16"), b'{"x":', b'[]', b'{}\n\n{}']
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(Invalid):
                parse_records(raw)

    def test_dataset_bounds(self):
        for raw in [b"", b"{}\n" * 2001, b" " * (MAX_FILE + 1),
                    b'{"x":"' + b"x" * MAX_LINE + b'"}',
                    b'{"x":' + b"[" * 22 + b"0" + b"]" * 22 + b"}"]:
            with self.subTest(length=len(raw)), self.assertRaises(Invalid):
                parse_records(raw)

    def test_existing_directory_is_never_overwritten(self):
        self.publish()
        before = {p.name: p.read_bytes() for p in self.output.iterdir()}
        result = self.cli("export", self.source, "--policy", self.policy_path, "--out", self.output)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.output.iterdir()})

    def test_two_publishers_cannot_interleave_a_bundle(self):
        command = [sys.executable, "-m", "trace_scrub", "export", str(self.source),
                   "--policy", str(self.policy_path), "--out", str(self.output)]
        processes = [subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) for _ in range(2)]
        for process in processes:
            process.communicate(timeout=10)
        self.assertEqual(sorted(p.returncode for p in processes), [0, 2])
        self.assertTrue(verify(self.output, self.source)["source_verified"])

    def test_partial_write_has_no_completion_marker_and_cannot_verify(self):
        real_open = Path.open

        def interrupted(path, *args, **kwargs):
            if path == self.output / "report.json":
                raise OSError("SYNTHETIC_PRIVATE_OS_DETAIL")
            return real_open(path, *args, **kwargs)

        with patch.object(Path, "open", interrupted), self.assertRaises(OSError):
            self.publish()
        self.assertFalse((self.output / "manifest.json").exists())
        with self.assertRaises(Invalid):
            verify(self.output)
        recovered = self.root / "recovered"
        export(self.source, self.policy_path, recovered)
        self.assertTrue(verify(recovered)["verified"])

    def test_filesystem_errors_do_not_echo_private_path(self):
        result = self.cli("export", self.source, "--policy", self.policy_path,
                          "--out", self.root / "SYNTHETIC_PRIVATE_PATH" / "bundle")
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("SYNTHETIC", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink support")
    def test_symlink_source_and_artifact_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.source)
        with self.assertRaises(Invalid):
            export(link, self.policy_path, self.output)
        self.publish()
        target = self.output / "records.jsonl"
        saved = self.root / "saved"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaises(Invalid):
            verify(self.output)

    def test_digest_corruption_and_unexpected_files_rejected(self):
        self.publish()
        target = self.output / "records.jsonl"
        original = target.read_bytes()
        target.write_bytes(original + b" ")
        with self.assertRaisesRegex(Invalid, "digest mismatch"):
            verify(self.output)
        target.write_bytes(original)
        (self.output / "unexpected.txt").touch()
        with self.assertRaisesRegex(Invalid, "unexpected files"):
            verify(self.output)

    def test_rehashed_raw_value_fails_output_policy(self):
        self.publish()
        path = self.output / "records.jsonl"
        rows = parse_records(path.read_bytes())
        rows[0]["prompt"] = "SYNTHETIC_LEAK"
        path.write_bytes(b"".join(encode(row) for row in rows))
        self.rehash()
        with self.assertRaisesRegex(Invalid, "mask"):
            verify(self.output)

    def test_rehashed_dropped_field_fails_output_policy(self):
        self.publish()
        path = self.output / "records.jsonl"
        rows = parse_records(path.read_bytes())
        rows[0]["debug"] = "SYNTHETIC_LEAK"
        path.write_bytes(b"".join(encode(row) for row in rows))
        self.rehash()
        with self.assertRaises(Invalid):
            verify(self.output)

    def test_report_cannot_include_unrecognized_metadata(self):
        self.publish()
        path = self.output / "report.json"
        report = decode(path.read_bytes())
        report["actions"]["SYNTHETIC_PRIVATE_FIELD"] = 1
        path.write_bytes(encode(report))
        self.rehash()
        with self.assertRaises(Invalid):
            verify(self.output)

    def test_source_reproduction_detects_valid_but_incorrect_counts(self):
        self.publish()
        path = self.output / "report.json"
        report = decode(path.read_bytes())
        report["actions"]["drop"] += 1
        path.write_bytes(encode(report))
        self.rehash()
        self.assertTrue(verify(self.output)["verified"])
        with self.assertRaisesRegex(Invalid, "reproduce"):
            verify(self.output, self.source)

    def test_source_verification_is_not_original_source_identity(self):
        self.publish()
        self.rows[0]["prompt"] = "different private content is still masked"
        self.save_rows(self.rows)
        self.assertTrue(verify(self.output, self.source)["source_verified"])
        self.rows[0]["duration_ms"] = 42
        self.save_rows(self.rows)
        with self.assertRaisesRegex(Invalid, "reproduce"):
            verify(self.output, self.source)

    def test_separately_approved_policy_detects_rehashed_policy_change(self):
        self.publish()
        changed = copy.deepcopy(self.policy)
        changed["fields"]["prompt"] = {"action": "enum", "values": [MASK, "private"]}
        (self.output / "policy.json").write_bytes(encode(changed))
        self.rehash()
        # A self-consistent bundle alone does not establish policy authenticity.
        self.assertTrue(verify(self.output)["verified"])
        with self.assertRaisesRegex(Invalid, "supplied policy"):
            verify(self.output, policy_path=self.policy_path)

    def test_approved_policy_comparison_ignores_formatting(self):
        self.publish()
        self.policy_path.write_text(json.dumps(self.policy, indent=4), encoding="utf-8")
        self.assertTrue(verify(self.output, policy_path=self.policy_path)["policy_verified"])


if __name__ == "__main__":
    unittest.main()
