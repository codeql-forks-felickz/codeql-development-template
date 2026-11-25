"""Offline tests for scan_database.py. Run: python -m unittest test_scan_database"""

import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
import scan_database as sd  # noqa: E402

YML = """---
sourceLocationPrefix: /home/runner/work/app/app
primaryLanguage: rust
creationMetadata:
  sha: 0123456789abcdef0123456789abcdef01234567
  cliVersion: 2.27.5
  creationTime: 2026-11-24T18:43:33.986163900Z
buildMode: none
"""


def archive(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        for name, data in entries.items():
            bundle.writestr(name, data)
    return buffer.getvalue()


class Query(unittest.TestCase):
    def test_a_pattern_becomes_a_ql_string(self):
        self.assertEqual(sd.ql_string('a"b\\c%'), '"a\\"b\\\\c%"')

    def test_the_query_holds_the_pattern_once_and_both_target_cases(self):
        ql = sd.calls_query("%handlers%")
        self.assertEqual(ql.count('"%handlers%"'), 1)
        self.assertIn("call.getStaticTarget().getCanonicalPath()", ql)
        self.assertIn('target = "<unresolved>"', ql)


class Rows(unittest.TestCase):
    CSV = ('"col0","col1","col2","col3"\n'
           '"b.rs",12,"... .path()","<unresolved>"\n'
           '"a.rs",3,"...::format(...)","alloc::fmt::format"\n'
           '"a.rs",9,"...::with(...)","<unresolved>"\n')

    def test_rows_are_read_with_the_line_as_a_number(self):
        rows = sd.parse_calls(self.CSV)
        self.assertEqual(rows[0], {"file": "b.rs", "line": 12, "call": "... .path()", "target": "<unresolved>"})
        self.assertEqual(len(rows), 3)

    def test_calls_are_listed_in_file_and_line_order_with_a_count(self):
        text = sd.format_calls(sd.parse_calls(self.CSV))
        self.assertEqual(text.splitlines()[:3], [
            "a.rs:3  ...::format(...)  ->  alloc::fmt::format",
            "a.rs:9  ...::with(...)  ->  <unresolved>",
            "b.rs:12  ... .path()  ->  <unresolved>",
        ])
        self.assertEqual(text.splitlines()[-1], "3 call(s), 2 without a target")

    def test_only_the_calls_without_a_target_can_be_asked_for(self):
        text = sd.format_calls(sd.parse_calls(self.CSV), unresolved_only=True)
        self.assertNotIn("alloc::fmt::format", text)
        self.assertEqual(text.splitlines()[-1], "3 call(s), 2 without a target")


class Download(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.out = self.root / "out"

    def tearDown(self):
        # a plain rmtree cannot delete the long paths of a database on Windows
        shutil.rmtree(sd.long_path(self.root), ignore_errors=True)

    def fake_gh(self, payload: bytes, code: int = 0):
        calls = []

        def run(cmd, stdout=None, stderr=None, **kwargs):
            calls.append(cmd)
            if stdout is not None and code == 0:
                stdout.write(payload)
            return subprocess.CompletedProcess(cmd, code, b"", b"HTTP 404: Not Found" if code else b"")

        return run, calls

    def test_the_database_is_fetched_with_gh_and_unpacked_below_db(self):
        payload = archive({"rust/codeql-database.yml": YML.encode(), "rust/src/a.rs": b"fn main() {}"})
        run, calls = self.fake_gh(payload)
        with mock.patch.object(sd.subprocess, "run", run):
            db = sd.download("owner/name", "rust", self.out)
        self.assertEqual(db, self.out / "db" / "rust")
        self.assertTrue((db / "src" / "a.rs").is_file())
        self.assertFalse((self.out / "rust.zip").exists())
        self.assertEqual(calls[0][:2], ["gh", "api"])
        self.assertIn("repos/owner/name/code-scanning/codeql/databases/rust", calls[0][-1])
        self.assertIn("Accept: application/zip", calls[0])

    def test_a_failed_request_leaves_no_archive_and_says_why(self):
        run, _ = self.fake_gh(b"", code=1)
        with mock.patch.object(sd.subprocess, "run", run):
            with self.assertRaises(SystemExit) as caught:
                sd.download("owner/name", "rust", self.out)
        self.assertIn("404", str(caught.exception))
        self.assertFalse((self.out / "rust.zip").exists())

    def test_an_entry_that_leaves_the_target_is_refused(self):
        bad = self.root / "bad.zip"
        bad.write_bytes(archive({"../escape.txt": b"x"}))
        with self.assertRaises(SystemExit):
            sd.extract(bad, self.out)
        self.assertFalse((self.root / "escape.txt").exists())

    @unittest.skipUnless(sys.platform == "win32", "paths over 260 characters are only a limit on Windows")
    def test_a_path_over_260_characters_is_unpacked(self):
        deep = "/".join(["a-long-directory-name-inside-a-database"] * 8) + "/file.trap"
        bad = self.root / "deep.zip"
        bad.write_bytes(archive({"rust/" + deep: b"x"}))
        sd.extract(bad, self.out)
        self.assertTrue(os.path.exists("\\\\?\\" + str((self.out / "rust" / deep).resolve())))


class Info(unittest.TestCase):
    def test_the_build_fields_are_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "codeql-database.yml").write_text(YML, encoding="utf-8")
            info = sd.database_info(Path(tmp))
        self.assertEqual(info["primaryLanguage"], "rust")
        self.assertEqual(info["buildMode"], "none")
        self.assertEqual(info["cliVersion"], "2.27.5")
        self.assertEqual(info["sha"], "0123456789abcdef0123456789abcdef01234567")


if __name__ == "__main__":
    unittest.main()
