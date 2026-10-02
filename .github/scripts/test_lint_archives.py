import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from lint_archives import extract_entries, lint_entries, main


class LintArchivesTest(unittest.TestCase):
    def test_extract_entries(self):
        content = """# Archives
| Log Origin | Archive Location | |
|------------|------------------|--|
| base | https://archive.org/details/base † | [.torrent](https://archive.org/base.torrent) |
| split | https://archive.org/details/split https://archive.org/details/split_ext1 |
| other | https://example.com/archive/ ||
| torrent-only | *too large for the Internet Archive* | [.torrent](local.torrent) |
Not a table row
"""
        self.assertEqual(extract_entries(content), [
            ("base", "https://archive.org/details/base", "https://archive.org/base.torrent"),
            ("split", "https://archive.org/details/split https://archive.org/details/split_ext1", None),
            ("other", "https://example.com/archive/", None),
            ("torrent-only", "*too large for the Internet Archive*", "local.torrent"),
        ])

    @patch("lint_archives.subprocess.run")
    def test_invocations_and_failure_aggregation(self, run):
        run.side_effect = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
        entries = [
            ("base", "https://archive.org/details/base", "https://example.com/base.torrent"),
            ("split", "https://archive.org/details/split https://archive.org/details/split_ext1", None),
            ("torrent-only", "*no archive URL*", "local.torrent"),
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertFalse(lint_entries(Path("/tmp/linter"), entries))
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0], [
            "/tmp/linter", "-origin", "base", "-url", "https://archive.org/details/base",
            "-torrent", "https://example.com/base.torrent",
        ])
        self.assertEqual(run.call_args_list[1].args[0], [
            "/tmp/linter", "-origin", "split", "-url",
            "https://archive.org/details/split https://archive.org/details/split_ext1",
        ])
        self.assertIn("SKIP: torrent-only", output.getvalue())
        self.assertIn("Linting failed!", output.getvalue())

    @patch("lint_archives.subprocess.run")
    def test_success(self, run):
        run.return_value = subprocess.CompletedProcess([], 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(lint_entries(Path("/tmp/linter"), [("origin", "https://example.com", None)]))

    @patch("lint_archives.subprocess.run")
    @patch("lint_archives.Path.read_text", return_value="| origin | https://example.com |\n")
    @patch("sys.argv", ["lint_archives.py"])
    def test_build_once(self, read_text, run):
        run.return_value = subprocess.CompletedProcess([], 0)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 0)
        self.assertEqual(run.call_count, 2)
        build = run.call_args_list[0]
        self.assertEqual(build.args[0][:3], ["go", "build", "-o"])
        self.assertTrue(build.kwargs["check"])
        self.assertEqual(run.call_args_list[1].args[0][0], build.args[0][3])


if __name__ == "__main__":
    unittest.main()
