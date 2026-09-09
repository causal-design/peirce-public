# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from pathlib import Path
import os
import sys
import tempfile
import time
import unittest

from _package import cli_runner

run_argv = cli_runner.run_argv


class CliRunnerTests(unittest.TestCase):
    def test_literal_argv_eof_and_stdin(self):
        result = run_argv([sys.executable, "-c", "import sys; print(sys.stdin.read())"], stdin="hello")
        self.assertEqual(result["state"], "exited")
        self.assertEqual(result["stdout"].strip(), "hello")

    def test_both_streams_are_drained_and_bounded(self):
        result = run_argv(
            [sys.executable, "-c", "import sys; print('o'*200000); print('e'*200000, file=sys.stderr)"],
            max_output_bytes=1024,
        )
        self.assertEqual(result["state"], "exited")
        self.assertTrue(result["stdout_truncated"])
        self.assertTrue(result["stderr_truncated"])
        self.assertGreater(result["stdout_omitted_bytes"], 0)
        self.assertGreater(result["stderr_omitted_bytes"], 0)

    def test_timeout_cleans_process_group_and_reports_uncertainty(self):
        result = run_argv([sys.executable, "-c", "import time; time.sleep(30)"], timeout_seconds=.1)
        self.assertEqual(result["state"], "timed_out")
        self.assertTrue(result["uncertain"])

    def test_timeout_kills_a_real_descendant_in_the_inherited_group(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            pid_file = Path(tmp) / "descendant.pid"
            code = (
                "import os, subprocess, sys, time; "
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                "open(sys.argv[1], 'w').write(f'{os.getpid()}:{child.pid}:{os.getpgid(child.pid)}'); "
                "time.sleep(30)"
            )
            result = run_argv([sys.executable, "-c", code, str(pid_file)], timeout_seconds=.1)
            self.assertEqual(result["state"], "timed_out")
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline and not pid_file.exists():
                time.sleep(.01)
            self.assertTrue(pid_file.exists())
            parent_pid, child_pid, group_id = (int(value) for value in pid_file.read_text().split(":"))
            self.assertEqual(group_id, parent_pid)
            self.assertNotEqual(child_pid, os.getpid())
            self.assertNotEqual(group_id, os.getpgrp())
            while True:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    self.fail("descendant survived process-group timeout cleanup")
                time.sleep(.01)

    def test_signaled_execution_is_uncertain(self):
        result = run_argv([sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"])
        self.assertEqual(result["state"], "signaled")
        self.assertEqual(result["signal"], 15)
        self.assertTrue(result["uncertain"])

    def test_non_finite_timeout_is_rejected_without_spawn(self):
        for timeout in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(timeout=timeout):
                self.assertEqual(run_argv(["/path/that/cannot/spawn"], timeout_seconds=timeout)["state"], "rejected")

    def test_input_and_argv_limits_reject_without_spawn(self):
        self.assertEqual(run_argv([], stdin=None)["state"], "rejected")
        self.assertEqual(run_argv(["/bin/true"], stdin="x" * 3, max_stdin_bytes=2)["state"], "rejected")


if __name__ == "__main__":
    unittest.main()
