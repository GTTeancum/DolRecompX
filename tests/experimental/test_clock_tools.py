#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ClockTools(unittest.TestCase):
    def test_failed_rerun_invalidates_prior_success(self):
        with tempfile.TemporaryDirectory(prefix="clock failed run ") as folder:
            output = Path(folder)
            report = output / "report.json"
            report.write_text('{"passed":true}\n')
            result = subprocess.run([sys.executable, str(ROOT / "tests/experimental/test_clock_targets.py"),
                                     "--output", str(output), "--clang", str(output / "missing-compiler")],
                                    text=True, capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json.loads(report.read_text())["passed"])

    def test_arithmetic_vectors_reproduce(self):
        with tempfile.TemporaryDirectory(prefix="clock vectors ") as folder:
            output = Path(folder) / "arithmetic_vectors.h"
            command = [sys.executable, str(ROOT / "tools/timing/generate_arithmetic_vectors.py"),
                       "--output", str(output)]
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            original = output.read_bytes()
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(original.count(b"{UINT64_C("), 12468)


if __name__ == "__main__":
    unittest.main()
