#!/usr/bin/env python3
"""Exercise offline platform selection using a synthetic, non-game DOL."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

EXECUTABLE: Path


class OfflineCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="dolrecompx-offline-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        dol = bytearray(0x108)
        for offset, value in ((0, 0x100), (0x48, 0x80004000),
                              (0x90, 8), (0xE0, 0x80004000),
                              (0x100, 0x3860002A), (0x104, 0x4E800020)):
            struct.pack_into(">I", dol, offset, value)
        (self.root / "fixture.dol").write_bytes(dol)
        self.env = dict(os.environ)
        self.env.pop("DOLRECOMP_GAMETDB_TITLES", None)

    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(EXECUTABLE), *args], cwd=self.root,
                              env=self.env, text=True, capture_output=True,
                              timeout=20, check=False)

    def assert_wii(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cpu: Broadway (Wii)", result.stdout)
        self.assertNotIn("using GameCube mode", result.stderr)
        self.assertTrue((self.root / "output/TEST01_generated/TEST01.c").is_file(),
                        result.stdout + result.stderr)

    def test_explicit_title_preserves_default_broadway(self) -> None:
        self.assert_wii(self.run_cli("fixture.dol", "TEST01", "output"))

    def test_explicit_title_and_cpu(self) -> None:
        self.assert_wii(self.run_cli("--cpu", "broadway", "fixture.dol", "TEST01", "output"))

    def test_title_without_output_directory(self) -> None:
        result = self.run_cli("fixture.dol", "TEST01")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "TEST01_generated/TEST01.c").is_file())
        self.assertIn("cpu: Broadway (Wii)", result.stdout)

    def test_explicit_gamecube_still_works(self) -> None:
        result = self.run_cli("--gamecube", "fixture.dol", "output")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cpu: Gekko (GameCube)", result.stdout)
        self.assertTrue((self.root / "output/generated/generated.c").is_file())

    def test_invalid_explicit_title_is_not_silently_accepted(self) -> None:
        result = self.run_cli("fixture.dol", "BAD!ID", "output")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("title id must contain only", result.stderr)

    def test_legacy_titleless_output_directory(self) -> None:
        result = self.run_cli("fixture.dol", "legacy-output")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cpu: Gekko (GameCube)", result.stdout)
        self.assertTrue((self.root / "legacy-output/generated/generated.c").is_file())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dolrecomp", type=Path)
    args = parser.parse_args()
    EXECUTABLE = args.dolrecomp.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
