#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rebuild clean provenance and exercise fail-closed synthetic cost validation."""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/timing"))
sys.dont_write_bytecode = True
import generate_costs as gen

parser = argparse.ArgumentParser()
parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
parser.add_argument("--cc-path")
args, remaining = parser.parse_known_args()


class FunctionalCosts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = [args.cc_path] if args.cc_path else shlex.split(args.cc)
        cls.outputs = gen.build(compiler=cls.compiler)
        cls.manifest = json.loads(cls.outputs[gen.MANIFEST])
        cls.inputs = gen.verify_inputs()
        cls.enum = gen.parse_decoder_enum(cls.inputs["src/frontend/decoder.h"].decode())
        cls.refs, cls.lookup = gen.parse_reference(cls.inputs["tools/timing/reference/PPCTables.cpp"].decode())
        cls.probe_lines = ["cases " + str(gen.EXPECTED_CASES)]
        for row in cls.manifest["opcodes"]:
            cls.probe_lines.append("%d %d %d %08x %s" % (
                row["opcode"], row["modeled_units"] or 0, row["synthetic_case_count"],
                int(row["representative_raw"], 16), " ".join(map(str, row["reference_ids"]))))

    def reject(self, lines):
        with self.assertRaises(gen.ValidationError):
            gen.parse_probe("\n".join(lines), self.enum, self.refs, self.lookup)

    def mutate(self, row, column, value):
        lines = self.probe_lines.copy()
        fields = lines[row + 1].split()
        fields[column] = str(value)
        lines[row + 1] = " ".join(fields)
        return lines

    def test_exact_generated_artifacts(self):
        for path, content in self.outputs.items():
            self.assertEqual((ROOT / path).read_bytes(), content, path)

    def test_inventory_and_identity(self):
        for line in self.outputs[gen.INVENTORY].decode().splitlines():
            digest, path = line.split()
            self.assertEqual(gen.sha(self.outputs[path]), digest)
        self.assertIn(gen.sha(self.outputs[gen.MANIFEST]).encode(), self.outputs[gen.HEADER])

    def test_clean_provenance_allowlist(self):
        provenance = self.manifest["provenance"]
        self.assertEqual(set(provenance), {"reference_revision", "reference_url", "inputs", "generator_inputs"})
        self.assertEqual(provenance["reference_url"], gen.REFERENCE_URL)
        paths = [r["path"] for r in provenance["inputs"] + provenance["generator_inputs"]]
        self.assertEqual(set(paths), set(gen.PINNED_INPUTS) | set(gen.GENERATOR_INPUTS))
        for path in paths:
            self.assertFalse(Path(path).is_absolute())
            self.assertNotIn("..", Path(path).parts)
        for forbidden in (b"/workspace/", b"/home/", b"/Users/", b"original_project_path",
                          b"opcode-weight-mapping", b"reference-manifest", b"game_data", b"generated/chunks"):
            self.assertNotIn(forbidden, self.outputs[gen.MANIFEST])

    def test_complete_synthetic_coverage(self):
        rows = self.manifest["opcodes"]
        self.assertEqual(len(rows), 237)
        self.assertEqual(sum(r["synthetic_case_count"] for r in rows), 16_398_400)
        self.assertEqual(sum(r["valid"] for r in rows), 236)
        self.assertIsNone(rows[0]["modeled_units"])
        self.assertEqual(rows[222]["modeled_units"], 4)
        self.assertTrue(all(r["synthetic_case_count"] > 0 for r in rows))

    def test_missing_enum(self):
        self.reject(self.probe_lines[:-1])

    def test_duplicate_enum(self):
        self.reject(self.mutate(1, 0, 0))

    def test_lost_case(self):
        self.reject(self.mutate(1, 2, 1))

    def test_unknown_not_free_execution(self):
        self.reject(self.mutate(0, 1, 1))

    def test_zero_known_cost(self):
        self.reject(self.mutate(1, 1, 0))

    def test_conflicting_cost(self):
        self.reject(self.mutate(1, 1, 99))

    def test_bad_reference(self):
        self.reject(self.mutate(1, 4, len(self.refs)))

    def test_bad_sample_word(self):
        self.reject(self.mutate(1, 3, "100000000"))

    def test_changed_pinned_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in gen.PINNED_INPUTS:
                dest = root / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((ROOT / path).read_bytes())
            for path in gen.PINNED_INPUTS:
                dest = root / path
                old = dest.read_bytes()
                dest.write_bytes(old + b"\n")
                with self.assertRaises(gen.ValidationError):
                    gen.verify_inputs(root)
                dest.write_bytes(old)

    def test_changed_decoder_enum(self):
        source = self.inputs["src/frontend/decoder.h"].decode()
        with self.assertRaises(gen.ValidationError):
            gen.parse_decoder_enum(source.replace("PPC_OP_UNKNOWN", "PPC_OP_STALE"))

    def test_changed_reference_table(self):
        source = self.inputs["tools/timing/reference/PPCTables.cpp"].decode()
        with self.assertRaises(gen.ValidationError):
            gen.parse_reference(source.replace("s_primary_table", "s_unrecognized_table"))

    def test_relocated_regeneration(self):
        with tempfile.TemporaryDirectory(prefix="clean costs ") as folder:
            root = Path(folder)
            for path in list(gen.PINNED_INPUTS) + gen.GENERATOR_INPUTS:
                dest = root / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / path, dest)
            # Only allowlisted public source and the generator exist in this tree.
            self.assertEqual(gen.build(root=root, compiler=self.compiler), self.outputs)

    def test_concurrent_input_change_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for path in list(gen.PINNED_INPUTS) + gen.GENERATOR_INPUTS:
                dest = root / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((ROOT / path).read_bytes())
            original = gen.enumerate_costs

            def change_then_probe(*values):
                source = root / "src/frontend/decoder.c"
                source.write_bytes(source.read_bytes() + b"\n")
                return original(*values)

            with mock.patch.object(gen, "enumerate_costs", side_effect=change_then_probe):
                with self.assertRaisesRegex(gen.ValidationError, "source changed during generation"):
                    gen.build(root=root, compiler=self.compiler)

    def test_check_is_read_only(self):
        folder = ROOT / "tools/timing"
        before = {str(p.relative_to(folder)): p.read_bytes() for p in folder.rglob("*") if p.is_file()}
        command = [sys.executable, str(folder / "generate_costs.py"), "--check", "--cc", shlex.join(self.compiler)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        after = {str(p.relative_to(folder)): p.read_bytes() for p in folder.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_validation_under_python_optimized(self):
        command = [sys.executable, "-B", "-O", "-c",
                   "import sys;sys.path.insert(0,sys.argv[1]);import generate_costs as g;"
                   "g.require(False,'still checked')", str(ROOT / "tools/timing")]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still checked", result.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *remaining])
