#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Linux-only synthetic checks for incomplete evidence delivery and input."""
import pathlib
import subprocess
import sys
import tempfile

certify, discover = sys.argv[1:]
with tempfile.TemporaryDirectory() as directory:
    root = pathlib.Path(directory)
    source = root / "synthetic.pc-raw"
    source.write_text("1000 4e800020\n")
    normal = subprocess.run([discover, str(source), str(root / "normal")], capture_output=True)
    if normal.returncode:
        raise RuntimeError("synthetic driver baseline failed: " + normal.stderr.decode())
    broken = root / "broken"
    broken.mkdir()
    (broken / "discovery.json").symlink_to("/dev/full")
    if subprocess.run([discover, str(source), str(broken)], capture_output=True).returncode == 0:
        raise RuntimeError("report write/close failure was ignored")
    with open("/dev/full", "wb") as full:
        result = subprocess.run([certify], input=b"1000 4e800020\n", stdout=full, stderr=subprocess.PIPE)
    if result.returncode == 0:
        raise RuntimeError("certificate stdout failure was ignored")
    for text in ["1000 4e800020\n1004", "1000 4e800020\n1004 100000000", "fffffffc 60000000\n0 4e800020"]:
        source.write_text(text)
        if subprocess.run([discover, str(source), str(root / "invalid")], capture_output=True).returncode == 0:
            raise RuntimeError("incomplete, oversized or wrapping input was accepted")
print("PASS: checked evidence delivery and malformed input refusal")
