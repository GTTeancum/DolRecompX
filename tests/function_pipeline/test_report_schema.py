#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generic report shape, retention and decode-failure checks."""
import json
from pathlib import Path
import subprocess
import sys
inputs = '1000 38600001 4e800020\n1000 00000000\n\nnot_hex 44\n1001 4e800020\n'
run = subprocess.run([sys.argv[1]], input=inputs, text=True, capture_output=True, check=True)
reports = [json.loads(x) for x in run.stdout.splitlines()]
assert len(reports) == 5
assert all(x['status'] == 'OPEN' for x in reports)
assert reports[0]['unknown_decode_count'] == 0
assert reports[1]['unknown_decode_count'] == 1
assert not any(x.get('native_abi_plan', {}).get('eligible', False) for x in reports)
assert all(x.get('mutates_ir', False) is False for x in reports)
assert all(x['valid_ir'] is False for x in reports[2:])
try:
    import jsonschema
except ImportError:
    print('Five report/decode retention checks passed; optional jsonschema validation unavailable')
else:
    schema = json.loads((Path(__file__).resolve().parents[2] / 'docs/function-certification.schema.json').read_text())
    for report in reports:
        jsonschema.validate(report, schema)
    print('Five report/decode retention checks and JSON Schema validation passed')
