#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independently replay saved QF_BV queries with a bounded Z3 C API context."""
import argparse, ctypes, hashlib, json, pathlib, re
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('directory',type=pathlib.Path)
parser.add_argument('--expected-count',type=int)
parser.add_argument('--identity-manifest',type=pathlib.Path)
args=parser.parse_args()
root=args.directory
identity=json.loads(args.identity_manifest.read_text()) if args.identity_manifest else None
def require(condition,message):
    if not condition:raise RuntimeError(str(message))
z3=ctypes.CDLL('libz3.so.4')
ptr=ctypes.c_void_p
z3.Z3_mk_config.restype=ptr
z3.Z3_set_param_value.argtypes=[ptr,ctypes.c_char_p,ctypes.c_char_p]
z3.Z3_mk_context.argtypes=[ptr];z3.Z3_mk_context.restype=ptr
z3.Z3_del_config.argtypes=[ptr];z3.Z3_del_context.argtypes=[ptr]
z3.Z3_eval_smtlib2_string.argtypes=[ptr,ctypes.c_char_p];z3.Z3_eval_smtlib2_string.restype=ctypes.c_char_p
count=0
for cert in sorted(root.glob('*.certificate')):
    fields=dict(line.split('=',1) for line in cert.read_text().splitlines())
    query=cert.with_suffix('.smt2').read_bytes()
    require(hashlib.sha256(query).hexdigest()==fields['query'],cert)
    require(re.fullmatch('[0-9a-f]{64}',fields['implementation']) and re.fullmatch('[0-9a-f]{64}',fields['solver_library']),cert)
    if identity:
        require(fields['implementation']==identity['idiom_id'],(cert,'stale idiom implementation'))
        require(fields.get('certification_implementation')==identity['certification_id'],(cert,'stale certifier implementation'))
    cfg=z3.Z3_mk_config();z3.Z3_set_param_value(cfg,b'timeout',b'10000')
    ctx=z3.Z3_mk_context(cfg);z3.Z3_del_config(cfg)
    try:result=z3.Z3_eval_smtlib2_string(ctx,query).decode().strip()
    finally:z3.Z3_del_context(ctx)
    require(fields['result']=='UNSAT' and result=='unsat',(cert,result))
    count+=1
require(count,'No proofs found')
if args.expected_count is not None:require(count==args.expected_count,'Incomplete proof set')
print(json.dumps({'independent_smt_replays':count,'all_unsat':True}))
