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
ptr=ctypes.c_void_p; string=ctypes.c_char_p; uint=ctypes.c_uint
for name,arguments,result in [
    ('Z3_mk_config',[],ptr),('Z3_set_param_value',[ptr,string,string],None),
    ('Z3_mk_context',[ptr],ptr),('Z3_del_config',[ptr],None),('Z3_del_context',[ptr],None),
    ('Z3_mk_string_symbol',[ptr,string],ptr),('Z3_mk_solver_for_logic',[ptr,ptr],ptr),
    ('Z3_solver_inc_ref',[ptr,ptr],None),('Z3_solver_dec_ref',[ptr,ptr],None),
    ('Z3_mk_params',[ptr],ptr),('Z3_params_inc_ref',[ptr,ptr],None),('Z3_params_dec_ref',[ptr,ptr],None),
    ('Z3_params_set_uint',[ptr,ptr,ptr,uint],None),('Z3_solver_set_params',[ptr,ptr,ptr],None),
    ('Z3_solver_from_string',[ptr,ptr,string],None),('Z3_solver_check',[ptr,ptr],ctypes.c_int),
    ('Z3_get_error_code',[ptr],uint)]:
    function=getattr(z3,name);function.argtypes=arguments;function.restype=result
error_handler=ctypes.CFUNCTYPE(None,ptr,uint)(lambda context,error:None)
z3.Z3_set_error_handler.argtypes=[ptr,ctypes.c_void_p]
def no_error(context):require(z3.Z3_get_error_code(context)==0,'Solver API error')
def replay(query):
    cfg=z3.Z3_mk_config();require(cfg,'Missing solver configuration')
    try:
        z3.Z3_set_param_value(cfg,b'proof',b'true')
        ctx=z3.Z3_mk_context(cfg);require(ctx,'Missing solver context')
    finally:z3.Z3_del_config(cfg)
    solver=None;params=None
    try:
        z3.Z3_set_error_handler(ctx,error_handler)
        logic=z3.Z3_mk_string_symbol(ctx,b'QF_BV');no_error(ctx);require(logic,'Missing solver logic')
        solver=z3.Z3_mk_solver_for_logic(ctx,logic);no_error(ctx);require(solver,'Missing solver')
        z3.Z3_solver_inc_ref(ctx,solver);no_error(ctx)
        params=z3.Z3_mk_params(ctx);no_error(ctx);require(params,'Missing solver parameters')
        z3.Z3_params_inc_ref(ctx,params);no_error(ctx)
        key=z3.Z3_mk_string_symbol(ctx,b'timeout');no_error(ctx);require(key,'Missing timeout key')
        z3.Z3_params_set_uint(ctx,params,key,10000);no_error(ctx)
        z3.Z3_solver_set_params(ctx,solver,params);no_error(ctx)
        z3.Z3_solver_from_string(ctx,solver,query);no_error(ctx)
        result=z3.Z3_solver_check(ctx,solver);no_error(ctx)
        return result
    finally:
        if params:z3.Z3_params_dec_ref(ctx,params)
        if solver:z3.Z3_solver_dec_ref(ctx,solver)
        z3.Z3_del_context(ctx)
count=0
for cert in sorted(root.glob('*.certificate')):
    fields=dict(line.split('=',1) for line in cert.read_text().splitlines())
    require(fields.get('evidence_format')=='z3-shared-proof-dag.v1',(cert,'unsupported proof encoding'))
    query=cert.with_suffix('.smt2').read_bytes()
    require(hashlib.sha256(query).hexdigest()==fields['query'],cert)
    require(re.fullmatch('[0-9a-f]{64}',fields['implementation']) and re.fullmatch('[0-9a-f]{64}',fields['solver_library']),cert)
    if identity:
        require(fields['implementation']==identity['idiom_id'],(cert,'stale idiom implementation'))
        require(fields.get('certification_implementation')==identity['certification_id'],(cert,'stale certifier implementation'))
    result=replay(query)
    require(fields['result']=='UNSAT' and result==-1,(cert,result))
    count+=1
require(count,'No proofs found')
if args.expected_count is not None:require(count==args.expected_count,'Incomplete proof set')
print(json.dumps({'independent_smt_replays':count,'all_unsat':True}))
