#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Differential-test actual-DolIR test lowerers and recovered C/LLVM artifacts."""
import ctypes, hashlib, json, os, pathlib, random, re, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
evidence=pathlib.Path(sys.argv[1]) if len(sys.argv)>1 else root/'build/evidence-final'
clang=os.environ.get('CLANG','clang')
clang_version=subprocess.check_output([clang,'--version'],text=True).splitlines()[0]
rng=random.Random(0xAC398712)
rows=[]
for path in sorted(evidence.glob('rem*.certificate')):
    stem=path.stem
    bits,power,out=map(int,re.fullmatch(r'rem(32|64)_(\d+)_(\d+)',stem).groups())
    artifact_paths=[evidence/(stem+'.c'),evidence/(stem+'.ll'),evidence/(stem+'_original.c'),evidence/(stem+'_original.ll')]
    library=evidence/(stem+'.so')
    subprocess.run([clang,'-O2','-fPIC','-shared',*map(str,artifact_paths),'-o',str(library)],check=True,capture_output=True)
    lib=ctypes.CDLL(str(library.resolve()))
    functions=[]
    for suffix in ['c','llvm','original_c','original_llvm']:
        fn=getattr(lib,stem+'_'+suffix);fn.argtypes=[ctypes.c_uint64];fn.restype=ctypes.c_uint64;functions.append(fn)
    cases=[0,1,2,-1,-2,1<<(bits-1),(1<<(bits-1))-1,1<<power,(1<<power)-1,(1<<power)+1,-(1<<power),-(1<<power)-1]
    cases += [rng.getrandbits(64) for _ in range(10000)]
    for value in cases:
        x=value&((1<<bits)-1)
        if x>>(bits-1):x-=1<<bits
        remainder=abs(x)%(1<<power)
        if x<0:remainder=-remainder
        expected=remainder&((1<<out)-1)
        actual=[fn(value&((1<<64)-1)) for fn in functions]
        if any(v!=expected for v in actual):raise AssertionError((stem,value,expected,actual))
    rows.append({'artifact':stem,'input_bits':bits,'power':power,'output_bits':out,'cases':len(cases),'all_four_implementations_match':True,'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in artifact_paths}})
report={'scope':'synthetic actual-DolIR pure-expression test lowerers versus typed recovered C/LLVM; not whole guest execution','compiler':clang_version,'artifacts':len(rows),'cases_per_implementation':sum(r['cases'] for r in rows),'rows':rows}
if not rows:raise RuntimeError('No differential artifacts found')
(evidence/'differential-results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='rows'}))
