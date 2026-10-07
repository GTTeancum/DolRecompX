// SPDX-License-Identifier: GPL-3.0-or-later
// One-shot allocation failures must not produce partial accepted provenance.
#include "function_certification.h"
#include "analysis/checked_serialization.h"
#include "verified_idioms.h"
#include <openssl/evp.h>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <new>
#include <stdexcept>

// Test-only dynamic API interception; production libraries have no fault hooks.
static bool refuse_proof=false,force_unknown=false;
static const char *override_evidence=nullptr;
static const char *(*actual_ast_to_string)(void*,void*)=nullptr;
static void *(*actual_get_proof)(void*,void*)=nullptr;
static int (*actual_solver_check)(void*,void*)=nullptr;
extern "C" void *__real_dlsym(void*,const char*);
static void *checked_proof(void *c,void *solver){return refuse_proof?nullptr:actual_get_proof(c,solver);}
static int checked_result(void *c,void *solver){return force_unknown?0:actual_solver_check(c,solver);}
static const char *checked_text(void *c,void *ast){return override_evidence?override_evidence:actual_ast_to_string(c,ast);}
// dlsym can run during sanitizer startup, before its interceptors are ready.
__attribute__((no_sanitize("address","undefined")))
static bool symbolIs(const char *a,const char *b){while(*a&&*a==*b){++a;++b;}return *a==*b;}
extern "C" __attribute__((no_sanitize("address","undefined")))
void *__wrap_dlsym(void *handle,const char *name){
    void *symbol=__real_dlsym(handle,name);
    if(symbol&&symbolIs(name,"Z3_solver_get_proof")){actual_get_proof=reinterpret_cast<decltype(actual_get_proof)>(symbol);return reinterpret_cast<void*>(&checked_proof);}
    if(symbol&&symbolIs(name,"Z3_solver_check")){actual_solver_check=reinterpret_cast<decltype(actual_solver_check)>(symbol);return reinterpret_cast<void*>(&checked_result);}
    if(symbol&&symbolIs(name,"Z3_ast_to_string")){actual_ast_to_string=reinterpret_cast<decltype(actual_ast_to_string)>(symbol);return reinterpret_cast<void*>(&checked_text);}
    return symbol;
}

static size_t allocation_count=0,fail_at=0;
static bool armed=false;
void *operator new(size_t size){
    if(armed && ++allocation_count==fail_at)throw std::bad_alloc();
    if(void *p=std::malloc(size?size:1))return p;
    throw std::bad_alloc();
}
void *operator new[](size_t size){return ::operator new(size);}
void operator delete(void *p)noexcept{std::free(p);}
void operator delete[](void *p)noexcept{std::free(p);}
void operator delete(void *p,size_t)noexcept{std::free(p);}
void operator delete[](void *p,size_t)noexcept{std::free(p);}
static void arm(size_t n){allocation_count=0;fail_at=n;armed=true;}
static void require(bool value,const char *why){if(!value)throw std::runtime_error(why);}
static size_t injected_cases=0;

template<class F>static void stringFailures(const char *name,F function){
    const auto baseline=function();
    arm(0);auto again=function();armed=false;const size_t count=allocation_count;
    require(again==baseline,"unstable baseline serialization");
    for(size_t n=1;n<=count;++n){
        std::string got;bool returned=false;arm(n);
        try{got=function();armed=false;returned=true;}catch(...){armed=false;}
        require(!returned||got==baseline,"allocation failure returned altered serialization");
        ++injected_cases;
    }
    std::cout<<name<<": "<<count<<" allocation positions checked\n";
}

struct Fixture {
    DolIRModule module{};DolIRValue root=0;
    Fixture(){
        dolir_module_init(&module);
        auto *f=dolir_add_function(&module,"synthetic_provenance",0x1000,0x1004);
        auto *b=dolir_add_block(f,0x1000);b->raw=0x60000000;b->cycle_cost=1;
        auto constant=[&](u32 n){return dolir_constant(f,b,DOLIR_TYPE_I32,n,0x1000);};
        auto binary=[&](DolIROp op,DolIRValue a,DolIRValue c){DolIRValue v[]={a,c};return dolir_append(f,b,op,DOLIR_TYPE_I32,v,2,0,0,0x1000,0);};
        auto x=dolir_state_read(f,b,DOLIR_STATE_GPR0,0x1000);
        auto sign=binary(DOLIR_OP_ASHR,x,constant(31));auto bias=binary(DOLIR_OP_AND,sign,constant(31));
        auto sum=binary(DOLIR_OP_ADD,x,bias);root=binary(DOLIR_OP_SUB,binary(DOLIR_OP_AND,sum,constant(31)),bias);
        auto lr=dolir_state_read(f,b,DOLIR_STATE_LR,0x1000);
        b->terminator.kind=DOLIR_TERM_INDIRECT;b->terminator.target_value=binary(DOLIR_OP_AND,lr,constant(~3u));
        b->terminator.condition=dolir_constant(f,b,DOLIR_TYPE_I1,1,0x1000);b->terminator.guest_pc=0x1000;
        require(dolir_verify(&module,stderr),"synthetic fixture invalid");
    }
    ~Fixture(){dolir_module_free(&module);}
    DolIRFunction &function(){return module.functions[0];}
};

static dolidiom::RegionContract contractFor(DolIRFunction &f,DolIRValue root){
    dolidiom::RegionContract r;r.roots={root};r.source_cut_fingerprint=dolidiom::sourceCutFingerprint(f);
    auto &c=r.function;c.source_fingerprint=dolcert::sourceFingerprint(f);
    c.entries_and_code=c.observations=c.exception_resume={dolcert::EvidenceGrade::Verified,"synthetic-provenance-test-environment"};
    const auto source=c.source_fingerprint,contract=dolcert::contractFingerprint(c);
    c.verify_evidence=[source,contract](const dolcert::EvidenceRequest &q){return q.source_fingerprint==source&&q.contract_fingerprint==contract&&q.entry_blocks==std::vector<u32>{0}&&q.proof_id=="synthetic-provenance-test-environment";};
    return r;
}

int main(){try{
    require(dolanalysis::completeSExpressions("(proof |a(b)| \"x)\"\"(y\")",1),"quoted SMT text rejected");
    require(!dolanalysis::completeSExpressions("(let ((x",1)&&!dolanalysis::completeSExpressions("(proof ...)",1)&&!dolanalysis::completeSExpressions("(proof) trailing",1)&&!dolanalysis::completeSExpressions("(proof)",2),"incomplete SMT text admitted");
    require(dolanalysis::completeProofDag("#1 := false\n[asserted #1]: false\n",2),"complete proof DAG rejected");
    require(!dolanalysis::completeProofDag("[asserted #1]: false\n",2)&&!dolanalysis::completeProofDag("[asserted]: false",2)&&!dolanalysis::completeProofDag("#2 := [asserted]: false\n",3),"incomplete proof DAG admitted");
    Fixture original;auto &f=original.function();auto contract=contractFor(f,original.root);
    auto other=contract.function;++other.max_edges;
    require(dolcert::contractFingerprint(other)!=dolcert::contractFingerprint(contract.function),"different contracts collide");
    stringFailures("source",[&]{return dolcert::sourceFingerprint(f);});
    stringFailures("contract",[&]{return dolcert::contractFingerprint(contract.function);});
    stringFailures("changed contract",[&]{return dolcert::contractFingerprint(other);});
    stringFailures("cuts",[&]{return dolidiom::sourceCutFingerprint(f);});
    const std::string input(2048,'x');
    stringFailures("sha256",[&]{return dolidiom::sha256(input);});
    const auto certificate=dolcert::certify(f,contract.function);
    stringFailures("JSON",[&]{return dolcert::toJson(certificate);});
    const dolidiom::SRemPow2 expression{1,DOLIR_TYPE_I32,DOLIR_TYPE_I32,5};
    stringFailures("C artifact",[&]{return dolidiom::emitRecoveredC(expression,"synthetic_remainder");});
    stringFailures("LLVM artifact",[&]{return dolidiom::emitRecoveredLLVM(expression,"synthetic_remainder");});

    dolidiom::Options on;on.enabled=true;
    auto report=dolidiom::discover(f,on);dolidiom::Candidate candidate;bool found=false;
    for(const auto &c:report.candidates)if(c.root==original.root&&c.expression.power==5&&c.proof.status=="UNSAT"){candidate=c;found=true;}
    require(found,"no synthetic candidate");
    auto oversized=f;oversized.value_count=1000002;
    require(dolidiom::discover(oversized,on).candidates.empty(),"oversized canonical source admitted");
    require(dolidiom::verify(oversized,candidate).status!="UNSAT","oversized proof admitted");
    auto empty_identity=candidate;empty_identity.source_fingerprint.clear();
    require(dolidiom::verify(f,empty_identity).status!="UNSAT","empty source identity admitted");
    const auto proof=dolidiom::verify(f,candidate);
    require(proof.query.rfind("(set-logic QF_BV)",0)==0&&proof.query.find("produce-proofs")==std::string::npos,"query modifies proof mode after context initialization");
    require(proof.solver_output.rfind("unsat\n",0)==0&&proof.solver_output.size()>6&&proof.solver_output.find("(error")==std::string::npos,"proof configuration did not produce an UNSAT proof");
    const auto original_fingerprint=dolcert::sourceFingerprint(f);
    refuse_proof=true;
    require(dolidiom::verify(f,candidate).status=="SOLVER_PROOF_FAILED","missing proof authorized UNSAT");
    require(!dolidiom::apply(f,candidate,contract,on).changed&&dolcert::sourceFingerprint(f)==original_fingerprint,"missing proof authorized a rewrite");
    refuse_proof=false;
    for(const char *broken:{"(let ((x", "(error \"unavailable\")", "(proof ...)", "(proof) trailing", "()", "[]: false\n", "[error]: false\n", "[asserted] junk [asserted]: false\n", "#1 := false\n[asserted #2]: false\n", "#1 := ([)]\n[asserted #1]: false\n", "#1 := false\n#1 := false\n[asserted #1]: false\n"}){
        override_evidence=broken;
        require(dolidiom::verify(f,candidate).status=="SOLVER_PROOF_FAILED","incomplete proof text authorized UNSAT");
        require(!dolidiom::apply(f,candidate,contract,on).changed&&dolcert::sourceFingerprint(f)==original_fingerprint,"incomplete proof text authorized a rewrite");
    }
    override_evidence=nullptr;force_unknown=true;
    require(dolidiom::verify(f,candidate).status=="UNKNOWN_OR_ERROR","UNKNOWN authorized UNSAT");
    require(!dolidiom::apply(f,candidate,contract,on).changed&&dolcert::sourceFingerprint(f)==original_fingerprint,"UNKNOWN authorized a rewrite");
    force_unknown=false;
    arm(0);auto proof_again=dolidiom::verify(f,candidate);armed=false;size_t count=allocation_count;
    require(proof_again.status=="UNSAT","baseline proof failed");
    for(size_t n=1;n<=count;++n){
        dolidiom::Proof got;bool returned=false;arm(n);
        try{got=dolidiom::verify(f,candidate);armed=false;returned=true;}catch(...){armed=false;}
        if(returned&&got.status=="UNSAT")require(got.query==proof.query&&got.query_sha256==proof.query_sha256&&got.implementation_sha256==proof.implementation_sha256&&got.solver_library_sha256==proof.solver_library_sha256&&got.solver_output==proof.solver_output&&got.evidence_format==proof.evidence_format&&got.proof_root_id==proof.proof_root_id,"allocation failure admitted altered proof");
        ++injected_cases;
    }
    std::cout<<"verify: "<<count<<" allocation positions checked\n";
    auto false_candidate=candidate;false_candidate.expression.power=4;
    const auto counterexample=dolidiom::verify(f,false_candidate);
    require(counterexample.status=="SAT","counterexample baseline missing");
    arm(0);auto counterexample_again=dolidiom::verify(f,false_candidate);armed=false;count=allocation_count;
    require(counterexample_again.solver_output==counterexample.solver_output,"unstable counterexample baseline");
    for(size_t n=1;n<=count;++n){
        dolidiom::Proof got;bool returned=false;arm(n);
        try{got=dolidiom::verify(f,false_candidate);armed=false;returned=true;}catch(...){armed=false;}
        if(returned&&(got.status=="SAT"||got.status=="UNSAT"))require(got.status=="SAT"&&got.query==counterexample.query&&got.query_sha256==counterexample.query_sha256&&got.solver_output==counterexample.solver_output&&got.evidence_format==counterexample.evidence_format,"allocation failure admitted altered counterexample");
        ++injected_cases;
    }
    std::cout<<"counterexample: "<<count<<" allocation positions checked\n";
    Fixture baseline;auto allowed=contractFor(baseline.function(),baseline.root);
    arm(0);auto changed=dolidiom::apply(baseline.function(),candidate,allowed,on);armed=false;count=allocation_count;
    require(changed.changed,"baseline apply failed");const auto after=changed.after_fingerprint;
    for(size_t n=1;n<=count;++n){
        Fixture item;auto admission=contractFor(item.function(),item.root);auto &source=item.function();
        auto before=dolcert::sourceFingerprint(source);auto *instructions=source.blocks[0].instructions;auto *types=source.value_types;
        auto *blocks=source.blocks;auto old_capacity=source.blocks[0].instruction_capacity,old_value_capacity=source.value_capacity;
        auto old_count=source.blocks[0].instruction_count,old_values=source.value_count;
        dolidiom::ApplyResult result;bool returned=false;arm(n);
        try{result=dolidiom::apply(source,candidate,admission,on);armed=false;returned=true;}catch(...){armed=false;}
        if(returned&&result.changed)require(result.before_fingerprint==before&&result.after_fingerprint==after&&dolcert::sourceFingerprint(source)==after,"allocation failure admitted altered rewrite");
        else require(dolcert::sourceFingerprint(source)==before&&source.blocks==blocks&&source.blocks[0].instruction_capacity==old_capacity&&source.value_capacity==old_value_capacity&&source.blocks[0].instructions==instructions&&source.value_types==types&&source.blocks[0].instruction_count==old_count&&source.value_count==old_values,"exception or rejection changed source ownership");
        ++injected_cases;
    }
    std::cout<<"apply: "<<count<<" allocation positions checked\n";

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    require(EVP_set_default_properties(nullptr,"provider=definitely_missing")==1,"provider fault injection failed");
    bool refused=false;try{(void)dolcert::contractFingerprint(contract.function);}catch(...){refused=true;}
    require(EVP_set_default_properties(nullptr,"")==1,"provider reset failed");
    require(refused,"failed SHA provider yielded a fingerprint");
    require(dolcert::contractFingerprint(contract.function).size()==64,"provider did not recover");
    std::cout<<"SHA provider refusal/recovery checked\n";
#else
    std::cout<<"SHA provider fault injection requires OpenSSL 3; skipped\n";
#endif
    std::cout<<"PASS: "<<injected_cases<<" one-shot allocation cases\n";return 0;
}catch(const std::exception &e){armed=false;std::cerr<<e.what()<<'\n';return 1;}}
