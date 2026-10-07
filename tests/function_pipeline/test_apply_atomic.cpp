// SPDX-License-Identifier: GPL-3.0-or-later
// Failure injection is confined to this Linux test executable, never the public API.
#include "verified_idioms.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
using namespace dolidiom;
static bool fail_validation=true;
static unsigned validations=0;
extern "C" bool __real_dolir_verify(const DolIRModule*,FILE*);
extern "C" bool __wrap_dolir_verify(const DolIRModule *m,FILE *out){++validations;return fail_validation?false:__real_dolir_verify(m,out);}
static void check(bool x,const char *why){if(!x)throw std::runtime_error(why);}
int main(){DolIRModule m{};try{
    dolir_module_init(&m);auto *f=dolir_add_function(&m,"atomic_test",0x1000,0x1004);auto *b=dolir_add_block(f,0x1000);b->cycle_cost=1;
    auto constant=[&](u32 n){return dolir_constant(f,b,DOLIR_TYPE_I32,n,0x1000);};
    auto binary=[&](DolIROp op,DolIRValue a,DolIRValue c){DolIRValue v[]={a,c};return dolir_append(f,b,op,DOLIR_TYPE_I32,v,2,0,0,0x1000,0);};
    auto x=dolir_state_read(f,b,DOLIR_STATE_GPR0,0x1000);
    auto sign=binary(DOLIR_OP_ASHR,x,constant(31));auto bias=binary(DOLIR_OP_AND,sign,constant(31));
    auto sum=binary(DOLIR_OP_ADD,x,bias);auto root=binary(DOLIR_OP_SUB,binary(DOLIR_OP_AND,sum,constant(31)),bias);
    dolir_state_write(f,b,DOLIR_STATE_GPR31,sign,0x1000);
    auto lr=dolir_state_read(f,b,DOLIR_STATE_LR,0x1000);b->terminator.kind=DOLIR_TERM_INDIRECT;
    b->terminator.target_value=binary(DOLIR_OP_AND,lr,constant(~3u));b->terminator.condition=dolir_constant(f,b,DOLIR_TYPE_I1,1,0x1000);
    Options on;on.enabled=true;auto report=discover(*f,on);Candidate candidate;bool found=false;
    for(auto &c:report.candidates)if(c.root==root&&c.expression.power==5&&c.proof.status=="UNSAT"){candidate=c;found=true;}
    check(found,"candidate not found");RegionContract contract;contract.source_cut_fingerprint=sourceCutFingerprint(*f);contract.roots={root};
    contract.function.source_fingerprint=sourceFingerprint(*f);contract.function.entries_and_code=contract.function.observations=contract.function.exception_resume={dolcert::EvidenceGrade::Verified,"atomic-test-controlled-environment"};
    const auto source=contract.function.source_fingerprint,contract_id=dolcert::contractFingerprint(contract.function);
    contract.function.verify_evidence=[source,contract_id](const dolcert::EvidenceRequest &r){return r.source_fingerprint==source&&r.contract_fingerprint==contract_id&&r.entry_blocks==std::vector<u32>{0}&&r.model=="exact-original-cuts/full-state-observation"&&r.proof_id=="atomic-test-controlled-environment"&&(r.obligation=="ENTRY_POPULATION_OR_CODE_STABILITY_UNPROVED"||r.obligation=="EXCEPTION_RESUME_CLOSURE_UNPROVED"||r.obligation=="EXACT_OBSERVATION_AND_MUTATION_CONTRACT_UNPROVED");};
    auto *old_instructions=b->instructions;auto *old_types=f->value_types;auto *old_blocks=f->blocks;
    auto rejected=apply(*f,candidate,contract,on);
    check(!rejected.changed&&validations==1,"forced post-verification failure did not reject");
    check(std::find(rejected.reasons.begin(),rejected.reasons.end(),"POST_REWRITE_VERIFY_FAILED")!=rejected.reasons.end(),"wrong rejection reason");
    check(sourceFingerprint(*f)==source&&b->instructions==old_instructions&&f->value_types==old_types&&f->blocks==old_blocks,"failed transaction mutated source or ownership");
    fail_validation=false;auto accepted=apply(*f,candidate,contract,on);check(accepted.changed&&validations==2,"valid retry not committed");
    check(__real_dolir_verify(&m,stderr),"committed result invalid");dolir_module_free(&m);
    std::cout<<"{\"forced_verifier_failure_atomic\":true,\"validated_retry_committed\":true}\n";return 0;
}catch(const std::exception &e){dolir_module_free(&m);std::cerr<<e.what()<<'\n';return 1;}}
