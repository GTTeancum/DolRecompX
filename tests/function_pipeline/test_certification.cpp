// SPDX-License-Identifier: GPL-3.0-or-later
#include "function_certification.h"
#include "ir/dolir_builder.h"
#include <cstdlib>
#include <iostream>
using namespace dolcert;
#define CHECK(x) do{if(!(x)){std::cerr<<__FILE__<<':'<<__LINE__<<": "#x"\n";std::exit(1);}}while(0)
struct Module {
 DolIRModule m{};Module(){dolir_module_init(&m);}~Module(){dolir_module_free(&m);}
 DolIRFunction &words(std::initializer_list<u32> raw){std::vector<PPCInst> is;for(auto w:raw)is.push_back(ppc_decode(w,0x1000+is.size()*4));CHECK(dolir_build_chunk(&m,is.data(),is.size(),0x1000));CHECK(dolir_verify(&m,stderr));return m.functions[0];}
 DolIRFunction &empty(u32 blocks=1){auto *f=dolir_add_function(&m,"synthetic",0x1000,0x1000+4*blocks);for(u32 i=0;i<blocks;i++){auto *b=dolir_add_block(f,0x1000+i*4);b->cycle_cost=1;b->terminator.guest_pc=b->guest_address;}return *f;}
};
Contract trusted(const DolIRFunction &f){
 Contract c;c.source_fingerprint=sourceFingerprint(f);c.entries_and_code=c.exception_resume=c.observations={EvidenceGrade::Verified,"synthetic-closed-world-test-harness-v1"};
 // This is a bounded synthetic environment: no other entrants, writers,
 // callbacks, exceptions or observers; original cuts retained, no execution
 // transformation. It is NOT a production evidence verifier.
 c.verify_evidence=[fingerprint=c.source_fingerprint](const EvidenceRequest &r){return r.source_fingerprint==fingerprint && r.proof_id=="synthetic-closed-world-test-harness-v1";};return c;
}
void ret(DolIRFunction &f,DolIRBlock &b,DolIRValue value=0){if(!value)value=dolir_state_read(&f,&b,DOLIR_STATE_LR,b.guest_address);b.terminator.kind=DOLIR_TERM_INDIRECT;b.terminator.target_value=value;b.terminator.condition=dolir_constant(&f,&b,DOLIR_TYPE_I1,1,b.guest_address);}
bool reasonHas(const Certificate &c,const char *code){for(auto &r:c.reasons)if(r.code==code)return true;return false;}
int main(){u32 tests=0;
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto before=sourceFingerprint(f);auto c=certify(f);CHECK(c.status==Status::Open);CHECK(!c.abi.eligible);CHECK(c.blocks.back().returns_incoming_lr);CHECK(sourceFingerprint(f)==before);++tests;auto t=trusted(f);c=certify(f,t);CHECK(c.status==Status::Closed);CHECK(c.abi.eligible);CHECK(c.abi.exact_original_cuts_required);CHECK(!c.abi.termination_proved);++tests;t.verify_evidence={};c=certify(f,t);CHECK(c.status==Status::Conditional);CHECK(!c.abi.eligible);++tests;t=trusted(f);t.source_fingerprint="stale";CHECK(certify(f,t).status==Status::Open);++tests;}
 {Module m;auto &f=m.words({0x48001001,0x4e800020});auto c=certify(f,trusted(f));CHECK(c.status==Status::Open);CHECK(c.effect_summary.opaque);CHECK(!c.blocks[1].returns_incoming_lr);CHECK(reasonHas(c,"OPAQUE_CALL_NO_ABI_ASSUMPTIONS"));++tests;}
 {Module m;auto &f=m.words({0x7c0802a6,0x48001001,0x7c0803a6,0x4e800020});auto c=certify(f,trusted(f));CHECK(c.status==Status::Open);CHECK(!c.blocks[3].returns_incoming_lr);++tests;}
 {Module m;auto &f=m.words({0x7c0802a6,0x7c0803a6,0x4e800020});auto c=certify(f,trusted(f));CHECK(c.status==Status::Closed);CHECK(c.blocks[2].returns_incoming_lr);++tests;}
 {Module m;auto &f=m.words({0x4e800420});auto c=certify(f,trusted(f));CHECK(c.status==Status::Open);CHECK(reasonHas(c,"UNKNOWN_INDIRECT_TARGET"));++tests;}
 {Module m;auto &f=m.words({0x44000002});auto c=certify(f,trusted(f));CHECK(c.status==Status::Open);CHECK(c.effect_summary.exception_resume);++tests;}
 {Module m;auto &f=m.words({0x4c000064});auto c=certify(f,trusted(f));CHECK(c.status==Status::Open);CHECK(reasonHas(c,"RFI_TARGET_AND_RESUME_UNPROVED"));++tests;}
 {Module m;auto &f=m.words({0x80640000,0x4e800020});auto c=certify(f,trusted(f));CHECK(c.effect_summary.memory_write && c.effect_summary.callback && c.effect_summary.host_bindings && c.effect_summary.terminal_partial_effect);CHECK(c.status==Status::Open);++tests;}
 {Module m;auto &f=m.words({0x38630001,0x2c03000a,0x4180fff8,0x4e800020});auto c=certify(f,trusted(f));CHECK(c.status==Status::Closed);CHECK(!c.abi.termination_proved);++tests;}
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto t=trusted(f);t.entry_blocks={0,1};auto c=certify(f,t);CHECK(c.status==Status::Open);CHECK(!c.blocks[1].returns_incoming_lr);++tests;}
 {Module m;auto &f=m.empty();auto &b=f.blocks[0];b.terminator.kind=DOLIR_TERM_RETURN;b.terminator.target_addresses[0]=0x2000;auto c=certify(f,trusted(f));CHECK(c.status==Status::Open);CHECK(reasonHas(c,"DOLIR_RETURN_IS_LITERAL_SIDE_EXIT"));++tests;}
 {Module m;auto &f=m.empty(2);auto &b=f.blocks[0];auto addr=dolir_constant(&f,&b,DOLIR_TYPE_I32,0x2000,0x1000);auto ptr=dolir_append(&f,&b,DOLIR_OP_GUEST_LOAD,DOLIR_TYPE_I32,&addr,1,0,4,0x1000,DOLIR_EFFECT_READ_MEMORY|DOLIR_EFFECT_MAY_EXIT);ret(f,b,ptr);ret(f,f.blocks[1]);auto t=trusted(f);auto c=certify(f,t);CHECK(c.status==Status::Open);++tests;t.immutable_words.push_back({0x2000,0x1004,{EvidenceGrade::Verified,"synthetic-closed-world-test-harness-v1"},{EvidenceGrade::Verified,"synthetic-closed-world-test-harness-v1"}});c=certify(f,t);CHECK(c.status==Status::Closed);CHECK(c.effect_summary.memory_read && !c.effect_summary.memory_write);CHECK(c.blocks[1].returns_incoming_lr);++tests;t.immutable_words[0].plain_read.grade=EvidenceGrade::Conditional;CHECK(certify(f,t).status==Status::Open);++tests;}
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto t=trusted(f);t.max_iterations=0;auto c=certify(f,t);CHECK(!c.analysis_complete && !c.abi.eligible);CHECK(reasonHas(c,"ANALYSIS_BUDGET_EXCEEDED"));++tests;}
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto t=trusted(f);f.blocks[0].cycle_cost=0;auto c=certify(f,t);CHECK(c.status==Status::Open);CHECK(reasonHas(c,"MISSING_ORIGINAL_CYCLE_COST"));++tests;}
 {Module m;auto &f=m.empty();auto &b=f.blocks[0];auto x=dolir_constant(&f,&b,DOLIR_TYPE_I32,0x2000,0x1000);ret(f,b,x);auto t=trusted(f);auto c=certify(f,t);CHECK(c.status==Status::Open);CHECK(reasonHas(c,"EXTERNAL_TRANSFER_UNPROVED"));++tests;}

 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto t=trusted(f);auto digest=contractFingerprint(t);auto checker=t.verify_evidence;t.verify_evidence=[checker,digest](const EvidenceRequest&r){return r.contract_fingerprint==digest && checker(r);};CHECK(certify(f,t).status==Status::Closed);t.entry_blocks={0,1};CHECK(contractFingerprint(t)!=digest);CHECK(certify(f,t).status!=Status::Closed);++tests;}
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto t=trusted(f);t.max_values=1;CHECK(!certify(f,t).valid_ir);++tests;t=trusted(f);t.max_block_value_product=0;CHECK(!certify(f,t).valid_ir);++tests;}
 {Module m;auto &f=m.empty();auto &b=f.blocks[0];ret(f,b);auto saved=b.instructions;b.instructions=nullptr;CHECK(sourceFingerprint(f).empty());CHECK(!certify(f).valid_ir);b.instructions=saved;++tests;}
 {Module m;auto &f=m.empty();auto &b=f.blocks[0];ret(f,b);b.instructions[0].op=static_cast<DolIROp>(-1);CHECK(!certify(f).valid_ir);++tests;}

 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto t=trusted(f);t.verify_evidence=[](const EvidenceRequest&)->bool{throw 42;};auto c=certify(f,t);CHECK(c.status!=Status::Closed);CHECK(reasonHas(c,"EVIDENCE_CHECKER_FAILURE"));++tests;}
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto baseline=sourceFingerprint(f);auto check=[&](auto &field,auto replacement){auto saved=field;field=replacement;CHECK(sourceFingerprint(f)!=baseline);field=saved;++tests;};
  check(f.guest_start,f.guest_start+4);check(f.guest_end,f.guest_end+4);check(f.block_count,f.block_count-1);check(f.value_count,f.value_count-1);check(f.value_types[1],DOLIR_TYPE_I64);
  auto &b=f.blocks[0];check(b.guest_address,b.guest_address+4);check(b.raw,b.raw^1);check(b.cycle_cost,b.cycle_cost+1);check(b.instruction_count,b.instruction_count-1);
  auto &i=b.instructions[0];check(i.op,DOLIR_OP_NOT);check(i.type,DOLIR_TYPE_I16);check(i.result,i.result+1);check(i.operand_count,u8(i.operand_count+1));check(i.operands[0],i.operands[0]+1);check(i.aux,i.aux+1);check(i.immediate,i.immediate+1);check(i.guest_pc,i.guest_pc+4);check(i.effects,i.effects^1);check(i.state_uses[0],i.state_uses[0]^1);check(i.state_defs[0],i.state_defs[0]^1);check(i.address_domain,DOLIR_ADDRESS_MEM1);check(i.address_lower,i.address_lower+1);check(i.address_upper,i.address_upper+1);check(i.exact_fp,!i.exact_fp);
  auto &t=b.terminator;check(t.kind,DOLIR_TERM_BRANCH);check(t.condition,t.condition+1);check(t.target_value,t.target_value+1);check(t.targets[0],t.targets[0]+1);check(t.target_addresses[0],t.target_addresses[0]+4);check(t.guest_pc,t.guest_pc+4);check(t.raw,t.raw^1);check(t.linked,!t.linked);
  auto c=trusted(f);c.entry_blocks={0,1};auto first=contractFingerprint(c);c.entry_blocks={1,0};CHECK(contractFingerprint(c)==first);c.entry_blocks={0};CHECK(contractFingerprint(c)!=first);++tests;
 }

 {Module m;auto &f=m.empty();auto &b=f.blocks[0];auto lr=dolir_state_read(&f,&b,DOLIR_STATE_LR,0x1000);dolir_state_write(&f,&b,DOLIR_STATE_CR0,lr,0x1000);auto cr=dolir_state_read(&f,&b,DOLIR_STATE_CR0,0x1000);dolir_state_write(&f,&b,DOLIR_STATE_LR,cr,0x1000);ret(f,b);auto c=certify(f,trusted(f));CHECK(c.status==Status::Open && !c.blocks[0].returns_incoming_lr);++tests;}
 {Module m;auto &f=m.words({0x38600001,0x4e800020});auto c=trusted(f);auto old=f.value_count;f.value_count=UINT32_MAX;c.max_values=UINT32_MAX;c.max_block_value_product=UINT64_MAX;CHECK(!certify(f,c).valid_ir);f.value_count=old;++tests;}
 u32 random=0x9259abcdu;
 for(auto op:{DOLIR_OP_ADD,DOLIR_OP_SUB,DOLIR_OP_MUL,DOLIR_OP_AND,DOLIR_OP_OR,DOLIR_OP_XOR,DOLIR_OP_SHL,DOLIR_OP_LSHR})for(u32 n=0;n<128;n++){
   random=random*1664525u+1013904223u;u32 left=random;random=random*1664525u+1013904223u;u32 right=n==0?0:random;
   if(op==DOLIR_OP_SHL || op==DOLIR_OP_LSHR)right&=31;
   u32 expected=0;switch(op){case DOLIR_OP_ADD:expected=left+right;break;case DOLIR_OP_SUB:expected=left-right;break;case DOLIR_OP_MUL:expected=left*right;break;case DOLIR_OP_AND:expected=left&right;break;case DOLIR_OP_OR:expected=left|right;break;case DOLIR_OP_XOR:expected=left^right;break;case DOLIR_OP_SHL:expected=left<<right;break;case DOLIR_OP_LSHR:expected=left>>right;break;default:break;}
   Module m;auto &f=m.empty();auto &b=f.blocks[0];DolIRValue operands[]={dolir_constant(&f,&b,DOLIR_TYPE_I32,left,0x1000),dolir_constant(&f,&b,DOLIR_TYPE_I32,right,0x1000)};
   auto value=dolir_append(&f,&b,op,DOLIR_TYPE_I32,operands,2,0,0,0x1000,0);ret(f,b,value);auto c=certify(f,trusted(f));CHECK(!c.edges.empty());CHECK(c.edges[0].target_address==expected);CHECK(c.edges[0].target_provenance=="proved-value-constant");++tests;
 }
 std::cout<<tests<<" adversarial/positive/property synthetic certification cases passed\n";
}
