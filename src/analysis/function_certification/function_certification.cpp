// SPDX-License-Identifier: GPL-3.0-or-later
#include "function_certification.h"
#include <algorithm>
#include <deque>
#include <map>
#include <set>
#include <limits>
#include <cstring>
#include <type_traits>

namespace dolcert { namespace {
template<class E> int64_t enumValue(const E &e){std::underlying_type_t<E> v;std::memcpy(&v,&e,sizeof v);return v;}
StateMask full() { StateMask m{}; for(u32 s=0;s<DOLIR_STATE_COUNT;s++) m[s/64]|=u64(1)<<(s%64); return m; }
void bit(StateMask &m,u32 s) {m[s/64]|=u64(1)<<(s%64);}
void join(StateMask &a,const StateMask &b) {for(size_t k=0;k<a.size();k++)a[k]|=b[k];}
void aliases(StateMask &m) {
  auto has=[&](u32 s){return bool(m[s/64]&(u64(1)<<(s%64)));};
  bool cr=has(DOLIR_STATE_CR);for(u32 s=DOLIR_STATE_CR0;s<=DOLIR_STATE_CR7;s++)cr|=has(s);
  if(cr){bit(m,DOLIR_STATE_CR);for(u32 s=DOLIR_STATE_CR0;s<=DOLIR_STATE_CR7;s++)bit(m,s);}
  bool xer=has(DOLIR_STATE_XER)||has(DOLIR_STATE_XER_CA)||has(DOLIR_STATE_XER_OV)||has(DOLIR_STATE_XER_SO);
  if(xer)for(u32 s=DOLIR_STATE_XER;s<=DOLIR_STATE_XER_SO;s++)bit(m,s);
}
void top(TypedEffects &e) {
  e.state_may_read=e.state_may_write=full();
  e.memory_read=e.memory_write=e.mmio=e.fifo=e.fault=e.partial_effect=true;
  e.exit=e.callback=e.returning_mutation=e.time=e.reservation=true;
  e.coherence=e.mode=e.exception_resume=e.opaque=true;
  e.host_bindings=e.precommit_refusal=e.returning_exception=e.terminal_partial_effect=true;
}
Status worst(Status a,Status b) { return static_cast<Status>(std::max(int(a),int(b))); }
void reason(Certificate &c,const char *dim,const char *code,u32 block=DOLIR_NO_BLOCK) {
  auto same=[&](const Reason &r){return r.dimension==dim && r.code==code && r.block==block;};
  if(std::find_if(c.reasons.begin(),c.reasons.end(),same)==c.reasons.end()) c.reasons.push_back({dim,code,block});
}
Status evidence(Certificate &c,const Contract &contract,const Evidence &e,bool bound,const char *dim,const char *missing,u32 address=0,u32 value=0) {
  EvidenceRequest query;query.source_fingerprint=c.source_fingerprint;query.contract_fingerprint=c.contract_fingerprint;query.obligation=missing;query.proof_id=e.proof_id;query.entry_blocks=contract.entry_blocks;query.address=address;query.value=value;
  bool verified=false;
  if(bound && e.grade==EvidenceGrade::Verified && !e.proof_id.empty() && contract.verify_evidence){try{verified=contract.verify_evidence(query);}catch(...){reason(c,dim,"EVIDENCE_CHECKER_FAILURE");}}
  c.evidence.push_back({query,e.grade,verified});
  if(!bound || e.grade==EvidenceGrade::Unproved || e.proof_id.empty()){reason(c,dim,missing);return Status::Open;}
  if(!verified){reason(c,dim,"UNVERIFIED_CONDITION");return Status::Conditional;}
  c.accepted_evidence.push_back(std::string(dim)+":"+e.proof_id);
  return Status::Closed;
}
unsigned width(DolIRType t){switch(t){case DOLIR_TYPE_I1:return 1;case DOLIR_TYPE_I8:return 8;case DOLIR_TYPE_I16:return 16;case DOLIR_TYPE_I32:return 32;case DOLIR_TYPE_I64:return 64;default:return 0;}}
u64 mask(unsigned w){return w==64?~u64(0):(u64(1)<<w)-1;}
enum class Kind { Unknown, Constant, IncomingLR, IncomingLRAligned };
struct Value {
  Kind kind=Kind::Unknown; u64 bits=0;
  bool operator==(const Value &v) const{return kind==v.kind && bits==v.bits;}
  bool operator!=(const Value &v) const{return !(*this==v);}
};
Value constant(u64 n,unsigned w=32){return {Kind::Constant,n&mask(w)};}
Value merge(Value a,Value b){return a==b?a:Value{};}
using State=std::array<Value,DOLIR_STATE_COUNT>;
struct Eval { State state{}; Value condition{},target{}; std::vector<Value> values; };
struct Analysis {
  const DolIRFunction &f;const Contract &contract;Certificate &c;
  std::map<u32,u32> addresses;
  std::map<u32,u32> immutable;
  std::vector<std::vector<bool>> plain;
  bool immutability_safe=true;
  Analysis(const DolIRFunction &fn,const Contract &ct,Certificate &cert):f(fn),contract(ct),c(cert){}
  bool valid() {
    if(!f.block_count || f.block_count>contract.max_blocks || f.block_count>4096 || !f.value_count || f.value_count>contract.max_values || f.value_count>1000001 || u64(f.block_count)*f.value_count>contract.max_block_value_product || f.guest_start>=f.guest_end || !f.blocks || !f.value_types)return false;
    if(enumValue(f.value_types[0])!=DOLIR_TYPE_VOID)return false;
    for(u32 v=1;v<f.value_count;v++)if(enumValue(f.value_types[v])<=DOLIR_TYPE_VOID || enumValue(f.value_types[v])>DOLIR_TYPE_V2F64)return false;
    u64 count=0;
    std::vector<bool> definitions(f.value_count);
    for(u32 b=0;b<f.block_count;b++){
      const auto &bl=f.blocks[b];count+=bl.instruction_count;
      if(bl.instruction_count && !bl.instructions)return false;
      if(count>contract.max_instructions || count>1000000 || bl.guest_address<f.guest_start || bl.guest_address>=f.guest_end || (bl.guest_address&3) || !addresses.emplace(bl.guest_address,b).second)return false;
      if(enumValue(bl.terminator.kind)<=DOLIR_TERM_NONE || enumValue(bl.terminator.kind)>DOLIR_TERM_RFI)return false;
      std::set<u32> available;
      for(u32 k=0;k<bl.instruction_count;k++){
        const auto &i=bl.instructions[k];
        if(enumValue(i.op)<DOLIR_OP_PHI || enumValue(i.op)>DOLIR_OP_HELPER_CALL || enumValue(i.type)<DOLIR_TYPE_VOID || enumValue(i.type)>DOLIR_TYPE_V2F64 || i.result>=f.value_count || i.operand_count>4)return false;
        if(enumValue(i.address_domain)<DOLIR_ADDRESS_UNKNOWN || enumValue(i.address_domain)>DOLIR_ADDRESS_FIFO || (i.address_domain!=DOLIR_ADDRESS_UNKNOWN && i.address_lower>i.address_upper))return false;
        if((i.type==DOLIR_TYPE_VOID)!=(i.result==0))return false;
        if(i.result && (definitions[i.result] || f.value_types[i.result]!=i.type))return false;
        for(u32 n=0;n<i.operand_count;n++)if(!i.operands[n] || i.operands[n]>=f.value_count)return false;
        for(u32 n=0;n<i.operand_count;n++)if(!available.count(i.operands[n]))reason(c,"cfg","CROSS_BLOCK_OR_FORWARD_SSA_UNSUPPORTED",b);
        if(i.op==DOLIR_OP_STATE_READ || i.op==DOLIR_OP_STATE_WRITE){
          if(i.aux>=DOLIR_STATE_COUNT)return false;
          if(i.op==DOLIR_OP_STATE_READ && (i.operand_count || i.type!=dolir_state_type(DolIRStateSlot(i.aux))))return false;
          if(i.op==DOLIR_OP_STATE_WRITE && (i.operand_count!=1 || i.type!=DOLIR_TYPE_VOID || f.value_types[i.operands[0]]!=dolir_state_type(DolIRStateSlot(i.aux))))return false;
        }
        if(i.op==DOLIR_OP_CONSTANT && i.operand_count)return false;
        auto operandType=[&](u32 n){return f.value_types[i.operands[n]];};
        bool binaryInteger=(i.op>=DOLIR_OP_ADD && i.op<=DOLIR_OP_XOR) || (i.op>=DOLIR_OP_SHL && i.op<=DOLIR_OP_ROTL);
        bool comparison=i.op>=DOLIR_OP_ICMP_EQ && i.op<=DOLIR_OP_ICMP_SLE;
        if(binaryInteger && (i.operand_count!=2 || !width(i.type) || operandType(0)!=i.type || operandType(1)!=i.type))return false;
        if(comparison && (i.operand_count!=2 || i.type!=DOLIR_TYPE_I1 || !width(operandType(0)) || operandType(0)!=operandType(1)))return false;
        if(i.op==DOLIR_OP_SELECT && (i.operand_count!=3 || operandType(0)!=DOLIR_TYPE_I1 || operandType(1)!=i.type || operandType(2)!=i.type))return false;
        if((i.op==DOLIR_OP_NOT || i.op==DOLIR_OP_CLZ || i.op==DOLIR_OP_BSWAP) && (i.operand_count!=1 || !width(i.type) || operandType(0)!=i.type))return false;
        if(i.op==DOLIR_OP_TRUNC && (i.operand_count!=1 || !width(i.type) || width(operandType(0))<=width(i.type)))return false;
        if((i.op==DOLIR_OP_ZEXT || i.op==DOLIR_OP_SEXT) && (i.operand_count!=1 || !width(operandType(0)) || width(operandType(0))>=width(i.type)))return false;
        if(i.op==DOLIR_OP_BITCAST && i.operand_count!=1)return false;
        if(i.op==DOLIR_OP_GUEST_LOAD && (i.operand_count!=1 || operandType(0)!=DOLIR_TYPE_I32))return false;
        if(i.op==DOLIR_OP_GUEST_STORE && (i.operand_count!=2 || operandType(0)!=DOLIR_TYPE_I32 || i.type!=DOLIR_TYPE_VOID))return false;
        if(i.result){definitions[i.result]=true;available.insert(i.result);}
        if(i.op==DOLIR_OP_GUEST_STORE || i.op==DOLIR_OP_HELPER_CALL || (i.effects&DOLIR_EFFECT_WRITE_MEMORY))immutability_safe=false;
      }
      const auto &t=bl.terminator;
      if(t.condition && (t.condition>=f.value_count || f.value_types[t.condition]!=DOLIR_TYPE_I1 || !available.count(t.condition)))return false;
      if((t.kind==DOLIR_TERM_COND_BRANCH || t.kind==DOLIR_TERM_INDIRECT) && !t.condition)return false;
      if(t.kind==DOLIR_TERM_INDIRECT && (!t.target_value || t.target_value>=f.value_count || f.value_types[t.target_value]!=DOLIR_TYPE_I32 || !available.count(t.target_value)))return false;
      for(u32 n=0;n<2;n++)if(t.targets[n]!=DOLIR_NO_BLOCK && (t.targets[n]>=f.block_count || f.blocks[t.targets[n]].guest_address!=t.target_addresses[n]))return false;
      if(t.linked || t.kind==DOLIR_TERM_FALLBACK || t.kind==DOLIR_TERM_SYSTEM_CALL || t.kind==DOLIR_TERM_RFI)immutability_safe=false;
    }
    return true;
  }
  Value compute(const DolIRInstruction &i,const std::vector<Value> &v,State &s,bool plainRead) {
    Value a=i.operand_count?v[i.operands[0]]:Value{},b=i.operand_count>1?v[i.operands[1]]:Value{};
    unsigned w=width(i.type);
    u32 expected=i.op==DOLIR_OP_STATE_READ?DOLIR_EFFECT_READ_STATE:i.op==DOLIR_OP_STATE_WRITE?DOLIR_EFFECT_WRITE_STATE:0;
    if(!plainRead && i.effects!=expected){s=State{};return {};}
    if(i.op==DOLIR_OP_CONSTANT)return w?constant(i.immediate,w):Value{};
    if(i.op==DOLIR_OP_STATE_READ)return s[i.aux];
    if(i.op==DOLIR_OP_STATE_WRITE){
      StateMask affected{};bit(affected,i.aux);aliases(affected);
      for(u32 x=0;x<DOLIR_STATE_COUNT;x++)if(affected[x/64]&(u64(1)<<(x%64)))s[x]={};
      // Only unaliased integer architectural storage is forwarded. Packed
      // CR/XER, virtual fields and control slots have materialization semantics
      // beyond a plain copy, so v1 refuses provenance through those slots.
      if(i.aux<=DOLIR_STATE_GPR31 || i.aux==DOLIR_STATE_LR || i.aux==DOLIR_STATE_CTR)s[i.aux]=a;
      return {};
    }
    if(i.op==DOLIR_OP_GUEST_LOAD && plainRead && a.kind==Kind::Constant){auto it=immutable.find(u32(a.bits));if(it!=immutable.end())return constant(it->second);}
    if(i.op==DOLIR_OP_GUEST_LOAD || i.op==DOLIR_OP_GUEST_STORE || i.op==DOLIR_OP_HELPER_CALL || (i.effects & ~(DOLIR_EFFECT_READ_STATE|DOLIR_EFFECT_WRITE_STATE))){s=State{};return {};}
    if(!w)return {};
    if(i.op==DOLIR_OP_BITCAST && i.operand_count==1 && f.value_types[i.operands[0]]==i.type)return a;
    if(i.op==DOLIR_OP_SELECT && i.operand_count==3){if(a.kind==Kind::Constant)return v[i.operands[a.bits?1:2]];return merge(v[i.operands[1]],v[i.operands[2]]);}
    if(i.op==DOLIR_OP_AND && w==32){
      if(a.kind==Kind::Constant)std::swap(a,b);
      if(b.kind==Kind::Constant && b.bits==0xfffffffcu && (a.kind==Kind::IncomingLR || a.kind==Kind::IncomingLRAligned))return {Kind::IncomingLRAligned,0};
    }
    if(i.op==DOLIR_OP_OR && a.kind==Kind::Constant && a.bits==0)return b;
    if(i.op==DOLIR_OP_OR && b.kind==Kind::Constant && b.bits==0)return a;
    if(i.op==DOLIR_OP_ADD && b.kind==Kind::Constant && !b.bits)return a;
    if(i.op==DOLIR_OP_ADD && a.kind==Kind::Constant && !a.bits)return b;
    if(a.kind!=Kind::Constant)return {};
    if(i.operand_count==1){
      if(i.op==DOLIR_OP_TRUNC || i.op==DOLIR_OP_ZEXT)return constant(a.bits,w);
      if(i.op==DOLIR_OP_NOT)return constant(~a.bits,w);
      if(i.op==DOLIR_OP_SEXT){unsigned old=width(f.value_types[i.operands[0]]);if(old && old<w){u64 x=a.bits&mask(old);if(x&(u64(1)<<(old-1)))x|=~mask(old);return constant(x,w);}}
    }
    if(b.kind!=Kind::Constant)return {};
    switch(i.op){
      case DOLIR_OP_ADD:return constant(a.bits+b.bits,w);
      case DOLIR_OP_SUB:return constant(a.bits-b.bits,w);
      case DOLIR_OP_MUL:return constant(a.bits*b.bits,w);
      case DOLIR_OP_AND:return constant(a.bits&b.bits,w);
      case DOLIR_OP_OR:return constant(a.bits|b.bits,w);
      case DOLIR_OP_XOR:return constant(a.bits^b.bits,w);
      case DOLIR_OP_SHL:return b.bits<w?constant(a.bits<<b.bits,w):Value{};
      case DOLIR_OP_LSHR:return b.bits<w?constant(a.bits>>b.bits,w):Value{};
      case DOLIR_OP_ICMP_EQ:return constant(a.bits==b.bits,1);
      case DOLIR_OP_ICMP_NE:return constant(a.bits!=b.bits,1);
      case DOLIR_OP_ICMP_ULT:return constant(a.bits<b.bits,1);
      case DOLIR_OP_ICMP_ULE:return constant(a.bits<=b.bits,1);
      default:return {};
    }
  }
  Eval evaluate(u32 index,State incoming) {
    Eval e;e.state=incoming;e.values.resize(f.value_count);
    const auto &b=f.blocks[index];
    for(u32 k=0;k<b.instruction_count;k++){
      const auto &i=b.instructions[k];auto value=compute(i,e.values,e.state,plain[index][k]);
      if(i.result)e.values[i.result]=value;
    }
    const auto &t=b.terminator;e.condition=t.condition?e.values[t.condition]:constant(1,1);e.target=t.target_value?e.values[t.target_value]:Value{};
    return e;
  }
};
}

Certificate certify(const DolIRFunction &f,const Contract &contract) {
  Certificate c;
#ifdef DOLCERT_IMPLEMENTATION_ID
  c.implementation_id=DOLCERT_IMPLEMENTATION_ID;
#else
  c.implementation_id="unversioned-experimental-build";
#endif
  c.contract_fingerprint=contractFingerprint(contract);
  Analysis a(f,contract,c);
  c.abi.preserve_or_materialize=c.abi.materialize_at_every_original_cut=full();
  if(!a.valid()){reason(c,"input","INVALID_OR_OVERSIZED_DOLIR");top(c.effect_summary);c.abi.semantic_live_in=c.abi.may_live_out=full();return c;}
  c.valid_ir=true;c.source_fingerprint=sourceFingerprint(f);
  if(c.source_fingerprint.empty()){c.valid_ir=false;reason(c,"input","FINGERPRINT_HARD_LIMIT");top(c.effect_summary);c.abi.semantic_live_in=c.abi.may_live_out=full();return c;}
  bool bound=!contract.source_fingerprint.empty() && contract.source_fingerprint==c.source_fingerprint;
  if(!contract.source_fingerprint.empty() && !bound)reason(c,"input","CONTRACT_FINGERPRINT_MISMATCH");
  c.entries=evidence(c,contract,contract.entries_and_code,bound,"entries","ENTRY_POPULATION_OR_CODE_STABILITY_UNPROVED");
  c.observations=evidence(c,contract,contract.observations,bound,"observations","EXACT_OBSERVATION_AND_MUTATION_CONTRACT_UNPROVED");
  auto resume=evidence(c,contract,contract.exception_resume,bound,"cfg","EXCEPTION_RESUME_CLOSURE_UNPROVED");
  c.cfg=resume;c.returns=Status::Closed;c.effects=Status::Closed;
  for(const auto &r:c.reasons)if(r.code=="CROSS_BLOCK_OR_FORWARD_SSA_UNSUPPORTED")c.cfg=Status::Open;
  if(contract.entry_blocks.empty()){reason(c,"entries","EMPTY_ENTRY_SET");c.entries=Status::Open;return c;}
  for(u32 b:contract.entry_blocks)if(b>=f.block_count){reason(c,"entries","INVALID_ENTRY_BLOCK");c.entries=Status::Open;return c;}
  // Immutable contracts never originate from data classification or byte scans.
  for(const auto &word:contract.immutable_words){
    auto lifetime=evidence(c,contract,word.lifetime_and_aliases,bound,"effects","IMMUTABLE_LIFETIME_UNPROVED",word.address,word.value);
    auto service=evidence(c,contract,word.plain_read,bound,"effects","PLAIN_READ_UNPROVED",word.address,word.value);
    if(lifetime!=Status::Closed || service!=Status::Closed || !a.immutability_safe || (word.address&3)){
      reason(c,"effects","IMMUTABLE_WORD_NOT_USABLE");continue;
    }
    auto existing=a.immutable.find(word.address);
    if(existing!=a.immutable.end() && existing->second!=word.value){reason(c,"effects","CONTRADICTORY_IMMUTABLE_VALUES");c.effects=Status::Open;a.immutable.clear();break;}
    a.immutable[word.address]=word.value;
  }
  a.plain.resize(f.block_count);
  // Constant address must be computed locally without relying on unaudited
  // range/address-domain annotations. Interblock addresses remain unknown here.
  for(u32 b=0;b<f.block_count;b++){
    const auto &block=f.blocks[b];a.plain[b].resize(block.instruction_count);
    std::vector<Value> values(f.value_count);State s{};
    for(u32 k=0;k<block.instruction_count;k++){
      const auto &i=block.instructions[k];
      if(i.op==DOLIR_OP_GUEST_LOAD && i.operand_count==1 && i.type==DOLIR_TYPE_I32 && i.aux==4 && !(i.effects & ~(DOLIR_EFFECT_READ_MEMORY|DOLIR_EFFECT_MAY_EXIT))){
        auto address=values[i.operands[0]];
        a.plain[b][k]=address.kind==Kind::Constant && a.immutable.count(u32(address.bits));
      }
      bool partialArithmetic=i.op==DOLIR_OP_UDIV || i.op==DOLIR_OP_SDIV;
      if(i.op==DOLIR_OP_SHL || i.op==DOLIR_OP_LSHR || i.op==DOLIR_OP_ASHR){auto shift=values[i.operands[1]];partialArithmetic=shift.kind!=Kind::Constant || shift.bits>=width(i.type);}
      if(partialArithmetic){top(c.effect_summary);c.effects=Status::Open;reason(c,"effects","PARTIAL_INTEGER_SEMANTICS_UNPROVED",b);}
      auto v=a.compute(i,values,s,a.plain[b][k]);if(i.result)values[i.result]=v;
      DolIRInstruction local=i;
      if(i.op==DOLIR_OP_STATE_READ || i.op==DOLIR_OP_STATE_WRITE){
        dolir_populate_effects(&local);
        for(u32 w=0;w<DOLIR_STATE_MASK_WORDS;w++){c.effect_summary.state_may_read[w]|=local.state_uses[w];c.effect_summary.state_may_write[w]|=local.state_defs[w];}
        if(i.aux==DOLIR_STATE_TIMEBASE || i.aux==DOLIR_STATE_DOWNCOUNT)c.effect_summary.time=true;
        if(i.aux==DOLIR_STATE_RESERVE_ADDR || i.aux==DOLIR_STATE_RESERVE_VALID)c.effect_summary.reservation=true;
        if(i.aux==DOLIR_STATE_MSR || (i.aux>=DOLIR_STATE_SR0 && i.aux<=DOLIR_STATE_SR15))c.effect_summary.mode=true;
        if(i.aux==DOLIR_STATE_EXCEPTION || i.aux==DOLIR_STATE_PROGRAM_EXCEPTION || i.aux==DOLIR_STATE_SRR0 || i.aux==DOLIR_STATE_SRR1)c.effect_summary.exception_resume=true;
      }
      if(a.plain[b][k])c.effect_summary.memory_read=true;
      else if(i.op==DOLIR_OP_GUEST_LOAD || i.op==DOLIR_OP_GUEST_STORE || i.op==DOLIR_OP_HELPER_CALL || (i.effects & ~(DOLIR_EFFECT_READ_STATE|DOLIR_EFFECT_WRITE_STATE))){
        top(c.effect_summary);c.effects=Status::Open;reason(c,"effects",i.op==DOLIR_OP_HELPER_CALL?"OPAQUE_HELPER_EFFECTS":"UNPROVED_MEMORY_OR_EFFECT_SERVICE",b);
      }
      // Unsupported explicit state side effects on nominally pure ops are TOP.
      else if(i.op!=DOLIR_OP_STATE_READ && i.op!=DOLIR_OP_STATE_WRITE && i.effects){top(c.effect_summary);c.effects=Status::Open;reason(c,"effects","UNSUPPORTED_STATE_EFFECT_METADATA",b);}
    }
    const auto &t=block.terminator;
    if(t.linked){top(c.effect_summary);c.effects=Status::Open;reason(c,"effects","OPAQUE_CALL_NO_ABI_ASSUMPTIONS",b);}
    if(t.kind==DOLIR_TERM_FALLBACK || t.kind==DOLIR_TERM_SYSTEM_CALL || t.kind==DOLIR_TERM_RFI){top(c.effect_summary);c.effects=Status::Open;reason(c,"effects","EXCEPTION_OR_FALLBACK_EFFECTS",b);}
    if(!block.cycle_cost){reason(c,"observations","MISSING_ORIGINAL_CYCLE_COST",b);c.observations=Status::Open;}
  }
  bit(c.effect_summary.state_may_write,DOLIR_STATE_PC);
  bit(c.effect_summary.state_may_read,DOLIR_STATE_DOWNCOUNT);
  bit(c.effect_summary.state_may_write,DOLIR_STATE_DOWNCOUNT);
  c.effect_summary.time=true;
  aliases(c.effect_summary.state_may_read);aliases(c.effect_summary.state_may_write);
  c.abi.may_live_out=c.effect_summary.state_may_write;
  // Keep actual upstream ABI/liveness analysis as a separately named baseline.
  c.abi.existing_analysis.start=f.guest_start;c.abi.existing_analysis.end=f.guest_end;
  dolllvm_analyze_function_abi(&f,&c.abi.existing_analysis);
  std::vector<State> in(f.block_count);std::vector<bool> reached(f.block_count),queued(f.block_count);
  std::vector<std::set<u32>> succ(f.block_count);std::deque<u32> work;
  auto schedule=[&](u32 b,const State &state){
    bool changed=!reached[b];if(!reached[b]){in[b]=state;reached[b]=true;}else for(u32 s=0;s<DOLIR_STATE_COUNT;s++){auto v=merge(in[b][s],state[s]);if(v!=in[b][s]){in[b][s]=v;changed=true;}}
    if(changed && !queued[b]){work.push_back(b);queued[b]=true;}
  };
  for(u32 b:contract.entry_blocks){State initial{};if(b==0)initial[DOLIR_STATE_LR]={Kind::IncomingLR,0};schedule(b,initial);}
  u64 iterations=0,edgecount=0;
  auto graph=[&](u32 b,const Eval &e,bool report){
    const auto &t=f.blocks[b].terminator;
    auto emit=[&](u32 addr,std::string kind,std::string provenance,Status certainty,const State &state,bool internalAllowed=true){
      auto found=a.addresses.find(addr);u32 dest=found==a.addresses.end()?DOLIR_NO_BLOCK:found->second;
      if(report)c.edges.push_back({b,dest,addr,kind,provenance,certainty});
      if(internalAllowed && dest!=DOLIR_NO_BLOCK){if(succ[b].insert(dest).second)edgecount++;if(!report)schedule(dest,state);}
      else if(report && kind!="call" && kind!="return"){c.cfg=Status::Open;c.returns=Status::Open;c.effects=Status::Open;top(c.effect_summary);reason(c,"cfg","EXTERNAL_TRANSFER_UNPROVED",b);}
    };
    bool yes=e.condition.kind!=Kind::Constant || e.condition.bits!=0;
    bool no=e.condition.kind!=Kind::Constant || e.condition.bits==0;
    auto transfer=[&](u32 address,std::string provenance){
      if(t.linked){emit(address,"call",provenance,Status::Closed,e.state,false);emit(t.guest_pc+4,"unproved_call_continuation","opaque-callee",Status::Open,State{});if(report){c.cfg=Status::Open;reason(c,"cfg","CALL_RETURN_AND_CLOBBERS_UNPROVED",b);}}
      else emit(address,"branch",provenance,Status::Closed,e.state);
    };
    if(t.kind==DOLIR_TERM_BRANCH || t.kind==DOLIR_TERM_FALLTHROUGH){transfer(t.target_addresses[0],"direct-constant");}
    else if(t.kind==DOLIR_TERM_COND_BRANCH){if(yes)transfer(t.target_addresses[0],"direct-constant");if(no)emit(t.target_addresses[1],"fallthrough","condition-false",Status::Closed,e.state);}
    else if(t.kind==DOLIR_TERM_INDIRECT){
      if(yes){
        if(!t.linked && (e.target.kind==Kind::IncomingLR || e.target.kind==Kind::IncomingLRAligned)){
          if(report){c.edges.push_back({b,DOLIR_NO_BLOCK,0,"return",e.target.kind==Kind::IncomingLR?"incomingLR":"incomingLR&~3",Status::Closed});c.blocks[b].returns_incoming_lr=true;c.blocks[b].transfer_provenance=c.edges.back().target_provenance;}
        }else if(e.target.kind==Kind::Constant){transfer(u32(e.target.bits),"proved-value-constant");if(report)c.blocks[b].transfer_provenance="proved-value-constant";}
        else{
          if(report){c.edges.push_back({b,DOLIR_NO_BLOCK,0,t.linked?"unknown-call":"unknown-indirect","unknown",Status::Open});c.cfg=Status::Open;c.returns=Status::Open;c.effects=Status::Open;top(c.effect_summary);reason(c,"cfg","UNKNOWN_INDIRECT_TARGET",b);}
          // Unknown incoming edges cannot silently disappear from state flow.
          for(u32 dest=0;dest<f.block_count;dest++){if(succ[b].insert(dest).second)edgecount++;if(!report)schedule(dest,State{});}
          if(t.linked)emit(t.guest_pc+4,"unproved_call_continuation","opaque-callee",Status::Open,State{});
        }
      }
      if(no)emit(t.target_addresses[1],"fallthrough","condition-false",Status::Closed,e.state);
    }else{
      if(report){c.cfg=Status::Open;c.returns=Status::Open;c.effects=Status::Open;top(c.effect_summary);reason(c,"cfg",t.kind==DOLIR_TERM_RFI?"RFI_TARGET_AND_RESUME_UNPROVED":t.kind==DOLIR_TERM_RETURN?"DOLIR_RETURN_IS_LITERAL_SIDE_EXIT":"SIDE_EXIT_OR_EXCEPTION_UNPROVED",b);c.edges.push_back({b,DOLIR_NO_BLOCK,t.target_addresses[0],"side-exit","literal-or-runtime",Status::Open});}
    }
  };
  while(!work.empty()){
    if(++iterations>contract.max_iterations || edgecount>contract.max_edges){reason(c,"cfg","ANALYSIS_BUDGET_EXCEEDED");c.cfg=c.returns=c.effects=Status::Open;top(c.effect_summary);c.abi.semantic_live_in=c.abi.may_live_out=full();return c;}
    u32 b=work.front();work.pop_front();queued[b]=false;graph(b,a.evaluate(b,in[b]),false);
  }
  c.blocks.resize(f.block_count);
  for(u32 b=0;b<f.block_count;b++){c.blocks[b].index=b;c.blocks[b].address=f.blocks[b].guest_address;c.blocks[b].reachable_from_declared_entries=reached[b];if(reached[b])graph(b,a.evaluate(b,in[b]),true);}
  bool anyreturn=false;for(const auto &b:c.blocks)anyreturn|=b.returns_incoming_lr;
  if(!anyreturn){c.returns=Status::Open;reason(c,"returns","NO_PROVED_INCOMING_LR_RETURN");}
  // Conservative semantic use analysis. No must-def kill across services/calls;
  // virtual CR/XER aliases are widened and exact observations demand full state.
  std::vector<StateMask> use(f.block_count),def(f.block_count);
  for(u32 b=0;b<f.block_count;b++){
    for(u32 k=0;k<f.blocks[b].instruction_count;k++){
      const auto &i=f.blocks[b].instructions[k];
      if(i.op==DOLIR_OP_STATE_READ)bit(use[b],i.aux);
      if(i.op==DOLIR_OP_STATE_WRITE)bit(def[b],i.aux);
      if((i.op==DOLIR_OP_GUEST_LOAD && !a.plain[b][k]) || i.op==DOLIR_OP_GUEST_STORE || i.op==DOLIR_OP_HELPER_CALL){use[b]=def[b]=full();}
    }
    if(f.blocks[b].terminator.linked)use[b]=def[b]=full();
    aliases(use[b]);aliases(def[b]);c.blocks[b].live_in=use[b];c.blocks[b].live_out=def[b];join(c.abi.semantic_live_in,use[b]);
  }
  // Full materialization is deliberately not substituted by caller-volatile ABI.
  for(auto &b:c.blocks){b.live_in=full();b.live_out=full();}
  c.abi.may_live_out=c.effect_summary.state_may_write;
  join(c.abi.semantic_live_in,c.effect_summary.state_may_read);
  c.analysis_complete=true;
  c.status=worst(worst(worst(c.entries,c.cfg),worst(c.effects,c.returns)),c.observations);
  c.abi.eligible=c.status==Status::Closed;
  if(!c.abi.eligible)reason(c,"abi","CERTIFICATE_NOT_CLOSED");
  return c;
}
const char *statusName(Status s){switch(s){case Status::Closed:return "CLOSED";case Status::Conditional:return "CONDITIONAL";default:return "OPEN";}}
}
