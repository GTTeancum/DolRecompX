// SPDX-License-Identifier: GPL-3.0-or-later
#include "function_certification.h"
#include "analysis/checked_serialization.h"
#include <iomanip>
#include <sstream>
namespace dolcert { namespace {
std::string quote(const std::string &s){dolanalysis::CheckedOutput o;o<<'"';for(unsigned char x:s){if(x=='"'||x=='\\')o<<'\\'<<char(x);else if(x<32)o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<unsigned(x);else o<<char(x);}o<<'"';return o.str();}
void slots(std::ostream &o,const StateMask &m){o<<'[';bool comma=false;for(u32 s=0;s<DOLIR_STATE_COUNT;s++)if(m[s/64]&(u64(1)<<(s%64))){if(comma)o<<',';comma=true;o<<s;}o<<']';}
StateMask copy(const u64 *m){StateMask a{};for(size_t n=0;n<a.size();n++)a[n]=m[n];return a;}
const char *grade(EvidenceGrade g){return g==EvidenceGrade::Verified?"VERIFIED_CLAIM":g==EvidenceGrade::Conditional?"CONDITIONAL":"UNPROVED";}
}
std::string toJson(const Certificate &c){
 dolanalysis::CheckedOutput o;o<<std::boolalpha;
 o<<"{\"schema\":"<<quote(c.schema)<<",\"source_fingerprint\":"<<quote(c.source_fingerprint)<<",\"contract_fingerprint\":"<<quote(c.contract_fingerprint)<<",\"implementation_id\":"<<quote(c.implementation_id)<<",\"model\":"<<quote(c.model)<<",\"scope\":"<<quote(c.scope)<<",\"status\":"<<quote(statusName(c.status));
 o<<",\"valid_ir\":"<<c.valid_ir<<",\"analysis_complete\":"<<c.analysis_complete<<",\"mutates_ir\":"<<c.mutates_ir<<",\"prunes_code\":"<<c.prunes_code<<",\"changes_timing\":"<<c.changes_timing;
 o<<",\"dimensions\":{\"entries\":"<<quote(statusName(c.entries))<<",\"cfg\":"<<quote(statusName(c.cfg))<<",\"effects\":"<<quote(statusName(c.effects))<<",\"returns\":"<<quote(statusName(c.returns))<<",\"observations\":"<<quote(statusName(c.observations))<<'}';
 o<<",\"reasons\":[";for(size_t n=0;n<c.reasons.size();n++){if(n)o<<',';const auto &r=c.reasons[n];o<<"{\"dimension\":"<<quote(r.dimension)<<",\"code\":"<<quote(r.code)<<",\"block\":"<<r.block<<'}';}o<<']';
 o<<",\"evidence\":[";for(size_t n=0;n<c.evidence.size();n++){if(n)o<<',';const auto &r=c.evidence[n];o<<"{\"obligation\":"<<quote(r.request.obligation)<<",\"proof_id\":"<<quote(r.request.proof_id)<<",\"contract_fingerprint\":"<<quote(r.request.contract_fingerprint)<<",\"source_fingerprint\":"<<quote(r.request.source_fingerprint)<<",\"address\":"<<r.request.address<<",\"value\":"<<r.request.value<<",\"model\":"<<quote(r.request.model)<<",\"entry_blocks\":[";for(size_t k=0;k<r.request.entry_blocks.size();k++){if(k)o<<',';o<<r.request.entry_blocks[k];}o<<"],\"supplied_grade\":"<<quote(grade(r.supplied_grade))<<",\"independently_verified\":"<<r.independently_verified<<'}';}o<<']';
 o<<",\"effects\":{\"state_may_read\":";slots(o,c.effect_summary.state_may_read);o<<",\"state_may_write\":";slots(o,c.effect_summary.state_may_write);
 #define FLAG(x) o<<",\"" #x "\":"<<c.effect_summary.x;
 FLAG(memory_read) FLAG(memory_write) FLAG(mmio) FLAG(fifo) FLAG(fault) FLAG(partial_effect) FLAG(exit) FLAG(callback) FLAG(returning_mutation) FLAG(time) FLAG(reservation) FLAG(coherence) FLAG(mode) FLAG(exception_resume) FLAG(opaque) FLAG(host_bindings) FLAG(precommit_refusal) FLAG(returning_exception) FLAG(terminal_partial_effect) FLAG(sound_overapproximation)
 #undef FLAG
 o<<"},";
 o<<"\"edges\":[";for(size_t n=0;n<c.edges.size();n++){if(n)o<<',';const auto &e=c.edges[n];o<<"{\"block\":"<<e.block<<",\"target_block\":"<<e.target_block<<",\"target_address\":"<<e.target_address<<",\"kind\":"<<quote(e.kind)<<",\"target_provenance\":"<<quote(e.target_provenance)<<",\"certainty\":"<<quote(statusName(e.certainty))<<'}';}o<<']';
 o<<",\"blocks\":[";for(size_t n=0;n<c.blocks.size();n++){if(n)o<<',';const auto &b=c.blocks[n];o<<"{\"index\":"<<b.index<<",\"address\":"<<b.address<<",\"reachable_from_declared_entries\":"<<b.reachable_from_declared_entries<<",\"returns_incoming_lr\":"<<b.returns_incoming_lr<<",\"transfer_provenance\":"<<quote(b.transfer_provenance)<<",\"live_in\":";slots(o,b.live_in);o<<",\"live_out\":";slots(o,b.live_out);o<<'}';}o<<']';
 o<<",\"native_abi_plan\":{\"eligible\":"<<c.abi.eligible<<",\"exact_original_cuts_required\":"<<c.abi.exact_original_cuts_required<<",\"termination_proved\":"<<c.abi.termination_proved<<",\"guest_stack_elision_allowed\":"<<c.abi.guest_stack_elision_allowed;
 o<<",\"semantic_live_in\":";slots(o,c.abi.semantic_live_in);o<<",\"may_live_out\":";slots(o,c.abi.may_live_out);o<<",\"preserve_or_materialize\":";slots(o,c.abi.preserve_or_materialize);o<<",\"materialize_at_every_original_cut\":";slots(o,c.abi.materialize_at_every_original_cut);
 o<<",\"existing_advisory_analysis\":{\"abi_flags\":"<<c.abi.existing_analysis.abi_flags<<",\"abi_blockers\":"<<c.abi.existing_analysis.abi_blockers<<",\"semantic_input_state\":";slots(o,copy(c.abi.existing_analysis.semantic_input_state));o<<",\"may_def_state\":";slots(o,copy(c.abi.existing_analysis.may_def_state));o<<"}}}";return o.str();
}
}
