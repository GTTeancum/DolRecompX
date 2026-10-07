// SPDX-License-Identifier: GPL-3.0-or-later
#include "verified_idioms.h"
#include "function_certification.h"
#include "analysis/checked_serialization.h"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <stdexcept>
#include <openssl/sha.h>

namespace dolidiom {
namespace {
bool boundedShape(const DolIRFunction &f) {
    if(!f.block_count || f.block_count>4096 || !f.blocks || !f.value_count || f.value_count>1000001 || !f.value_types) return false;
    uint64_t count=0;
    for(unsigned v=0;v<f.value_count;v++)if(f.value_types[v]>DOLIR_TYPE_V2F64)return false;
    for(unsigned b=0;b<f.block_count;b++) {
        const auto &block=f.blocks[b];count+=block.instruction_count;
        if(count>1000000 || (block.instruction_count&&!block.instructions))return false;
        if(block.terminator.kind>DOLIR_TERM_RFI)return false;
        for(unsigned i=0;i<block.instruction_count;i++){
            const auto &n=block.instructions[i];if(n.op>DOLIR_OP_HELPER_CALL||n.type>DOLIR_TYPE_V2F64||n.operand_count>4||n.result>=f.value_count)return false;
            for(unsigned j=0;j<n.operand_count;j++)if(!n.operands[j]||n.operands[j]>=f.value_count)return false;
        }
    }
    return true;
}
unsigned width(DolIRType t) {
    switch (t) { case DOLIR_TYPE_I1:return 1; case DOLIR_TYPE_I8:return 8;
    case DOLIR_TYPE_I16:return 16; case DOLIR_TYPE_I32:return 32;
    case DOLIR_TYPE_I64:return 64; default:return 0; }
}
uint64_t mask(unsigned w) { return w == 64 ? UINT64_MAX : (uint64_t(1) << w) - 1; }
std::string nodeText(const DolIRInstruction &n) {
    dolanalysis::CheckedOutput s;
    s << unsigned(n.op) << ':' << unsigned(n.type) << ':' << n.result << ':'
      << unsigned(n.operand_count) << ':' << n.aux << ':' << n.immediate << ':'
      << n.guest_pc << ':' << n.effects << ':' << unsigned(n.address_domain) << ':'
      << n.address_lower << ':' << n.address_upper << ':' << n.exact_fp;
    for (auto v : n.operands) s << ':' << v;
    for (auto v : n.state_uses) s << ':' << v;
    for (auto v : n.state_defs) s << ':' << v;
    return s.str();
}
std::string cuts(const DolIRFunction &f) {
    dolanalysis::CheckedOutput s;
    s << "cuts-v1:" << f.guest_start << ':' << f.guest_end << ':' << f.block_count;
    for (unsigned b=0;b<f.block_count;b++) {
        const auto &n=f.blocks[b]; const auto &t=n.terminator;
        s << '\n' << b << ':' << n.guest_address << ':' << n.raw << ':' << n.cycle_cost
          << ':' << unsigned(t.kind) << ':' << t.condition << ':' << t.target_value
          << ':' << t.targets[0] << ':' << t.targets[1] << ':' << t.target_addresses[0]
          << ':' << t.target_addresses[1] << ':' << t.guest_pc << ':' << t.raw << ':' << t.linked;
    }
    return s.str();
}
struct Ref { const DolIRInstruction *n; unsigned block, index; };
struct Graph {
    const DolIRFunction &f;
    std::map<DolIRValue,Ref> defs;
    std::string error;
    explicit Graph(const DolIRFunction &function):f(function) {
        if(!boundedShape(f)){error="INVALID_OR_OVERSIZED_DOLIR";return;}
        for(unsigned b=0;b<f.block_count;b++) for(unsigned i=0;i<f.blocks[b].instruction_count;i++) {
            const auto &n=f.blocks[b].instructions[i];
            if(n.operand_count>4) {error="INVALID_OPERAND_COUNT";return;}
            if(n.result) {
                if(n.result>=f.value_count || f.value_types[n.result]!=n.type || defs.count(n.result)) {
                    error="INVALID_SSA_DEFINITION";return;
                }
                defs[n.result]={&n,b,i};
            } else if(n.type!=DOLIR_TYPE_VOID) {error="INVALID_SSA_DEFINITION";return;}
        }
    }
    const DolIRInstruction *node(DolIRValue v) const {
        auto i=defs.find(v); return i==defs.end()?nullptr:i->second.n;
    }
    bool constant(DolIRValue v,uint64_t &x,unsigned depth=0) const {
        auto n=node(v); if(!n || depth>128 || !width(n->type) || n->effects)return false;
        unsigned w=width(n->type);
        if(n->op==DOLIR_OP_CONSTANT && !n->operand_count){x=n->immediate&mask(w);return true;}
        if(n->operand_count!=2)return false;
        auto a=node(n->operands[0]),b=node(n->operands[1]);
        if(!a||!b||a->type!=n->type||b->type!=n->type)return false;
        uint64_t av,bv;if(!constant(a->result,av,depth+1)||!constant(b->result,bv,depth+1))return false;
        switch(n->op){case DOLIR_OP_AND:x=av&bv;break;case DOLIR_OP_OR:x=av|bv;break;case DOLIR_OP_XOR:x=av^bv;break;case DOLIR_OP_ADD:x=av+bv;break;case DOLIR_OP_SUB:x=av-bv;break;default:return false;}
        x&=mask(w);return true;
    }
};
struct Projection {
    DolIRFunction view{};
    std::vector<std::vector<DolIRInstruction>> segments;
    std::vector<DolIRBlock> blocks;
    std::map<DolIRValue,std::pair<unsigned,unsigned>> originals;
    std::map<DolIRValue,std::vector<std::pair<DolIRValue,DolIRValue>>> assumptions;
    std::string error;
    explicit Projection(const DolIRFunction &f) {
        Graph original(f);if(!original.error.empty()){error=original.error;return;}
        std::vector<unsigned> predecessors(f.block_count);
        for(unsigned b=0;b<f.block_count;b++)for(auto t:f.blocks[b].terminator.targets)if(t<f.block_count)predecessors[t]++;
        std::map<unsigned,DolIRValue> state;
        std::map<DolIRValue,DolIRValue> aliases;
                for(unsigned b=0;b<f.block_count;b++) {
            bool continuation=false;
            if(b){auto &prev=f.blocks[b-1];auto &t=prev.terminator;
                continuation=t.kind==DOLIR_TERM_FALLTHROUGH && !t.linked && t.targets[0]==b && t.targets[1]==DOLIR_NO_BLOCK && predecessors[b]==1 && t.target_addresses[0]==f.blocks[b].guest_address && prev.guest_address+4==f.blocks[b].guest_address;}
            if(!continuation){segments.emplace_back();state.clear();aliases.clear();}
            for(unsigned j=0;j<f.blocks[b].instruction_count;j++) {
                const auto &src=f.blocks[b].instructions[j];auto n=src;
                std::vector<std::pair<DolIRValue,DolIRValue>> forwards;
                for(unsigned k=0;k<n.operand_count;k++){auto a=aliases.find(n.operands[k]);if(a!=aliases.end()){forwards.emplace_back(n.operands[k],a->second);n.operands[k]=a->second;}}
                if(n.op==DOLIR_OP_STATE_READ && n.aux<=DOLIR_STATE_GPR31 && n.operand_count==0 && n.type==DOLIR_TYPE_I32 && n.effects==DOLIR_EFFECT_READ_STATE) {
                    auto v=state.find(n.aux);if(v!=state.end()) {aliases[n.result]=v->second;}else state[n.aux]=n.result;
                } else if(n.op==DOLIR_OP_STATE_WRITE && n.aux<=DOLIR_STATE_GPR31 && n.operand_count==1 && n.type==DOLIR_TYPE_VOID && n.effects==DOLIR_EFFECT_WRITE_STATE) {
                    state[n.aux]=n.operands[0];
                } else if(n.op==DOLIR_OP_STATE_WRITE || n.op==DOLIR_OP_STATE_READ) {
                    // Only disjoint GPR state is forwarded. Other state aliases are intentionally unsupported.
                    if(n.effects & ~(DOLIR_EFFECT_READ_STATE|DOLIR_EFFECT_WRITE_STATE)) {state.clear();aliases.clear();}
                } else if(n.effects || n.op==DOLIR_OP_HELPER_CALL || n.op==DOLIR_OP_GUEST_LOAD || n.op==DOLIR_OP_GUEST_STORE) {
                    state.clear();aliases.clear();
                }
                if(n.result){originals[n.result]={b,j};assumptions[n.result]=forwards;}
                segments.back().push_back(n);
            }
        }
        blocks.resize(segments.size());
        for(unsigned b=0;b<segments.size();b++){blocks[b].instructions=segments[b].data();blocks[b].instruction_count=segments[b].size();}
        view=f;view.blocks=blocks.data();view.block_count=blocks.size();
    }
};
bool noMasks(const DolIRInstruction &n) {
    for(auto x:n.state_defs)if(x)return false;
    for(auto x:n.state_uses)if(x)return false;
    return !n.exact_fp;
}
struct Dag {
    const Graph &g; unsigned block, root_index, max_nodes; DolIRValue boundary = 0;
    std::set<DolIRValue> visiting, done, leaves;
    std::vector<DolIRValue> order;
    std::string error;
    bool walk(DolIRValue v) {
        if(done.count(v))return true;
        if(visiting.count(v)){error="CYCLIC_DAG";return false;}
        auto it=g.defs.find(v); if(it==g.defs.end()){error="UNDEFINED_VALUE";return false;}
        if(it->second.block!=block || it->second.index>root_index){error="CROSS_CUT_OR_NONDOMINATING_VALUE";return false;}
        const auto &n=*it->second.n; unsigned w=width(n.type);
        if(!w){error="UNSUPPORTED_TYPE";return false;}
        if(done.size()+visiting.size()>=max_nodes){error="DAG_BUDGET_EXCEEDED";return false;}
        if(v==boundary) {
            leaves.insert(v);done.insert(v);order.push_back(v);return true;
        }
        if(n.op==DOLIR_OP_STATE_READ) {
            if(n.operand_count || n.aux>=DOLIR_STATE_COUNT || dolir_state_type(DolIRStateSlot(n.aux))!=n.type || n.effects!=DOLIR_EFFECT_READ_STATE){error="INVALID_INPUT_READ";return false;}
            // Preserve this actual read as an opaque SSA leaf; never invent noalias or state forwarding.
            leaves.insert(v);done.insert(v);order.push_back(v);return true;
        }
        if(n.effects || !noMasks(n)){error="EFFECTFUL_DAG";return false;}
        if(n.address_domain!=DOLIR_ADDRESS_UNKNOWN){error="UNEXPECTED_ADDRESS_METADATA";return false;}
        unsigned arity=2;
        switch(n.op) {
          case DOLIR_OP_CONSTANT:arity=0;break;
          case DOLIR_OP_NOT:case DOLIR_OP_TRUNC:case DOLIR_OP_ZEXT:case DOLIR_OP_SEXT:arity=1;break;
          case DOLIR_OP_SELECT:arity=3;break;
          case DOLIR_OP_ADD:case DOLIR_OP_SUB:case DOLIR_OP_MUL:case DOLIR_OP_AND:
          case DOLIR_OP_OR:case DOLIR_OP_XOR:case DOLIR_OP_SHL:case DOLIR_OP_LSHR:
          case DOLIR_OP_ASHR:case DOLIR_OP_ROTL:case DOLIR_OP_ICMP_EQ:case DOLIR_OP_ICMP_NE:case DOLIR_OP_ICMP_ULT:case DOLIR_OP_ICMP_ULE:case DOLIR_OP_ICMP_SLT:case DOLIR_OP_ICMP_SLE:break;
          default:error="UNSUPPORTED_OR_EFFECTFUL_OP";return false;
        }
        if(n.operand_count!=arity){error="INVALID_ARITY";return false;}
        visiting.insert(v);
        for(unsigned j=0;j<arity;j++) if(!walk(n.operands[j]))return false;
        auto ow=[&](unsigned j){return width(g.node(n.operands[j])->type);};
        if(n.op==DOLIR_OP_TRUNC) {if(ow(0)<=w){error="INVALID_TRUNC";return false;}}
        else if(n.op==DOLIR_OP_ZEXT||n.op==DOLIR_OP_SEXT) {if(ow(0)>=w){error="INVALID_EXTENSION";return false;}}
        else if(n.op==DOLIR_OP_SELECT) {if(ow(0)!=1||ow(1)!=w||ow(2)!=w){error="TYPE_MISMATCH";return false;}}
        else if(n.op>=DOLIR_OP_ICMP_EQ&&n.op<=DOLIR_OP_ICMP_SLE) {if(w!=1||ow(0)!=ow(1)){error="TYPE_MISMATCH";return false;}}
        else for(unsigned j=0;j<arity;j++) if(ow(j)!=w){error="TYPE_MISMATCH";return false;}
        if(n.op==DOLIR_OP_SHL||n.op==DOLIR_OP_LSHR||n.op==DOLIR_OP_ASHR||n.op==DOLIR_OP_ROTL) {
            uint64_t k; if(!g.constant(n.operands[1],k)){error="DYNAMIC_SHIFT_UNSUPPORTED";return false;}
            if(n.op!=DOLIR_OP_ROTL && k>=w){error="SHIFT_POISON_UNPROVEN";return false;}
        }
        visiting.erase(v);done.insert(v);order.push_back(v);return true;
    }
};
std::vector<std::pair<DolIRValue,DolIRValue>> forwardsFor(const Projection &p,const Dag &d) {
    std::set<std::pair<DolIRValue,DolIRValue>> values;
    for(auto v:d.order){auto it=p.assumptions.find(v);if(it!=p.assumptions.end())values.insert(it->second.begin(),it->second.end());}
    return {values.begin(),values.end()};
}
std::vector<unsigned> blocksFor(const Projection &p,const Dag &d,const std::vector<std::pair<DolIRValue,DolIRValue>> &forwards) {
    std::set<unsigned> values;for(auto v:d.order)values.insert(p.originals.at(v).first);
    for(auto [a,b]:forwards){values.insert(p.originals.at(a).first);values.insert(p.originals.at(b).first);}
    return {values.begin(),values.end()};
}
std::string sym(DolIRValue v){return "v"+std::to_string(v);}
std::string bv(uint64_t n,unsigned w){return "(_ bv"+std::to_string(n&mask(w))+" "+std::to_string(w)+")";}
std::string expression(const Graph &g,const DolIRInstruction &n) {
    unsigned w=width(n.type);auto a=[&](unsigned j){return sym(n.operands[j]);};
    auto bin=[&](const char *op){return std::string("(")+op+" "+a(0)+" "+a(1)+")";};
    switch(n.op){
      case DOLIR_OP_CONSTANT:return bv(n.immediate,w);
      case DOLIR_OP_ADD:return bin("bvadd");case DOLIR_OP_SUB:return bin("bvsub");
      case DOLIR_OP_MUL:return bin("bvmul");case DOLIR_OP_AND:return bin("bvand");
      case DOLIR_OP_OR:return bin("bvor");case DOLIR_OP_XOR:return bin("bvxor");
      case DOLIR_OP_SHL:return bin("bvshl");case DOLIR_OP_LSHR:return bin("bvlshr");
      case DOLIR_OP_ASHR:return bin("bvashr");
      case DOLIR_OP_NOT:return "(bvnot "+a(0)+")";
      case DOLIR_OP_ROTL:{uint64_t k=0;g.constant(n.operands[1],k);return "((_ rotate_left "+std::to_string(k%w)+") "+a(0)+")";}
      case DOLIR_OP_TRUNC:return "((_ extract "+std::to_string(w-1)+" 0) "+a(0)+")";
      case DOLIR_OP_ZEXT:case DOLIR_OP_SEXT:return "((_ "+std::string(n.op==DOLIR_OP_ZEXT?"zero_extend":"sign_extend")+" "+std::to_string(w-width(g.node(n.operands[0])->type))+") "+a(0)+")";
      case DOLIR_OP_ICMP_EQ:return "(ite (= "+a(0)+" "+a(1)+") #b1 #b0)";
      case DOLIR_OP_ICMP_NE:return "(ite (= "+a(0)+" "+a(1)+") #b0 #b1)";
      case DOLIR_OP_ICMP_ULT:return "(ite (bvult "+a(0)+" "+a(1)+") #b1 #b0)";
      case DOLIR_OP_ICMP_ULE:return "(ite (bvule "+a(0)+" "+a(1)+") #b1 #b0)";
      case DOLIR_OP_ICMP_SLE:return "(ite (bvsle "+a(0)+" "+a(1)+") #b1 #b0)";
      case DOLIR_OP_ICMP_SLT:return "(ite (bvslt "+a(0)+" "+a(1)+") #b1 #b0)";
      case DOLIR_OP_SELECT:return "(ite (= "+a(0)+" #b1) "+a(1)+" "+a(2)+")";
      default:throw std::runtime_error("unsupported DAG operation");
    }
}
std::string dagText(const Graph &g,const Dag &d) {
    dolanalysis::CheckedOutput s;for(auto v:d.order)s<<nodeText(*g.node(v))<<'\n';return s.str();
}
std::string query(const Graph &g,const Dag &d,const Candidate &c) {
    dolanalysis::CheckedOutput s;s<<"(set-option :produce-proofs true)\n(set-logic QF_BV)\n";
    for(auto v:d.order) {
        auto &n=*g.node(v);unsigned w=width(n.type);
        if(d.leaves.count(v))s<<"(declare-fun "<<sym(v)<<" () (_ BitVec "<<w<<"))\n";
        else s<<"(define-fun "<<sym(v)<<" () (_ BitVec "<<w<<") "<<expression(g,n)<<")\n";
    }
    unsigned iw=width(c.expression.input_type),ow=width(c.expression.output_type);
    std::string rhs="(bvsrem "+sym(c.expression.input)+" "+bv(uint64_t(1)<<c.expression.power,iw)+")";
    if(ow<iw)rhs="((_ extract "+std::to_string(ow-1)+" 0) "+rhs+")";
    s<<"(assert (not (= "<<sym(c.root)<<" "<<rhs<<")))\n(check-sat)\n";
    return s.str();
}
struct Solver {
    struct CloseLibrary {void operator()(void *handle)const noexcept{dlclose(handle);}};
    std::unique_ptr<void,CloseLibrary> library;
    void *lib=nullptr; std::string error,version,library_hash;
    using P=void*;
    P(*mk_config)();void(*set_param)(P,const char*,const char*);void(*del_config)(P);
    P(*mk_context)(P);void(*del_context)(P);const char*(*eval)(P,const char*);
    void(*get_version)(unsigned*,unsigned*,unsigned*,unsigned*);
    void(*set_error_handler)(P,void(*)(P,unsigned));
    template<class T>void get(T &fn,const char *name) {fn=reinterpret_cast<T>(dlsym(lib,name));if(!fn)error="SOLVER_API_UNAVAILABLE";}
    Solver() {
        lib=dlopen("libz3.so.4",RTLD_NOW|RTLD_LOCAL);library.reset(lib);if(!lib){error="SOLVER_UNAVAILABLE";return;}
        get(mk_config,"Z3_mk_config");get(set_param,"Z3_set_param_value");get(del_config,"Z3_del_config");
        get(mk_context,"Z3_mk_context");get(del_context,"Z3_del_context");get(eval,"Z3_eval_smtlib2_string");get(get_version,"Z3_get_version");get(set_error_handler,"Z3_set_error_handler");
        if(!error.empty())return;
        unsigned a,b,c,d;get_version(&a,&b,&c,&d);version=std::to_string(a)+"."+std::to_string(b)+"."+std::to_string(c)+"."+std::to_string(d);
        Dl_info info{};if(dladdr(reinterpret_cast<void*>(eval),&info)&&info.dli_fname)library_hash=fileSha256(info.dli_fname);
        if(!dolanalysis::isSha256(library_hash))error="SOLVER_IDENTITY_UNAVAILABLE";
    }
    Proof run(const std::string &q,unsigned timeout) {
        Proof p;p.query=q;p.query_sha256=sha256(q);p.solver_version=version;p.solver_library_sha256=library_hash;
        #ifdef DOLIDIOM_IMPLEMENTATION_SHA256
        p.implementation_sha256=DOLIDIOM_IMPLEMENTATION_SHA256;
#else
        p.status="IMPLEMENTATION_IDENTITY_UNAVAILABLE";return p;
#endif
        if(!dolanalysis::isSha256(p.query_sha256)||!dolanalysis::isSha256(p.implementation_sha256)){p.status="INVALID_PROOF_IDENTITY";return p;}
        if(!error.empty()){p.status=error;return p;}
        const auto timeout_text=std::to_string(timeout);
        std::unique_ptr<void,void(*)(P)> cfg(mk_config(),del_config);
        if(!cfg){p.status="SOLVER_CONFIGURATION_FAILED";return p;}
        set_param(cfg.get(),"proof","true");set_param(cfg.get(),"timeout",timeout_text.c_str());
        std::unique_ptr<void,void(*)(P)> ctx(mk_context(cfg.get()),del_context);
        if(!ctx){p.status="SOLVER_CONTEXT_FAILED";return p;}
        cfg.reset();set_error_handler(ctx.get(),[](P,unsigned){});
        const char *r=eval(ctx.get(),q.c_str());p.solver_output=r?r:"";
        if(p.solver_output=="unsat\n") {
            p.status="UNSAT";
            const char *proof=eval(ctx.get(),"(get-proof)");if(proof)p.solver_output+=proof;
        } else if(p.solver_output=="sat\n") {
            p.status="SAT";const char *model=eval(ctx.get(),"(get-model)");if(model)p.solver_output+=model;
        } else p.status="UNKNOWN_OR_ERROR";
        return p;
    }
};
}
const char *implementationIdentity() {
#ifdef DOLIDIOM_IMPLEMENTATION_SHA256
    return DOLIDIOM_IMPLEMENTATION_SHA256;
#else
    return "";
#endif
}
std::string sha256(const std::string &s) {
    return dolanalysis::sha256(s.data(),s.size());
}
std::string fileSha256(const std::string &path) {
    std::ifstream f(path,std::ios::binary);if(!f)return "";
    f.exceptions(std::ios::badbit);
    std::string bytes;char buffer[16384];
    while(f.read(buffer,sizeof(buffer)) || f.gcount())bytes.append(buffer,static_cast<size_t>(f.gcount()));
    if(!f.eof())return "";
    return sha256(bytes);
}
std::string sourceFingerprint(const DolIRFunction &f) {
    if(!boundedShape(f))return "";
    return dolcert::sourceFingerprint(f);
}
std::string sourceCutFingerprint(const DolIRFunction &f){return boundedShape(f)?sha256(cuts(f)):"";}
Proof verify(const DolIRFunction &f,const Candidate &c,unsigned timeout) {
    Proof bad;bad.status="STALE_OR_INVALID_CANDIDATE";
    if(!boundedShape(f)||!timeout||timeout>60000)return bad;
    const auto source=sourceFingerprint(f),cut=sourceCutFingerprint(f);
    if(!dolanalysis::isSha256(source)||!dolanalysis::isSha256(cut)||!dolanalysis::isSha256(c.dag_fingerprint)||c.source_fingerprint!=source||c.source_cut_fingerprint!=cut)return bad;
    Projection p(f);if(!p.error.empty())return bad;
    Graph g(p.view);if(!g.error.empty())return bad;
    auto it=g.defs.find(c.root);if(it==g.defs.end()||p.originals[c.root]!=std::make_pair(c.block,c.instruction))return bad;
    Dag d{g,it->second.block,it->second.index,128,c.expression.input,{},{},{},{},{}};
    if(!d.walk(c.root)||d.leaves.size()!=1||!d.leaves.count(c.expression.input))return bad;
    auto forwards=forwardsFor(p,d);
    if(forwards!=c.reaching_state_forwardings || c.conditional_on_state_forwarding!=!forwards.empty() || c.source_blocks!=blocksFor(p,d,forwards))return bad;
    unsigned iw=width(c.expression.input_type),ow=width(c.expression.output_type);
    if(iw<8||ow==0||ow>iw||c.expression.power>=iw-1||g.node(c.expression.input)->type!=c.expression.input_type||g.node(c.root)->type!=c.expression.output_type)return bad;
    if(dagText(g,d).empty()||sha256(dagText(g,d))!=c.dag_fingerprint||d.order!=c.source_values||nodeText(f.blocks[c.block].instructions[c.instruction])!=c.original_instruction)return bad;
    static Solver solver;
    return solver.run(query(g,d,c),timeout);
}
Report discover(const DolIRFunction &f,const Options &o) {
    Report r;if(!o.enabled){r.reasons.push_back("DISABLED_BY_DEFAULT");return r;}
    if(!boundedShape(f)){r.reasons.push_back("INVALID_OR_OVERSIZED_DOLIR");return r;}
    if(!o.solver_timeout_ms||o.solver_timeout_ms>60000||!o.max_nodes||o.max_nodes>128||!o.max_candidates||o.max_candidates>10000){r.reasons.push_back("INVALID_RESOURCE_BUDGET");return r;}
    Projection p(f);if(!p.error.empty()){r.reasons.push_back(p.error);return r;}
    Graph g(p.view);if(!g.error.empty()){r.reasons.push_back(g.error);return r;}
    const auto source=sourceFingerprint(f),cut=sourceCutFingerprint(f);
    if(!dolanalysis::isSha256(source)||!dolanalysis::isSha256(cut)){r.reasons.push_back("INVALID_SOURCE_IDENTITY");return r;}
    for(auto &[v,ref]:g.defs) {
        const auto *root=ref.n;const auto *base=root;
        if(base->op==DOLIR_OP_TRUNC&&base->operand_count==1)base=g.node(base->operands[0]);
        if(!base||base->op!=DOLIR_OP_SUB)continue;
        Dag d{g,ref.block,ref.index,o.max_nodes,0,{},{},{},{},{}};
        if(!d.walk(v)){r.reasons.push_back(d.error);continue;}
        if(d.leaves.size()!=1){r.reasons.push_back("REQUIRES_ONE_OPAQUE_INPUT");continue;}
        auto input=*d.leaves.begin();unsigned iw=width(g.node(input)->type),ow=width(root->type);
        if(iw<8||ow>iw||!ow)continue;
        // Structural anchors are low-bit masks or rounded-multiple masks in the dependency DAG.
        // They only propose a type/power. No candidate is accepted without universal equivalence.
        std::set<unsigned> powers;
        for(auto dv:d.order){auto n=g.node(dv);if(n->op!=DOLIR_OP_AND||n->operand_count!=2)continue;
            for(unsigned j=0;j<2;j++){uint64_t m;if(!g.constant(n->operands[j],m)||width(n->type)!=iw)continue;
                for(unsigned k=0;k<iw-1;k++){uint64_t low=(uint64_t(1)<<k)-1;if(m==low||m==(mask(iw)^low))powers.insert(k);}
            }
        }
        // Also recognize x - (((x + bias) ashr k) shl k), including k=0.
        for(auto dv:d.order){auto n=g.node(dv);if(n->op!=DOLIR_OP_SHL||n->operand_count!=2)continue;
            auto inner=g.node(n->operands[0]);uint64_t a,b;
            if(inner&&inner->op==DOLIR_OP_ASHR&&inner->operand_count==2&&g.constant(n->operands[1],a)&&g.constant(inner->operands[1],b)&&a==b&&a<iw-1)powers.insert(unsigned(a));
        }
        for(auto k:powers){if(r.candidates.size()>=o.max_candidates){r.reasons.push_back("CANDIDATE_BUDGET_EXCEEDED");return r;}
            Candidate c;c.block=p.originals[v].first;c.instruction=p.originals[v].second;c.root=v;c.expression={input,g.node(input)->type,root->type,k};c.source_values=d.order;
            c.source_fingerprint=source;c.source_cut_fingerprint=cut;c.dag_fingerprint=sha256(dagText(g,d));c.original_instruction=nodeText(f.blocks[c.block].instructions[c.instruction]);
            c.reaching_state_forwardings=forwardsFor(p,d);
            c.conditional_on_state_forwarding=!c.reaching_state_forwardings.empty();
            c.source_blocks=blocksFor(p,d,c.reaching_state_forwardings);
            if(c.conditional_on_state_forwarding)c.reasons.push_back("STATE_FORWARDING_REQUIRES_ENTRY_AND_MUTATION_CLOSURE");
            c.proof=verify(f,c,o.solver_timeout_ms);if(c.proof.status!="UNSAT")c.reasons.push_back("SEMANTIC_EQUIVALENCE_NOT_PROVEN");
            r.candidates.push_back(std::move(c));
        }
    }
    return r;
}
ApplyResult apply(DolIRFunction &f,const Candidate &c,const RegionContract &contract,const Options &o) {
    ApplyResult r;r.before_fingerprint=sourceFingerprint(f);auto reject=[&](const char *s){r.reasons.push_back(s);};
    if(!boundedShape(f)){reject("INVALID_OR_OVERSIZED_DOLIR");return r;}
    if(!dolanalysis::isSha256(r.before_fingerprint))reject("INVALID_SOURCE_IDENTITY");
    if(!o.enabled)reject("DISABLED_BY_DEFAULT");
    if(!o.solver_timeout_ms||o.solver_timeout_ms>60000)reject("INVALID_RESOURCE_BUDGET");
    if(contract.schema!="dolrecomp.validated-pure-region.v1")reject("MISSING_FUNCTION_CERTIFICATION");
    if(contract.roots!=std::vector<DolIRValue>{c.root})reject("ROOT_CONTRACT_MISMATCH");
    if(contract.function.source_fingerprint!=r.before_fingerprint||c.source_fingerprint!=r.before_fingerprint)reject("SOURCE_FINGERPRINT_MISMATCH");
    if(contract.source_cut_fingerprint!=sourceCutFingerprint(f)||c.source_cut_fingerprint!=sourceCutFingerprint(f))reject("SOURCE_CUT_MISMATCH");
    if(!r.reasons.empty())return r;
    auto certification=dolcert::certify(f,contract.function);
    r.function_contract_fingerprint=certification.contract_fingerprint;
    r.certification_implementation_id=certification.implementation_id;
    if(!certification.valid_ir||!certification.analysis_complete)reject("FUNCTION_CERTIFICATION_INCOMPLETE");
    if(certification.entries!=dolcert::Status::Closed)reject("ENTRY_NOT_CLOSED");
    if(certification.effects!=dolcert::Status::Closed)reject("EFFECTS_NOT_CLOSED");
    if(certification.observations!=dolcert::Status::Closed)reject("OBSERVATIONS_NOT_CLOSED");
    if(certification.cfg!=dolcert::Status::Closed)reject("CFG_OR_RESUME_NOT_CLOSED");
    // Current upstream backends/certifier have no cross-block SSA transport contract.
    // Report conditional projected candidates, but never introduce such SSA during lowering.
    if(c.source_blocks.size()!=1||c.conditional_on_state_forwarding)reject("CROSS_CUT_LOWERING_NOT_IMPLEMENTED");
    if(!r.reasons.empty())return r;
    r.replay_proof=verify(f,c,o.solver_timeout_ms);if(r.replay_proof.status!="UNSAT"){reject("REPLAY_PROOF_FAILED");return r;}
    auto &block=f.blocks[c.block];const auto original=block.instructions[c.instruction];
    unsigned iw=width(c.expression.input_type),ow=width(c.expression.output_type);unsigned added=ow==iw?3:4;
    if(f.value_count>UINT32_MAX-added || block.instruction_count>UINT32_MAX-added){reject("ALLOCATION_OVERFLOW");return r;}
    unsigned new_count=block.instruction_count+added,new_values=f.value_count+added;
    std::unique_ptr<DolIRInstruction,decltype(&std::free)> inst_owner(static_cast<DolIRInstruction*>(std::calloc(new_count,sizeof(DolIRInstruction))),std::free);
    std::unique_ptr<DolIRType,decltype(&std::free)> types_owner(static_cast<DolIRType*>(std::malloc(size_t(new_values)*sizeof(DolIRType))),std::free);
    auto *inst=inst_owner.get();auto *types=types_owner.get();
    if(!inst||!types){reject("OUT_OF_MEMORY");return r;}
    std::memcpy(types,f.value_types,size_t(f.value_count)*sizeof(DolIRType));
    std::memcpy(inst,block.instructions,size_t(c.instruction)*sizeof(DolIRInstruction));
    unsigned at=c.instruction,next=f.value_count;
    auto emit=[&](DolIROp op,DolIRValue a,DolIRValue b,unsigned count,uint64_t imm,DolIRValue result,DolIRType type){
        auto &n=inst[at++];n.op=op;n.type=type;n.result=result;n.operand_count=count;n.operands[0]=a;n.operands[1]=b;n.immediate=imm;n.guest_pc=original.guest_pc;
        types[result]=type;dolir_populate_effects(&n);
    };
    auto divisor=next++;emit(DOLIR_OP_CONSTANT,0,0,0,uint64_t(1)<<c.expression.power,divisor,c.expression.input_type);
    auto quotient=next++;emit(DOLIR_OP_SDIV,c.expression.input,divisor,2,0,quotient,c.expression.input_type);
    auto multiple=next++;emit(DOLIR_OP_MUL,quotient,divisor,2,0,multiple,c.expression.input_type);
    if(ow==iw)emit(DOLIR_OP_SUB,c.expression.input,multiple,2,0,c.root,c.expression.output_type);
    else {auto rem=next++;emit(DOLIR_OP_SUB,c.expression.input,multiple,2,0,rem,c.expression.input_type);emit(DOLIR_OP_TRUNC,rem,0,1,0,c.root,c.expression.output_type);}
    std::memcpy(inst+at,block.instructions+c.instruction+1,size_t(block.instruction_count-c.instruction-1)*sizeof(DolIRInstruction));
    std::unique_ptr<DolIRBlock,decltype(&std::free)> blocks_owner(static_cast<DolIRBlock*>(std::malloc(size_t(f.block_count)*sizeof(DolIRBlock))),std::free);
    auto *staged_blocks=blocks_owner.get();
    if(!staged_blocks){reject("OUT_OF_MEMORY");return r;}
    std::memcpy(staged_blocks,f.blocks,size_t(f.block_count)*sizeof(DolIRBlock));
    staged_blocks[c.block].instructions=inst;
    staged_blocks[c.block].instruction_count=staged_blocks[c.block].instruction_capacity=new_count;
    DolIRFunction staged=f;staged.blocks=staged_blocks;staged.value_types=types;
    staged.value_count=staged.value_capacity=new_values;
    DolIRModule staged_module{};staged_module.functions=&staged;staged_module.function_count=1;
    const bool valid=dolir_verify(&staged_module,stderr);
    if(!valid){reject("POST_REWRITE_VERIFY_FAILED");return r;}
    r.after_fingerprint=sourceFingerprint(staged);
    if(!dolanalysis::isSha256(r.after_fingerprint)){reject("POST_REWRITE_FINGERPRINT_FAILED");return r;}
    // No allocating or fallible work remains after ownership is committed.
    std::free(block.instructions);block.instructions=inst_owner.release();block.instruction_count=new_count;block.instruction_capacity=new_count;
    std::free(f.value_types);f.value_types=types_owner.release();f.value_count=new_values;f.value_capacity=new_values;
    r.changed=true;return r;
}
std::string emitRecoveredC(const SRemPow2 &e,const std::string &name) {
    unsigned iw=width(e.input_type),ow=width(e.output_type);if(iw<8||!ow||ow>iw||e.power>=iw-1)throw std::runtime_error("invalid typed expression");
    dolanalysis::CheckedOutput s;s<<"#include <stdint.h>\n#include <string.h>\nuint64_t "<<name<<"(uint64_t input) {\n  uint"<<iw<<"_t bits = (uint"<<iw<<"_t)input;\n  int"<<iw<<"_t x; memcpy(&x, &bits, sizeof x);\n  int"<<iw<<"_t r = (int"<<iw<<"_t)(x % (int"<<iw<<"_t)UINT64_C("<<(uint64_t(1)<<e.power)<<"));\n  return ((uint64_t)(uint"<<iw<<"_t)r) & UINT64_C("<<mask(ow)<<");\n}\n";return s.str();
}
std::string emitRecoveredLLVM(const SRemPow2 &e,const std::string &name) {
    unsigned iw=width(e.input_type),ow=width(e.output_type);if(iw<8||!ow||ow>iw||e.power>=iw-1)throw std::runtime_error("invalid typed expression");
    dolanalysis::CheckedOutput s;s<<"define i64 @"<<name<<"(i64 %input) {\n";std::string x="%input";
    if(iw<64){s<<"  %x = trunc i64 %input to i"<<iw<<"\n";x="%x";}
    s<<"  %r = srem i"<<iw<<' '<<x<<", "<<(uint64_t(1)<<e.power)<<"\n";std::string r="%r";
    if(ow<iw){s<<"  %n = trunc i"<<iw<<" %r to i"<<ow<<"\n";r="%n";}
    if(ow<64){s<<"  %out = zext i"<<ow<<' '<<r<<" to i64\n";r="%out";}
    s<<"  ret i64 "<<r<<"\n}\n";return s.str();
}
}
