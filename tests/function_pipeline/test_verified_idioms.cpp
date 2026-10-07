// SPDX-License-Identifier: GPL-3.0-or-later
#include "verified_idioms.h"
#include "ir/dolir_builder.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <cstring>
#include <climits>
#define CHECK(x) do { if(!(x)) throw std::runtime_error(std::string(__FILE__)+":"+std::to_string(__LINE__)+": " #x); } while(0)
using namespace dolidiom;
static DolIRValue op(DolIRFunction *f,DolIRBlock *b,DolIROp o,DolIRType t,DolIRValue a,DolIRValue c=0){DolIRValue args[]={a,c};return dolir_append(f,b,o,t,args,c?2:1,0,0,b->guest_address,0);}
struct Fixture {
    DolIRModule m{};DolIRFunction *f=nullptr;DolIRValue input=0,root=0,sign=0;
    Fixture(unsigned bits,unsigned power,unsigned out=0,unsigned shape=0,bool wrong=false) {
        dolir_module_init(&m);f=dolir_add_function(&m,"synthetic",0x1000,0x1004);auto b=dolir_add_block(f,0x1000);b->raw=0x1234;b->cycle_cost=7;b->terminator.kind=DOLIR_TERM_RETURN;
        auto t=bits==64?DOLIR_TYPE_I64:DOLIR_TYPE_I32;
        input=dolir_state_read(f,b,bits==64?DOLIR_STATE_TIMEBASE:DOLIR_STATE_GPR0,0x1000);
        auto c=[&](uint64_t x){return dolir_constant(f,b,t,x,0x1000);};
        sign=op(f,b,DOLIR_OP_ASHR,t,input,c(bits-1));
        auto low=(uint64_t(1)<<power)-1;DolIRValue bias;
        if(shape==1) bias=op(f,b,DOLIR_OP_LSHR,t,sign,c(power?bits-power:bits-1));
        else if(shape==2)bias=op(f,b,DOLIR_OP_AND,t,op(f,b,DOLIR_OP_ROTL,t,sign,c((power+7)%bits)),c(low));
        else bias=op(f,b,DOLIR_OP_AND,t,sign,c(low));
        if(wrong)bias=op(f,b,DOLIR_OP_XOR,t,bias,c(1));
        auto sum=op(f,b,DOLIR_OP_ADD,t,input,bias);
        if(shape==3){auto q=op(f,b,DOLIR_OP_ASHR,t,sum,c(power));auto product=op(f,b,DOLIR_OP_SHL,t,q,c(power));root=op(f,b,DOLIR_OP_SUB,t,input,product);}
        else if(shape==4){auto product=op(f,b,DOLIR_OP_AND,t,sum,c(~low));root=op(f,b,DOLIR_OP_SUB,t,input,product);}
        else {auto narrow=op(f,b,DOLIR_OP_AND,t,sum,c(low));root=op(f,b,DOLIR_OP_SUB,t,narrow,bias);}
        if(out&&out<bits)root=op(f,b,DOLIR_OP_TRUNC,out==1?DOLIR_TYPE_I1:out==8?DOLIR_TYPE_I8:out==16?DOLIR_TYPE_I16:DOLIR_TYPE_I32,root);
        // An independent architectural consumer of an intermediate must survive apply.
        if(bits==32)dolir_state_write(f,b,DOLIR_STATE_GPR31,sign,0x1000);
        auto lr=dolir_state_read(f,b,DOLIR_STATE_LR,0x1000);
        auto lr_mask=dolir_constant(f,b,DOLIR_TYPE_I32,0xfffffffcu,0x1000);
        b->terminator.kind=DOLIR_TERM_INDIRECT;
        b->terminator.condition=dolir_constant(f,b,DOLIR_TYPE_I1,1,0x1000);
        b->terminator.target_value=op(f,b,DOLIR_OP_AND,DOLIR_TYPE_I32,lr,lr_mask);
    }
    ~Fixture(){dolir_module_free(&m);}
};
static unsigned width(DolIRType t){switch(t){case DOLIR_TYPE_I1:return 1;case DOLIR_TYPE_I8:return 8;case DOLIR_TYPE_I16:return 16;case DOLIR_TYPE_I32:return 32;case DOLIR_TYPE_I64:return 64;default:throw std::runtime_error("type");}}
static uint64_t mask(unsigned w){return w==64?UINT64_MAX:(uint64_t(1)<<w)-1;}
static uint64_t ashr(uint64_t x,unsigned k,unsigned w){x&=mask(w);if(!k)return x;return (x>>k)|((x>>(w-1))?(mask(w)^mask(w-k)):0);}
static uint64_t evaluate(const DolIRFunction &f,DolIRValue root,uint64_t input){
    std::map<DolIRValue,uint64_t> v;
    for(unsigned b=0;b<f.block_count;b++)for(unsigned j=0;j<f.blocks[b].instruction_count;j++){
        const auto &i=f.blocks[b].instructions[j];if(!i.result)continue;auto w=width(i.type);auto a=v[i.operands[0]],c=v[i.operands[1]];uint64_t n=0;
        switch(i.op){case DOLIR_OP_STATE_READ:n=input;break;case DOLIR_OP_CONSTANT:n=i.immediate;break;case DOLIR_OP_ADD:n=a+c;break;case DOLIR_OP_SUB:n=a-c;break;case DOLIR_OP_MUL:n=a*c;break;case DOLIR_OP_AND:n=a&c;break;case DOLIR_OP_XOR:n=a^c;break;
          case DOLIR_OP_ASHR:n=ashr(a,c,w);break;case DOLIR_OP_LSHR:n=a>>c;break;case DOLIR_OP_SHL:n=a<<c;break;case DOLIR_OP_ROTL:c%=w;n=c?((a<<c)|(a>>(w-c))):a;break;case DOLIR_OP_TRUNC:n=a;break;
          case DOLIR_OP_SDIV:{CHECK(c && !(c>>(w-1)));bool neg=(a>>(w-1))&1;uint64_t magnitude=neg?((-a)&mask(w)):a;uint64_t q=magnitude/c;n=neg?-q:q;break;}
          default:throw std::runtime_error("eval op");}
        v[i.result]=n&mask(w);
    }
    return v.at(root);
}
static const Candidate *find(const Report &r,DolIRValue root,unsigned power){for(auto &c:r.candidates)if(c.root==root&&c.expression.power==power&&c.proof.status=="UNSAT")return &c;return nullptr;}
static RegionContract closed(const Fixture &x,const Candidate &c){
    RegionContract r;r.function.source_fingerprint=sourceFingerprint(*x.f);r.source_cut_fingerprint=sourceCutFingerprint(*x.f);r.roots={c.root};
    r.function.entries_and_code=r.function.exception_resume=r.function.observations={dolcert::EvidenceGrade::Verified,"synthetic-closed-world-test-harness"};
    const auto *f=x.f;const auto fingerprint=r.function.source_fingerprint;const auto contract_id=dolcert::contractFingerprint(r.function);
    r.function.verify_evidence=[f,fingerprint,contract_id](const dolcert::EvidenceRequest &q){
        // This callback is authority only for the locally constructed, non-executable synthetic harness.
        return f->block_count==1 && q.source_fingerprint==fingerprint && sourceFingerprint(*f)==fingerprint && q.proof_id=="synthetic-closed-world-test-harness" && q.contract_fingerprint==contract_id && q.entry_blocks==std::vector<u32>{0} && q.model=="exact-original-cuts/full-state-observation" &&
          (q.obligation=="ENTRY_POPULATION_OR_CODE_STABILITY_UNPROVED" || q.obligation=="EXACT_OBSERVATION_AND_MUTATION_CONTRACT_UNPROVED" || q.obligation=="EXCEPTION_RESUME_CLOSURE_UNPROVED");
    };return r;
}
static std::vector<uint64_t> values(unsigned bits,unsigned k){std::vector<uint64_t>x={0,1,2,UINT64_MAX,UINT64_MAX-1,uint64_t(1)<<(bits-1),(uint64_t(1)<<(bits-1))-1,(uint64_t(1)<<k)-1,uint64_t(1)<<k,(uint64_t(1)<<k)+1,-(uint64_t(1)<<k),-(uint64_t(1)<<k)-1};uint64_t s=0x8bf43a39;for(int i=0;i<128;i++){s^=s<<13;s^=s>>7;s^=s<<17;x.push_back(s);}return x;}
static std::string originalC(const DolIRFunction &f,DolIRValue root,const std::string &name){
    std::ostringstream s;s<<"#include <stdint.h>\nstatic uint64_t m(unsigned w){return w==64?UINT64_MAX:(UINT64_C(1)<<w)-1;}\nstatic uint64_t asr(uint64_t x,unsigned k,unsigned w){return !k?x:(x>>k)|((x>>(w-1))?(m(w)^m(w-k)):0);}\nstatic uint64_t rot(uint64_t x,unsigned k,unsigned w){k%=w;return k?((x<<k)|(x>>(w-k)))&m(w):x;}\nuint64_t "<<name<<"(uint64_t input){\n";
    for(unsigned b=0;b<f.block_count;b++)for(unsigned j=0;j<f.blocks[b].instruction_count;j++){
      auto &n=f.blocks[b].instructions[j];if(!n.result)continue;auto w=width(n.type);auto a="v"+std::to_string(n.operands[0]),c="v"+std::to_string(n.operands[1]);std::string e;
      switch(n.op){case DOLIR_OP_STATE_READ:e="input";break;case DOLIR_OP_CONSTANT:e="UINT64_C("+std::to_string(n.immediate)+")";break;
      case DOLIR_OP_ADD:e=a+"+"+c;break;case DOLIR_OP_SUB:e=a+"-"+c;break;case DOLIR_OP_MUL:e=a+"*"+c;break;case DOLIR_OP_AND:e=a+"&"+c;break;case DOLIR_OP_XOR:e=a+"^"+c;break;
      case DOLIR_OP_SHL:e=a+"<<"+c;break;case DOLIR_OP_LSHR:e=a+">>"+c;break;case DOLIR_OP_ASHR:e="asr("+a+","+c+","+std::to_string(w)+")";break;case DOLIR_OP_ROTL:e="rot("+a+","+c+","+std::to_string(w)+")";break;case DOLIR_OP_TRUNC:e=a;break;default:throw std::runtime_error("original C op");}
      s<<"uint64_t v"<<n.result<<" = ("<<e<<") & m("<<w<<");\n";
    }
    s<<"return v"<<root<<";\n}\n";return s.str();
}
static std::string originalLLVM(const DolIRFunction &f,DolIRValue root,const std::string &name){
    std::ostringstream s;std::set<unsigned> rotations;
    s<<"define i64 @"<<name<<"(i64 %input) {\n";
    for(unsigned b=0;b<f.block_count;b++)for(unsigned j=0;j<f.blocks[b].instruction_count;j++){
      auto &n=f.blocks[b].instructions[j];if(!n.result)continue;auto w=width(n.type);auto t="i"+std::to_string(w),a="%v"+std::to_string(n.operands[0]),c="%v"+std::to_string(n.operands[1]);std::string e;
      switch(n.op){case DOLIR_OP_STATE_READ:e=w==64?"or i64 %input, 0":"trunc i64 %input to "+t;break;case DOLIR_OP_CONSTANT:e="or "+t+" "+std::to_string(n.immediate&mask(w))+", 0";break;
      case DOLIR_OP_ADD:e="add "+t+" "+a+", "+c;break;case DOLIR_OP_SUB:e="sub "+t+" "+a+", "+c;break;case DOLIR_OP_MUL:e="mul "+t+" "+a+", "+c;break;case DOLIR_OP_AND:e="and "+t+" "+a+", "+c;break;case DOLIR_OP_XOR:e="xor "+t+" "+a+", "+c;break;
      case DOLIR_OP_SHL:e="shl "+t+" "+a+", "+c;break;case DOLIR_OP_LSHR:e="lshr "+t+" "+a+", "+c;break;case DOLIR_OP_ASHR:e="ashr "+t+" "+a+", "+c;break;
      case DOLIR_OP_ROTL:rotations.insert(w);e="call "+t+" @llvm.fshl."+t+"("+t+" "+a+", "+t+" "+a+", "+t+" "+c+")";break;
      case DOLIR_OP_TRUNC:e="trunc i"+std::to_string(width(f.value_types[n.operands[0]]))+" "+a+" to "+t;break;default:throw std::runtime_error("original LLVM op");}
      s<<"  %v"<<n.result<<" = "<<e<<'\n';
    }
    auto ow=width(f.value_types[root]);if(ow<64)s<<"  %out = zext i"<<ow<<" %v"<<root<<" to i64\n  ret i64 %out\n";else s<<"  ret i64 %v"<<root<<"\n";
    s<<"}\n";for(auto w:rotations)s<<"declare i"<<w<<" @llvm.fshl.i"<<w<<"(i"<<w<<", i"<<w<<", i"<<w<<")\n";return s.str();
}
static std::string effectBytes(const DolIRFunction &f){std::string s;for(unsigned b=0;b<f.block_count;b++)for(unsigned j=0;j<f.blocks[b].instruction_count;j++){auto &n=f.blocks[b].instructions[j];if(n.effects)s.append(reinterpret_cast<const char*>(&n),sizeof n);}return s;}
static void save(const DolIRFunction &f,const Candidate &c,const std::filesystem::path &dir,const std::string &name){
    std::ofstream(dir/(name+".smt2"))<<c.proof.query;
    std::ofstream(dir/(name+".proof"))<<c.proof.solver_output;
    std::ofstream(dir/(name+".certificate"))<<"schema="<<schema<<"\nsource="<<c.source_fingerprint<<"\ncuts="<<c.source_cut_fingerprint<<"\ndag="<<c.dag_fingerprint<<"\nquery="<<c.proof.query_sha256<<"\nsolver="<<c.proof.solver_version<<"\nsolver_library="<<c.proof.solver_library_sha256<<"\nimplementation="<<c.proof.implementation_sha256<<"\nresult="<<c.proof.status<<'\n';
    std::ofstream(dir/(name+".c"))<<emitRecoveredC(c.expression,name+"_c");
    std::ofstream(dir/(name+".ll"))<<emitRecoveredLLVM(c.expression,name+"_llvm");
    std::ofstream(dir/(name+"_original.c"))<<originalC(f,c.root,name+"_original_c");
    std::ofstream(dir/(name+"_original.ll"))<<originalLLVM(f,c.root,name+"_original_llvm");
}
static unsigned builderTests(const std::filesystem::path &dir,const Options &o){
    auto x=[](unsigned r,unsigned a,unsigned b,unsigned xo){return (31u<<26)|(r<<21)|(a<<16)|(b<<11)|(xo<<1);};
    auto rl=[](unsigned r,unsigned a,unsigned sh,unsigned mb,unsigned me){return (21u<<26)|(r<<21)|(a<<16)|(sh<<11)|(mb<<6)|(me<<1);};
    unsigned count=0;
    for(unsigned k=1;k<31;k++){
        std::vector<u32> raw={x(3,4,31,824),rl(4,4,(k+7)%32,32-k,31),x(5,3,4,266),rl(5,5,0,32-k,31),x(3,4,5,40),0x4e800020};
        std::vector<PPCInst> words;for(unsigned i=0;i<raw.size();i++)words.push_back(ppc_decode(raw[i],0x4000+4*i));
        DolIRModule m;dolir_module_init(&m);CHECK(dolir_build_chunk(&m,words.data(),words.size(),0x4000));auto &f=m.functions[0];
        auto before=sourceFingerprint(f);auto report=discover(f,o);const Candidate *found=nullptr;
        for(auto &c:report.candidates)if(c.expression.power==k&&c.proof.status=="UNSAT")found=&c;
        CHECK(found);CHECK(found->conditional_on_state_forwarding);CHECK(found->source_blocks.size()>1);CHECK(sourceFingerprint(f)==before);
        CHECK(!apply(f,*found,{},o).changed);auto forged=*found;forged.source_blocks={forged.block};forged.conditional_on_state_forwarding=false;CHECK(verify(f,forged).status=="STALE_OR_INVALID_CANDIDATE");
        forged=*found;forged.reaching_state_forwardings.clear();CHECK(verify(f,forged).status=="STALE_OR_INVALID_CANDIDATE");
        if(k==5){std::ofstream(dir/"builder.smt2")<<found->proof.query;std::ofstream(dir/"builder.proof")<<found->proof.solver_output;std::ofstream listing(dir/"builder.words");for(unsigned i=0;i<raw.size();i++)listing<<std::hex<<(0x4000+4*i)<<' '<<raw[i]<<'\n';}
        dolir_module_free(&m);count++;
        // A mutated bias must not obtain the intended remainder certificate.
        raw.insert(raw.begin()+2,(26u<<26)|(4u<<21)|(4u<<16)|1u);words.clear();for(unsigned i=0;i<raw.size();i++)words.push_back(ppc_decode(raw[i],0x4000+4*i));
        dolir_module_init(&m);CHECK(dolir_build_chunk(&m,words.data(),words.size(),0x4000));auto bad=discover(m.functions[0],o);for(auto &c:bad.candidates)CHECK(!(c.expression.power==k&&c.proof.status=="UNSAT"));dolir_module_free(&m);
    }return count;
}
int main(int argc,char **argv){try{
    CHECK(argc==2);std::filesystem::path dir=argv[1];std::filesystem::create_directories(dir);std::filesystem::create_directories(dir/"all-proofs");Options enabled;enabled.enabled=true;
    unsigned positives=0,negative=0,rejected=0;
    auto builder_positive=builderTests(dir,enabled);
    for(unsigned bits:{32u,64u})for(unsigned k=0;k<bits-1;k++)for(unsigned shape:{0u,1u,2u,3u,4u}){
        if(shape==1&&k==0)continue;
        unsigned out=(k%4==0?1:k%4==1?8:k%4==2?16:bits);
        Fixture x(bits,k,out,shape);auto before=sourceFingerprint(*x.f);CHECK(discover(*x.f).candidates.empty());CHECK(sourceFingerprint(*x.f)==before);
        auto r=discover(*x.f,enabled);auto p=find(r,x.root,k);CHECK(p);
        auto seq=values(bits,k);std::vector<uint64_t> expected;for(auto a:seq)expected.push_back(evaluate(*x.f,x.root,a));
        CHECK(!apply(*x.f,*p,closed(x,*p)).changed);CHECK(sourceFingerprint(*x.f)==before);
        CHECK(!apply(*x.f,*p,{},enabled).changed);CHECK(sourceFingerprint(*x.f)==before);
        if(shape==2 && (k<4||k==bits-2))save(*x.f,*p,dir,"rem"+std::to_string(bits)+"_"+std::to_string(k)+"_"+std::to_string(out));
        auto cuts=sourceCutFingerprint(*x.f);auto effects=effectBytes(*x.f);auto applied=apply(*x.f,*p,closed(x,*p),enabled);CHECK(applied.changed);
        auto key="w"+std::to_string(bits)+"-k"+std::to_string(k)+"-shape"+std::to_string(shape)+"-out"+std::to_string(out);
        std::ofstream(dir/"all-proofs"/(key+".smt2"))<<applied.replay_proof.query;
        std::ofstream(dir/"all-proofs"/(key+".solver"))<<applied.replay_proof.solver_output;
        std::ofstream(dir/"all-proofs"/(key+".certificate"))<<"schema="<<schema<<"\nsource="<<applied.before_fingerprint<<"\nafter="<<applied.after_fingerprint<<"\ncontract="<<applied.function_contract_fingerprint<<"\ncertification_implementation="<<applied.certification_implementation_id<<"\nquery="<<applied.replay_proof.query_sha256<<"\nsolver="<<applied.replay_proof.solver_version<<"\nsolver_library="<<applied.replay_proof.solver_library_sha256<<"\nimplementation="<<applied.replay_proof.implementation_sha256<<"\nresult="<<applied.replay_proof.status<<'\n';
        CHECK(sourceCutFingerprint(*x.f)==cuts);CHECK(effectBytes(*x.f)==effects);
        CHECK(dolir_verify(&x.m,stderr));for(unsigned i=0;i<seq.size();i++)CHECK(evaluate(*x.f,x.root,seq[i])==expected[i]);
        CHECK(!apply(*x.f,*p,closed(x,*p),enabled).changed);positives++;
    }
    for(unsigned bits:{32u,64u})for(unsigned k:{1u,5u,15u}){
        Fixture x(bits,k,0,2,true);auto r=discover(*x.f,enabled);CHECK(!find(r,x.root,k));bool sat=false;for(auto &c:r.candidates)if(c.root==x.root&&c.expression.power==k)sat|=c.proof.status=="SAT";CHECK(sat);negative++;
    }
    {Fixture x(32,5);auto r=discover(*x.f,enabled);auto p=find(r,x.root,5);CHECK(p);auto c=*p;c.expression.power=4;CHECK(verify(*x.f,c).status=="SAT");auto good=closed(x,*p);good.function.verify_evidence={};CHECK(!apply(*x.f,*p,good,enabled).changed);rejected++;x.f->blocks[0].cycle_cost++;CHECK(verify(*x.f,*p).status=="STALE_OR_INVALID_CANDIDATE");CHECK(!apply(*x.f,*p,good,enabled).changed);rejected++;}
    {Fixture x(32,5);for(unsigned i=0;i<x.f->blocks[0].instruction_count;i++)if(x.f->blocks[0].instructions[i].op==DOLIR_OP_ADD)x.f->blocks[0].instructions[i].effects=DOLIR_EFFECT_MAY_RAISE;CHECK(discover(*x.f,enabled).candidates.empty());rejected++;}
    {Fixture x(32,5);for(unsigned i=0;i<x.f->blocks[0].instruction_count;i++)if(x.f->blocks[0].instructions[i].op==DOLIR_OP_ASHR)x.f->blocks[0].instructions[i].operands[1]=x.input;CHECK(discover(*x.f,enabled).candidates.empty());rejected++;}
    std::cout<<"{\"positive_rewrites\":"<<positives<<",\"semantic_negative_controls\":"<<negative<<",\"explicit_rejection_cases\":"<<rejected<<",\"builder_positive\":"<<builder_positive<<",\"builder_negative\":"<<builder_positive<<"}\n";
    return 0;
}catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}}
