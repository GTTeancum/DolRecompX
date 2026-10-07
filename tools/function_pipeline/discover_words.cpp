// SPDX-License-Identifier: GPL-3.0-or-later
// Generic read-only driver. Input is a caller-selected contiguous PC/raw listing.
#include "verified_idioms.h"
#include "ir/dolir_builder.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>
using namespace dolidiom;
static std::string quote(const std::string &s){std::string r="\"";for(auto c:s){if(c=='\"'||c=='\\')r+='\\';if(c=='\n')r+="\\n";else if(c=='\r')r+="\\r";else r+=c;}return r+'\"';}
static void writeChecked(const std::filesystem::path &path,const std::string &text){
    std::ofstream stream;stream.exceptions(std::ios::badbit|std::ios::failbit);
    stream.open(path,std::ios::binary);stream<<text;stream.close();
}
int main(int argc,char **argv){try{
    if(argc!=3)throw std::runtime_error("usage: discover_words INPUT.pc-raw OUTPUT_DIRECTORY");
    std::ifstream in(argv[1]);in.exceptions(std::ios::badbit);if(!in)throw std::runtime_error("cannot read input");
    std::vector<PPCInst> words;uint32_t pc,raw;uint32_t base=0;
    while(in>>std::hex>>pc){if(!(in>>std::hex>>raw))throw std::runtime_error("incomplete PC/raw pair");if(words.empty())base=pc;if(words.size()>=100000||uint64_t(base)+words.size()*4>UINT32_MAX||pc!=base+words.size()*4)throw std::runtime_error("noncontiguous or oversized input");words.push_back(ppc_decode(raw,pc));}
    if(!in.eof()||words.empty())throw std::runtime_error("invalid or empty input");
    DolIRModule m;dolir_module_init(&m);if(!dolir_build_chunk(&m,words.data(),words.size(),base)||m.function_count!=1||!dolir_verify(&m,stderr))throw std::runtime_error("invalid lifted DolIR");
    auto &f=m.functions[0];const auto original=sourceFingerprint(f);Options o;o.enabled=true;auto r=discover(f,o);
    std::filesystem::path out(argv[2]);std::filesystem::create_directories(out);std::ofstream json;json.exceptions(std::ios::badbit|std::ios::failbit);json.open(out/"discovery.json",std::ios::binary);
    json<<"{\"schema\":"<<quote(schema)<<",\"implementation_sha256\":"<<quote(implementationIdentity())<<",\"source_fingerprint\":"<<quote(original)<<",\"source_blocks\":"<<f.block_count<<",\"source_unchanged\":"<<(sourceFingerprint(f)==original?"true":"false")<<",\"rewrites\":0,\"candidates\":[";
    unsigned index=0;
    for(const auto &c:r.candidates){if(index)json<<',';std::string stem="candidate-"+std::to_string(index++);
        writeChecked(out/(stem+".smt2"),c.proof.query);writeChecked(out/(stem+".solver"),c.proof.solver_output);
        json<<"{\"root\":"<<c.root<<",\"block\":"<<c.block<<",\"input\":"<<c.expression.input<<",\"input_type\":"<<quote(dolir_type_name(c.expression.input_type))<<",\"output_type\":"<<quote(dolir_type_name(c.expression.output_type))<<",\"power\":"<<c.expression.power<<",\"equivalence\":"<<quote(c.proof.status)<<",\"conditional_on_state_forwarding\":"<<(c.conditional_on_state_forwarding?"true":"false")<<",\"source_cut_sha256\":"<<quote(c.source_cut_fingerprint)<<",\"dag_sha256\":"<<quote(c.dag_fingerprint)<<",\"query_sha256\":"<<quote(c.proof.query_sha256)<<",\"solver_version\":"<<quote(c.proof.solver_version)<<",\"solver_library_sha256\":"<<quote(c.proof.solver_library_sha256)<<",\"implementation_sha256\":"<<quote(c.proof.implementation_sha256)<<",\"query\":"<<quote(stem+".smt2")<<",\"solver_output\":"<<quote(stem+".solver")<<",\"source_values\":[";
        bool comma=false;for(auto v:c.source_values){if(comma)json<<',';json<<v;comma=true;}json<<"],\"source_blocks\":[";comma=false;for(auto b:c.source_blocks){if(comma)json<<',';json<<b;comma=true;}json<<"],\"state_forwardings\":[";comma=false;for(auto [a,b]:c.reaching_state_forwardings){if(comma)json<<',';json<<'['<<a<<','<<b<<']';comma=true;}json<<"],\"reasons\":[";comma=false;for(auto &x:c.reasons){if(comma)json<<',';json<<quote(x);comma=true;}json<<"]}";
    }
    json<<"],\"reasons\":[";bool comma=false;for(auto &reason:r.reasons){if(comma)json<<',';json<<quote(reason);comma=true;}json<<"]}\n";
    json.close();
    if(sourceFingerprint(f)!=original)throw std::runtime_error("read-only discovery modified source");
    std::cout.exceptions(std::ios::badbit|std::ios::failbit);std::cout<<"candidates="<<r.candidates.size()<<" source_unchanged=true rewrites=0\n";std::cout.flush();dolir_module_free(&m);return 0;
}catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}}
