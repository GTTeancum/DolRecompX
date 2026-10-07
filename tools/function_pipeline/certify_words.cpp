// SPDX-License-Identifier: GPL-3.0-or-later
#include "function_certification.h"
#include "ir/dolir_builder.h"
#include <iostream>
#include <sstream>
#include <limits>
int main(){try{
  std::cin.exceptions(std::ios::badbit);std::cout.exceptions(std::ios::badbit|std::ios::failbit);
  std::string line;size_t number=0;
  while(std::getline(std::cin,line)){
    ++number;std::istringstream s(line);s.exceptions(std::ios::badbit);std::string token;std::vector<u32> words;bool valid=true;
    while(s>>token){try{size_t end=0;auto x=std::stoull(token,&end,16);if(end!=token.size()||x>UINT32_MAX)valid=false;else words.push_back(u32(x));}catch(const std::invalid_argument &){valid=false;}catch(const std::out_of_range &){valid=false;}}
    if(words.size()<2 || words.size()>4097 || (words[0]&3) || u64(words[0])+4*(words.size()-1)>UINT32_MAX)valid=false;
    if(!valid){std::cout<<"{\"schema\":\"dolrecomp.function-certification.v1\",\"line\":"<<number<<",\"status\":\"OPEN\",\"valid_ir\":false,\"error\":\"INVALID_INPUT\"}\n";continue;}
    std::vector<PPCInst> insts;u32 unknown=0;for(size_t n=1;n<words.size();n++){auto i=ppc_decode(words[n],words[0]+4*(n-1));unknown+=i.op==PPC_OP_UNKNOWN;insts.push_back(i);}
    DolIRModule module;dolir_module_init(&module);
    bool built=dolir_build_chunk(&module,insts.data(),insts.size(),words[0]);
    if(!built || !dolir_verify(&module,stderr))std::cout<<"{\"schema\":\"dolrecomp.function-certification.v1\",\"line\":"<<number<<",\"status\":\"OPEN\",\"valid_ir\":false,\"error\":\"BUILD_OR_VERIFY_FAILED\"}\n";
    else {auto json=dolcert::toJson(dolcert::certify(module.functions[0]));json.pop_back();std::cout<<json<<",\"input_line\":"<<number<<",\"unknown_decode_count\":"<<unknown<<'}'<<'\n';}
    dolir_module_free(&module);
  }
  std::cout.flush();return 0;
}catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}}
