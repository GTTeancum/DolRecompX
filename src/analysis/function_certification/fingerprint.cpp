// SPDX-License-Identifier: GPL-3.0-or-later
#include "function_certification.h"
#include "analysis/checked_serialization.h"
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <type_traits>
namespace dolcert {
namespace {template<class E> int64_t enumValue(const E &e){std::underlying_type_t<E> v;std::memcpy(&v,&e,sizeof v);return v;}}
std::string sourceFingerprint(const DolIRFunction &f) {
  if(!f.blocks || !f.value_types || !f.block_count || f.block_count>4096 || !f.value_count || f.value_count>1000001)return {};
  u64 instructions=0;for(u32 b=0;b<f.block_count;b++){const auto &x=f.blocks[b];instructions+=x.instruction_count;if(instructions>1000000 || (x.instruction_count && !x.instructions))return {};}
  std::vector<unsigned char> bytes;
  auto put = [&](u64 n) { for (u32 i=0;i<8;i++) bytes.push_back((n>>(8*i))&255); };
  put(1); put(f.guest_start); put(f.guest_end); put(f.block_count); put(f.value_count);
  for(u32 v=0;v<f.value_count;v++) put(enumValue(f.value_types[v]));
  for(u32 b=0;b<f.block_count;b++) {
    const auto &x=f.blocks[b]; put(x.guest_address);put(x.raw);put(x.cycle_cost);put(x.instruction_count);
    for(u32 k=0;k<x.instruction_count;k++) {
      const auto &i=x.instructions[k];put(enumValue(i.op));put(enumValue(i.type));put(i.result);put(i.operand_count);
      for(auto v:i.operands)put(v);
      put(i.aux);put(i.immediate);put(i.guest_pc);put(i.effects);
      for(auto v:i.state_uses)put(v);
      for(auto v:i.state_defs)put(v);
      put(enumValue(i.address_domain));put(i.address_lower);put(i.address_upper);put(i.exact_fp);
    }
    const auto &t=x.terminator;put(enumValue(t.kind));put(t.condition);put(t.target_value);
    for(auto v:t.targets)put(v);
    for(auto v:t.target_addresses)put(v);
    put(t.guest_pc);put(t.raw);put(t.linked);
  }
  return dolanalysis::sha256(bytes.data(),bytes.size());
}
std::string contractFingerprint(const Contract &c) {
  dolanalysis::CheckedOutput data;auto text=[&](const std::string &s){data<<s.size()<<':'<<s<<';';};
  auto ev=[&](const Evidence &e){data<<int(e.grade)<<';';text(e.proof_id);};
  text("dolcert-contract-v1/exact-original-cuts/full-state-observation");text(c.source_fingerprint);
  auto entries=c.entry_blocks;std::sort(entries.begin(),entries.end());entries.erase(std::unique(entries.begin(),entries.end()),entries.end());
  data<<entries.size()<<';';for(auto x:entries)data<<x<<';';
  data<<c.max_blocks<<';'<<c.max_instructions<<';'<<c.max_values<<';'<<c.max_block_value_product<<';'<<c.max_iterations<<';'<<c.max_edges<<';';
  ev(c.entries_and_code);ev(c.exception_resume);ev(c.observations);
  auto words=c.immutable_words;std::sort(words.begin(),words.end(),[](const ImmutableWord&a,const ImmutableWord&b){return a.address<b.address || (a.address==b.address && a.value<b.value);});
  data<<words.size()<<';';for(const auto&w:words){data<<w.address<<';'<<w.value<<';';ev(w.lifetime_and_aliases);ev(w.plain_read);}
  auto input=data.str();return dolanalysis::sha256(input.data(),input.size());
}

}
