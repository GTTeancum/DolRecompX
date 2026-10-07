// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DOLRECOMP_VERIFIED_IDIOMS_H
#define DOLRECOMP_VERIFIED_IDIOMS_H
#include "ir/dolir.h"
#include "function_certification.h"
#include <cstdint>
#include <string>
#include <vector>

namespace dolidiom {
inline constexpr const char *schema = "dolrecomp.verified-idiom.v1";
const char *implementationIdentity();
struct Options {
    bool enabled = false;
    unsigned max_nodes = 128;
    unsigned solver_timeout_ms = 10000;
    unsigned max_candidates = 256;
};
struct SRemPow2 {
    DolIRValue input = 0;
    DolIRType input_type = DOLIR_TYPE_VOID;
    DolIRType output_type = DOLIR_TYPE_VOID;
    unsigned power = 0;
};
struct Proof {
    std::string status, query, query_sha256, solver_output;
    std::string solver_version, solver_library_sha256, implementation_sha256;
};
struct Candidate {
    unsigned block = 0, instruction = 0;
    DolIRValue root = 0;
    SRemPow2 expression;
    std::vector<DolIRValue> source_values;
    std::vector<unsigned> source_blocks;
    std::vector<std::pair<DolIRValue,DolIRValue>> reaching_state_forwardings;
    bool conditional_on_state_forwarding = false;
    std::string source_fingerprint, source_cut_fingerprint, dag_fingerprint;
    std::string original_instruction;
    Proof proof;
    std::vector<std::string> reasons;
};
struct Report {
    std::vector<Candidate> candidates;
    std::vector<std::string> reasons;
};
// Every apply obtains a fresh FunctionCertificationv1 through its trusted checker.
struct RegionContract {
    std::string schema = "dolrecomp.validated-pure-region.v1";
    dolcert::Contract function;
    std::string source_cut_fingerprint;
    std::vector<DolIRValue> roots;
};
struct ApplyResult {
    bool changed = false;
    std::vector<std::string> reasons;
    std::string before_fingerprint, after_fingerprint;
    std::string function_contract_fingerprint, certification_implementation_id;
    Proof replay_proof;
};
std::string sourceFingerprint(const DolIRFunction &);
std::string sourceCutFingerprint(const DolIRFunction &);
std::string sha256(const std::string &);
std::string fileSha256(const std::string &);
Report discover(const DolIRFunction &, const Options & = {});
// Always reconstructs the source DAG and reruns the solver; never trusts a saved status.
Proof verify(const DolIRFunction &, const Candidate &, unsigned timeout_ms = 10000);
ApplyResult apply(DolIRFunction &, const Candidate &, const RegionContract &,
                  const Options & = {});
std::string emitRecoveredC(const SRemPow2 &, const std::string &name);
std::string emitRecoveredLLVM(const SRemPow2 &, const std::string &name);
}
#endif
