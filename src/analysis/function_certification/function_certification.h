// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DOLRECOMP_FUNCTION_CERTIFICATION_V1_H
#define DOLRECOMP_FUNCTION_CERTIFICATION_V1_H
#include "ir/dolir.h"
#include "backend/llvm/llvm_backend.h"
#include <array>
#include <functional>
#include <string>
#include <vector>

namespace dolcert {
constexpr const char *Schema = "dolrecomp.function-certification.v1";
using StateMask = std::array<u64, DOLIR_STATE_MASK_WORDS>;
enum class Status { Closed, Conditional, Open };
enum class EvidenceGrade { Unproved, Conditional, Verified };
// Evidence is supplied by an independent verifier. A label is NOT a proof.
// All evidence must describe this exact source fingerprint and invocation.
struct Evidence {
  EvidenceGrade grade = EvidenceGrade::Unproved;
  std::string proof_id;
};
struct EvidenceRequest {
  std::string source_fingerprint, contract_fingerprint, obligation, proof_id;
  std::vector<u32> entry_blocks;
  std::string model="exact-original-cuts/full-state-observation";
  u32 address=0, value=0; // populated for immutable-word obligations
};
struct EvidenceRecord {
  EvidenceRequest request;
  EvidenceGrade supplied_grade=EvidenceGrade::Unproved;
  bool independently_verified=false;
};
struct ImmutableWord {
  u32 address = 0, value = 0;
  // Exact guest big-endian U32 contents, all aliases/writers excluded for the
  // entire invocation, and this read is plain/nonfaulting/nonobserving.
  Evidence lifetime_and_aliases;
  Evidence plain_read;
};
struct Contract {
  std::string source_fingerprint;
  // Trusted checker boundary. An absent/rejecting checker cannot yield CLOSED.
  // The checker must validate the actual obligation, not merely a proof label.
  std::function<bool(const EvidenceRequest &)> verify_evidence;
  std::vector<u32> entry_blocks{0};
  // Complete real entry population, stable code, no hidden interior entry.
  Evidence entries_and_code;
  // No unrepresented exception/resume entry or architectural state mutation.
  Evidence exception_resume;
  // Original cuts/costs/order retained, exact/current timing, full architectural
  // state observable; no observer mutation outside explicit IR services.
  Evidence observations;
  std::vector<ImmutableWord> immutable_words;
  u32 max_blocks = 4096, max_instructions = 1000000, max_values = 1000001;
  u64 max_block_value_product = 16000000;
  u32 max_iterations = 1000000, max_edges = 1000000;
};
struct Reason { std::string dimension, code; u32 block = DOLIR_NO_BLOCK; };
struct TypedEffects {
  StateMask state_may_read{}, state_may_write{};
  bool memory_read=false, memory_write=false, mmio=false, fifo=false;
  bool fault=false, partial_effect=false, exit=false, callback=false;
  bool returning_mutation=false, time=false, reservation=false;
  bool coherence=false, mode=false, exception_resume=false, opaque=false;
  bool host_bindings=false, precommit_refusal=false;
  bool returning_exception=false, terminal_partial_effect=false;
  // Complete conservative overapproximation, including TOP for unknown effects.
  bool sound_overapproximation=true;
};
struct Edge {
  u32 block=0, target_block=DOLIR_NO_BLOCK, target_address=0;
  std::string kind, target_provenance;
  Status certainty=Status::Open;
};
struct BlockReport {
  u32 index=0, address=0;
  bool reachable_from_declared_entries=false;
  std::string transfer_provenance;
  bool returns_incoming_lr=false;
  StateMask live_in{}, live_out{};
};
struct NativeABIPlan {
  bool eligible=false;
  // This pass emits no ABI, code or attributes. Eligibility is only a plan.
  StateMask semantic_live_in{}, may_live_out{}, preserve_or_materialize{};
  StateMask materialize_at_every_original_cut{};
  bool exact_original_cuts_required=true;
  bool termination_proved=false;
  bool guest_stack_elision_allowed=false;
  DolLLVMFunctionRange existing_analysis{}; // Advisory, never a certificate.
};
struct Certificate {
  std::string schema=Schema, source_fingerprint;
  std::string implementation_id, contract_fingerprint;
  Status status=Status::Open, entries=Status::Open, cfg=Status::Open;
  Status effects=Status::Open, returns=Status::Open, observations=Status::Open;
  bool valid_ir=false, analysis_complete=false;
  bool mutates_ir=false, prunes_code=false, changes_timing=false;
  std::vector<Reason> reasons;
  std::vector<std::string> accepted_evidence;
  std::vector<EvidenceRecord> evidence;
  std::string model="exact-original-cuts/full-state-observation";
  std::string scope="declared-region-under-checked-external-contract";
  std::vector<Edge> edges;
  std::vector<BlockReport> blocks;
  TypedEffects effect_summary;
  NativeABIPlan abi;
};
// Canonical field encoding, SHA256, excluding allocation capacity/pointers/name.
// Requires actual allocated DolIR arrays. Returns empty on structurally invalid
// or over-hard-limit input; semantic validity is established only by certify.
// Arbitrary invalid C/C++ pointers cannot be validated by this API.
std::string sourceFingerprint(const DolIRFunction &function);
std::string contractFingerprint(const Contract &contract);
Certificate certify(const DolIRFunction &function, const Contract &contract = {});
std::string toJson(const Certificate &certificate);
const char *statusName(Status status);
}
#endif
