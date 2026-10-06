/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DOLRECOMP_EXPERIMENTAL_CLOCK_CONTRACT_H
#define DOLRECOMP_EXPERIMENTAL_CLOCK_CONTRACT_H
/* Experimental contracts only. No production CPU layout or timing ABI promise. */
#include <stdint.h>
#define FC_PROVIDER_ABI_VERSION 1u
#define FC_SYNTHETIC_CORE_ABI_VERSION 1u

typedef enum {
    FC_OK = 0, FC_YIELD = 1, FC_STOP_DEFERRED = 2, FC_STALE_HANDLE = 3,
    FC_ERR_FIXTURE = 10, FC_ERR_PROFILE, FC_ERR_STATE, FC_ERR_UNKNOWN_OPCODE,
    FC_ERR_UNITS_OVERFLOW, FC_ERR_RETIRED_OVERFLOW, FC_ERR_TRACE_CAPACITY,
    FC_ERR_QUEUE_CAPACITY, FC_ERR_SEQUENCE_OVERFLOW, FC_ERR_GENERATION_OVERFLOW,
    FC_ERR_DEADLINE, FC_ERR_UNSUPPORTED_PROGRAM, FC_ERR_UNSUPPORTED_EVENT,
    FC_ERR_BACKLOG, FC_ERR_REFUSED, FC_ERR_PARTIAL_EFFECT, FC_ERR_EXCEPTION,
    FC_ERR_PROVIDER
} FcResult;
/* A null pointer or versioned null/null provider preserves stored-TB behavior.
 * Status-returning callbacks must prevalidate before anchor/shadow/output mutation.
 * On FC_OK callbacks must write the complete 64-bit output. A refusal may record
 * terminal/error diagnostics, but must not commit timebase/anchor or other
 * architectural effects. The adapter cannot roll back arbitrary context changes.
 * CPU shadow is materialized only after FC_OK. The legality/policy gate is
 * separate. Context lifetime belongs to the caller; no no-alias promise is made. */
typedef FcResult (*FcProviderRead)(void *, uint32_t cia, uint32_t reg, uint64_t *);
typedef FcResult (*FcProviderWrite)(void *, uint32_t cia, uint32_t reg, uint32_t, uint64_t *);
typedef struct { uint32_t abi; void *context; FcProviderRead read_full; FcProviderWrite write_half; } FcProvider;
FcResult fc_provider_validate(const FcProvider *);
/* Small CPU-independent shadow adapter. Caller must perform original legality,
 * privilege and the separate PPCTimebaseAccess policy gate BEFORE these calls. */
FcResult fc_provider_read_shadow(const FcProvider *, uint64_t *shadow, uint32_t cia,
                                 uint32_t reg, uint32_t *value);
FcResult fc_provider_write_shadow(const FcProvider *, uint64_t *shadow, uint32_t cia,
                                  uint32_t reg, uint32_t value);
#endif
