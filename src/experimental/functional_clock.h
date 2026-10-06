/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DOLRECOMP_EXPERIMENTAL_FUNCTIONAL_CLOCK_H
#define DOLRECOMP_EXPERIMENTAL_FUNCTIONAL_CLOCK_H
/* Synthetic functional timing only. No CPU/device emulation or hardware latency claim. */
#include <stdint.h>
#include <stddef.h>
#include "cpu/functional_clock_costs.h"
#include "experimental/clock_contract.h"
#define FC_QUEUE_CAPACITY 32u
#define FC_TRACE_CAPACITY 512u
#define FC_BOUNDARY_SERVICE_LIMIT 64u
#define FC_DOMAIN_SYNTHETIC 1u
#define FC_DOMAIN_DEC 2u
#define FC_DOMAIN_SI 4u
#define FC_DOMAIN_VI 8u
#define FC_DOMAIN_DSP 16u
#define FC_DOMAIN_AI 32u
#define FC_DOMAIN_GPU 64u
#define FC_DOMAIN_IRQ 128u
#define FC_DOMAIN_IPC 256u
#define FC_DOMAIN_ALL 511u

typedef enum { FC_EVENT_MARK = 1, FC_EVENT_CHAIN = 2, FC_EVENT_UNSUPPORTED = 3 } FcEventKind;
typedef enum { FC_TRACE_BEGIN = 1, FC_TRACE_RETIRE, FC_TRACE_READ,
    FC_TRACE_WRITE, FC_TRACE_EVENT } FcTraceKind;
typedef struct { uint32_t id, generation; } FcEventHandle;
typedef struct {
    uint64_t deadline, period;
    uint32_t id, domain, kind, payload, chain_remaining;
} FcEventSpec;
typedef struct {
    FcEventSpec spec;
    uint64_t sequence;
    uint32_t generation, pending;
} FcEvent;
typedef struct {
    uint64_t units, retired, tb, old_tb, anchor_units, anchor_tb, deadline, lateness;
    uint32_t kind, cia, raw, reg, value, phase, event_id, generation, payload;
} FcTrace;
typedef struct {
    uint32_t core_abi, abi, synthetic_only, declared_domains, active_domains, entry_pc;
    const char *model_id, *cost_sha256;
    uint64_t initial_tb;
    uint32_t initial_phase;
    const FcEventSpec *events;
    size_t event_count;
} FcFixture;
typedef struct {
    uint64_t completed_units, retired_instructions, anchor_units, anchor_tb;
    uint64_t slice_remaining, next_sequence;
    uint32_t anchor_phase, pc, active_cia, active_raw, active_cost;
    uint32_t instruction_active, initialized, terminal, settling;
    uint32_t deferred_reason, failure_cia, failure_raw, failure_cost, failure_access;
    uint32_t partial_effect, active_domains, queue_count, trace_count;
    FcResult result;
    FcEvent events[FC_QUEUE_CAPACITY];
    FcTrace trace[FC_TRACE_CAPACITY];
} FcClock;

/* A fixture must declare every domain; each active domain needs a known deadline.
 * Real device events are fixture-only unsupported sentinels. No fake completion. */
FcResult fc_init(FcClock *, const FcFixture *);
FcResult fc_boundary(FcClock *);
FcResult fc_slice(FcClock *, uint64_t instruction_budget);
FcResult fc_begin(FcClock *, uint32_t cia, uint32_t raw, unsigned opcode, uint32_t abi);
FcResult fc_retire(FcClock *, uint32_t next_pc);
FcResult fc_abort(FcClock *, FcResult reason, uint32_t access_index, uint32_t partial_effect);
FcResult fc_defer_stop(FcClock *, uint32_t reason);
/* Pure checked observation: TB wraps modulo 2^64; elapsed units never do. */
FcResult fc_tb_at(uint64_t units, uint64_t anchor_units, uint64_t anchor_tb,
                  uint32_t phase, uint64_t *tb);
FcResult fc_peek(const FcClock *, uint64_t *tb);
/* Call only after the CPU's existing legality/privilege and policy checks. */
FcResult fc_read_full(FcClock *, uint32_t cia, uint32_t read_reg, uint64_t *tb);
FcResult fc_write_half(FcClock *, uint32_t cia, uint32_t write_reg, uint32_t value, uint64_t *tb);
FcResult fc_schedule(FcClock *, const FcEventSpec *, FcEventHandle *);
FcResult fc_cancel(FcClock *, FcEventHandle);
FcResult fc_replace(FcClock *, FcEventHandle, const FcEventSpec *, FcEventHandle *);
FcResult fc_deadline_after(FcClock *, uint64_t delay, uint64_t *deadline);

/* Adapter supplied by this bounded implementation; contract users need not link it. */
FcProvider fc_provider(FcClock *);
#endif
