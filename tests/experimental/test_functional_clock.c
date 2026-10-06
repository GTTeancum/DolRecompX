/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "experimental/functional_clock.h"
#ifndef FC_FREESTANDING
#include <stdio.h>
#endif
#define OP_ADDI 3u
#define OP_ORI 9u
#define OP_STWU 20u
#define OP_MTSPR 49u
#define OP_MFTB 50u
#define OP_DIVW 211u
#define OP_ICBI 222u
static unsigned checks;
static uint64_t digest = UINT64_C(1469598103934665603);
static FcClock a, b, saved;
#define CHECK(x) do { ++checks; if (!(x)) return __LINE__; } while (0)
static void hash64(uint64_t x) { unsigned i; for(i=0;i<8;++i) { digest ^= (unsigned char)x; digest *= UINT64_C(1099511628211); x >>= 8; } }
static int equal_bytes(const void *ap, const void *bp, size_t n) {
    const unsigned char *p=ap,*q=bp; while(n--) if(*p++!=*q++) return 0; return 1;
}
static FcFixture fixture(uint64_t tb, uint32_t phase, const FcEventSpec *events, size_t n, uint32_t active) {
    FcFixture f; f.core_abi=FC_SYNTHETIC_CORE_ABI_VERSION; f.abi=FC_TIMING_ABI_VERSION; f.synthetic_only=1;
    f.declared_domains=FC_DOMAIN_ALL; f.active_domains=active; f.entry_pc=0x80001000;
    f.model_id=FC_MODEL_ID; f.cost_sha256=FC_COST_MANIFEST_SHA256;
    f.initial_tb=tb; f.initial_phase=phase; f.events=events; f.event_count=n; return f;
}
static FcResult start(FcClock *s, uint64_t tb, uint32_t phase) {
    FcFixture f=fixture(tb,phase,0,0,0); return fc_init(s,&f);
}
static FcResult step(FcClock *s, unsigned op) {
    FcResult r=fc_begin(s,s->pc,0,op,FC_TIMING_ABI_VERSION);
    if(r!=FC_OK) return r;
    return fc_retire(s,s->pc+4);
}
static int test_arithmetic(void) {
    uint64_t out=123; uint32_t phase; unsigned i;
    const uint64_t points[]={0,11,12,13}; const uint64_t expected[]={0,0,1,1};
    for(i=0;i<4;++i) { CHECK(fc_tb_at(points[i],0,0,0,&out)==FC_OK); CHECK(out==expected[i]); }
    for(phase=0;phase<12;++phase) for(i=0;i<48;++i) {
        CHECK(fc_tb_at(i,0,7,phase,&out)==FC_OK); CHECK(out==7+(i+phase)/12);
    }
    CHECK(fc_tb_at(UINT64_MAX,0,0,11,&out)==FC_OK);
    CHECK(out==UINT64_C(1537228672809129302));
    CHECK(fc_tb_at(12,0,UINT64_MAX,0,&out)==FC_OK); CHECK(out==0);
    out=456; CHECK(fc_tb_at(10,11,0,0,&out)==FC_ERR_STATE); CHECK(out==456);
    CHECK(fc_tb_at(0,0,0,12,&out)==FC_ERR_STATE); CHECK(out==456);
    CHECK(start(&a,UINT64_MAX,11)==FC_OK); CHECK(step(&a,OP_ADDI)==FC_OK);
    CHECK(fc_peek(&a,&out)==FC_OK && out==0); CHECK(a.completed_units==1); hash64(out);
    return 0;
}
static int test_retirement(void) {
    uint64_t out; uint32_t before;
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_slice(&a,1)==FC_OK);
    CHECK(fc_begin(&a,a.pc,0x7c0003d6,OP_DIVW,1)==FC_OK); CHECK(a.active_cost==40);
    CHECK(fc_peek(&a,&out)==FC_OK && out==0); CHECK(fc_peek(&a,&out)==FC_OK && out==0);
    CHECK(a.completed_units==0 && a.retired_instructions==0);
    CHECK(fc_retire(&a,0x80001004)==FC_YIELD); CHECK(a.completed_units==40 && a.retired_instructions==1);
    before=a.trace_count; CHECK(fc_begin(&a,a.pc,0,OP_ADDI,1)==FC_YIELD);
    CHECK(a.trace_count==before && !a.instruction_active && a.completed_units==40);
    CHECK(fc_slice(&a,1)==FC_OK); CHECK(step(&a,OP_ORI)==FC_YIELD); CHECK(a.completed_units==41);
    CHECK(fc_retire(&a,a.pc+4)==FC_ERR_STATE); CHECK(a.completed_units==41 && a.retired_instructions==2);
    CHECK(fc_slice(&a,1)==FC_ERR_STATE);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,9,OP_ADDI,1)==FC_OK);
    CHECK(fc_begin(&a,a.pc,10,OP_ADDI,1)==FC_ERR_STATE); CHECK(a.failure_raw==9 && a.completed_units==0);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,0,0,1)==FC_ERR_UNKNOWN_OPCODE);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,0,237,1)==FC_ERR_UNKNOWN_OPCODE);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,0,OP_ADDI,2)==FC_ERR_PROFILE);
    CHECK(start(&a,0,0)==FC_OK); a.completed_units=UINT64_MAX-3;
    CHECK(step(&a,OP_ICBI)==FC_ERR_UNITS_OVERFLOW); CHECK(a.completed_units==UINT64_MAX-3 && !a.instruction_active);
    CHECK(start(&a,0,0)==FC_OK); a.retired_instructions=UINT64_MAX;
    CHECK(step(&a,OP_ADDI)==FC_ERR_RETIRED_OVERFLOW && a.completed_units==0);
    CHECK(start(&a,0,0)==FC_OK); a.completed_units=UINT64_MAX-1;
    CHECK(step(&a,OP_ADDI)==FC_OK && a.completed_units==UINT64_MAX);
    CHECK(step(&a,OP_ADDI)==FC_ERR_UNITS_OVERFLOW);
    CHECK(start(&a,0,0)==FC_OK); a.trace_count=FC_TRACE_CAPACITY-1;
    CHECK(step(&a,OP_ADDI)==FC_ERR_TRACE_CAPACITY && a.completed_units==0);
    CHECK(start(&a,0,0)==FC_OK); CHECK(step(&a,OP_ICBI)==FC_OK && a.completed_units==4);
    hash64(a.completed_units); return 0;
}
static int test_stop_phases(void) {
    uint32_t memory=55, ra=77; uint64_t out=99;
    CHECK(start(&a,0,0)==FC_OK); CHECK(step(&a,OP_ADDI)==FC_OK);
    CHECK(fc_begin(&a,a.pc,0x12345678,OP_STWU,1)==FC_OK);
    CHECK(fc_abort(&a,FC_ERR_REFUSED,0,0)==FC_ERR_REFUSED);
    CHECK(memory==55 && ra==77 && a.completed_units==1 && a.retired_instructions==1);
    CHECK(a.failure_raw==0x12345678 && a.failure_cost==1 && !a.instruction_active);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,1,OP_STWU,1)==FC_OK);
    memory=123; CHECK(fc_defer_stop(&a,42)==FC_OK); ra=88;
    CHECK(fc_retire(&a,a.pc+4)==FC_STOP_DEFERRED);
    CHECK(memory==123 && ra==88 && a.completed_units==1 && a.retired_instructions==1 && a.deferred_reason==42);
    CHECK(fc_read_full(&a,a.pc,268,&out)==FC_STOP_DEFERRED && out==99);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,2,OP_STWU,1)==FC_OK);
    memory=456; CHECK(fc_abort(&a,FC_ERR_REFUSED,2,1)==FC_ERR_PARTIAL_EFFECT);
    CHECK(memory==456 && a.completed_units==0 && a.partial_effect && a.failure_access==2);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,3,OP_ADDI,1)==FC_OK);
    CHECK(fc_abort(&a,FC_ERR_EXCEPTION,0,0)==FC_ERR_EXCEPTION && a.completed_units==0);
    CHECK(start(&a,0,0)==FC_OK); CHECK(fc_begin(&a,a.pc,4,OP_ADDI,1)==FC_OK);
    CHECK(fc_abort(&a,FC_ERR_PARTIAL_EFFECT,1,0)==FC_ERR_PARTIAL_EFFECT && a.partial_effect==1);
    return 0;
}
static int read_half(FcClock *s, uint32_t reg, uint32_t *out) {
    uint64_t full; FcResult r=fc_begin(s,s->pc,0,OP_MFTB,1); if(r!=FC_OK) return 0;
    if(fc_read_full(s,s->pc,reg,&full)!=FC_OK) return 0;
    *out=reg==268?(uint32_t)full:(uint32_t)(full>>32);
    return fc_retire(s,s->pc+4)==FC_OK;
}
static int test_provider(void) {
    uint64_t full=11, other; uint32_t hi1,lo,hi2,reads,pc;
    FcProvider p, half={0}; half.abi=FC_PROVIDER_ABI_VERSION;
    CHECK(start(&a,UINT64_C(0xffffffff),11)==FC_OK);
    reads=0; do { CHECK(read_half(&a,269,&hi1)); CHECK(read_half(&a,268,&lo)); CHECK(read_half(&a,269,&hi2)); ++reads; } while(hi1!=hi2);
    CHECK(reads==2 && hi2==1 && lo==0); CHECK(a.retired_instructions==6 && a.completed_units==6);
    CHECK(start(&a,UINT64_C(0xffffffff),0)==FC_OK); CHECK(step(&a,OP_DIVW)==FC_OK);
    CHECK(fc_begin(&a,a.pc,0,OP_MTSPR,1)==FC_OK); pc=a.pc;
    p=fc_provider(&a); CHECK(fc_provider_validate(&p)==FC_OK);
    CHECK(p.write_half(p.context,pc,284,0xabcdef12,&full)==FC_OK);
    CHECK(full==UINT64_C(0x1abcdef12) && a.anchor_units==40 && a.anchor_phase==0);
    CHECK(a.trace[a.trace_count-1].kind==FC_TRACE_WRITE && a.trace[a.trace_count-1].old_tb==UINT64_C(0x100000002));
    CHECK(p.read_full(p.context,pc,268,&other)==FC_OK && other==full);
    CHECK(a.completed_units==40); CHECK(fc_retire(&a,pc+4)==FC_OK);
    CHECK(step(&a,OP_DIVW)==FC_OK); CHECK(fc_peek(&a,&other)==FC_OK);
    CHECK(fc_begin(&a,a.pc,0,OP_MTSPR,1)==FC_OK);
    CHECK(p.write_half(p.context,a.pc,285,0x12345678,&full)==FC_OK);
    CHECK(full==(UINT64_C(0x1234567800000000)|(uint32_t)other));
    CHECK(a.anchor_phase==0 && a.anchor_units==a.completed_units);
    CHECK(fc_retire(&a,a.pc+4)==FC_OK);
    CHECK(fc_provider_validate(0)==FC_OK && fc_provider_validate(&half)==FC_OK);
    half=p; half.write_half=0; CHECK(fc_provider_validate(&half)==FC_ERR_PROVIDER);
    half=p; half.read_full=0; CHECK(fc_provider_validate(&half)==FC_ERR_PROVIDER);
    half=p; half.context=0; CHECK(fc_provider_validate(&half)==FC_ERR_PROVIDER);
    CHECK(start(&a,8,11)==FC_OK); CHECK(fc_begin(&a,a.pc,0,OP_MTSPR,1)==FC_OK);
    a.trace_count=FC_TRACE_CAPACITY-1; full=123;
    CHECK(fc_write_half(&a,a.pc,284,55,&full)==FC_ERR_TRACE_CAPACITY);
    CHECK(full==123 && a.anchor_tb==8 && a.anchor_phase==11 && a.completed_units==0);
    CHECK(start(&a,8,11)==FC_OK); CHECK(fc_begin(&a,a.pc,0,OP_MTSPR,1)==FC_OK);
    CHECK(fc_write_half(&a,a.pc,268,55,&full)==FC_ERR_PROVIDER && a.anchor_tb==8);
    CHECK(start(&a,8,11)==FC_OK); full=123;
    CHECK(fc_read_full(&a,a.pc,268,&full)==FC_ERR_STATE && full==123);
    hash64(full); return 0;
}
/* Contract-only CPU shim: does not assert or replace actual CPU opcode legality. */
static unsigned policy_calls, provider_calls;
static FcResult rejecting_read(void *ctx, uint32_t cia, uint32_t reg, uint64_t *out) {
    (void)ctx; (void)cia; (void)reg; (void)out; ++provider_calls; return FC_ERR_REFUSED;
}
static FcResult rejecting_write(void *ctx, uint32_t cia, uint32_t reg, uint32_t val, uint64_t *out) {
    (void)ctx; (void)cia; (void)reg; (void)val; (void)out; ++provider_calls; return FC_ERR_REFUSED;
}
static FcResult gated_read(const FcProvider *p, uint64_t *shadow, int legal, int policy_reject, uint32_t *gpr) {
    if(!legal) return FC_ERR_EXCEPTION;
    ++policy_calls; if(policy_reject) return FC_ERR_REFUSED;
    return fc_provider_read_shadow(p,shadow,0x80001000,268,gpr);
}
static int test_shadow_adapter(void) {
    uint64_t shadow=UINT64_C(0x12345678abcdef01); uint32_t gpr=77;
    FcProvider p={FC_PROVIDER_ABI_VERSION,&a,rejecting_read,rejecting_write}, half=p;
    CHECK(fc_provider_read_shadow(0,&shadow,1,268,&gpr)==FC_OK && gpr==0xabcdef01);
    CHECK(fc_provider_read_shadow(0,&shadow,1,269,&gpr)==FC_OK && gpr==0x12345678);
    CHECK(fc_provider_write_shadow(0,&shadow,1,284,0xffeeddcc)==FC_OK && shadow==UINT64_C(0x12345678ffeeddcc));
    CHECK(fc_provider_write_shadow(0,&shadow,1,285,0x99887766)==FC_OK && shadow==UINT64_C(0x99887766ffeeddcc));
    gpr=77; policy_calls=provider_calls=0;
    CHECK(gated_read(&p,&shadow,0,1,&gpr)==FC_ERR_EXCEPTION);
    CHECK(policy_calls==0 && provider_calls==0 && gpr==77);
    CHECK(gated_read(&p,&shadow,1,1,&gpr)==FC_ERR_REFUSED);
    CHECK(policy_calls==1 && provider_calls==0 && gpr==77);
    CHECK(gated_read(&p,&shadow,1,0,&gpr)==FC_ERR_REFUSED);
    CHECK(policy_calls==2 && provider_calls==1 && gpr==77 && shadow==UINT64_C(0x99887766ffeeddcc));
    CHECK(fc_provider_write_shadow(&p,&shadow,1,284,12)==FC_ERR_REFUSED && shadow==UINT64_C(0x99887766ffeeddcc));
    half.write_half=0; CHECK(fc_provider_read_shadow(&half,&shadow,1,268,&gpr)==FC_ERR_PROVIDER && gpr==77);
    CHECK(start(&a,UINT64_C(0xffffffff),11)==FC_OK); p=fc_provider(&a); shadow=0;
    CHECK(fc_begin(&a,a.pc,0,OP_MFTB,1)==FC_OK);
    CHECK(fc_provider_read_shadow(&p,&shadow,a.pc,268,&gpr)==FC_OK && shadow==UINT64_C(0xffffffff));
    CHECK(fc_retire(&a,a.pc+4)==FC_OK); CHECK(fc_begin(&a,a.pc,0,OP_MTSPR,1)==FC_OK);
    CHECK(fc_provider_write_shadow(&p,&shadow,a.pc,284,42)==FC_OK && shadow==UINT64_C(0x10000002a));
    CHECK(fc_retire(&a,a.pc+4)==FC_OK); return 0;
}
static int test_fixture(void) {
    FcFixture f=fixture(0,0,0,0,0); FcEventSpec event={100,0,1,FC_DOMAIN_SI,FC_EVENT_UNSUPPORTED,99,0};
    CHECK(start(&a,99,3)==FC_OK); saved=a;
    f.core_abi=0; CHECK(fc_init(&a,&f)==FC_ERR_PROFILE && equal_bytes(&a,&saved,sizeof(a)));
    f.core_abi=FC_SYNTHETIC_CORE_ABI_VERSION;
    f.synthetic_only=2; CHECK(fc_init(&a,&f)==FC_ERR_FIXTURE && equal_bytes(&a,&saved,sizeof(a)));
    f.synthetic_only=0; CHECK(fc_init(&a,&f)==FC_ERR_FIXTURE && equal_bytes(&a,&saved,sizeof(a)));
    f.synthetic_only=1; f.initial_phase=12; CHECK(fc_init(&a,&f)==FC_ERR_FIXTURE);
    f.initial_phase=0; f.model_id="wrong"; CHECK(fc_init(&a,&f)==FC_ERR_PROFILE);
    f.model_id=FC_MODEL_ID; f.cost_sha256="wrong"; CHECK(fc_init(&a,&f)==FC_ERR_PROFILE);
    f.cost_sha256=FC_COST_MANIFEST_SHA256; f.declared_domains^=FC_DOMAIN_DEC; CHECK(fc_init(&a,&f)==FC_ERR_FIXTURE);
    f.declared_domains=FC_DOMAIN_ALL; f.active_domains=FC_DOMAIN_DEC; CHECK(fc_init(&a,&f)==FC_ERR_FIXTURE);
    f.events=&event; f.event_count=1; CHECK(fc_init(&a,&f)==FC_ERR_FIXTURE);
    f.active_domains=FC_DOMAIN_SI; CHECK(fc_init(&a,&f)==FC_OK);
    CHECK(a.events[0].pending && !a.terminal);
    CHECK(fc_cancel(&a,(FcEventHandle){1,1})==FC_ERR_UNSUPPORTED_PROGRAM && a.events[0].pending);
    CHECK(fc_init(&a,&f)==FC_OK); event.kind=FC_EVENT_MARK; event.domain=FC_DOMAIN_SYNTHETIC;
    CHECK(fc_replace(&a,(FcEventHandle){1,1},&event,0)==FC_ERR_UNSUPPORTED_PROGRAM && a.events[0].pending);
    return 0;
}
static int test_null_state(void) {
    uint64_t out=77;
    FcEventHandle handle={0,0};
    CHECK(fc_boundary(0)==FC_ERR_STATE);
    CHECK(fc_slice(0,1)==FC_ERR_STATE);
    CHECK(fc_begin(0,0,0,OP_ADDI,FC_TIMING_ABI_VERSION)==FC_ERR_STATE);
    CHECK(fc_retire(0,0)==FC_ERR_STATE);
    CHECK(fc_abort(0,FC_ERR_REFUSED,0,0)==FC_ERR_STATE);
    CHECK(fc_defer_stop(0,1)==FC_ERR_STATE);
    CHECK(fc_peek(0,&out)==FC_ERR_STATE && out==77);
    CHECK(fc_read_full(0,0,268,&out)==FC_ERR_STATE && out==77);
    CHECK(fc_write_half(0,0,284,1,&out)==FC_ERR_STATE && out==77);
    CHECK(fc_schedule(0,0,0)==FC_ERR_STATE);
    CHECK(fc_cancel(0,handle)==FC_ERR_STATE);
    CHECK(fc_replace(0,handle,0,0)==FC_ERR_STATE);
    CHECK(fc_deadline_after(0,1,&out)==FC_ERR_STATE && out==77);
    return 0;
}
static int event_init(FcClock *s, FcEventSpec *es, size_t n, uint32_t active) {
    FcFixture f=fixture(0,0,es,n,active); return fc_init(s,&f)==FC_OK;
}
static int test_events(void) {
    FcEventSpec es[FC_QUEUE_CAPACITY], e; FcEventHandle h,h2; unsigned i, n; uint64_t deadline=123;
    es[0]=(FcEventSpec){7,0,3,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,33,0};
    es[1]=(FcEventSpec){7,0,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,11,0};
    es[2]=(FcEventSpec){40,0,2,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,22,0};
    CHECK(event_init(&a,es,3,FC_DOMAIN_SYNTHETIC)); CHECK(step(&a,OP_DIVW)==FC_OK);
    CHECK(a.completed_units==40 && a.queue_count==0 && a.trace_count==5);
    CHECK(a.trace[2].event_id==3 && a.trace[3].event_id==1 && a.trace[4].event_id==2);
    CHECK(a.trace[2].deadline==7 && a.trace[2].lateness==33 && a.trace[2].units==40);
    es[0]=(FcEventSpec){0,0,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,1,0};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); CHECK(fc_slice(&a,0)==FC_YIELD);
    CHECK(a.trace_count==1 && a.trace[0].kind==FC_TRACE_EVENT && !a.queue_count && a.completed_units==0);
    es[0]=(FcEventSpec){7,7,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,1,0};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); CHECK(step(&a,OP_DIVW)==FC_OK);
    CHECK(a.trace_count==7 && a.events[0].spec.deadline==42);
    for(i=0;i<5;++i) CHECK(a.trace[i+2].deadline==7*(i+1) && a.trace[i+2].lateness==40-7*(i+1));
    es[0]=(FcEventSpec){0,0,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_CHAIN,1,FC_BOUNDARY_SERVICE_LIMIT+1};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); CHECK(fc_boundary(&a)==FC_ERR_BACKLOG);
    CHECK(a.trace_count==FC_BOUNDARY_SERVICE_LIMIT && a.events[0].pending && a.completed_units==0);
    es[0]=(FcEventSpec){7,0,1,FC_DOMAIN_SI,FC_EVENT_UNSUPPORTED,0,0};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SI)); CHECK(step(&a,OP_DIVW)==FC_ERR_UNSUPPORTED_EVENT);
    CHECK(a.completed_units==40 && a.retired_instructions==1 && a.events[0].pending && a.queue_count==1);
    CHECK(fc_begin(&a,a.pc,0,OP_ADDI,1)==FC_ERR_UNSUPPORTED_EVENT);
    es[1]=(FcEventSpec){8,0,2,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,123,0};
    es[2]=(FcEventSpec){7,0,3,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,456,0};
    CHECK(event_init(&a,es,3,FC_DOMAIN_SI|FC_DOMAIN_SYNTHETIC));
    CHECK(step(&a,OP_DIVW)==FC_ERR_UNSUPPORTED_EVENT && a.queue_count==1 && a.events[0].pending);
    CHECK(a.trace_count==4 && a.trace[2].event_id==3 && a.trace[3].event_id==2);
    es[0].deadline=0; CHECK(event_init(&a,es,1,FC_DOMAIN_SI)); CHECK(step(&a,OP_DIVW)==FC_ERR_UNSUPPORTED_EVENT);
    CHECK(a.completed_units==0 && a.retired_instructions==0);
    es[0]=(FcEventSpec){100,0,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,1,0};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); h=(FcEventHandle){1,1};
    e=es[0]; e.deadline=9; CHECK(fc_replace(&a,h,&e,&h2)==FC_OK && h2.generation==2);
    CHECK(fc_cancel(&a,h)==FC_STALE_HANDLE && a.events[0].spec.deadline==9);
    CHECK(fc_cancel(&a,h2)==FC_OK && !a.queue_count);
    CHECK(fc_cancel(&a,h2)==FC_STALE_HANDLE);
    e.deadline=0; CHECK(fc_schedule(&a,&e,&h)==FC_OK && h.generation==4);
    CHECK(fc_boundary(&a)==FC_OK && a.trace_count==1);
    CHECK(fc_cancel(&a,h)==FC_STALE_HANDLE);
    CHECK(fc_schedule(&a,&e,&h)==FC_OK && h.generation==5);
    for(i=0;i<FC_QUEUE_CAPACITY;++i) es[i]=(FcEventSpec){100+i,0,i+1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,i,0};
    CHECK(event_init(&a,es,FC_QUEUE_CAPACITY,FC_DOMAIN_SYNTHETIC)); saved=a;
    CHECK(fc_schedule(&a,&es[0],&h)==FC_ERR_QUEUE_CAPACITY);
    CHECK(a.queue_count==FC_QUEUE_CAPACITY && equal_bytes(a.events,saved.events,sizeof(a.events)) && a.next_sequence==saved.next_sequence);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.next_sequence=UINT64_MAX;
    e=es[1]; CHECK(fc_schedule(&a,&e,&h)==FC_ERR_SEQUENCE_OVERFLOW && !a.events[1].pending);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.events[1].generation=UINT32_MAX;
    CHECK(fc_schedule(&a,&e,&h)==FC_ERR_GENERATION_OVERFLOW && !a.events[1].pending);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); h=(FcEventHandle){1,1}; e=es[0]; e.period=UINT64_MAX;
    CHECK(fc_replace(&a,h,&e,&h2)==FC_ERR_DEADLINE && a.events[0].generation==1 && a.events[0].spec.deadline==100);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.completed_units=UINT64_MAX;
    CHECK(fc_deadline_after(&a,1,&deadline)==FC_ERR_DEADLINE && deadline==123);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); e=es[1]; e.kind=FC_EVENT_UNSUPPORTED; e.domain=FC_DOMAIN_SI;
    CHECK(fc_schedule(&a,&e,&h)==FC_ERR_UNSUPPORTED_PROGRAM && !a.events[1].pending);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); CHECK(step(&a,OP_ADDI)==FC_OK); e=es[1]; e.deadline=0;
    CHECK(fc_schedule(&a,&e,&h)==FC_ERR_DEADLINE && !a.events[1].pending);
    /* Deferred successful stop still settles due events after full retirement. */
    es[0].deadline=1; CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC));
    CHECK(fc_begin(&a,a.pc,0,OP_ADDI,1)==FC_OK); CHECK(fc_defer_stop(&a,1)==FC_OK);
    CHECK(fc_retire(&a,a.pc+4)==FC_STOP_DEFERRED && a.trace[2].kind==FC_TRACE_EVENT && a.completed_units==1);
    /* Periodic deadline overflow preserves the due event and has no service trace. */
    es[0]=(FcEventSpec){UINT64_MAX-1,1,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,1,0};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.completed_units=UINT64_MAX;
    CHECK(fc_boundary(&a)==FC_ERR_DEADLINE && a.trace_count==1 && a.events[0].spec.deadline==UINT64_MAX);
    /* Trace exhaustion refuses an event before its synthetic effect. */
    es[0].deadline=0; es[0].period=0; CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.trace_count=FC_TRACE_CAPACITY;
    CHECK(fc_boundary(&a)==FC_ERR_TRACE_CAPACITY && a.events[0].pending);
    es[0]=(FcEventSpec){100,0,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,1,0};
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.events[0].generation=UINT32_MAX;
    h=(FcEventHandle){1,UINT32_MAX};
    CHECK(fc_cancel(&a,h)==FC_ERR_GENERATION_OVERFLOW && a.events[0].pending && a.events[0].generation==UINT32_MAX);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.events[0].generation=UINT32_MAX; h2=(FcEventHandle){17,18};
    CHECK(fc_replace(&a,h,&es[0],&h2)==FC_ERR_GENERATION_OVERFLOW);
    CHECK(h2.id==17 && h2.generation==18 && a.events[0].spec.deadline==100);
    es[0].deadline=0; es[0].period=1;
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.next_sequence=UINT64_MAX;
    CHECK(fc_boundary(&a)==FC_ERR_SEQUENCE_OVERFLOW && a.trace_count==0 && a.events[0].spec.deadline==0);
    CHECK(event_init(&a,es,1,FC_DOMAIN_SYNTHETIC)); a.events[0].generation=UINT32_MAX;
    CHECK(fc_boundary(&a)==FC_ERR_GENERATION_OVERFLOW && a.trace_count==0 && a.events[0].spec.deadline==0);
    n=a.trace_count; hash64(n); return 0;
}
static int scenario(FcClock *s, uint64_t budget) {
    FcEventSpec es[3]={{7,0,1,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,33,0},
        {40,0,2,FC_DOMAIN_SYNTHETIC,FC_EVENT_MARK,44,0},
        {1000,0,3,FC_DOMAIN_SI,FC_EVENT_UNSUPPORTED,0,0}};
    unsigned i; uint64_t out; FcResult r;
    CHECK(event_init(s,es,3,FC_DOMAIN_SYNTHETIC|FC_DOMAIN_SI)); CHECK(fc_slice(s,budget)==FC_OK);
    for(i=0;i<30;++i) {
        unsigned opcode=i%3==0?OP_DIVW:OP_ICBI;
        if(i==7 || i==23) opcode=OP_MTSPR;
        r=fc_begin(s,s->pc,i,opcode,1);
        if(r==FC_YIELD) { CHECK(fc_slice(s,budget)==FC_OK); r=fc_begin(s,s->pc,i,opcode,1); }
        CHECK(r==FC_OK);
        if(i==7 || i==23) CHECK(fc_write_half(s,s->pc,i==7?284:285,i*19,&out)==FC_OK);
        else CHECK(fc_read_full(s,s->pc,268,&out)==FC_OK);
        r=fc_retire(s,s->pc+4); CHECK(r==FC_OK || r==FC_YIELD);
    }
    CHECK(fc_boundary(s)==FC_OK); s->slice_remaining=0; s->result=FC_OK;
    return 0;
}
static void hash_clock(const FcClock *s) {
    unsigned i;
#define H(x) hash64(s->x)
    H(completed_units); H(retired_instructions); H(anchor_units); H(anchor_tb);
    H(slice_remaining); H(next_sequence); H(anchor_phase); H(pc); H(active_cia); H(active_raw);
    H(active_cost); H(instruction_active); H(initialized); H(terminal); H(settling); H(deferred_reason);
    H(failure_cia); H(failure_raw); H(failure_cost); H(failure_access); H(partial_effect);
    H(active_domains); H(queue_count); H(trace_count); H(result);
#undef H
    for(i=0;i<FC_QUEUE_CAPACITY;++i) {
        const FcEvent *e=&s->events[i];
#define H(x) hash64(e->x)
        H(spec.deadline); H(spec.period); H(spec.id); H(spec.domain); H(spec.kind);
        H(spec.payload); H(spec.chain_remaining); H(sequence); H(generation); H(pending);
#undef H
    }
    for(i=0;i<s->trace_count;++i) {
        const FcTrace *t=&s->trace[i];
#define H(x) hash64(t->x)
        H(units); H(retired); H(tb); H(old_tb); H(anchor_units); H(anchor_tb); H(deadline); H(lateness);
        H(kind); H(cia); H(raw); H(reg); H(value); H(phase); H(event_id); H(generation); H(payload);
#undef H
    }
}
static int test_dirty_padding(void) {
    FcEventSpec x,y; unsigned char *xp=(unsigned char *)&x,*yp=(unsigned char *)&y; size_t i;
    for(i=0;i<sizeof(x);++i) { xp[i]=0xaa; yp[i]=0xbb; }
    x.deadline=y.deadline=100; x.period=y.period=0; x.id=y.id=1;
    x.domain=y.domain=FC_DOMAIN_SYNTHETIC; x.kind=y.kind=FC_EVENT_MARK;
    x.payload=y.payload=1; x.chain_remaining=y.chain_remaining=0;
    CHECK(event_init(&a,&x,1,FC_DOMAIN_SYNTHETIC)); CHECK(event_init(&b,&y,1,FC_DOMAIN_SYNTHETIC));
    CHECK(equal_bytes(&a,&b,sizeof(a))); return 0;
}
static int test_slice_invariance(void) {
    unsigned i,j; const uint64_t budgets[]={1,2,3,7,29,30,31,UINT64_MAX};
    CHECK(scenario(&a,UINT64_MAX)==0);
    for(i=0;i<sizeof(budgets)/sizeof(budgets[0]);++i) {
        CHECK(scenario(&b,budgets[i])==0); CHECK(equal_bytes(&a,&b,sizeof(a)));
    }
    for(j=0;j<a.trace_count;++j) { hash64(a.trace[j].units); hash64(a.trace[j].tb); hash64(a.trace[j].kind); }
    hash_clock(&a); return 0;
}
#include "arithmetic_vectors.h"
static int test_oracle_vectors(void) {
    unsigned i; uint64_t out;
    for(i=0;i<sizeof(oracle_vectors)/sizeof(oracle_vectors[0]);++i) {
        const OracleVector *v=&oracle_vectors[i];
        CHECK(fc_tb_at(v->c,v->a,v->b,v->p,&out)==FC_OK); CHECK(out==v->want); hash64(out);
    }
    return 0;
}
int fc_test_all(unsigned *count, uint64_t *hash) {
    int r;
#define RUN(x) do { r=x(); if(r) return r; } while(0)
    RUN(test_arithmetic); RUN(test_retirement); RUN(test_stop_phases); RUN(test_provider);
    RUN(test_shadow_adapter); RUN(test_fixture); RUN(test_null_state); RUN(test_events); RUN(test_dirty_padding); RUN(test_slice_invariance); RUN(test_oracle_vectors);
    *count=checks; *hash=digest; return 0;
}
#ifndef FC_FREESTANDING
int main(void) {
    unsigned count=0; uint64_t hash=0; int r=fc_test_all(&count,&hash);
    if(r) { printf("FAIL line=%d checks=%u\n",r,checks); return 1; }
    printf("PASS checks=%u digest=%016llx\n",count,(unsigned long long)hash); return 0;
}
#endif
