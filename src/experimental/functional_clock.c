/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "experimental/functional_clock.h"
#define FC_MAGIC 0x46434C31u
#define U64_MAX UINT64_MAX

static void zero_bytes(void *p, size_t n) { unsigned char *b = p; while (n--) *b++ = 0; }
static int same_string(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static FcResult fail(FcClock *s, FcResult r) {
    if (s->terminal) return s->result;
    if (s->instruction_active) {
        s->failure_cia = s->active_cia; s->failure_raw = s->active_raw;
        s->failure_cost = s->active_cost;
    }
    s->instruction_active = 0; s->terminal = 1; s->result = r;
    return r;
}
static FcResult usable(FcClock *s) {
    if (!s || s->initialized != FC_MAGIC) return FC_ERR_STATE;
    return s->terminal ? s->result : FC_OK;
}
/* Fixed-divisor binary division is exact and freestanding on i386 at O0 and Oz;
 * avoids unprovided __udivdi3 / __aulldiv runtime dependencies. */
static uint64_t div12(uint64_t n, uint32_t *rem) {
    uint32_t high = (uint32_t)(n >> 32), low = (uint32_t)n;
    uint32_t qhigh = 0, qlow = 0, r = 0; unsigned i;
    /* Only 32-bit variable operations and constant 64-bit shifts: -Oz i386
     * otherwise imports __lshrdi3/__ashldi3 for a variable 64-bit shift. */
    for (i = 0; i < 64; ++i) {
        r = (r << 1) | (high >> 31);
        high = (high << 1) | (low >> 31); low <<= 1;
        qhigh = (qhigh << 1) | (qlow >> 31); qlow <<= 1;
        if (r >= 12) { r -= 12; qlow |= 1; }
    }
    *rem = r; return ((uint64_t)qhigh << 32) | qlow;
}
FcResult fc_tb_at(uint64_t c, uint64_t a, uint64_t b, uint32_t phase, uint64_t *out) {
    uint64_t ticks; uint32_t remainder;
    if (!out || a > c || phase >= 12) return FC_ERR_STATE;
    ticks = div12(c - a, &remainder);
    /* ticks <= floor(UINT64_MAX/12); no overflow in this extra tick. */
    ticks += (remainder + phase >= 12);
    *out = b + ticks; return FC_OK;
}
FcResult fc_peek(const FcClock *s, uint64_t *out) {
    if (!s || s->initialized != FC_MAGIC) return FC_ERR_STATE;
    return fc_tb_at(s->completed_units, s->anchor_units, s->anchor_tb, s->anchor_phase, out);
}
static int trace_room(const FcClock *s, uint32_t count) {
    return s->trace_count <= FC_TRACE_CAPACITY && count <= FC_TRACE_CAPACITY - s->trace_count;
}
static FcTrace *trace_new(FcClock *s, uint32_t kind) {
    FcTrace *t = &s->trace[s->trace_count++];
    zero_bytes(t, sizeof(*t)); t->kind = kind; t->units = s->completed_units;
    t->retired = s->retired_instructions; t->cia = s->active_cia; t->raw = s->active_raw;
    t->anchor_units = s->anchor_units; t->anchor_tb = s->anchor_tb; t->phase = s->anchor_phase;
    return t;
}
static FcResult validate_event(const FcEventSpec *e, int fixture) {
    if (!e || !e->id || e->id > FC_QUEUE_CAPACITY || !e->domain ||
        (e->domain & (e->domain - 1)) || (e->domain & ~FC_DOMAIN_ALL)) return FC_ERR_UNSUPPORTED_PROGRAM;
    if (e->kind == FC_EVENT_UNSUPPORTED) {
        if (!fixture || e->domain == FC_DOMAIN_SYNTHETIC || e->period || e->chain_remaining)
            return FC_ERR_UNSUPPORTED_PROGRAM;
    } else {
        if (e->domain != FC_DOMAIN_SYNTHETIC ||
            (e->kind != FC_EVENT_MARK && e->kind != FC_EVENT_CHAIN)) return FC_ERR_UNSUPPORTED_PROGRAM;
        if ((e->kind == FC_EVENT_MARK && e->chain_remaining) ||
            (e->kind == FC_EVENT_CHAIN && e->period)) return FC_ERR_UNSUPPORTED_PROGRAM;
    }
    if (e->period > U64_MAX - e->deadline) return FC_ERR_DEADLINE;
    return FC_OK;
}
static FcResult capacity_for_event(FcClock *s, const FcEvent *slot, int replacing) {
    if (!replacing && s->queue_count >= FC_QUEUE_CAPACITY) return FC_ERR_QUEUE_CAPACITY;
    if (s->next_sequence == U64_MAX) return FC_ERR_SEQUENCE_OVERFLOW;
    if (slot->generation == UINT32_MAX) return FC_ERR_GENERATION_OVERFLOW;
    return FC_OK;
}
static void put_event(FcClock *s, const FcEventSpec *e, FcEventHandle *out) {
    FcEvent *slot = &s->events[e->id - 1];
    if (!slot->pending) ++s->queue_count;
    /* Do not import caller struct padding into deterministic session snapshots. */
    slot->spec.deadline = e->deadline; slot->spec.period = e->period;
    slot->spec.id = e->id; slot->spec.domain = e->domain; slot->spec.kind = e->kind;
    slot->spec.payload = e->payload; slot->spec.chain_remaining = e->chain_remaining;
    ++slot->generation; slot->sequence = s->next_sequence++;
    slot->pending = 1;
    if (out) { out->id = e->id; out->generation = slot->generation; }
}
FcResult fc_init(FcClock *s, const FcFixture *f) {
    FcClock temp; size_t i; uint32_t represented = 0; FcResult r;
    if (!s || !f || f->synthetic_only != 1u || f->initial_phase >= 12 ||
        f->declared_domains != FC_DOMAIN_ALL || (f->active_domains & ~FC_DOMAIN_ALL) ||
        f->event_count > FC_QUEUE_CAPACITY || (f->event_count && !f->events)) return FC_ERR_FIXTURE;
    if (f->core_abi != FC_SYNTHETIC_CORE_ABI_VERSION ||
        f->abi != FC_TIMING_ABI_VERSION || !same_string(f->model_id, FC_MODEL_ID) ||
        !same_string(f->cost_sha256, FC_COST_MANIFEST_SHA256)) return FC_ERR_PROFILE;
    zero_bytes(&temp, sizeof(temp)); temp.initialized = FC_MAGIC; temp.anchor_tb = f->initial_tb;
    temp.anchor_phase = f->initial_phase; temp.pc = f->entry_pc;
    temp.slice_remaining = U64_MAX; temp.active_domains = f->active_domains;
    for (i = 0; i < f->event_count; ++i) {
        const FcEventSpec *e = &f->events[i]; r = validate_event(e, 1);
        if (r != FC_OK) return r;
        if (!(f->active_domains & e->domain) || temp.events[e->id - 1].pending) return FC_ERR_FIXTURE;
        represented |= e->domain; put_event(&temp, e, 0);
    }
    if (represented != f->active_domains) return FC_ERR_FIXTURE;
    *s = temp; return FC_OK;
}
FcResult fc_schedule(FcClock *s, const FcEventSpec *e, FcEventHandle *out) {
    FcResult r = usable(s); FcEvent *slot;
    if (r != FC_OK) return r;
    r = validate_event(e, 0); if (r != FC_OK) return fail(s, r);
    if (!(s->active_domains & e->domain)) return fail(s, FC_ERR_UNSUPPORTED_PROGRAM);
    slot = &s->events[e->id - 1];
    if (slot->pending) return fail(s, s->queue_count == FC_QUEUE_CAPACITY ? FC_ERR_QUEUE_CAPACITY : FC_ERR_STATE);
    if (e->deadline < s->completed_units) return fail(s, FC_ERR_DEADLINE);
    r = capacity_for_event(s, slot, 0); if (r != FC_OK) return fail(s, r);
    put_event(s, e, out); return FC_OK;
}
static FcEvent *find_handle(FcClock *s, FcEventHandle h) {
    FcEvent *e;
    if (!h.id || h.id > FC_QUEUE_CAPACITY) return 0;
    e = &s->events[h.id - 1];
    return e->pending && e->generation == h.generation ? e : 0;
}
FcResult fc_cancel(FcClock *s, FcEventHandle h) {
    FcEvent *e; FcResult r = usable(s); if (r != FC_OK) return r;
    e = find_handle(s, h); if (!e) return FC_STALE_HANDLE;
    if (e->spec.kind == FC_EVENT_UNSUPPORTED) return fail(s, FC_ERR_UNSUPPORTED_PROGRAM);
    if (e->generation == UINT32_MAX) return fail(s, FC_ERR_GENERATION_OVERFLOW);
    e->pending = 0; ++e->generation; --s->queue_count; return FC_OK;
}
FcResult fc_replace(FcClock *s, FcEventHandle h, const FcEventSpec *spec, FcEventHandle *out) {
    FcEvent *e; FcResult r = usable(s); if (r != FC_OK) return r;
    e = find_handle(s, h); if (!e) return FC_STALE_HANDLE;
    if (e->spec.kind == FC_EVENT_UNSUPPORTED) return fail(s, FC_ERR_UNSUPPORTED_PROGRAM);
    r = validate_event(spec, 0); if (r != FC_OK) return fail(s, r);
    if (spec->id != h.id || !(s->active_domains & spec->domain)) return fail(s, FC_ERR_UNSUPPORTED_PROGRAM);
    if (spec->deadline < s->completed_units) return fail(s, FC_ERR_DEADLINE);
    r = capacity_for_event(s, e, 1); if (r != FC_OK) return fail(s, r);
    put_event(s, spec, out); return FC_OK;
}
FcResult fc_deadline_after(FcClock *s, uint64_t delay, uint64_t *out) {
    FcResult r = usable(s); if (r != FC_OK) return r;
    if (!out || delay > U64_MAX - s->completed_units) return fail(s, FC_ERR_DEADLINE);
    *out = s->completed_units + delay; return FC_OK;
}
static FcEvent *earliest(FcClock *s, int supported_only) {
    FcEvent *best = 0; unsigned i;
    for (i = 0; i < FC_QUEUE_CAPACITY; ++i) {
        FcEvent *e = &s->events[i];
        if (e->pending && (!supported_only || e->spec.kind != FC_EVENT_UNSUPPORTED) && (!best || e->spec.deadline < best->spec.deadline ||
            (e->spec.deadline == best->spec.deadline && e->sequence < best->sequence))) best = e;
    }
    return best;
}
FcResult fc_boundary(FcClock *s) {
    uint32_t serviced = 0; FcResult r = usable(s); FcEvent *e;
    if (r != FC_OK) return r;
    if (s->instruction_active || s->settling) return fail(s, FC_ERR_STATE);
    s->settling = 1;
    while ((e = earliest(s, 1)) != 0 && e->spec.deadline <= s->completed_units) {
        FcEventSpec next = e->spec; FcTrace *t; int repeats;
        if (serviced == FC_BOUNDARY_SERVICE_LIMIT) { r = FC_ERR_BACKLOG; break; }
        if (!trace_room(s, 1)) { r = FC_ERR_TRACE_CAPACITY; break; }
        repeats = (e->spec.period != 0 || e->spec.chain_remaining != 0);
        if (repeats) {
            if (next.period > U64_MAX - next.deadline) { r = FC_ERR_DEADLINE; break; }
            next.deadline += next.period;
            if (next.chain_remaining) --next.chain_remaining;
            r = capacity_for_event(s, e, 1); if (r != FC_OK) break;
        }
        /* All failure/capacity checks precede this synthetic event's effect. */
        t = trace_new(s, FC_TRACE_EVENT); t->event_id = e->spec.id;
        t->generation = e->generation; t->payload = e->spec.payload;
        t->deadline = e->spec.deadline; t->lateness = s->completed_units - e->spec.deadline;
        if (repeats) put_event(s, &next, 0);
        else { e->pending = 0; --s->queue_count; }
        ++serviced;
    }
    s->settling = 0;
    if (r != FC_OK) return fail(s, r);
    e = earliest(s, 0);
    if (e && e->spec.deadline <= s->completed_units) return fail(s, FC_ERR_UNSUPPORTED_EVENT);
    if (s->deferred_reason) return fail(s, FC_STOP_DEFERRED);
    return FC_OK;
}
FcResult fc_slice(FcClock *s, uint64_t count) {
    FcResult r = fc_boundary(s); if (r != FC_OK) return r;
    s->slice_remaining = count; s->result = count ? FC_OK : FC_YIELD;
    return s->result;
}
FcResult fc_begin(FcClock *s, uint32_t cia, uint32_t raw, unsigned opcode, uint32_t abi) {
    FcResult r = usable(s); unsigned cost;
    if (r != FC_OK) return r;
    if (s->instruction_active) return fail(s, FC_ERR_STATE);
    s->pc = cia; s->failure_cia = cia; s->failure_raw = raw;
    s->failure_cost = fc_opcode_cost(opcode);
    if (abi != FC_TIMING_ABI_VERSION) return fail(s, FC_ERR_PROFILE);
    r = fc_boundary(s); if (r != FC_OK) return r;
    if (!s->slice_remaining) {
        s->failure_cia = 0; s->failure_raw = 0; s->failure_cost = 0;
        s->result = FC_YIELD; return FC_YIELD;
    }
    cost = fc_opcode_cost(opcode); if (!cost) return fail(s, FC_ERR_UNKNOWN_OPCODE);
    if (cost > U64_MAX - s->completed_units) return fail(s, FC_ERR_UNITS_OVERFLOW);
    if (s->retired_instructions == U64_MAX) return fail(s, FC_ERR_RETIRED_OVERFLOW);
    if (!trace_room(s, 2)) return fail(s, FC_ERR_TRACE_CAPACITY);
    s->active_cia = cia; s->active_raw = raw; s->active_cost = cost;
    s->instruction_active = 1; s->result = FC_OK;
    s->failure_cia = 0; s->failure_raw = 0; s->failure_cost = 0;
    trace_new(s, FC_TRACE_BEGIN)->value = cost;
    return FC_OK;
}
FcResult fc_retire(FcClock *s, uint32_t next_pc) {
    FcTrace *t; FcResult r = usable(s); if (r != FC_OK) return r;
    if (!s->instruction_active || s->settling || !s->active_cost || !s->slice_remaining ||
        !trace_room(s, 1) || s->active_cost > U64_MAX - s->completed_units ||
        s->retired_instructions == U64_MAX) return fail(s, FC_ERR_STATE);
    s->completed_units += s->active_cost; ++s->retired_instructions;
    --s->slice_remaining; s->pc = next_pc; s->instruction_active = 0;
    t = trace_new(s, FC_TRACE_RETIRE); t->value = s->active_cost;
    r = fc_boundary(s); if (r != FC_OK) return r;
    s->result = s->slice_remaining ? FC_OK : FC_YIELD; return s->result;
}
FcResult fc_abort(FcClock *s, FcResult reason, uint32_t access, uint32_t partial) {
    FcResult r = usable(s); if (r != FC_OK) return r;
    if (!s->instruction_active || (reason != FC_ERR_REFUSED && reason != FC_ERR_PARTIAL_EFFECT &&
        reason != FC_ERR_EXCEPTION)) return fail(s, FC_ERR_STATE);
    s->failure_access = access; s->partial_effect = (partial || reason == FC_ERR_PARTIAL_EFFECT) ? 1u : 0u;
    return fail(s, s->partial_effect ? FC_ERR_PARTIAL_EFFECT : reason);
}
FcResult fc_defer_stop(FcClock *s, uint32_t reason) {
    FcResult r = usable(s); if (r != FC_OK) return r;
    if (!s->instruction_active || !reason || s->deferred_reason) return fail(s, FC_ERR_STATE);
    s->deferred_reason = reason; return FC_OK;
}
static FcResult access_ready(FcClock *s, uint32_t cia) {
    FcResult r = usable(s); if (r != FC_OK) return r;
    if (!s->instruction_active || s->active_cia != cia) return fail(s, FC_ERR_STATE);
    /* Reserve the retirement trace before committing an observed access. */
    if (!trace_room(s, 2)) return fail(s, FC_ERR_TRACE_CAPACITY);
    return FC_OK;
}
FcResult fc_read_full(FcClock *s, uint32_t cia, uint32_t reg, uint64_t *out) {
    FcResult r = access_ready(s, cia); uint64_t tb; FcTrace *t;
    if (r != FC_OK) return r;
    if (!out || (reg != 268 && reg != 269)) return fail(s, FC_ERR_PROVIDER);
    r = fc_peek(s, &tb); if (r != FC_OK) return fail(s, r);
    t = trace_new(s, FC_TRACE_READ); t->reg = reg; t->tb = tb;
    t->value = reg == 268 ? (uint32_t)tb : (uint32_t)(tb >> 32);
    *out = tb; return FC_OK;
}
FcResult fc_write_half(FcClock *s, uint32_t cia, uint32_t reg, uint32_t value, uint64_t *out) {
    FcResult r = access_ready(s, cia); uint64_t old, tb; FcTrace *t;
    if (r != FC_OK) return r;
    if (!out || (reg != 284 && reg != 285)) return fail(s, FC_ERR_PROVIDER);
    r = fc_peek(s, &old); if (r != FC_OK) return fail(s, r);
    tb = reg == 284 ? ((old & UINT64_C(0xffffffff00000000)) | value) :
        ((old & UINT64_C(0xffffffff)) | ((uint64_t)value << 32));
    /* Internal peek is not a second architectural read/callback. */
    t = trace_new(s, FC_TRACE_WRITE); t->reg = reg; t->value = value; t->old_tb = old; t->tb = tb;
    s->anchor_units = s->completed_units; s->anchor_tb = tb; s->anchor_phase = 0;
    *out = tb; return FC_OK;
}
static FcResult provider_read(void *p, uint32_t cia, uint32_t reg, uint64_t *out) {
    return fc_read_full(p, cia, reg, out);
}
static FcResult provider_write(void *p, uint32_t cia, uint32_t reg, uint32_t value, uint64_t *out) {
    return fc_write_half(p, cia, reg, value, out);
}
FcProvider fc_provider(FcClock *s) {
    FcProvider p; p.abi = FC_PROVIDER_ABI_VERSION; p.context = s; p.read_full = provider_read; p.write_half = provider_write; return p;
}
