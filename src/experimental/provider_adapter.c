/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "experimental/clock_contract.h"
FcResult fc_provider_read_shadow(const FcProvider *p, uint64_t *shadow,
                                 uint32_t cia, uint32_t reg, uint32_t *value) {
    FcResult r; uint64_t tb;
    if (!shadow || !value || (reg != 268 && reg != 269)) return FC_ERR_PROVIDER;
    r = fc_provider_validate(p); if (r != FC_OK) return r;
    tb = *shadow;
    if (p && p->read_full) {
        r = p->read_full(p->context, cia, reg, &tb); if (r != FC_OK) return r;
    }
    *shadow = tb; *value = reg == 268 ? (uint32_t)tb : (uint32_t)(tb >> 32);
    return FC_OK;
}
FcResult fc_provider_write_shadow(const FcProvider *p, uint64_t *shadow,
                                  uint32_t cia, uint32_t reg, uint32_t value) {
    FcResult r; uint64_t tb;
    if (!shadow || (reg != 284 && reg != 285)) return FC_ERR_PROVIDER;
    r = fc_provider_validate(p); if (r != FC_OK) return r;
    tb = *shadow;
    if (p && p->write_half) {
        r = p->write_half(p->context, cia, reg, value, &tb); if (r != FC_OK) return r;
    } else {
        tb = reg == 284 ? ((*shadow & UINT64_C(0xffffffff00000000)) | value) :
                         ((*shadow & UINT64_C(0xffffffff)) | ((uint64_t)value << 32));
    }
    *shadow = tb; return FC_OK;
}

FcResult fc_provider_validate(const FcProvider *p) {
    if (!p) return FC_OK;
    if (p->abi != FC_PROVIDER_ABI_VERSION) return FC_ERR_PROVIDER;
    if (!p->read_full && !p->write_half) return FC_OK;
    return p->read_full && p->write_half && p->context ? FC_OK : FC_ERR_PROVIDER;
}
