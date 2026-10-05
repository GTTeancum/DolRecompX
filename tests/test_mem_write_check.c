/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "cpu/cpu.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,cases,observed,journaled,reject_write,expected_width,bank;
static u32 expected_address;static u64 expected_value;static jmp_buf escape;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL case %u line %u: %s\n",cases,__LINE__,#x);exit(1);}}while(0)
static void before(CPUState *c,u32 a,u64 v,u8 n,void *user){
    CHECK(user==c);CHECK(a==expected_address);CHECK(v==expected_value);CHECK(n==expected_width);
    CHECK(c->reserve_valid);CHECK(journaled==0);
    const u8 *p=(bank?c->mem2:c->ram)+(a&0xfff);
    for(unsigned j=0;j<n;++j)CHECK(p[j]==0);
    ++observed;if(reject_write)longjmp(escape,1);
}
static void journal(u32 a,u32 n,void *u){
    CPUState *c=u;CHECK(a==(expected_address&0xfff));CHECK(n==expected_width);
    CHECK(observed==1);CHECK(!c->reserve_valid);++journaled;
}
static void store(CPUState *c,u32 a,u64 v,unsigned n){
    switch(n){case 1:mem_write8(c,a,(u8)v);break;case 2:mem_write16(c,a,(u16)v);break;
        case 4:mem_write32(c,a,(u32)v);break;case 8:mem_write64(c,a,v);break;default:abort();}
}
int main(void){
    CPUState *c=calloc(1,sizeof(*c));CHECK(c);
    c->ram_size=c->mem2_size=4096;c->ram=calloc(1,4096);c->mem2=calloc(1,4096);CHECK(c->ram&&c->mem2);
    for(bank=0;bank<2;++bank)for(unsigned alias=0;alias<2;++alias)
    for(expected_width=1;expected_width<=8;expected_width*=2)for(reject_write=0;reject_write<2;++reject_write){
        ++cases;memset(c->ram,0,4096);memset(c->mem2,0,4096);observed=journaled=0;
        expected_address=(bank?0x90000000u:0x80000000u)|(alias?0x40000000u:0)|0x40;
        expected_value=UINT64_C(0x123456789abcdef0);if(expected_width<8)expected_value&=(UINT64_C(1)<<(8*expected_width))-1;
        c->reserve_valid=true;c->reserve_addr=expected_address^0x40000000u;
        ppc_set_mem_write_journal(journal,c);ppc_set_mem_write_check(before,c);
        if(!setjmp(escape)){store(c,expected_address,expected_value,expected_width);CHECK(!reject_write);}
        CHECK(observed==1);CHECK(journaled==(reject_write||bank?0u:1u));CHECK(c->reserve_valid==(reject_write!=0));
        u8 *p=(bank?c->mem2:c->ram)+0x40;
        for(unsigned j=0;j<expected_width;++j)CHECK(p[j]==(reject_write?0:(u8)(expected_value>>(8*(expected_width-j-1)))));
    }
    ppc_set_mem_write_check(NULL,NULL);ppc_set_mem_write_journal(NULL,NULL);
    /* A wide unaligned scalar access can overlap the reserved line at its tail. */
    for(unsigned b=0;b<2;++b)for(unsigned a=0;a<3;++a){
        const u32 bases[]={0,0x80000000u,0xc0000000u};++cases;
        c->reserve_addr=(b?0x90000000u:0x80000000u)+0x60;c->reserve_valid=true;
        ppc_clear_reservation_for_store(c,bases[a]+(b?0x10000000u:0)+0x5c,8);CHECK(!c->reserve_valid);
        c->reserve_valid=true;ppc_clear_reservation_for_store(c,bases[a]+(b?0:0x10000000u)+0x5c,8);CHECK(c->reserve_valid);
        ppc_clear_reservation_for_store(c,bases[a]+(b?0x10000000u:0)+0x5c,4);CHECK(c->reserve_valid);
    }
    cpu_free(c);free(c);printf("PASS: %u pre-store policy cases; %u checks\n",cases,checks);return 0;
}
