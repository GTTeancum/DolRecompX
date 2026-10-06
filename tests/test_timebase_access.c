/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "cpu/cpu.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static CPUState cpu,before,reference;
static u8 ram[64],saved_ram[64];
static unsigned cases,checks,calls,reject_access,observed,journaled;
static u16 expected_reg;
static bool expected_write;
static u32 expected_value,expected_cia;
static jmp_buf escape;
#define CHECK(x) do{++checks;if(!(x)){fprintf(stderr,"clock case %u line %u: %s\n",cases,__LINE__,#x);exit(1);}}while(0)
static void policy(CPUState*c,u16 reg,bool write,u32 value,u32 cia){
    CHECK(c==&cpu && reg==expected_reg && write==expected_write);
    CHECK(value==expected_value && cia==expected_cia);
    CHECK(c->timebase==before.timebase && c->reserve_valid && c->reserve_addr==before.reserve_addr);
    CHECK(!memcmp(c->gpr,before.gpr,sizeof(c->gpr)));
    ++calls;if(reject_access)longjmp(escape,1);
}
static void check_store(CPUState*c,u32 a,u64 v,u8 w,void*u){(void)c;(void)a;(void)v;(void)w;(void)u;++observed;}
static void journal(u32 a,u32 w,void*u){(void)a;(void)w;(void)u;++journaled;}
static void setup(unsigned variant,unsigned user){
    memset(&cpu,0,sizeof(cpu));memset(ram,0x5a,sizeof(ram));
    cpu.runtime_cpu=variant;cpu.msr=user?0x4000:0;
    cpu.timebase=UINT64_C(0x123456789abcdef0);cpu.reserve_valid=true;cpu.reserve_addr=0x80000020;
    cpu.ram=ram;cpu.ram_size=sizeof(ram);cpu.pc=0x80001110;
    for(unsigned i=0;i<32;++i)cpu.gpr[i]=0xa5010000u+i;
    calls=observed=journaled=0;
}
int main(void){
    ppc_set_mem_write_check(check_store,NULL);ppc_set_mem_write_journal(journal,NULL);
    /* Null policy preserves standalone storage semantics, including user reads. */
    for(unsigned variant=0;variant<2;++variant)for(unsigned user=0;user<2;++user){
        ++cases;setup(variant,user);
        CHECK(ppc_mftb(&cpu,268,0x1230)==0x9abcdef0);
        CHECK(ppc_mftb(&cpu,269,0x1234)==0x12345678 && !cpu.exception);
        CHECK(ppc_mfspr(&cpu,268,0x1230)==0x9abcdef0);
        CHECK(ppc_mfspr(&cpu,269,0x1234)==0x12345678 && !cpu.exception);
        if(!user){ppc_mtspr(&cpu,284,0x87654321,0x1238);CHECK(cpu.timebase==UINT64_C(0x1234567887654321));
            ppc_mtspr(&cpu,285,0xabcdef01,0x123c);CHECK(cpu.timebase==UINT64_C(0xabcdef0187654321));}
    }
    for(unsigned variant=0;variant<2;++variant)for(unsigned user=0;user<2;++user)
    for(unsigned op=0;op<6;++op)for(reject_access=0;reject_access<2;++reject_access){
        if(user && (op==2 || op==3))continue;
        ++cases;setup(variant,user);cpu.timebase_access=policy;
        const u16 regs[]={268,269,284,285,268,269};
        expected_reg=regs[op];expected_write=op==2 || op==3;
        expected_value=expected_write?0x87654321:0;expected_cia=0x80002340+4*op;
        before=cpu;memcpy(saved_ram,ram,sizeof(ram));
        if(!setjmp(escape)){
            if(expected_write)ppc_mtspr(&cpu,expected_reg,expected_value,expected_cia);
            else cpu.gpr[3]=op>=4?ppc_mfspr(&cpu,expected_reg,expected_cia):ppc_mftb(&cpu,expected_reg,expected_cia);
            CHECK(!reject_access);
        }
        CHECK(calls==1 && !observed && !journaled && !memcmp(ram,saved_ram,sizeof(ram)));
        if(reject_access)CHECK(!memcmp(&cpu,&before,sizeof(cpu)));
        else if(expected_write)CHECK(cpu.timebase==(op==2?UINT64_C(0x1234567887654321):UINT64_C(0x876543219abcdef0)));
        else CHECK(cpu.gpr[3]==(op==0||op==4?0x9abcdef0u:0x12345678u));
    }
    reject_access=1;
    /* Exhaustively preserve reserved u16 TBR behavior, without invoking hook. */
    for(unsigned reg=0;reg<65536;++reg){
        if(reg==268 || reg==269)continue;
        ++cases;setup(0,reg&1);reference=cpu;
        CHECK(ppc_mftb(&reference,(u16)reg,0x80004560)==0);
        cpu.timebase_access=policy;
        CHECK(ppc_mftb(&cpu,(u16)reg,0x80004560)==0 && !calls);
        reference.timebase_access=policy;CHECK(!memcmp(&cpu,&reference,sizeof(cpu)));
        CHECK(cpu.program_exception==PPC_PROGRAM_ILLEGAL && cpu.srr0==0x80004560);
    }
    /* Write privilege precedes policy; illegal SPR encodings remain illegal. */
    const u16 aliases[]={268,269,284,285};
    for(unsigned variant=0;variant<2;++variant)for(unsigned user=0;user<2;++user)
    for(unsigned op=0;op<2;++op)for(unsigned i=0;i<4;++i){
        if((op && !user && i>=2) || (!op && i<2))continue;
        ++cases;setup(variant,user);reference=cpu;cpu.timebase_access=policy;
        if(op){ppc_mtspr(&reference,aliases[i],0x12345678,0x80003450);ppc_mtspr(&cpu,aliases[i],0x12345678,0x80003450);}
        else{CHECK(ppc_mfspr(&reference,aliases[i],0x80003450)==0);CHECK(ppc_mfspr(&cpu,aliases[i],0x80003450)==0);}
        reference.timebase_access=policy;CHECK(!memcmp(&cpu,&reference,sizeof(cpu)) && !calls);
        CHECK(cpu.program_exception==(user && (op || i>=2)?PPC_PROGRAM_PRIV:PPC_PROGRAM_ILLEGAL));
    }
    ++cases;setup(1,0);cpu.timebase_access=policy;cpu.external_user_data=ram;cpu_reset(&cpu);
    CHECK(cpu.timebase_access==policy && cpu.external_user_data==ram && cpu.runtime_cpu==1);
    CHECK(!cpu.timebase && !cpu.reserve_valid && !cpu.gpr[3]);
    for(unsigned i=0;i<sizeof(ram);++i)CHECK(!ram[i]);
    ++cases;CPUState *fresh=malloc(sizeof(*fresh));CHECK(fresh);memset(fresh,0xa5,sizeof(*fresh));
    CHECK(cpu_init(fresh) && !fresh->timebase_access);cpu_free(fresh);free(fresh);
    ppc_set_mem_write_check(NULL,NULL);ppc_set_mem_write_journal(NULL,NULL);
    printf("PASS: %u CPU timebase policy cases; %u checks\n",cases,checks);return 0;
}
