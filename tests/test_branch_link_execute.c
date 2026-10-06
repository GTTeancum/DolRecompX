/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "cpu/cpu.h"
#include <stdio.h>
#include <string.h>

typedef struct { u32 pc,raw; void (*function)(CPUState*); } BranchCase;
extern const BranchCase branch_cases[];
extern const unsigned branch_case_count;
extern unsigned dolrecomp_call_depth;
void func_90000000(CPUState*);
void func_90001000(CPUState*);
void func_90002000(CPUState*);
void func_91000000(CPUState*);
void func_93000000(CPUState*);
static unsigned checks;
static u8 ram[32];
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"branch-link line %d: %s\n",__LINE__,#x);return 0;} } while(0)

/* Architectural branch pseudocode, independently evaluated from the raw word.
   LR is a destination regardless of the condition; dynamic targets use old state. */
static void expected_branch(CPUState* c,u32 raw,u32 cia) {
    const unsigned primary=raw>>26,bo=(raw>>21)&31u,bi=(raw>>16)&31u;
    u32 target;
    if(primary==19)target=(((raw>>1)&1023u)==16?c->lr:c->ctr)&~3u;
    else {
        u32 bits=primary==18?raw&0x03fffffcu:raw&0x0000fffcu;
        u32 sign=primary==18?0x02000000u:0x00008000u;
        u32 offset=(bits^sign)-sign;
        target=(raw&2u)?offset:cia+offset;
    }
    bool take=true;
    if(primary!=18){
        if(!(bo&4u)){
            --c->ctr;
            take=(bo&2u)?c->ctr==0:c->ctr!=0;
        }
        if(!(bo&16u))take=take&&(((c->cr>>(31u-bi))&1u)==((bo>>3)&1u));
    }
    if(raw&1u)c->lr=cia+4u;
    c->pc=take?target:cia+4u;
    --c->downcount;
}

static void setup(CPUState* c,u32 pc,u32 cr,u32 ctr,u32 lr) {
    memset(c,0,sizeof(*c));
    c->pc=pc;c->cr=cr;c->ctr=ctr;c->lr=lr;c->downcount=512;
    c->ram=ram;c->ram_size=sizeof(ram);c->reserve_valid=true;c->reserve_addr=0x80000010u;
    c->xer=0xa0000000u;c->fpscr=0x12345678u;c->timebase=UINT64_C(0x12345678abcdef01);
    for(unsigned i=0;i<32;++i){c->gpr[i]=0xa5010000u+i;c->fpr[i]=(double)i+0.5;c->ps1[i]=-(double)i;}
}

static int matrix(void) {
    const u32 crs[]={0,UINT32_MAX,0x80000000u,0x01000000u,1};
    const u32 ctrs[]={0,1,2,3,UINT32_MAX,0x70000103u};
    const u32 lrs[]={0x2003u,0,UINT32_MAX,0x70000202u};
    unsigned cases=0;
    for(unsigned n=0;n<branch_case_count;++n)
    for(unsigned cr=0;cr<sizeof(crs)/sizeof(crs[0]);++cr)
    for(unsigned ctr=0;ctr<sizeof(ctrs)/sizeof(ctrs[0]);++ctr)
    for(unsigned lr=0;lr<sizeof(lrs)/sizeof(lrs[0]);++lr){
        CPUState actual,expected;
        setup(&actual,branch_cases[n].pc,crs[cr],ctrs[ctr],lrs[lr]);expected=actual;
        expected_branch(&expected,branch_cases[n].raw,branch_cases[n].pc);
        branch_cases[n].function(&actual);
        ++cases;++checks;
        if(memcmp(&actual,&expected,sizeof(actual))){
            fprintf(stderr,"branch raw=%08x cia=%08x cr=%08x ctr=%08x lr=%08x: got pc=%08x lr=%08x ctr=%08x, expected pc=%08x lr=%08x ctr=%08x\n",
                    branch_cases[n].raw,branch_cases[n].pc,crs[cr],ctrs[ctr],lrs[lr],actual.pc,actual.lr,actual.ctr,expected.pc,expected.lr,expected.ctr);
            return 0;
        }
    }
    printf("PASS: %u generated single-branch full-state cases\n",cases);
    return 1;
}

static int routing(void) {
    void (*functions[])(CPUState*)={func_90000000,func_90001000,func_90002000,func_91000000};
    const u32 entries[]={0x90000000u,0x90001000u,0x90002000u,0x91000000u};
    for(unsigned kind=0;kind<4;++kind)for(unsigned taken=0;taken<2;++taken){
        CPUState c;
        setup(&c,entries[kind],taken?0x80000000u:0,entries[kind]+12u,0x70000003u);c.gpr[3]=0;
        unsigned calls=0;
        do {functions[kind](&c);++calls;}while(c.pc>=entries[kind]&&c.pc<entries[kind]+28u&&calls<4);
        CHECK(calls==(kind==2&&taken?2u:1u));
        CHECK(c.pc==entries[kind]+0x108u);
        CHECK(c.lr==entries[kind]+(kind==1?20u:4u));
        CHECK(c.gpr[3]==(kind==1?(taken?3u:6u):(taken?3u:1u)));
        CHECK(c.ctr==entries[kind]+12u&&!c.exception);
        CHECK(c.downcount==512-(kind==1||taken?5:3));
    }
    CPUState c;
    setup(&c,0x91000000u,0x80000000u,7,0x70000003u);c.gpr[3]=0;
    unsigned old_depth=dolrecomp_call_depth;dolrecomp_call_depth=UINT32_MAX;
    func_91000000(&c);dolrecomp_call_depth=old_depth;
    CHECK(c.pc==0x91000100u&&c.lr==0x91000004u&&c.gpr[3]==0&&c.ctr==7);
    CHECK(c.downcount==511&&!c.exception);
    for(unsigned taken=0;taken<2;++taken){
        setup(&c,0x93000000u,taken?0x80000000u:0,7,0x70000003u);
        c.gpr[3]=0;c.downcount=-256;
        func_93000000(&c);
        CHECK(c.pc==(taken?0x93000000u:0x93000008u));
        CHECK(c.lr==0x93000008u&&c.gpr[3]==1&&c.ctr==7&&c.downcount==-258);
    }
    return 1;
}

int main(void) {
    memset(ram,0x5a,sizeof(ram));
    if(!matrix()||!routing())return 1;
    for(unsigned i=0;i<sizeof(ram);++i)if(ram[i]!=0x5a)return 1;
    printf("PASS: conditional linking, old targets, CTR and successful routing (%u checks)\n",checks);
    return 0;
}
