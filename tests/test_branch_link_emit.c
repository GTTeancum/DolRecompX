/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "backend/emitter.h"
#include "frontend/decoder.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct { u32 pc, raw; } Case;
static Case cases[2048];
static unsigned count;

static int one(FILE* out, u32 pc, u32 raw) {
    PPCInst inst=ppc_decode(raw,pc);
    if (inst.op==PPC_OP_UNKNOWN || count>=sizeof(cases)/sizeof(cases[0])) return 0;
    if (!emit_function(out,&inst,1,pc)) return 0;
    cases[count++]=(Case){pc,raw};
    return 1;
}

static int program(FILE* out,u32 pc,const u32* words,unsigned n) {
    PPCInst insts[8];
    if(n>8)return 0;
    for(unsigned i=0;i<n;++i)insts[i]=ppc_decode(words[i],pc+i*4);
    return emit_function(out,insts,n,pc);
}

int main(int argc,char**argv) {
    if(argc!=2)return 1;
    FILE* out=fopen(argv[1],"w");if(!out)return 1;
    emit_header(out);
    if(!one(out,0x1000,0x4d800021))return 1;
    const unsigned options[]={0,1,2,3,4,5,8,9,10,11,12,13,16,17,18,19,20};
    const unsigned bits[]={0,7,31};
    u32 pc=0x10000;
    for(unsigned form=0;form<4;++form)
    for(unsigned bo=0;bo<sizeof(options)/sizeof(options[0]);++bo)
    for(unsigned bi=0;bi<sizeof(bits)/sizeof(bits[0]);++bi)
    for(unsigned lk=0;lk<2;++lk) {
        unsigned option=options[bo];
        if(form==3 && !(option&4u))continue;
        u32 raw=(form<2?16u:19u)<<26;
        raw|=option<<21|bits[bi]<<16|lk;
        raw|=form==0?0x100u:form==1?0xff02u:form==2?16u<<1:528u<<1;
        if(!one(out,pc,raw))return 1;
        pc+=16;
    }
    for(unsigned aa=0;aa<2;++aa)for(unsigned lk=0;lk<2;++lk){
        if(!one(out,pc,(18u<<26)|0x100u|(aa<<1)|lk))return 1;
        pc+=16;
    }
    if(!one(out,0xfffffffcu,0x41802003u))return 1;
    for(unsigned bo=0;bo<32;++bo)if(!(bo&4u))
        if(ppc_decode((19u<<26)|(bo<<21)|(528u<<1)|1u,0x1000).op!=PPC_OP_UNKNOWN)return 1;
    fprintf(out,"typedef struct { u32 pc,raw; void (*function)(CPUState*); } BranchCase;\n");
    fprintf(out,"const BranchCase branch_cases[] = {\n");
    for(unsigned i=0;i<count;++i)
        fprintf(out,"{0x%08Xu,0x%08Xu,func_%08X},\n",cases[i].pc,cases[i].raw,cases[i].pc);
    fprintf(out,"};\nconst unsigned branch_case_count=%uu;\n",count);

    const u32 direct[]={0x4180000du,0x38630001u,0x48000100u,0x38630002u,0x4e800020u};
    if(!program(out,0x90000000u,direct,5))return 1;
    const u32 dynamic[]={0x4800000du,0x38630001u,0x48000100u,0x38630002u,0x4d800021u,0x38630004u,0x480000f0u};
    if(!program(out,0x90001000u,dynamic,7))return 1;
    const u32 counter[]={0x4d800421u,0x38630001u,0x48000100u,0x38630002u,0x4e800020u};
    if(!program(out,0x90002000u,counter,5))return 1;
    const u32 callee[]={0x38630002u,0x4e800020u};
    if(!program(out,0x91000100u,callee,2))return 1;
    const u32 chunk_starts[]={0x91000100u};
    emit_set_chunk_table(chunk_starts,1);
    const u32 cross[]={0x41800101u,0x38630001u,0x48000100u};
    if(!program(out,0x91000000u,cross,3))return 1;
    emit_set_chunk_table(NULL,0);
    const u32 backward[]={0x38630001u,0x4180fffdu};
    if(!program(out,0x93000000u,backward,2))return 1;
    emit_footer(out);
    return fclose(out)!=0;
}
