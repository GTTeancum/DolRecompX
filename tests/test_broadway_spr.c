// SPDX-License-Identifier: GPL-3.0-or-later
/* Synthetic runtime variant/SPR dispatch regressions; no game data. */
#include "cpu/cpu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, reads, writes;
static u32 received, origin;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); exit(1); } } while(0)
static u32 get(CPUState*c,u16 s,u32 pc){(void)c;CHECK(s==1011);++reads;origin=pc;return 0x13579bdf;}
static void put(CPUState*c,u16 s,u32 v,u32 pc){(void)c;CHECK(s==1011);++writes;received=v;origin=pc;}
static void setup(CPUState*c,u32 variant){memset(c,0,sizeof(*c));c->runtime_cpu=variant;c->spr_read=get;c->spr_write=put;reads=writes=0;}
int main(void){CPUState c;
    for(unsigned variant=0;variant<3;++variant){
        setup(&c,variant);u32 value=ppc_mfspr(&c,1011,0x1000);
        if(variant==PPC_RUNTIME_BROADWAY){CHECK(!c.exception&&reads==1&&value==0x13579bdf&&origin==0x1000);}
        else CHECK(c.program_exception==PPC_PROGRAM_ILLEGAL&&reads==0&&c.srr0==0x1000);
        setup(&c,variant);ppc_mtspr(&c,1011,0x2468ace0,0x1004);
        if(variant==PPC_RUNTIME_BROADWAY)CHECK(!c.exception&&writes==1&&received==0x2468ace0&&origin==0x1004);
        else CHECK(c.program_exception==PPC_PROGRAM_ILLEGAL&&writes==0&&c.srr0==0x1004);
        setup(&c,variant);c.msr=0x4000;(void)ppc_mfspr(&c,1011,0x1008);
        CHECK(c.program_exception==PPC_PROGRAM_PRIV&&reads==0&&c.srr0==0x1008);
        setup(&c,variant);c.msr=0x4000;ppc_mtspr(&c,1011,0,0x100c);
        CHECK(c.program_exception==PPC_PROGRAM_PRIV&&writes==0&&c.srr0==0x100c);
    }
    setup(&c,PPC_RUNTIME_BROADWAY);c.spr_read=NULL;(void)ppc_mfspr(&c,1011,0x1010);
    CHECK(c.program_exception==PPC_PROGRAM_ILLEGAL);
    setup(&c,PPC_RUNTIME_BROADWAY);c.spr_write=NULL;ppc_mtspr(&c,1011,0,0x1014);
    CHECK(c.program_exception==PPC_PROGRAM_ILLEGAL);
    const u16 reserved[]={1012,1023,1024,65535};
    for(unsigned i=0;i<4;++i){setup(&c,PPC_RUNTIME_BROADWAY);(void)ppc_mfspr(&c,reserved[i],0x1018);CHECK(c.program_exception==PPC_PROGRAM_ILLEGAL&&reads==0);
        setup(&c,PPC_RUNTIME_BROADWAY);ppc_mtspr(&c,reserved[i],0,0x101c);CHECK(c.program_exception==PPC_PROGRAM_ILLEGAL&&writes==0);}
    setup(&c,PPC_RUNTIME_BROADWAY);cpu_reset(&c);CHECK(c.runtime_cpu==PPC_RUNTIME_BROADWAY&&c.spr_read==get&&c.spr_write==put);
    c.spr_read=NULL;CHECK(ppc_mfspr(&c,287,0x1020)==PPC_BROADWAY_PVR);
    c.runtime_cpu=PPC_RUNTIME_GEKKO;CHECK(ppc_mfspr(&c,287,0x1024)==PPC_GEKKO_PVR);
    CHECK(cpu_init(&c));CHECK(c.runtime_cpu==PPC_RUNTIME_GEKKO);cpu_free(&c);
    printf("PASS: Broadway HID4 legality; %u checks\n",checks);return 0;
}
