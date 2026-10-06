#include <stdio.h>
#include <math.h>
#include <string.h>
#include <setjmp.h>

#include "../src/cpu/cpu.h"

void func_80004020(CPUState* ctx);
void func_80004040(CPUState* ctx);
void func_80004060(CPUState* ctx);
void func_80004068(CPUState* ctx);
void func_80004070(CPUState* ctx);

static u64 bits_of(f64 value) {
    u64 bits;
    memcpy(&bits, &value, sizeof(bits));
    return bits;
}

void func_80004100(CPUState* ctx);
void func_80004120(CPUState* ctx);
static unsigned spr_reads,spr_writes,cache_calls;
static u32 saved_hid0,cache_addresses[4];
static u8 cache_ops[4];
static u32 read_system(CPUState* c,u16 spr,u32 cia) {
    (void)c;(void)cia;if(spr!=1008) return 0;
    ++spr_reads;return saved_hid0;
}
static void write_system(CPUState* c,u16 spr,u32 value,u32 cia) {
    (void)c;(void)cia;if(spr==1008){++spr_writes;saved_hid0=value;}
}
static void cache_system(CPUState* c,u8 op,u32 address,u32 cia) {
    (void)c;(void)cia;
    if(cache_calls<4){cache_ops[cache_calls]=op;cache_addresses[cache_calls]=address;}
    ++cache_calls;
}
static int check_system_callbacks(CPUState* c) {
    cpu_reset(c);c->spr_read=read_system;c->spr_write=write_system;c->cache_control=cache_system;
    c->gpr[6]=0x80001005;c->gpr[7]=32;c->lr=0x81234560;
    saved_hid0=0x0011c664;c->pc=0x80004100;func_80004100(c);
    int ok=c->pc==c->lr&&!c->exception&&spr_reads==1&&spr_writes==1&&
        saved_hid0==0x0011ce64&&c->gpr[5]==saved_hid0&&cache_calls==3&&
        cache_ops[0]==PPC_CACHE_DCBF&&cache_ops[1]==PPC_CACHE_DCBST&&
        cache_ops[2]==PPC_CACHE_ICBI&&cache_addresses[0]==0x80001005&&
        cache_addresses[1]==0x80001025&&cache_addresses[2]==0x80001005;
    c->pc=0x80004120;func_80004120(c);
    ok &= c->pc==c->lr&&cache_calls==4&&cache_ops[3]==PPC_CACHE_DCBI;
    /* Privilege failures must not write the destination or call a host hook. */
    c->msr=0x4000;c->exception=0;c->gpr[5]=0xfeedface;c->pc=0x80004100;
    func_80004100(c);
    ok &= c->exception==PPC_EXC_PROGRAM&&c->gpr[5]==0xfeedface&&
          spr_reads==1&&spr_writes==1&&cache_calls==4;
    c->exception=0;c->msr=0x4000;c->pc=0x80004120;func_80004120(c);
    ok &= c->exception==PPC_EXC_PROGRAM&&cache_calls==4;
    printf("System callback sequence, address formation and privilege checks: %s\n",ok?"PASS":"FAIL");
    return ok;
}

void func_80004140(CPUState*);
void func_80004150(CPUState*);
void func_80004160(CPUState*);
void func_80004170(CPUState*);
void func_80004180(CPUState*);
void func_80004190(CPUState*);
void func_800041A0(CPUState*);
static jmp_buf clock_escape;
static unsigned clock_calls,clock_reject;
static u16 clock_reg;
static bool clock_write;
static u32 clock_value,clock_cia;
static void clock_policy(CPUState*c,u16 reg,bool write,u32 value,u32 cia) {
    (void)c;++clock_calls;clock_reg=reg;clock_write=write;clock_value=value;clock_cia=cia;
    if(clock_reject)longjmp(clock_escape,1);
}
static unsigned run_clock_function(CPUState*c,void (*function)(CPUState*)) {
    if(setjmp(clock_escape))return 1;
    function(c);
    return 0;
}
static int check_clock_generated(CPUState*c) {
    void (*const funcs[])(CPUState*)={func_80004140,func_80004150,func_80004160,
        func_80004170,func_80004180,func_80004190,func_800041A0};
    const u16 regs[]={268,269,284,285,268,269,270};
    int ok=1;
    for(unsigned which=0;which<7;++which)for(unsigned user=0;user<2;++user)
    for(unsigned hook=0;hook<3;++hook) {
        cpu_reset(c);c->msr=user?0x4000:0;c->timebase=UINT64_C(0x123456789abcdef0);
        c->gpr[3]=0xfeedface;c->reserve_valid=true;c->reserve_addr=0x80003020;
        c->lr=0x81234560;c->pc=0x80004140+which*16;c->timebase_access=hook?clock_policy:NULL;
        clock_calls=0;clock_reject=hook==2;
        const unsigned trapped=run_clock_function(c,funcs[which]);
        const int legal=which<6 && !(user && (which==2 || which==3));
        if(!legal) {
            ok &= !trapped && !clock_calls && c->exception==PPC_EXC_PROGRAM;
            ok &= c->program_exception==(user && which<4?PPC_PROGRAM_PRIV:PPC_PROGRAM_ILLEGAL);
            ok &= c->srr0==0x80004140+which*16 && c->timebase==UINT64_C(0x123456789abcdef0);
            /* Reserved MFTB retains the original generated zero assignment;
               privileged writes preserve the source. */
            ok &= c->gpr[3]==(which==6?0u:0xfeedfaceu);
        } else {
            ok &= !c->exception && clock_calls==(hook?1u:0u) && trapped==(hook==2);
            if(hook)ok &= clock_reg==regs[which] && clock_write==(which==2 || which==3) &&
                clock_value==(which==2||which==3?0xfeedfaceu:0u) && clock_cia==0x80004140+which*16;
            if(trapped)ok &= c->gpr[3]==0xfeedface && c->timebase==UINT64_C(0x123456789abcdef0);
            else if(which<2 || which>=4)ok &= c->gpr[3]==(which==0||which==4?0x9abcdef0u:0x12345678u);
            else ok &= c->timebase==(which==2?UINT64_C(0x12345678feedface):UINT64_C(0xfeedface9abcdef0));
        }
        ok &= c->reserve_valid && c->reserve_addr==0x80003020;
        if(!ok){fprintf(stderr,"generated clock failed: which=%u user=%u hook=%u\n",which,user,hook);return 0;}
    }
    c->timebase_access=NULL;
    printf("Generated clock opcode legality, policy and nonmutation (42 cases): %s\n",ok?"PASS":"FAIL");
    return ok;
}

int main(void) {
    CPUState cpu;
    if (!cpu_init(&cpu))
        return 1;

    cpu.pc = 0x80004020u;
    cpu.lr = 0x81234564u;
    cpu.gpr[3] = 1000;

    u32 calls = 0;
    while (cpu.pc != cpu.lr && calls < 32) {
        cpu.downcount = 0;
        func_80004020(&cpu);
        calls++;
    }

    int integer_ok = cpu.pc == cpu.lr && cpu.gpr[3] == 0 &&
                     (cpu.cr & 0xF0000000u) == 0x20000000u && calls < 20;
    if (!integer_ok) {
        fprintf(stderr, "pc=%08X r3=%u cr=%08X calls=%u\n",
                cpu.pc, cpu.gpr[3], cpu.cr, calls);
    }
    for (u32 i = 0; i < 1000; ++i)
        mem_write32(&cpu, 0x80001000u + i * 4u, i);
    cpu.pc = 0x80004040u;
    cpu.lr = 0x81234564u;
    cpu.gpr[3] = 1000;
    cpu.gpr[5] = 0x80001000u;
    calls = 0;
    while (cpu.pc != cpu.lr && calls < 32) {
        cpu.downcount = 0;
        func_80004040(&cpu);
        calls++;
    }
    int memory_ok = cpu.pc == cpu.lr && cpu.gpr[3] == 0 &&
                    cpu.gpr[4] == 999 && cpu.gpr[5] == 0x80001FA0u &&
                    calls < 24;
    if (!memory_ok) {
        fprintf(stderr, "memory pc=%08X r3=%u r4=%u r5=%08X calls=%u\n",
                cpu.pc, cpu.gpr[3], cpu.gpr[4], cpu.gpr[5], calls);
    }

    cpu.msr = 0x00002000u;
    cpu.lr = 0x81234564u;
    cpu.fpscr = 0;
    cpu.fpr[1] = NAN;
    cpu.fpr[2] = 1.0;
    cpu.pc = 0x80004060u;
    func_80004060(&cpu);
    int compare_ok = (cpu.fpscr & 0x00080000u) != 0 &&
                     ((cpu.fpscr >> 12) & 0xFu) == 1u &&
                     ((cpu.cr >> 20) & 0xFu) == 1u;

    cpu.fpscr = 0xA0000000u;
    cpu.cr = 0;
    cpu.fpr[1] = 1.25;
    cpu.fpr[2] = 2.5;
    cpu.pc = 0x80004068u;
    func_80004068(&cpu);
    int record_ok = cpu.fpr[3] == 3.75 && cpu.ps1[3] == 3.75 &&
                    ((cpu.cr >> 24) & 0xFu) == 0xAu;

    cpu.fpr[1] = 0x1.0000000000001p+0;
    cpu.fpr[2] = -0x1.0000000000001p+0;
    u64 merge_a = bits_of(cpu.fpr[1]);
    u64 merge_b = bits_of(cpu.fpr[2]);
    cpu.pc = 0x80004070u;
    func_80004070(&cpu);
    int merge_ok = bits_of(cpu.fpr[5]) == merge_a &&
                   bits_of(cpu.ps1[5]) == merge_b;

    if (!compare_ok || !record_ok || !merge_ok) {
        fprintf(stderr, "float compare=%d record=%d merge=%d fpscr=%08X cr=%08X\n",
                compare_ok, record_ok, merge_ok, cpu.fpscr, cpu.cr);
    }

    int system_ok=check_system_callbacks(&cpu);
    int clock_ok=check_clock_generated(&cpu);
    cpu_free(&cpu);
    return !(clock_ok && system_ok && integer_ok && memory_ok && compare_ok && record_ok && merge_ok);
}
