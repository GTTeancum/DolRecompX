/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include <stddef.h>
int fc_test_all(unsigned *, uint64_t *);
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d=dst; const unsigned char *s=src; while(n--) *d++=*s++; return dst;
}
void *memset(void *dst, int c, size_t n) {
    unsigned char *d=dst; while(n--) *d++=(unsigned char)c; return dst;
}
static void write_stdout(const char *s, unsigned n) {
    __asm__ volatile("int $0x80" : : "a"(4), "b"(1), "c"(s), "d"(n) : "memory");
}
static unsigned decimal(char *s, unsigned x) {
    char rev[16]; unsigned n=0,i; do { rev[n++]=(char)('0'+x%10); x/=10; } while(x);
    for(i=0;i<n;++i) s[i]=rev[n-i-1];
    return n;
}
int runner_main(void) {
    unsigned count=0, n=0, i; uint64_t digest=0; char buf[100];
    int r=fc_test_all(&count,&digest);
    const char *prefix=r?"FAIL line=":"PASS checks=";
    while(*prefix) buf[n++]=*prefix++;
    n+=decimal(buf+n,r?(unsigned)r:count);
    if(!r) {
        const char *word=" digest="; while(*word) buf[n++]=*word++;
        for(i=16;i>0;--i) {
            uint32_t word=i>8?(uint32_t)(digest>>32):(uint32_t)digest;
            buf[n++]="0123456789abcdef"[(word>>(((i-1)%8)*4))&15];
        }
    }
    buf[n++]='\n'; write_stdout(buf,n); return r?1:0;
}
