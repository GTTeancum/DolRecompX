// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DOLRECOMP_CHECKED_SERIALIZATION_H
#define DOLRECOMP_CHECKED_SERIALIZATION_H
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>
#include <locale>
#include <sstream>
#include <stdexcept>
#include <string>
#include <openssl/sha.h>

namespace dolanalysis {
// Stream allocation failures must never turn a prefix into valid provenance.
class CheckedOutput : public std::ostringstream {
public:
    CheckedOutput() {
        exceptions(std::ios::badbit | std::ios::failbit);
        imbue(std::locale::classic());
    }
};

inline bool isSha256(const std::string &value) {
    if(value.size()!=64)return false;
    for(unsigned char c:value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;
    return true;
}

// Reject prefixes silently returned by a third-party SMT pretty-printer.
// Only complete top-level lists are accepted; quoted text is not structural.
inline bool completeSExpressions(const char *text,size_t expected,size_t limit=8u*1024u*1024u) {
    if(!text||!expected)return false;
    size_t depth=0,forms=0;bool string=false,symbol=false,comment=false,top_head=false;
    for(size_t i=0;i<limit;++i){
        const unsigned char c=static_cast<unsigned char>(text[i]);
        if(!c)return !depth&&!string&&!symbol&&forms==expected;
        if(comment){if(c=='\n'||c=='\r')comment=false;continue;}
        if(string){if(c=='"'){if(i+1<limit&&text[i+1]=='"')++i;else string=false;}continue;}
        if(symbol){if(c=='|')symbol=false;else if(c=='\\'){if(i+1>=limit||!text[i+1])return false;++i;}continue;}
        if(c==';'){comment=true;continue;}
        if(c==' '||c=='\t'||c=='\n'||c=='\r')continue;
        if(c=='('){if(!depth){if(++forms>expected)return false;top_head=true;}++depth;continue;}
        if(c==')'){if(!depth||(depth==1&&top_head))return false;--depth;continue;}
        if(!depth)return false;
        if(top_head){
            top_head=false;
            if(std::strncmp(text+i,"error",5)==0){const char next=text[i+5];if(!next||next==')'||next==' '||next=='\t'||next=='\n'||next=='\r')return false;}
        }
        if(c=='"'){string=true;continue;}
        if(c=='|'){symbol=true;continue;}
        if(c=='.'&&i+2<limit&&text[i+1]=='.'&&text[i+2]=='.')return false;
    }
    return false;
}

// Z3 low-level proof output is a shared, postorder DAG. Check the final root
// and reference closure so an incomplete formatter result cannot become evidence.
inline bool completeProofDag(const char *text,uint32_t root,size_t limit=8u*1024u*1024u) {
    if(!text)return false;
    size_t length=0;while(length<limit&&text[length])++length;
    if(!length||length==limit||text[length-1]!='\n')return false;
    std::vector<uint32_t> definitions,references;
    size_t line=0;bool root_seen=false;
    auto number=[&](size_t &at,uint32_t &out){
        if(at>=length||text[at]<'0'||text[at]>'9')return false;
        uint64_t value=0;
        do{value=value*10+unsigned(text[at++]-'0');if(value>UINT32_MAX)return false;}while(at<length&&text[at]>='0'&&text[at]<='9');
        out=uint32_t(value);return true;
    };
    while(line<length){
        size_t at=line;const bool root_line=text[at]=='[';
        if(root_line){if(root_seen)return false;root_seen=true;}
        else {
            if(root_seen||text[at++]!='#')return false;
            uint32_t id;if(!number(at,id)||length-at<4||std::strncmp(text+at," := ",4))return false;
            definitions.push_back(id);at+=4;
        }
        char delimiters[128];size_t depth=0;bool string=false,symbol=false;
        const size_t body=at;
        if(root_line){
            size_t rule=body+1,end=rule;
            while(end<length&&((text[end]>='a'&&text[end]<='z')||(text[end]>='A'&&text[end]<='Z')||(text[end]>='0'&&text[end]<='9')||text[end]=='-'||text[end]=='_'))++end;
            if(end==rule||end==length||(text[end]!=']'&&text[end]!=' ')||(end-rule==5&&!std::strncmp(text+rule,"error",5)))return false;
        }
        for(;at<length&&text[at]!='\n';++at){
            const char c=text[at];
            if(string){if(c=='"'){if(at+1<length&&text[at+1]=='"')++at;else string=false;}continue;}
            if(symbol){if(c=='|')symbol=false;else if(c=='\\'){if(at+1>=length||text[at+1]=='\n')return false;++at;}continue;}
            if(c=='"'){string=true;continue;}if(c=='|'){symbol=true;continue;}
            if(c=='('||c=='['){if(depth==sizeof(delimiters))return false;delimiters[depth++]=c;}
            else if(c==')'||c==']'){if(!depth||delimiters[--depth]!=(c==')'?'(':'['))return false;
                if(root_line&&!depth&&(c!=']'||length-at!=9||std::strncmp(text+at,"]: false\n",9)))return false;}
            if(c=='.'&&at+2<length&&text[at+1]=='.'&&text[at+2]=='.')return false;
            if(c=='#'&&at+1<length&&text[at+1]>='0'&&text[at+1]<='9'){
                ++at;uint32_t ref;if(!number(at,ref))return false;references.push_back(ref);--at;
            }
        }
        if(at==length||at==body||depth||string||symbol)return false;
        if(root_line){
            if(at+1!=length||text[body]!='['||at-body<8||std::strncmp(text+at-8,"]: false",8))return false;
        }
        line=at+1;
    }
    if(!root_seen)return false;
    std::sort(definitions.begin(),definitions.end());
    if(std::adjacent_find(definitions.begin(),definitions.end())!=definitions.end()||std::binary_search(definitions.begin(),definitions.end(),root))return false;
    for(auto ref:references)if(!std::binary_search(definitions.begin(),definitions.end(),ref))return false;
    return true;
}

inline std::string sha256(const void *bytes,size_t size) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if(!SHA256(static_cast<const unsigned char*>(bytes),size,digest))
        throw std::runtime_error("SHA256 provider failed");
    static const char digits[]="0123456789abcdef";
    char hex[SHA256_DIGEST_LENGTH*2];
    for(size_t i=0;i<SHA256_DIGEST_LENGTH;++i){hex[2*i]=digits[digest[i]>>4];hex[2*i+1]=digits[digest[i]&15];}
    return std::string(hex,sizeof(hex));
}
}
#endif
