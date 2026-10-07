// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef DOLRECOMP_CHECKED_SERIALIZATION_H
#define DOLRECOMP_CHECKED_SERIALIZATION_H
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
