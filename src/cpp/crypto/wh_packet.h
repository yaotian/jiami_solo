// wh_packet.h — WHPKG v2（含 indicator_version、software_name）
#pragma once
#include "wh_crypto.h"
#include <string>
#include <vector>
#include <cstdint>

namespace wh {

constexpr char kPkgMagic[8] = { 'W','H','P','K','G',0,1,0 };
constexpr uint32_t kPkgVersion = 2;

enum ProductId : uint32_t {
    PRODUCT_T8_WH8 = 1,
    PRODUCT_WH6    = 2,
    PRODUCT_WH7    = 3,
};

struct PackageHeader {
    uint32_t product_id = PRODUCT_T8_WH8;
    int64_t  expire_unix = 0;
    std::string user;
    std::string contact;
    std::string indicator_version;
    std::string software_name;
    uint8_t  nonce[12]{};
    uint8_t  tag[16]{};
    std::vector<uint8_t> ciphertext;
};

constexpr uint8_t kPayloadDeliverySource = 0;
constexpr uint8_t kPayloadDeliveryXtrdRaw = 1;

struct PayloadPlain {
    std::string source;
    std::string note;
    // 文华设查看密码后保存的 XTRD 原始字节（含 <HEAD> + 密文 <CODE>）
    std::vector<uint8_t> xtrd_raw;
};

std::vector<uint8_t> package_build(const uint8_t master_key[32],
                                   const PackageHeader& hdr,
                                   const PayloadPlain& payload);

bool package_parse(const std::vector<uint8_t>& pkg,
                   const uint8_t master_key[32],
                   PackageHeader& hdr,
                   PayloadPlain& payload,
                   std::string* err = nullptr);

bool package_parse_header(const std::vector<uint8_t>& pkg,
                          PackageHeader& hdr,
                          std::string* err = nullptr);

inline void put_u16le(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back((uint8_t)(x & 0xff));
    v.push_back((uint8_t)(x >> 8));
}
inline void put_u32le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((uint8_t)(x & 0xff));
    v.push_back((uint8_t)((x >> 8) & 0xff));
    v.push_back((uint8_t)((x >> 16) & 0xff));
    v.push_back((uint8_t)((x >> 24) & 0xff));
}
inline void put_u64le(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back((uint8_t)((x >> (8 * i)) & 0xff));
}
inline void put_s64le(std::vector<uint8_t>& v, int64_t x) {
    put_u64le(v, (uint64_t)x);
}
inline bool get_u16le(const uint8_t* p, uint16_t& out) {
    out = (uint16_t)(p[0] | (p[1] << 8));
    return true;
}
inline bool get_u32le(const uint8_t* p, uint32_t& out) {
    out = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
          ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return true;
}
inline bool get_u64le(const uint8_t* p, uint64_t& out) {
    out = 0;
    for (int i = 0; i < 8; ++i) out |= (uint64_t)p[i] << (8 * i);
    return true;
}
inline bool get_s64le(const uint8_t* p, int64_t& out) {
    uint64_t u; if (!get_u64le(p, u)) return false;
    out = (int64_t)u; return true;
}

} // namespace wh
