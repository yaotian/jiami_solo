#include "wh_packet.h"
#include <cstring>

namespace wh {

static std::vector<uint8_t> payload_serialize(const PayloadPlain& p) {
    std::vector<uint8_t> v;
    put_u32le(v, (uint32_t)p.source.size());
    v.insert(v.end(), p.source.begin(), p.source.end());
    put_u16le(v, (uint16_t)p.note.size());
    v.insert(v.end(), p.note.begin(), p.note.end());
    uint8_t mode = p.xtrd_raw.empty() ? kPayloadDeliverySource : kPayloadDeliveryXtrdRaw;
    v.push_back(mode);
    if (mode == kPayloadDeliveryXtrdRaw) {
        put_u32le(v, (uint32_t)p.xtrd_raw.size());
        v.insert(v.end(), p.xtrd_raw.begin(), p.xtrd_raw.end());
    }
    return v;
}

static bool payload_deserialize(const uint8_t* data, size_t len, PayloadPlain& out) {
    out = PayloadPlain{};
    size_t off = 0;
    if (off + 4 > len) return false;
    uint32_t src_len; get_u32le(data + off, src_len); off += 4;
    if (off + src_len > len) return false;
    out.source.assign((const char*)(data + off), src_len);
    off += src_len;
    if (off + 2 > len) return false;
    uint16_t note_len; get_u16le(data + off, note_len); off += 2;
    if (off + note_len > len) return false;
    out.note.assign((const char*)(data + off), note_len);
    off += note_len;
    if (off >= len) return true;
    if (off + 1 > len) return false;
    uint8_t mode = data[off++];
    if (mode != kPayloadDeliveryXtrdRaw) return true;
    if (off + 4 > len) return false;
    uint32_t xtrd_len; get_u32le(data + off, xtrd_len); off += 4;
    if (off + xtrd_len > len) return false;
    out.xtrd_raw.assign(data + off, data + off + xtrd_len);
    return true;
}

static bool read_string_field(const uint8_t* d, size_t n, size_t& off, std::string& out,
                              const char* field, std::string* err) {
    if (off + 2 > n) {
        if (err) *err = std::string("bad ") + field;
        return false;
    }
    uint16_t len; get_u16le(d + off, len); off += 2;
    if (off + len > n) {
        if (err) *err = std::string("bad ") + field + " length";
        return false;
    }
    out.assign((const char*)(d + off), len);
    off += len;
    return true;
}

std::vector<uint8_t> package_build(const uint8_t master_key[32],
                                   const PackageHeader& hdr,
                                   const PayloadPlain& payload) {
    std::vector<uint8_t> pt = payload_serialize(payload);
    std::vector<uint8_t> ct(pt.size());

    uint8_t derived[32];
    uint8_t salt[10] = { 'W','H','-','P','A','Y','L','O','A','D' };
    hkdf_sha256(master_key, 32, salt, sizeof(salt),
                (const uint8_t*)hdr.user.data(), hdr.user.size(),
                derived, 32);

    GcmKey gk;
    aes256_key_expand(derived, gk);

    std::vector<uint8_t> aad;
    put_u32le(aad, hdr.product_id);
    put_s64le(aad, hdr.expire_unix);
    put_u16le(aad, (uint16_t)hdr.user.size());
    aad.insert(aad.end(), hdr.user.begin(), hdr.user.end());

    uint8_t tag[16];
    aes256gcm_encrypt(gk, hdr.nonce,
                      aad.data(), aad.size(),
                      pt.data(), pt.size(),
                      ct.data(), tag);

    std::vector<uint8_t> pkg;
    pkg.insert(pkg.end(), kPkgMagic, kPkgMagic + 8);
    put_u32le(pkg, kPkgVersion);
    size_t hdr_start = pkg.size();
    put_u32le(pkg, 0);

    put_u32le(pkg, hdr.product_id);
    put_s64le(pkg, hdr.expire_unix);
    put_u16le(pkg, (uint16_t)hdr.user.size());
    pkg.insert(pkg.end(), hdr.user.begin(), hdr.user.end());
    put_u16le(pkg, (uint16_t)hdr.contact.size());
    pkg.insert(pkg.end(), hdr.contact.begin(), hdr.contact.end());
    put_u16le(pkg, (uint16_t)hdr.indicator_version.size());
    pkg.insert(pkg.end(), hdr.indicator_version.begin(), hdr.indicator_version.end());
    put_u16le(pkg, (uint16_t)hdr.software_name.size());
    pkg.insert(pkg.end(), hdr.software_name.begin(), hdr.software_name.end());

    pkg.push_back(12);
    pkg.insert(pkg.end(), hdr.nonce, hdr.nonce + 12);
    pkg.insert(pkg.end(), tag, tag + 16);
    put_u32le(pkg, (uint32_t)ct.size());
    pkg.insert(pkg.end(), ct.begin(), ct.end());

    uint32_t hdr_len = (uint32_t)(pkg.size() - hdr_start - 4);
    uint8_t* p = pkg.data() + hdr_start;
    p[0] = (uint8_t)(hdr_len & 0xff);
    p[1] = (uint8_t)((hdr_len >> 8) & 0xff);
    p[2] = (uint8_t)((hdr_len >> 16) & 0xff);
    p[3] = (uint8_t)((hdr_len >> 24) & 0xff);
    return pkg;
}

bool package_parse_header(const std::vector<uint8_t>& pkg,
                          PackageHeader& hdr,
                          std::string* err) {
    auto fail = [&](const char* msg) -> bool {
        if (err) *err = msg;
        return false;
    };
    const uint8_t* d = pkg.data();
    size_t n = pkg.size();
    if (n < 16) return fail("package too small");
    if (memcmp(d, kPkgMagic, 8) != 0) return fail("bad magic");
    uint32_t version; get_u32le(d + 8, version);
    if (version != kPkgVersion) return fail("unsupported version");
    uint32_t hdr_len; get_u32le(d + 12, hdr_len);
    size_t off = 16;
    if (off + hdr_len > n) return fail("bad header length");

    hdr = PackageHeader{};
    if (off + 4 > n) return fail("truncated product_id");
    get_u32le(d + off, hdr.product_id); off += 4;
    if (off + 8 > n) return fail("truncated expire");
    get_s64le(d + off, hdr.expire_unix); off += 8;
    if (!read_string_field(d, n, off, hdr.user, "user", err)) return false;
    if (!read_string_field(d, n, off, hdr.contact, "contact", err)) return false;
    if (!read_string_field(d, n, off, hdr.indicator_version, "indicator_version", err))
        return false;
    if (!read_string_field(d, n, off, hdr.software_name, "software_name", err))
        return false;

    if (off + 1 > n) return fail("truncated nonce_len");
    uint8_t nonce_len = d[off]; off += 1;
    if (nonce_len != 12) return fail("bad nonce len");
    if (off + 12 > n) return fail("truncated nonce");
    memcpy(hdr.nonce, d + off, 12); off += 12;
    if (off + 16 > n) return fail("truncated tag");
    memcpy(hdr.tag, d + off, 16); off += 16;
    if (off + 4 > n) return fail("truncated ct_len");
    uint32_t ct_len; get_u32le(d + off, ct_len); off += 4;
    if (off + ct_len > n) return fail("bad ciphertext");
    hdr.ciphertext.assign(d + off, d + off + ct_len);
    return true;
}

bool package_parse(const std::vector<uint8_t>& pkg,
                   const uint8_t master_key[32],
                   PackageHeader& hdr,
                   PayloadPlain& payload,
                   std::string* err) {
    hdr = PackageHeader{};
    if (!package_parse_header(pkg, hdr, err)) return false;

    uint8_t derived[32];
    uint8_t salt[10] = { 'W','H','-','P','A','Y','L','O','A','D' };
    hkdf_sha256(master_key, 32, salt, sizeof(salt),
                (const uint8_t*)hdr.user.data(), hdr.user.size(),
                derived, 32);
    GcmKey gk;
    aes256_key_expand(derived, gk);

    std::vector<uint8_t> aad;
    put_u32le(aad, hdr.product_id);
    put_s64le(aad, hdr.expire_unix);
    put_u16le(aad, (uint16_t)hdr.user.size());
    aad.insert(aad.end(), hdr.user.begin(), hdr.user.end());

    std::vector<uint8_t> pt(hdr.ciphertext.size());
    if (!aes256gcm_decrypt(gk, hdr.nonce,
                           aad.data(), aad.size(),
                           hdr.ciphertext.data(), hdr.ciphertext.size(),
                           hdr.tag, pt.data())) {
        if (err) *err = "authentication failed (tampered or wrong key)";
        return false;
    }
    if (!payload_deserialize(pt.data(), pt.size(), payload)) {
        if (err) *err = "bad payload";
        return false;
    }
    return true;
}

} // namespace wh
