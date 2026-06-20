#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <string>
#include <vector>

#include "wh_license.h"
#include "../crypto/wh_crypto.h"

namespace wh {

namespace {

static const char kLicenseMagic[4] = {'R','E','G','\0'};
static const uint8_t kLicenseVersion = 1;

static std::string base64_url_encode(const uint8_t* data, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((len * 4 + 2) / 3);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) val |= ((uint32_t)data[i + 1]) << 8;
        if (i + 2 < len) val |= ((uint32_t)data[i + 2]);
        out.push_back(alphabet[(val >> 18) & 0x3F]);
        out.push_back(alphabet[(val >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? alphabet[(val >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? alphabet[val & 0x3F] : '=');
    }
    while (!out.empty() && out.back() == '=') out.pop_back();
    return out;
}

static int base64_url_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static std::vector<uint8_t> base64_url_decode(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() * 3 / 4);
    uint32_t val = 0;
    int bits = 0;
    for (char c : s) {
        int v = base64_url_value(c);
        if (v < 0) return {};
        val = (val << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            out.push_back((uint8_t)((val >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

static void compute_signature(const uint8_t* master_key, size_t key_len,
                              const LicenseInfo& lic,
                              uint8_t sig[16]) {
    uint8_t buf[18];
    buf[0] = kLicenseVersion;
    memcpy(buf + 1, lic.machine_hash, 8);
    memcpy(buf + 9, &lic.expire_unix, 8);
    buf[17] = lic.flags;
    uint8_t hmac[32];
    wh::hmac_sha256(master_key, key_len, buf, sizeof(buf), hmac);
    memcpy(sig, hmac, 16);
}

static bool machine_hash_prefix_match(const uint8_t* a, const uint8_t* b) {
    for (int i = 0; i < 8; ++i)
        if (a[i] != b[i]) return false;
    return true;
}

} // namespace

std::string license_generate(const uint8_t* master_key, size_t key_len,
                             const uint8_t* machine_hash, size_t hash_len,
                             int64_t expire_unix, uint8_t flags) {
    if (key_len < 16 || hash_len < 8) return "";
    LicenseInfo lic{};
    memcpy(lic.machine_hash, machine_hash, 8);
    lic.expire_unix = expire_unix;
    lic.flags = flags;
    compute_signature(master_key, key_len, lic, lic.signature);

    uint8_t buf[38];
    memcpy(buf + 0, kLicenseMagic, 4);
    buf[4] = kLicenseVersion;
    memcpy(buf + 5, lic.machine_hash, 8);
    memcpy(buf + 13, &lic.expire_unix, 8);
    buf[21] = lic.flags;
    memcpy(buf + 22, lic.signature, 16);
    return base64_url_encode(buf, sizeof(buf));
}

bool license_parse(const std::string& license_key, LicenseInfo& out) {
    std::string s;
    s.reserve(license_key.size());
    for (char c : license_key) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '=') continue;
        s.push_back(c);
    }
    auto raw = base64_url_decode(s);
    if (raw.size() != 38) return false;
    if (memcmp(raw.data(), kLicenseMagic, 4) != 0) return false;
    if (raw[4] != kLicenseVersion) return false;
    memcpy(out.machine_hash, raw.data() + 5, 8);
    memcpy(&out.expire_unix, raw.data() + 13, 8);
    out.flags = raw[21];
    memcpy(out.signature, raw.data() + 22, 16);
    return true;
}

bool license_verify(const LicenseInfo& lic,
                    const uint8_t* master_key, size_t key_len,
                    const uint8_t* machine_hash, size_t hash_len,
                    int64_t now_utc) {
    if (key_len < 16 || hash_len < 8) return false;
    uint8_t expected[16];
    compute_signature(master_key, key_len, lic, expected);
    if (memcmp(lic.signature, expected, 16) != 0) return false;
    if (!machine_hash_prefix_match(lic.machine_hash, machine_hash)) return false;
    if (lic.expire_unix > 0 && now_utc > lic.expire_unix) return false;
    return true;
}

} // namespace wh
