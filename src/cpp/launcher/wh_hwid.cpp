#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <string.h>
#include <string>
#include <vector>

#include "wh_hwid.h"
#include "../crypto/wh_crypto.h"

namespace wh {

namespace {

static void cpuid_exec(int func, int sub, int regs[4]) {
    __cpuidex(regs, func, sub);
}

static std::string get_cpu_vendor() {
    int regs[4]{};
    cpuid_exec(0, 0, regs);
    char buf[13]{};
    memcpy(buf + 0, &regs[1], 4);
    memcpy(buf + 4, &regs[3], 4);
    memcpy(buf + 8, &regs[2], 4);
    return std::string(buf);
}

static std::string get_cpu_brand() {
    int regs[4]{};
    cpuid_exec(0x80000000, 0, regs);
    if ((unsigned)regs[0] < 0x80000004) return "";
    char brand[49]{};
    for (int i = 0; i < 3; ++i) {
        cpuid_exec(0x80000002 + i, 0, regs);
        memcpy(brand + i * 16, regs, 16);
    }
    return std::string(brand);
}

static std::string get_cpu_info() {
    return get_cpu_vendor() + "|" + get_cpu_brand();
}

static std::string get_volume_serial() {
    wchar_t sys_dir[MAX_PATH]{};
    if (!GetWindowsDirectoryW(sys_dir, MAX_PATH)) return "";
    wchar_t root[4] = { sys_dir[0], L':', L'\\', L'\0' };
    if (root[0] == L'\\') return ""; // UNC
    DWORD serial = 0;
    if (!GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0))
        return "";
    char buf[16]{};
    sprintf_s(buf, "%08X", serial);
    return std::string(buf);
}

static std::string base32_encode(const uint8_t* data, size_t len) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string out;
    out.reserve((len * 8 + 4) / 5);
    int bits = 0;
    unsigned val = 0;
    for (size_t i = 0; i < len; ++i) {
        val = (val << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            out.push_back(alphabet[(val >> (bits - 5)) & 0x1F]);
            bits -= 5;
        }
    }
    if (bits > 0) {
        out.push_back(alphabet[(val << (5 - bits)) & 0x1F]);
    }
    return out;
}

static std::vector<uint8_t> base32_decode(const std::string& s) {
    static const int map[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() * 5 / 8);
    int bits = 0;
    unsigned val = 0;
    for (char c : s) {
        if ((unsigned char)c >= sizeof(map) / sizeof(map[0])) return {};
        int v = map[(unsigned char)c];
        if (v < 0) return {};
        val = (val << 5) | (unsigned)v;
        bits += 5;
        if (bits >= 8) {
            out.push_back((uint8_t)((val >> (bits - 8)) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

static std::vector<uint8_t> collect_machine_hash_input() {
    std::string cpu = get_cpu_info();
    std::string vol = get_volume_serial();
    std::string combined = "CPU:" + cpu + ";VOL:" + vol;
    std::vector<uint8_t> out(combined.begin(), combined.end());
    return out;
}

} // namespace

std::vector<uint8_t> get_machine_hash() {
    auto input = collect_machine_hash_input();
    uint8_t hash[32];
    wh::sha256(input.data(), input.size(), hash);
    return std::vector<uint8_t>(hash, hash + 16);
}

std::string get_machine_code() {
    auto hash = get_machine_hash();
    return base32_encode(hash.data(), hash.size());
}

bool machine_code_to_hash(const std::string& code, std::vector<uint8_t>& out) {
    out = base32_decode(code);
    return out.size() == 16;
}

} // namespace wh
