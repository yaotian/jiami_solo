// wh_crypto.h — 文华指标加密工具 · 共享加密核心（C++）
//
// 提供：
//   • SHA-256
//   • HMAC-SHA256 / HKDF-SHA256
//   • AES-256 块加密（仅正向，GCM 只需正向）
//   • AES-256-GCM 加密/解密（带 16 字节认证标签）
//
// 纯 C++ 实现，无外部依赖，MSVC 单文件可编译。
// 与 C# 端 (src/csharp/Manager/Crypto) 保持算法与字节序完全一致。
//
// 安全说明：本实现用于本工具自有的数据包封装。AES-GCM / SHA-2 均为标准算法。
// 密码学正确性以 NIST SP 800-38D / FIPS 180-4 为准。
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace wh {

constexpr size_t kSha256Len   = 32;
constexpr size_t kAesKeyLen   = 32;   // AES-256
constexpr size_t kAesBlockLen = 16;
constexpr size_t kGcmNonceLen = 12;   // 推荐的 GCM nonce 长度
constexpr size_t kGcmTagLen   = 16;

// ---------------- SHA-256 ----------------
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
inline void sha256(const std::vector<uint8_t>& data, uint8_t out[32]) {
    sha256(data.data(), data.size(), out);
}

// ---------------- HMAC-SHA256 ----------------
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[32]);

// ---------------- HKDF-SHA256 ----------------
// RFC 5869。info 可为空。
void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

// ---------------- AES-256-GCM ----------------
struct GcmKey {
    uint8_t round_keys[15 * 16];  // 15 轮密钥（AES-256: Nr=14，需 15*16）
};

void aes256_key_expand(const uint8_t key[32], GcmKey& k);

// 加密：plaintext -> ciphertext(同长) + tag[16]。nonce 12 字节。
// aad/aad_len 可为 nullptr/0（附加认证数据，参与认证但不加密）。
void aes256gcm_encrypt(const GcmKey& k,
                       const uint8_t nonce[12],
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* plaintext, size_t pt_len,
                       uint8_t* ciphertext,                 // >= pt_len
                       uint8_t tag[16]);

// 解密：返回 true 表示认证通过。失败时 ciphertext 内容未定义。
bool aes256gcm_decrypt(const GcmKey& k,
                       const uint8_t nonce[12],
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* ciphertext, size_t ct_len,
                       const uint8_t tag[16],
                       uint8_t* plaintext);                  // >= ct_len

// ---------------- 工具 ----------------
// CSPRNG：填入随机字节（Windows RNG）。失败返回 false。
bool random_bytes(uint8_t* out, size_t len);

} // namespace wh
