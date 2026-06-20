// wh_crypto.cpp — 文华指标加密工具 · 共享加密核心实现
//
// 纯标准 C++ 实现 SHA-256 / HMAC-SHA256 / HKDF-SHA256 / AES-256 / AES-256-GCM。
// 不依赖任何第三方密码库，便于 VMP 加壳与单文件分发。
// 与 C# 端 (src/csharp/Manager/Crypto) 保持算法与字节序完全一致。
#include "wh_crypto.h"

// CSPRNG 后端选择：
//   WH_HAVE_BCRYPT —— 使用 Windows BCryptGenRandom（正式构建，需 Windows SDK）
//   未定义时 —— 回退到用户层 RNG（仅用于无 SDK 环境下的算法自检，不可用于生产）
#ifdef WH_HAVE_BCRYPT
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt.lib")
#endif

#include <cstring>

namespace wh {

// ============================================================
// 字节序工具
// ============================================================
static void store64be(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void store32be(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (24 - 8 * i));
}

// ============================================================
// SHA-256 (FIPS 180-4)
// ============================================================
static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_compress(uint32_t H[8], const uint8_t blk[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (uint32_t)blk[i * 4] << 24 | (uint32_t)blk[i * 4 + 1] << 16 |
               (uint32_t)blk[i * 4 + 2] << 8 | (uint32_t)blk[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K256[i] + W[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint32_t H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t bitlen = (uint64_t)len * 8;

    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) sha256_compress(H, data + i * 64);

    uint8_t block[64];
    size_t rem = len - full * 64;
    memcpy(block, data + full * 64, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256_compress(H, block);
        memset(block, 0, 56);
    } else {
        memset(block + rem, 0, 56 - rem);
    }
    store64be(block + 56, bitlen);
    sha256_compress(H, block);

    for (int i = 0; i < 8; ++i) {
        out[i * 4]     = (uint8_t)(H[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(H[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(H[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(H[i]);
    }
}

// ============================================================
// HMAC-SHA256 (RFC 2104)
// ============================================================
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len,
                 uint8_t out[32]) {
    uint8_t k[64];
    if (key_len > 64) {
        sha256(key, key_len, k);
        memset(k + 32, 0, 32);
    } else {
        memcpy(k, key, key_len);
        memset(k + key_len, 0, 64 - key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    std::vector<uint8_t> inner(64 + msg_len);
    memcpy(inner.data(), ipad, 64);
    memcpy(inner.data() + 64, msg, msg_len);
    uint8_t inner_hash[32];
    sha256(inner.data(), inner.size(), inner_hash);

    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner_hash, 32);
    sha256(outer, 96, out);
}

// ============================================================
// HKDF-SHA256 (RFC 5869)
// ============================================================
void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    uint8_t prk[32];
    uint8_t default_salt[32];
    if (salt == nullptr || salt_len == 0) {
        memset(default_salt, 0, 32);
        salt = default_salt; salt_len = 32;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    uint8_t T[32];
    size_t T_len = 0;
    uint8_t counter = 1;
    size_t done = 0;
    std::vector<uint8_t> buf;
    while (done < out_len) {
        buf.clear();
        buf.insert(buf.end(), T, T + T_len);
        if (info && info_len) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(counter);
        hmac_sha256(prk, 32, buf.data(), buf.size(), T);
        T_len = 32;
        size_t n = (out_len - done < 32) ? (out_len - done) : 32;
        memcpy(out + done, T, n);
        done += n;
        ++counter;
    }
}

// ============================================================
// AES-256 (FIPS 197)
// ============================================================
static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void aes256_key_expand(const uint8_t key[32], GcmKey& k) {
    uint8_t* rk = k.round_keys;
    memcpy(rk, key, 32);
    // AES-256: Nk=8, Nr=14 -> 需要 (Nr+1)*Nb = 60 words = 240 字节
    for (int i = 8; i < 60; ++i) {
        uint8_t t[4] = { rk[(i-1)*4], rk[(i-1)*4+1], rk[(i-1)*4+2], rk[(i-1)*4+3] };
        if (i % 8 == 0) {
            uint8_t tmp = t[0]; t[0]=t[1]; t[1]=t[2]; t[2]=t[3]; t[3]=tmp;   // RotWord
            t[0]=sbox[t[0]]; t[1]=sbox[t[1]]; t[2]=sbox[t[2]]; t[3]=sbox[t[3]]; // SubWord
            t[0] ^= rcon[i/8];
        } else if (i % 8 == 4) {
            t[0]=sbox[t[0]]; t[1]=sbox[t[1]]; t[2]=sbox[t[2]]; t[3]=sbox[t[3]];
        }
        rk[i*4]   = rk[(i-8)*4]   ^ t[0];
        rk[i*4+1] = rk[(i-8)*4+1] ^ t[1];
        rk[i*4+2] = rk[(i-8)*4+2] ^ t[2];
        rk[i*4+3] = rk[(i-8)*4+3] ^ t[3];
    }
}

static void aes_add_round_key(uint8_t s[16], const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}
static void aes_sub_bytes(uint8_t s[16]) { for (int i = 0; i < 16; ++i) s[i] = sbox[s[i]]; }
static void aes_shift_rows(uint8_t s[16]) {
    uint8_t t;
    t = s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    t = s[2]; s[2]=s[10]; s[10]=t; t = s[6]; s[6]=s[14]; s[14]=t;
    t = s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}
static void aes_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = s + c * 4;
        uint8_t a0=col[0], a1=col[1], a2=col[2], a3=col[3];
        col[0] = (uint8_t)(gmul(a0,2) ^ gmul(a1,3) ^ a2 ^ a3);
        col[1] = (uint8_t)(a0 ^ gmul(a1,2) ^ gmul(a2,3) ^ a3);
        col[2] = (uint8_t)(a0 ^ a1 ^ gmul(a2,2) ^ gmul(a3,3));
        col[3] = (uint8_t)(gmul(a0,3) ^ a1 ^ a2 ^ gmul(a3,2));
    }
}

static void aes256_encrypt_block(const GcmKey& k, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[16];
    memcpy(s, in, 16);
    aes_add_round_key(s, k.round_keys);
    for (int r = 1; r <= 13; ++r) {
        aes_sub_bytes(s);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, k.round_keys + r * 16);
    }
    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_add_round_key(s, k.round_keys + 14 * 16);
    memcpy(out, s, 16);
}

// ============================================================
// AES-256-GCM (NIST SP 800-38D)
// ============================================================
// GF(2^128) 反射乘法：X = X * H
static void ghash_mult(uint8_t X[16], const uint8_t H[16]) {
    uint8_t Z[16] = {0};
    uint8_t V[16];
    memcpy(V, H, 16);
    for (int i = 0; i < 128; ++i) {
        if ((X[i/8] >> (7 - (i%8))) & 1) {
            for (int j = 0; j < 16; ++j) Z[j] ^= V[j];
        }
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; --j) V[j] = (uint8_t)((V[j] >> 1) | ((V[j-1] & 1) << 7));
        V[0] >>= 1;
        if (lsb) V[0] ^= 0xe1;
    }
    memcpy(X, Z, 16);
}

// 对数据进行完整 GHASH 累积（尾块自动补零到 16 字节）
static void ghash(uint8_t Y[16], const uint8_t H[16], const uint8_t* data, size_t len) {
    size_t full = len / 16;
    for (size_t i = 0; i < full; ++i) {
        for (int j = 0; j < 16; ++j) Y[j] ^= data[i * 16 + j];
        ghash_mult(Y, H);
    }
    size_t rem = len - full * 16;
    if (rem) {
        uint8_t blk[16] = {0};
        memcpy(blk, data + full * 16, rem);
        for (int j = 0; j < 16; ++j) Y[j] ^= blk[j];
        ghash_mult(Y, H);
    }
}

static void inc32(uint8_t cb[16]) {
    uint32_t c = ((uint32_t)cb[12] << 24) | ((uint32_t)cb[13] << 16) |
                 ((uint32_t)cb[14] << 8) | cb[15];
    c = (c + 1) & 0xffffffffu;
    cb[12] = (uint8_t)(c >> 24); cb[13] = (uint8_t)(c >> 16);
    cb[14] = (uint8_t)(c >> 8);  cb[15] = (uint8_t)c;
}

// GCTR：以 icb 为初始计数器
static void gctr(const GcmKey& k, const uint8_t icb[16],
                 const uint8_t* in, size_t len, uint8_t* out) {
    if (len == 0) return;
    uint8_t cb[16];
    memcpy(cb, icb, 16);
    size_t full = len / 16;
    for (size_t i = 0; i < full; ++i) {
        uint8_t ks[16];
        aes256_encrypt_block(k, cb, ks);
        for (int j = 0; j < 16; ++j) out[i*16+j] = in[i*16+j] ^ ks[j];
        inc32(cb);
    }
    size_t rem = len - full * 16;
    if (rem) {
        uint8_t ks[16];
        aes256_encrypt_block(k, cb, ks);
        for (size_t j = 0; j < rem; ++j) out[full*16+j] = in[full*16+j] ^ ks[j];
    }
}

void aes256gcm_encrypt(const GcmKey& k,
                       const uint8_t nonce[12],
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* plaintext, size_t pt_len,
                       uint8_t* ciphertext,
                       uint8_t tag[16]) {
    uint8_t H[16] = {0};
    aes256_encrypt_block(k, H, H);              // H = E_K(0^128)

    uint8_t J0[16] = {0};
    memcpy(J0, nonce, 12);
    J0[15] = 1;                                  // J0 = nonce || 0^31 || 1

    // C = GCTR(inc32(J0), P)
    uint8_t icb[16];
    memcpy(icb, J0, 16);
    inc32(icb);
    gctr(k, icb, plaintext, pt_len, ciphertext);

    // S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
    uint8_t Y[16] = {0};
    ghash(Y, H, aad, aad_len);
    ghash(Y, H, ciphertext, pt_len);
    uint8_t lenblk[16];
    store64be(lenblk, (uint64_t)aad_len * 8);
    store64be(lenblk + 8, (uint64_t)pt_len * 8);
    for (int j = 0; j < 16; ++j) Y[j] ^= lenblk[j];
    ghash_mult(Y, H);

    // T = MSB_t(GCTR_K(J0, S))
    uint8_t ks[16];
    aes256_encrypt_block(k, J0, ks);
    for (int j = 0; j < 16; ++j) tag[j] = Y[j] ^ ks[j];
}

bool aes256gcm_decrypt(const GcmKey& k,
                       const uint8_t nonce[12],
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* ciphertext, size_t ct_len,
                       const uint8_t tag[16],
                       uint8_t* plaintext) {
    uint8_t H[16] = {0};
    aes256_encrypt_block(k, H, H);

    uint8_t J0[16] = {0};
    memcpy(J0, nonce, 12);
    J0[15] = 1;

    // 先验算 tag
    uint8_t Y[16] = {0};
    ghash(Y, H, aad, aad_len);
    ghash(Y, H, ciphertext, ct_len);
    uint8_t lenblk[16];
    store64be(lenblk, (uint64_t)aad_len * 8);
    store64be(lenblk + 8, (uint64_t)ct_len * 8);
    for (int j = 0; j < 16; ++j) Y[j] ^= lenblk[j];
    ghash_mult(Y, H);

    uint8_t calc_tag[16];
    uint8_t ks[16];
    aes256_encrypt_block(k, J0, ks);
    for (int j = 0; j < 16; ++j) calc_tag[j] = Y[j] ^ ks[j];

    // 常量时间比较
    uint8_t diff = 0;
    for (int j = 0; j < 16; ++j) diff |= (uint8_t)(calc_tag[j] ^ tag[j]);
    if (diff) return false;

    // tag 通过，CTR 解密
    uint8_t icb[16];
    memcpy(icb, J0, 16);
    inc32(icb);
    gctr(k, icb, ciphertext, ct_len, plaintext);
    return true;
}

// ============================================================
// CSPRNG
// ============================================================
#ifdef WH_HAVE_BCRYPT
// 正式路径：Windows BCryptGenRandom（需 Windows SDK / bcrypt.lib）
bool random_bytes(uint8_t* out, size_t len) {
    return BCryptGenRandom(nullptr, out, (ULONG)len,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}
#else
// 回退路径（无 BCrypt 时）：仅用于无 SDK 环境自检
bool random_bytes(uint8_t* out, size_t len) {
    static uint64_t s = 0;
    if (s == 0) {
        s = 0x243F6A8885A308D3ULL;
    }
    size_t i = 0;
    while (i < len) {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        s *= 0x2545F4914F6CDD1DULL;
        out[i++] = (uint8_t)(s & 0xff);
    }
    return true;
}
#endif

} // namespace wh
