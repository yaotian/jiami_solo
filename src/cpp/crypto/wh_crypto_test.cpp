// wh_crypto_test.cpp — 密码学实现自检（NIST / RFC 官方测试向量）
//
// 用途：验证 SHA-256 / HMAC / HKDF / AES-256 / AES-256-GCM 实现正确。
// 同时做 C++ 端 package 打包/拆包的往返测试。
// 这是阶段 0 之前就能独立运行的正确性保证。
#include "wh_crypto.h"
#include "wh_packet.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;

static std::string hex(const uint8_t* p, size_t n) {
    std::string s; s.reserve(n * 2);
    static const char* h = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { s.push_back(h[p[i]>>4]); s.push_back(h[p[i]&0xf]); }
    return s;
}
static void check(const char* name, const std::string& got, const std::string& want) {
    bool ok = (got == want);
    printf("[%s] %s\n", ok ? "OK" : "FAIL", name);
    if (!ok) {
        g_fail++;
        printf("  got:  %s\n", got.c_str());
        printf("  want: %s\n", want.c_str());
    }
}

static void test_sha256() {
    // NIST: SHA-256("abc")
    uint8_t out[32];
    const char* m = "abc";
    wh::sha256((const uint8_t*)m, 3, out);
    check("sha256(abc)", hex(out, 32),
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // 长消息（56 字节，触发单块边界）
    m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    wh::sha256((const uint8_t*)m, 56, out);
    check("sha256(56B)", hex(out, 32),
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

static void test_hmac_sha256() {
    // RFC 4231 Test Case 1
    uint8_t key[20]; memset(key, 0x0b, 20);
    const char* msg = "Hi There";
    uint8_t out[32];
    wh::hmac_sha256(key, 20, (const uint8_t*)msg, 8, out);
    check("hmac-sha256(tc1)", hex(out, 32),
          "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

static void test_hkdf() {
    // RFC 5869 Test Case 1
    uint8_t ikm[22]; memset(ikm, 0x0b, 22);
    uint8_t salt[13] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c};
    uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    uint8_t okm[42];
    wh::hkdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42);
    check("hkdf-sha256(tc1)", hex(okm, 42),
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185665");
}

static void test_aes256() {
    // FIPS 197 附录 C.3 AES-256 单块
    uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    uint8_t in[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
    wh::GcmKey gk; wh::aes256_key_expand(key, gk);
    uint8_t out[16];
    // aes256_encrypt_block 是私有的，这里通过 GCM 间接覆盖；用 key_expand 的可观察点不便，
    // 改用一个已知 GCM 向量直接验证整条链。
    (void)out; (void)gk;
}

static void test_gcm() {
    // NIST GCM 测试用例 4（最常用：单块 + key 全 0/iv 全 0/plain 单块）
    uint8_t key[32] = {0};
    uint8_t iv[12]  = {0};
    uint8_t pt[16]  = {0};
    uint8_t ct[16]; uint8_t tag[16];
    wh::GcmKey gk; wh::aes256_key_expand(key, gk);
    wh::aes256gcm_encrypt(gk, iv, nullptr, 0, pt, 16, ct, tag);
    // AES-256-GCM NIST 向量（key=0, iv=0, pt=16字节0）
    //   ct  = cea7403d4d606b6e074ec5d3baf39d18
    //   tag = d0d1c8a799996bf0265b98b5d48ab919
    check("gcm-enc-ct",  hex(ct, 16), "cea7403d4d606b6e074ec5d3baf39d18");
    check("gcm-enc-tag", hex(tag, 16), "d0d1c8a799996bf0265b98b5d48ab919");

    // 解密往返
    uint8_t back[16];
    bool ok = wh::aes256gcm_decrypt(gk, iv, nullptr, 0, ct, 16, tag, back);
    check("gcm-decrypt-ok", ok ? "true" : "false", "true");
    check("gcm-decrypt-roundtrip", hex(back, 16), hex(pt, 16));

    // 篡改 tag 必失败
    uint8_t badtag[16]; memcpy(badtag, tag, 16); badtag[0] ^= 1;
    bool ok2 = wh::aes256gcm_decrypt(gk, iv, nullptr, 0, ct, 16, badtag, back);
    check("gcm-tamper-reject", ok2 ? "false" : "true", "true");
}

static void test_package() {
    // 主密钥（32 字节随机内容）
    uint8_t master[32];
    for (int i = 0; i < 32; ++i) master[i] = (uint8_t)(i * 7 + 3);

    wh::PackageHeader hdr{};
    hdr.product_id = wh::PRODUCT_T8_WH8;
    hdr.expire_unix = 1900000000LL; // 远期
    hdr.user = "客户张三";
    hdr.contact = "微信: zhangsan (到期请联系)";
    wh::random_bytes(hdr.nonce, 12);

    wh::PayloadPlain pl;
    pl.source = "// 我的指标\nRSI:=SMA(MAX(CLOSE-REF(CLOSE,1),0),6,1)/SMA(ABS(CLOSE-REF(CLOSE,1)),6,1)*100;\nRSI>70,BK;";
    pl.note = "RSI 超买买开示例";

    auto pkg = wh::package_build(master, hdr, pl);
    printf("[INFO] package size = %zu bytes\n", pkg.size());

    wh::PackageHeader hdr2{};
    wh::PayloadPlain pl2{};
    std::string err;
    bool ok = wh::package_parse(pkg, master, hdr2, pl2, &err);
    check("package-parse-ok", ok ? "true" : "false", "true");
    if (ok) {
        check("package-user", hdr2.user, hdr.user);
        check("package-contact", hdr2.contact, hdr.contact);
        check("package-expire", std::to_string(hdr2.expire_unix), std::to_string(hdr.expire_unix));
        check("package-source", pl2.source, pl.source);
        check("package-note", pl2.note, pl.note);
    }

    wh::PayloadPlain plx{};
    plx.note = "MYTEST";
    plx.xtrd_raw = { '<', 'H', 'E', 'A', 'D', '>', '\r', '\n', 'A', 'B', '\r', '\n',
                     '<', '/', 'H', 'E', 'A', 'D', '>', '\r', '\n', '<', 'C', 'O', 'D', 'E', '>', '\r', '\n',
                     '3', '6', '5', '6', '2', 'D', '0', 'B', 'C', 'C', '6', '2', '2', '0', '3', '8', 'E', '4', '4',
                     'E', '3', 'F', '6', 'B', 'B', 'E', 'C', '6', 'C', '4', 'D', '8', 'D', '6', '5', 'A', 'C', '0',
                     'C', 'B', '3', 'D', 'F', 'E', 'E', '4', 'D', 'E', '7', '9', 'F', '6', '1', 'A', 'C', 'F', 'C',
                     '5', 'B', 'C', 'F', '0', '0', '2', 'C', 'A', '1', '9', 'F', '8', '3', '1', '3', '2', '6', '3',
                     'D', 'A', '1', '5', '2', '7', '9', '6', '2', '6', 'D', '8', 'B', 'E', '6', '0', 'C', '8', '6',
                     'E', '4', 'F', '2', 'E', '3', 'C', 'F', '3', '6', '1', 'A', '3', '6', '0', 'C', '7', 'C', '9',
                     '4', '1', '3', '2', 'E', '6', '1', '5', '6', '1', '9', '4', '3', '7', '4', '4', 'C', '4', '0',
                     'B', 'D', 'F', '7', '5', '5', '3', '2', '6', 'D', 'C', '3', '2', '8', 'B', '8', '8', 'B', '4',
                     'A', '9', '1', 'D', 'F', 'D', '5', '7', '3', '3', '3', 'D', '3', 'E', '2', '3', '2', '8', '8',
                     '3', '6', 'A', '6', '7', '9', 'B', 'B', 'A', '3', 'D', 'F', '7', 'D', '2', 'D', '0', '1', '1',
                     'B', '0', 'C', '3', '4', '5', 'C', '6', '2', '3', 'E', '0', '7', '6', 'D', '5', '3', '6', '7',
                     'C', '4', '5', 'A', '8', '0', 'C', '5', '1', 'F', '0', 'C', '0', 'D', 'C', '5', 'A', '4', '4',
                     'A', '1', 'A', '4', '7', '1', '7', '6', '6', 'B', 'E', 'B', '4', 'A', 'D', '8', 'C', '9', 'A',
                     '0', '3', '\r', '\n', '<', '/', 'C', 'O', 'D', 'E', '>', '\r', '\n' };
    auto pkgx = wh::package_build(master, hdr, plx);
    wh::PayloadPlain plx2{};
    ok = wh::package_parse(pkgx, master, hdr2, plx2, &err);
    check("package-xtrd-parse", ok ? "true" : "false", "true");
    if (ok) {
        check("package-xtrd-len", std::to_string(plx2.xtrd_raw.size()), std::to_string(plx.xtrd_raw.size()));
        check("package-xtrd-protected",
              wh::xtrd_is_password_protected(plx2.xtrd_raw) ? "true" : "false", "true");
    }

    // 错误主密钥必须解密失败
    uint8_t bad[32]; memset(bad, 0, 32);
    wh::PackageHeader h3{}; wh::PayloadPlain p3{};
    bool ok2 = wh::package_parse(pkg, bad, h3, p3);
    check("package-wrong-key-reject", ok2 ? "false" : "true", "true");
}

int main() {
    test_sha256();
    test_hmac_sha256();
    test_hkdf();
    test_aes256();
    test_gcm();
    test_package();
    printf("\n==== %s (fails=%d) ====\n", g_fail ? "HAS FAILURES" : "ALL PASSED", g_fail);
    return g_fail ? 1 : 0;
}
