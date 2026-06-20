#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wh {

// 注册码结构（v1）：
//   magic "REG\0" (4) + version(1) + machine_hash[0:8](8) + expire_unix LE(8) + flags(1) + hmac[0:16](16)
//   总长 38 字节，再经 URL-safe base64 编码（去掉 '=' 填充）后给用户。
// 签名 = HMAC-SHA256(master_key, version || machine_hash || expire_unix || flags) 前 16 字节。

struct LicenseInfo {
    uint8_t machine_hash[8] = {0};
    int64_t expire_unix = 0;   // 0 = 永久
    uint8_t flags = 0;
    uint8_t signature[16] = {0};
};

// 生成注册码。master_key 32 字节；machine_hash 至少 8 字节。
std::string license_generate(const uint8_t* master_key, size_t key_len,
                             const uint8_t* machine_hash, size_t hash_len,
                             int64_t expire_unix, uint8_t flags = 0);

// 解析注册码字符串。失败返回 false。
bool license_parse(const std::string& license_key, LicenseInfo& out);

// 验证注册码：签名正确、机器码前缀匹配、未过期。
// now 为当前 UTC 时间戳；machine_hash 为当前机器码完整哈希（至少 8 字节）。
bool license_verify(const LicenseInfo& lic,
                    const uint8_t* master_key, size_t key_len,
                    const uint8_t* machine_hash, size_t hash_len,
                    int64_t now_utc);

} // namespace wh
