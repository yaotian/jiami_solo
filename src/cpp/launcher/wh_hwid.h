#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wh {

// 获取本机机器码（Base32 大写，无填充，26 字符）。
// 基于 CPU 信息 + 系统盘卷序列号 + 主板序列号（若可用）的 SHA256 前 16 字节。
std::string get_machine_code();

// 获取机器码原始 16 字节哈希。
std::vector<uint8_t> get_machine_hash();

// 将机器码字符串还原为 16 字节哈希。
bool machine_code_to_hash(const std::string& code, std::vector<uint8_t>& out);

} // namespace wh
