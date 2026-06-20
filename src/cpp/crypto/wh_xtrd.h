#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace wh {

// 将麦语言源码包装为 WT8 可加载的 .XTRD 文本格式
std::vector<uint8_t> xtrd_wrap_source(const std::string& source,
                                      const char* author = "WH8CRYPTO");
std::vector<uint8_t> xtrd_wrap_locked_view(const std::string& contact_utf8);

// 文华「设置查看密码」后的 XTRD：含 <HEAD>，<CODE> 为十六进制密文
bool xtrd_is_password_protected(const uint8_t* data, size_t len);
bool xtrd_is_password_protected(const std::vector<uint8_t>& data);

} // namespace wh
