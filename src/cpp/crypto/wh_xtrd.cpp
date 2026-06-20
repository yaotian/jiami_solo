#include "wh_xtrd.h"
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <cctype>

namespace wh {

static std::string utf8_to_gbk(const std::string& utf8) {
    if (utf8.empty()) return utf8;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (wlen <= 1) return utf8;
    std::vector<wchar_t> w((size_t)wlen);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, w.data(), wlen);
    int glen = WideCharToMultiByte(936, 0, w.data(), -1, nullptr, 0, nullptr, nullptr);
    if (glen <= 1) return utf8;
    std::string gbk((size_t)glen - 1, '\0');
    WideCharToMultiByte(936, 0, w.data(), -1, &gbk[0], glen, nullptr, nullptr);
    return gbk;
}

static std::string local_edit_time_gbk() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    wchar_t wbuf[64];
    swprintf_s(wbuf, L"%04d年%02d月%02d日%02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    char buf[64]{};
    WideCharToMultiByte(936, 0, wbuf, -1, buf, (int)sizeof(buf), nullptr, nullptr);
    return buf;
}

std::vector<uint8_t> xtrd_wrap_source(const std::string& source, const char* author) {
    std::string code_gbk = utf8_to_gbk(source);
    std::string body;
    body += "<PARAMDEFAULTSET>\r\n1\r\n\r\n</PARAMDEFAULTSET>\r\n";
    body += "<CODE>\r\n";
    body += code_gbk;
    if (!source.empty() && source.back() != '\n') {
        if (source.size() < 2 || source.compare(source.size() - 2, 2, "\r\n") != 0)
            body += "\r\n";
    }
    body += "\r\n</CODE>\r\n";
    body += "<VERSION>\r\n130112\r\n</VERSION>\r\n";
    body += "<EDITTIME>\r\n";
    body += local_edit_time_gbk();
    body += "\r\n</EDITTIME>\r\n";
    body += "<AUTHOR>\r\n";
    body += author ? author : "WH8CRYPTO";
    body += "\r\n</AUTHOR>\r\n";
    body += "<PROPERTY>\r\n1\r\n</PROPERTY>\r\n";
    body.push_back('\0');
    return std::vector<uint8_t>(body.begin(), body.end());
}

std::vector<uint8_t> xtrd_wrap_locked_view(const std::string& contact_utf8) {
    std::string msg = std::string(u8"// 本指标源码已加密保护，不可查看\r\n// ") +
        (contact_utf8.empty() ? std::string(u8"请联系开发者") : contact_utf8) +
        "\r\n";
    return xtrd_wrap_source(msg);
}

static bool section_body_is_hex_cipher(const std::string& body) {
    size_t n = 0;
    for (char c : body) {
        if (c == '\r' || c == '\n') continue;
        if (!std::isxdigit((unsigned char)c)) return false;
        ++n;
    }
    return n >= 32;
}

static bool find_tag_body(const std::string& text, const char* tag, std::string& out) {
    std::string open = std::string("<") + tag + ">";
    std::string close = std::string("</") + tag + ">";
    size_t s = text.find(open);
    if (s == std::string::npos) return false;
    s += open.size();
    while (s < text.size() && (text[s] == '\r' || text[s] == '\n')) ++s;
    size_t e = text.find(close, s);
    if (e == std::string::npos) return false;
    out.assign(text.substr(s, e - s));
    return true;
}

bool xtrd_is_password_protected(const uint8_t* data, size_t len) {
    if (!data || len < 16) return false;
    std::string text((const char*)data, len);
    if (text.find("<HEAD>") == std::string::npos) return false;
    std::string code;
    if (!find_tag_body(text, "CODE", code)) return false;
    return section_body_is_hex_cipher(code);
}

bool xtrd_is_password_protected(const std::vector<uint8_t>& data) {
    return xtrd_is_password_protected(data.data(), data.size());
}

} // namespace wh
