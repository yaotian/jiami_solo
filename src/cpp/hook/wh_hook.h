#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace wh_hook {

constexpr const wchar_t* kHookDllFileName = L"wh8crypto_v5.dll";
constexpr const wchar_t* kUserTypesSubdir = L"自编";
// 与 WT8 Order.ini 大小写一致，避免与「更新」自动扫描重复
constexpr const wchar_t* kDefaultVirtualFileName = L"WH8CRYPTO.XTRD";
// 兼容旧路径（部分 WT8 安装使用 TYPES\WH8Crypto\）
constexpr const wchar_t* kDefaultVirtualFolder = L"WH8Crypto";

constexpr uint64_t kVirtualHandleMagic = 0xDEAD0000FFFF0000ULL;
inline bool is_virtual_handle(HANDLE h) {
    return ((uint64_t)(uintptr_t)h & 0xFFFFFFFF00000000ULL) == kVirtualHandleMagic;
}

struct SharedMemLayout {
    static constexpr char kMagic[6] = {'W','H','S','M','M','\0'};
    static constexpr uint32_t kVersion = 3;
};

bool hook_install(const uint8_t* shared_mem, size_t mem_size);
void hook_uninstall();
// WH8 运行中仅刷新 payload，不卸载 MinHook（避免 wh8 随机退出）
bool hook_refresh_payload(const uint8_t* shared_mem, size_t mem_size);

} // namespace wh_hook
