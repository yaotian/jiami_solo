#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

namespace launcher {

int run();

bool is_debugger_present();
bool is_vm_detected();
bool is_time_rollback_detected();

bool check_authorization(int64_t expire_unix, const std::string& user,
                         const std::string& contact,
                         const std::string& indicator_version, bool* expired);

void show_expired_dialog(const std::string& user, const std::string& contact,
                         const std::string& indicator_version);

// 一机一码离线注册码校验。成功返回 true，失败返回 false 并弹窗提示。
bool check_machine_license(const uint8_t* master_key, size_t key_len,
                           const std::string& embedded_machine_code,
                           const std::string& embedded_license_key);

DWORD find_t8_process();
DWORD launch_t8_process();
std::wstring get_saved_t8_path();
void save_t8_path(const std::wstring& path);
std::wstring types_dir_from_t8_exe(const std::wstring& t8_exe);
std::wstring resolve_t8_exe_path(DWORD t8_pid);
bool register_in_order_ini(const std::wstring& order_ini,
                           const std::vector<std::wstring>& xtrd_names);
bool write_indicator_stub_files(const std::wstring& software_dir,
                                const std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& items);

bool inject_dll(DWORD target_pid, const std::wstring& dll_path);

HANDLE create_shared_memory(DWORD target_pid,
                            const uint8_t* master_key, size_t key_len,
                            const std::vector<uint8_t>& bundle,
                            const std::wstring& vdir);

std::vector<uint8_t> extract_resource(UINT res_id, const wchar_t* res_type);
std::wstring extract_hookdll_to_temp();
std::wstring extract_hookdll_to_t8(const std::wstring& t8_exe);

} // namespace launcher
