#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <cstring>

#include "wh_launcher.h"
#include "../crypto/wh_packet.h"
#include "../hook/wh_hook.h"
#include "wh_hwid.h"
#include "wh_license.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "comdlg32.lib")

#include "wh_launcher_config.h"

#ifndef WH_INDICATOR_VERSION
#define WH_INDICATOR_VERSION "1.0.0"
#endif
#ifndef WH_ENABLE_ANTI_DEBUG
#define WH_ENABLE_ANTI_DEBUG 0
#endif
#ifndef WH_LICENSE_KEY
#define WH_LICENSE_KEY ""
#endif
#ifndef WH_MACHINE_CODE
#define WH_MACHINE_CODE ""
#endif

#define WHPACKRES_TYPE MAKEINTRESOURCEW(256)
#define IDR_WHPACK_PACKAGE 101
#define IDR_WHPACK_HOOKDLL 102

static const wchar_t* kRegKey = L"Software\\WH8Crypto";
static const wchar_t* kRegLastRun = L"LastRunUTC";
static const wchar_t* kRegT8Path = L"T8ExePath";
static const wchar_t* kRegLicenseKey = L"LicenseKey";
static const wchar_t* kRegMachineCode = L"MachineCode";

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
} PEB, *PPEB;

static const wchar_t* kT8Names[] = {
    L"winwh8.exe", L"wh8.exe", L"wt8.exe", L"wh.exe", L"赢智.exe", nullptr
};

static std::vector<uint8_t> hex_to_vec(const char* hex) {
    size_t len = strlen(hex);
    std::vector<uint8_t> out(len / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        char buf[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtol(buf, nullptr, 16);
    }
    return out;
}

static int64_t get_current_unix_utc() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    int64_t ft100ns = ((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (ft100ns - 116444736000000000LL) / 10000000LL;
}

bool launcher::is_debugger_present() {
#if WH_ENABLE_ANTI_DEBUG
    if (IsDebuggerPresent()) return true;
#if defined(_WIN64)
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    if (peb && peb->BeingDebugged) return true;
#endif
    return false;
}

bool launcher::is_vm_detected() { return false; }

bool launcher::is_time_rollback_detected() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    int64_t now = ((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;

    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                        nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;

    DWORD sz = sizeof(int64_t);
    int64_t last = 0;
    if (RegQueryValueExW(h, kRegLastRun, nullptr, nullptr,
                         (LPBYTE)&last, &sz) == ERROR_SUCCESS) {
        if (now < last) { RegCloseKey(h); return true; }
    }
    RegSetValueExW(h, kRegLastRun, 0, REG_QWORD, (const BYTE*)&now, sizeof(now));
    RegCloseKey(h);
    return false;
}

void launcher::show_expired_dialog(const std::string& user, const std::string& contact,
                                   const std::string& indicator_version) {
    std::string msg = "授权已过期！\n\n";
    msg += "用户：" + user + "\n";
    msg += "版本：" + indicator_version + "\n\n";
    msg += "如需续期，请联系开发者：\n";
    msg += contact + "\n\n";
    msg += "联系后可获得最新版本的加密指标程序。";
    int wlen = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0);
    std::wstring wmsg(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, &wmsg[0], wlen);
    MessageBoxW(nullptr, wmsg.c_str(), L"文华指标授权过期",
                MB_OK | MB_ICONWARNING | MB_TOPMOST);
}

static std::wstring utf8_to_wstring(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len);
    out.pop_back();
    return out;
}

static std::string wstring_to_utf8(const std::wstring& s) {
    if (s.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &out[0], len, nullptr, nullptr);
    out.pop_back();
    return out;
}

static std::string reg_read_string(const wchar_t* name) {
    HKEY h;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegKey, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return "";
    char buf[512]{};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    LSTATUS st = RegQueryValueExW(h, name, nullptr, &type, (LPBYTE)buf, &sz);
    RegCloseKey(h);
    if (st != ERROR_SUCCESS || type != REG_SZ) return "";
    return std::string(buf);
}

static bool reg_write_string(const wchar_t* name, const std::string& value) {
    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &h, nullptr) != ERROR_SUCCESS)
        return false;
    std::wstring w = utf8_to_wstring(value);
    LSTATUS st = RegSetValueExW(h, name, 0, REG_SZ,
                                (const BYTE*)w.c_str(),
                                (DWORD)((w.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    return st == ERROR_SUCCESS;
}

struct LicenseDlgCtx {
    std::wstring machine_code;
    std::wstring license_key;
    bool ok = false;
    HWND hEdit = nullptr;
};

static INT_PTR CALLBACK LicenseDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    LicenseDlgCtx* ctx = (LicenseDlgCtx*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        ctx = (LicenseDlgCtx*)((LPCREATESTRUCT)lParam)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)ctx);
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        CreateWindowW(L"STATIC", L"机器码（请复制给开发者）：",
                      WS_VISIBLE | WS_CHILD, 10, 10, 360, 16, hWnd, (HMENU)100, hInst, nullptr);
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", ctx->machine_code.c_str(),
                        WS_VISIBLE | WS_CHILD | ES_READONLY | ES_AUTOHSCROLL,
                        10, 30, 360, 22, hWnd, (HMENU)101, hInst, nullptr);
        CreateWindowW(L"STATIC", L"注册码：",
                      WS_VISIBLE | WS_CHILD, 10, 65, 360, 16, hWnd, (HMENU)102, hInst, nullptr);
        ctx->hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
                                     10, 85, 360, 22, hWnd, (HMENU)103, hInst, nullptr);
        CreateWindowW(L"BUTTON", L"确定",
                      WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                      200, 125, 80, 26, hWnd, (HMENU)IDOK, hInst, nullptr);
        CreateWindowW(L"BUTTON", L"取消",
                      WS_VISIBLE | WS_CHILD,
                      290, 125, 80, 26, hWnd, (HMENU)IDCANCEL, hInst, nullptr);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK && ctx) {
            wchar_t buf[512]{};
            GetWindowTextW(ctx->hEdit, buf, 512);
            ctx->license_key = buf;
            ctx->ok = true;
            DestroyWindow(hWnd);
        } else if (LOWORD(wParam) == IDCANCEL && ctx) {
            DestroyWindow(hWnd);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

struct MachineCodeDlgCtx {
    std::wstring machine_code;
};

static INT_PTR CALLBACK MachineCodeDlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MachineCodeDlgCtx* ctx = (MachineCodeDlgCtx*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    switch (msg) {
    case WM_CREATE: {
        ctx = (MachineCodeDlgCtx*)((LPCREATESTRUCT)lParam)->lpCreateParams;
        SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)ctx);
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        CreateWindowW(L"STATIC", L"本程序已启用一机一码授权。",
                      WS_VISIBLE | WS_CHILD, 10, 10, 360, 16, hWnd, (HMENU)100, hInst, nullptr);
        CreateWindowW(L"STATIC", L"机器码（请选中后 Ctrl+C 复制给开发者）：",
                      WS_VISIBLE | WS_CHILD, 10, 35, 360, 16, hWnd, (HMENU)101, hInst, nullptr);
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", ctx->machine_code.c_str(),
                        WS_VISIBLE | WS_CHILD | ES_READONLY | ES_AUTOHSCROLL,
                        10, 55, 360, 22, hWnd, (HMENU)102, hInst, nullptr);
        CreateWindowW(L"STATIC", L"获取注册码后，关闭本窗口并重新运行程序。",
                      WS_VISIBLE | WS_CHILD, 10, 85, 360, 16, hWnd, (HMENU)103, hInst, nullptr);
        CreateWindowW(L"BUTTON", L"确定",
                      WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                      150, 115, 80, 26, hWnd, (HMENU)IDOK, hInst, nullptr);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK && ctx) {
            DestroyWindow(hWnd);
        } else if (LOWORD(wParam) == IDCANCEL && ctx) {
            DestroyWindow(hWnd);
        }
        return 0;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

static void show_machine_code_dialog(const std::string& machine_code) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = MachineCodeDlgProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"WH8MachineCodeDlg";
    if (!RegisterClassExW(&wc)) return;

    MachineCodeDlgCtx ctx;
    ctx.machine_code = utf8_to_wstring(machine_code);
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP,
        L"WH8MachineCodeDlg", L"一机一码授权",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 185,
        nullptr, nullptr, hInst, &ctx);
    if (!hDlg) {
        UnregisterClassW(L"WH8MachineCodeDlg", hInst);
        return;
    }
    ShowWindow(hDlg, SW_NORMAL);
    SetForegroundWindow(hDlg);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnregisterClassW(L"WH8MachineCodeDlg", hInst);
}

static std::string prompt_for_license_key(const std::string& machine_code) {
    HINSTANCE hInst = GetModuleHandleW(nullptr);
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = LicenseDlgProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"WH8LicenseDlg";
    if (!RegisterClassExW(&wc)) return "";

    LicenseDlgCtx ctx;
    ctx.machine_code = utf8_to_wstring(machine_code);
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP,
        L"WH8LicenseDlg", L"请输入注册码",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 210,
        nullptr, nullptr, hInst, &ctx);
    if (!hDlg) {
        UnregisterClassW(L"WH8LicenseDlg", hInst);
        return "";
    }
    ShowWindow(hDlg, SW_NORMAL);
    SetForegroundWindow(hDlg);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnregisterClassW(L"WH8LicenseDlg", hInst);
    return ctx.ok ? wstring_to_utf8(ctx.license_key) : "";
}

static void show_msg_utf8(const char* title, const char* msg, UINT icon);

bool launcher::check_machine_license(const uint8_t* master_key, size_t key_len,
                                     const std::string& embedded_machine_code,
                                     const std::string& embedded_license_key) {
    std::string current_machine_code = wh::get_machine_code();
    if (current_machine_code.empty()) {
        show_msg_utf8("授权错误", "无法读取本机机器码，程序无法运行。", MB_ICONERROR);
        return false;
    }

    std::vector<uint8_t> current_hash = wh::get_machine_hash();

    auto try_verify = [&](const std::string& key) -> bool {
        wh::LicenseInfo lic{};
        if (!wh::license_parse(key, lic)) return false;
        return wh::license_verify(lic, master_key, key_len, current_hash.data(), current_hash.size(),
                                  get_current_unix_utc());
    };

    // 1) 优先使用编译时嵌入的注册码（直接绑定机器）
    if (!embedded_license_key.empty()) {
        if (try_verify(embedded_license_key)) return true;
        show_msg_utf8("授权错误",
            "本机机器码与当前客户端不匹配，或注册码已过期。\n"
            "请联系开发者重新获取注册码。", MB_ICONERROR);
        return false;
    }

    // 2) 尝试注册表中已保存的注册码
    std::string saved_key = reg_read_string(kRegLicenseKey);
    if (!saved_key.empty() && try_verify(saved_key)) return true;

    // 3) 如果嵌入的机器码与当前机器不符，直接拒绝（严格绑定模式）
    if (!embedded_machine_code.empty()) {
        std::vector<uint8_t> embedded_hash;
        if (!wh::machine_code_to_hash(embedded_machine_code, embedded_hash) ||
            memcmp(embedded_hash.data(), current_hash.data(), 8) != 0) {
            show_msg_utf8("授权错误",
                "本机机器码与当前客户端不匹配。\n"
                "请联系开发者重新获取注册码。", MB_ICONERROR);
            return false;
        }
    }

    // 4) 弹窗让用户输入注册码
    show_machine_code_dialog(current_machine_code);

    for (int attempt = 0; attempt < 3; ++attempt) {
        std::string key = prompt_for_license_key(current_machine_code);
        if (key.empty()) break;
        if (try_verify(key)) {
            reg_write_string(kRegLicenseKey, key);
            reg_write_string(kRegMachineCode, current_machine_code);
            return true;
        }
        std::string err = "注册码无效、机器码不匹配或已过期，请重新输入。\n剩余次数：" +
                          std::to_string(2 - attempt) + " 次";
        show_msg_utf8("注册码错误", err.c_str(), MB_ICONERROR);
    }

    show_msg_utf8("授权失败", "未输入有效注册码，程序无法运行。", MB_ICONERROR);
    return false;
}

bool launcher::check_authorization(int64_t expire_unix, const std::string& user,
                                   const std::string& contact,
                                   const std::string& indicator_version, bool* expired) {
    if (expired) *expired = false;
    if (expire_unix == 0) return true;
    if (get_current_unix_utc() > expire_unix) {
        if (expired) *expired = true;
        show_expired_dialog(user, contact, indicator_version);
        return false;
    }
    return true;
}

DWORD launcher::find_t8_process() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; kT8Names[i]; ++i) {
                if (_wcsicmp(pe.szExeFile, kT8Names[i]) == 0) {
                    CloseHandle(snap);
                    return pe.th32ProcessID;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

std::wstring launcher::get_saved_t8_path() {
    HKEY h;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kRegKey, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return L"";
    wchar_t buf[MAX_PATH]{};
    DWORD sz = sizeof(buf);
    if (RegQueryValueExW(h, kRegT8Path, nullptr, nullptr, (LPBYTE)buf, &sz) != ERROR_SUCCESS) {
        RegCloseKey(h);
        return L"";
    }
    RegCloseKey(h);
    return buf;
}

void launcher::save_t8_path(const std::wstring& path) {
    HKEY h;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE,
                        nullptr, &h, nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExW(h, kRegT8Path, 0, REG_SZ,
                   (const BYTE*)path.c_str(),
                   (DWORD)((path.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
}

std::wstring launcher::types_dir_from_t8_exe(const std::wstring& t8_exe) {
    wchar_t dir[MAX_PATH]{};
    wcscpy_s(dir, t8_exe.c_str());
    PathRemoveFileSpecW(dir);
    std::wstring types = dir;
    types += L"\\Formula\\TYPES";
    return types;
}

std::wstring launcher::resolve_t8_exe_path(DWORD t8_pid) {
    std::wstring saved = get_saved_t8_path();
    if (!saved.empty() && GetFileAttributesW(saved.c_str()) != INVALID_FILE_ATTRIBUTES)
        return saved;

    if (t8_pid) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, t8_pid);
        if (hProc) {
            wchar_t path[MAX_PATH]{};
            DWORD sz = MAX_PATH;
            if (QueryFullProcessImageNameW(hProc, 0, path, &sz)) {
                CloseHandle(hProc);
                save_t8_path(path);
                return path;
            }
            CloseHandle(hProc);
        }
    }

    const wchar_t* fallbacks[] = {
        L"D:\\WT8模拟版\\wh8.exe",
        L"D:\\wh8迈科期货x64\\winwh8.exe",
        nullptr
    };
    for (int i = 0; fallbacks[i]; ++i) {
        if (GetFileAttributesW(fallbacks[i]) != INVALID_FILE_ATTRIBUTES) {
            save_t8_path(fallbacks[i]);
            return fallbacks[i];
        }
    }
    return L"";
}

static const uint8_t kBundleMagic[11] = {'W','H','B','U','N','D','L','E',0x00,0x01,0x00};

static bool parse_bundle(const std::vector<uint8_t>& bundle,
                         std::wstring& out_software_name,
                         std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& out_items,
                         std::string* err = nullptr) {
    auto fail = [&](const char* msg) -> bool {
        if (err) *err = msg;
        return false;
    };
    if (bundle.size() < sizeof(kBundleMagic)) return fail("bundle too small");
    if (memcmp(bundle.data(), kBundleMagic, sizeof(kBundleMagic)) != 0) return fail("bad bundle magic");
    size_t off = sizeof(kBundleMagic);
    if (off + 4 > bundle.size()) return fail("bad bundle version");
    uint32_t version = *(const uint32_t*)(bundle.data() + off); off += 4;
    if (version != 1) return fail("unsupported bundle version");
    if (off + 2 > bundle.size()) return fail("bad software_name length");
    uint16_t snlen = *(const uint16_t*)(bundle.data() + off); off += 2;
    if (off + snlen > bundle.size()) return fail("bad software_name");
    std::string sn((const char*)(bundle.data() + off), snlen);
    off += snlen;
    out_software_name.assign(sn.begin(), sn.end());
    if (off + 4 > bundle.size()) return fail("bad count");
    uint32_t count = *(const uint32_t*)(bundle.data() + off); off += 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (off + 2 > bundle.size()) return fail("bad name length");
        uint16_t nlen = *(const uint16_t*)(bundle.data() + off); off += 2;
        if (off + nlen > bundle.size()) return fail("bad name");
        std::string name((const char*)(bundle.data() + off), nlen);
        off += nlen;
        if (off + 4 > bundle.size()) return fail("bad pkg length");
        uint32_t plen = *(const uint32_t*)(bundle.data() + off); off += 4;
        if (off + plen > bundle.size()) return fail("bad pkg data");
        std::vector<uint8_t> pkg(bundle.data() + off, bundle.data() + off + plen);
        off += plen;
        std::wstring wname(name.begin(), name.end());
        out_items.emplace_back(wname, std::move(pkg));
    }
    return true;
}

static std::string base_name_of(const std::string& val) {
    std::string name = val;
    while (!name.empty() && (name.back() == '\r' || name.back() == '\n'))
        name.pop_back();
    size_t dot = name.find_last_of('.');
    return (dot != std::string::npos) ? name.substr(0, dot) : name;
}

static bool value_in_name_list(const std::string& val,
                               const std::vector<std::string>& names_u8) {
    std::string base = base_name_of(val);
    for (const std::string& n : names_u8) {
        if (_stricmp(base.c_str(), base_name_of(n).c_str()) == 0)
            return true;
    }
    return false;
}

static std::string rebuild_order_ini_with_indicators(std::string content,
                                                     const std::vector<std::string>& names_u8) {
    std::vector<std::string> lines;
    for (size_t i = 0; i < content.size(); ) {
        size_t j = content.find('\n', i);
        if (j == std::string::npos) j = content.size();
        std::string line = content.substr(i, j - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        i = j + 1;
    }

    std::vector<std::string> items;
    for (const std::string& line : lines) {
        if (line.rfind("ITEM", 0) == 0 && !value_in_name_list(line.substr(line.find('=') + 1), names_u8))
            items.push_back(line);
    }

    for (const std::string& name : names_u8) {
        char item_key[32];
        sprintf_s(item_key, "ITEM%04d", (int)items.size());
        items.push_back(std::string(item_key) + "=" + name);
    }

    std::string rebuilt = "[FILES]\r\n";
    char num_line[32];
    sprintf_s(num_line, "Num=%d", (int)items.size());
    rebuilt += num_line;
    rebuilt += "\r\n";
    for (const auto& item : items) {
        rebuilt += item;
        rebuilt += "\r\n";
    }
    return rebuilt;
}

bool launcher::write_indicator_stub_files(
    const std::wstring& software_dir,
    const std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& items) {
    if (software_dir.empty() || items.empty()) return false;

    CreateDirectoryW(software_dir.c_str(), nullptr);

    // 清理旧版单指标占位文件
    const wchar_t* legacy_names[] = {
        L"WH8Crypto.XTRD", L"WH8CRYPTO.XTRD", L"wh8crypto.xtrd", nullptr
    };
    for (int i = 0; legacy_names[i]; ++i)
        DeleteFileW((software_dir + L"\\" + legacy_names[i]).c_str());

    const DWORD kShare = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    for (const auto& item : items) {
        const std::wstring& name = item.first;
        const std::vector<uint8_t>& package = item.second;
        if (name.empty() || package.size() < 8 ||
            memcmp(package.data(), wh::kPkgMagic, 8) != 0)
            return false;

        std::wstring path = software_dir + L"\\" + name;
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesW(path.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);

        bool written = false;
        for (int attempt = 0; attempt < 5; ++attempt) {
            HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, kShare, nullptr,
                                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD n = 0;
                BOOL ok = WriteFile(hFile, package.data(), (DWORD)package.size(), &n, nullptr);
                CloseHandle(hFile);
                written = ok && n == package.size();
                if (written) break;
            }
            Sleep(200);
        }
        if (!written) return false;

        // 读回校验：客户磁盘上必须是 WHPKG 二次加密包
        HANDLE hVerify = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                     OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hVerify == INVALID_HANDLE_VALUE) return false;
        uint8_t magic[8]{};
        DWORD got = 0;
        BOOL ok = ReadFile(hVerify, magic, 8, &got, nullptr);
        CloseHandle(hVerify);
        if (!ok || got != 8 || memcmp(magic, wh::kPkgMagic, 8) != 0) return false;
    }
    return true;
}

bool launcher::register_in_order_ini(const std::wstring& order_ini,
                                     const std::vector<std::wstring>& xtrd_names) {
    if (GetFileAttributesW(order_ini.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;
    if (xtrd_names.empty()) return false;

    std::vector<std::string> names_u8;
    for (const std::wstring& xtrd_name : xtrd_names) {
        std::string name_u8;
        name_u8.reserve(xtrd_name.size());
        for (wchar_t ch : xtrd_name) {
            if (ch > 127) return false;
            name_u8.push_back((char)ch);
        }
        if (name_u8.empty()) return false;
        names_u8.push_back(name_u8);
    }

    const DWORD kShare = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    for (int attempt = 0; attempt < 5; ++attempt) {
        HANDLE hFile = CreateFileW(order_ini.c_str(), GENERIC_READ, kShare,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            Sleep(200);
            continue;
        }
        DWORD fsize = GetFileSize(hFile, nullptr);
        if (fsize == INVALID_FILE_SIZE || fsize > 1024 * 1024) {
            CloseHandle(hFile);
            return false;
        }
        std::string content(fsize, '\0');
        DWORD read = 0;
        if (!ReadFile(hFile, &content[0], fsize, &read, nullptr) || read != fsize) {
            CloseHandle(hFile);
            Sleep(200);
            continue;
        }
        CloseHandle(hFile);

        std::string new_content = rebuild_order_ini_with_indicators(content, names_u8);

        hFile = CreateFileW(order_ini.c_str(), GENERIC_WRITE, kShare, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            Sleep(200);
            continue;
        }
        DWORD written = 0;
        BOOL ok = WriteFile(hFile, new_content.data(), (DWORD)new_content.size(), &written, nullptr);
        CloseHandle(hFile);
        return ok && written == new_content.size();
    }
    return false;
}

static DWORD start_t8_exe(const std::wstring& exe_path) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmd(exe_path.begin(), exe_path.end());
    cmd.push_back(L'\0');
    if (!CreateProcessW(exe_path.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &si, &pi))
        return 0;
    CloseHandle(pi.hThread);
    DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    return pid;
}

DWORD launcher::launch_t8_process() {
    std::wstring saved = get_saved_t8_path();
    if (!saved.empty() && GetFileAttributesW(saved.c_str()) != INVALID_FILE_ATTRIBUTES) {
        DWORD pid = start_t8_exe(saved);
        if (pid) return pid;
    }

    const wchar_t* paths[] = {
        L"D:\\WT8模拟版\\wh8.exe",
        L"D:\\wh8迈科期货x64\\winwh8.exe",
        L"C:\\文华财经\\wh8\\winwh8.exe",
        L"D:\\文华财经\\wh8\\winwh8.exe",
        L"C:\\wh8\\winwh8.exe",
        L"D:\\wh8\\winwh8.exe",
        nullptr
    };
    for (int i = 0; paths[i]; ++i) {
        if (GetFileAttributesW(paths[i]) != INVALID_FILE_ATTRIBUTES) {
            save_t8_path(paths[i]);
            DWORD pid = start_t8_exe(paths[i]);
            if (pid) return pid;
        }
    }

    wchar_t filename[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = L"文华 T8/WH8/WT8 (*.exe)\0winwh8.exe;wt8.exe;wh8.exe\0所有文件 (*.*)\0*.*\0\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = L"请选择文华 T8/WH8/WT8 主程序";
    if (!GetOpenFileNameW(&ofn)) return 0;
    save_t8_path(filename);
    return start_t8_exe(filename);
}

bool launcher::inject_dll(DWORD target_pid, const std::wstring& dll_path) {
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, target_pid);
    if (!hProc) return false;

    size_t path_len = (dll_path.length() + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(hProc, nullptr, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hProc); return false; }

    if (!WriteProcessMemory(hProc, remote, dll_path.c_str(), path_len, nullptr)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoad = GetProcAddress(k32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
        (LPTHREAD_START_ROUTINE)pLoad, remote, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }
    WaitForSingleObject(hThread, 15000);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return exit_code != 0;
}

#ifndef WH_HOOK_VERSION
#define WH_HOOK_VERSION "5.0.9"
#endif

static HMODULE get_remote_module_base(DWORD pid, const wchar_t* module_name);

static std::string get_remote_hook_version(DWORD pid, const std::wstring& dll_path) {
    const wchar_t* mod_name = wcsrchr(dll_path.c_str(), L'\\');
    mod_name = mod_name ? mod_name + 1 : dll_path.c_str();
    HMODULE remote_base = get_remote_module_base(pid, mod_name);
    if (!remote_base) return "";

    HMODULE local = LoadLibraryW(dll_path.c_str());
    if (!local) return "";
    FARPROC sym = GetProcAddress(local, "Wh8CryptoHookVersion");
    if (!sym) {
        FreeLibrary(local);
        return "";
    }
    uintptr_t offset = (uintptr_t)sym - (uintptr_t)local;
    FreeLibrary(local);

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return "";
    char ver[32]{};
    SIZE_T n = 0;
    LPCVOID remote_sym = (LPCVOID)((uintptr_t)remote_base + offset);
    if (!ReadProcessMemory(hProc, remote_sym, ver, sizeof(ver) - 1, &n) || n == 0) {
        CloseHandle(hProc);
        return "";
    }
    CloseHandle(hProc);
    ver[sizeof(ver) - 1] = '\0';
    return std::string(ver);
}

static bool wh8_has_hook_module(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring name = me.szModule;
            for (auto& c : name) c = (wchar_t)towlower(c);
            if (name.find(L"wh8crypto") != std::wstring::npos)
                found = true;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static HMODULE get_remote_module_base(DWORD pid, const wchar_t* module_name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    HMODULE found = nullptr;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, module_name) == 0) {
                found = me.hModule;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

static bool trigger_hook_reload(DWORD target_pid, const std::wstring& dll_path) {
    HMODULE local = LoadLibraryW(dll_path.c_str());
    if (!local) return false;
    FARPROC fn_local = GetProcAddress(local, "Wh8CryptoReload");
    if (!fn_local) {
        FreeLibrary(local);
        return false;
    }
    uintptr_t offset = (uintptr_t)fn_local - (uintptr_t)local;
    FreeLibrary(local);

    const wchar_t* mod_name = wcsrchr(dll_path.c_str(), L'\\');
    mod_name = mod_name ? mod_name + 1 : dll_path.c_str();
    HMODULE remote = get_remote_module_base(target_pid, mod_name);
    if (!remote) return false;

    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                               PROCESS_VM_OPERATION | PROCESS_VM_READ,
                               FALSE, target_pid);
    if (!hProc) return false;

    auto remote_fn = (LPTHREAD_START_ROUTINE)((uintptr_t)remote + offset);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, remote_fn, nullptr, 0, nullptr);
    if (!hThread) {
        CloseHandle(hProc);
        return false;
    }
    WaitForSingleObject(hThread, 15000);
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    CloseHandle(hThread);
    CloseHandle(hProc);
    return exit_code == 0;
}

HANDLE launcher::create_shared_memory(DWORD target_pid,
                                      const uint8_t* master_key, size_t key_len,
                                      const std::vector<uint8_t>& bundle,
                                      const std::wstring& vdir) {
    size_t vdir_bytes = vdir.size() * sizeof(wchar_t);
    size_t total = 46 + 2 + vdir_bytes + 4 + bundle.size();

    std::vector<uint8_t> buf(total);
    memcpy(buf.data(), wh_hook::SharedMemLayout::kMagic, 6);
    *(uint32_t*)(buf.data() + 6) = wh_hook::SharedMemLayout::kVersion;
    memcpy(buf.data() + 14, master_key, key_len);

    size_t off = 46;
    *(uint16_t*)(buf.data() + off) = (uint16_t)vdir_bytes; off += 2;
    memcpy(buf.data() + off, vdir.c_str(), vdir_bytes); off += vdir_bytes;
    *(uint32_t*)(buf.data() + off) = (uint32_t)bundle.size(); off += 4;
    memcpy(buf.data() + off, bundle.data(), bundle.size());

    wchar_t name[128];
    swprintf_s(name, L"Global\\WH8_CRYPTO_%u", target_pid);
    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                     0, (DWORD)total, name);
    if (!hMap) {
        swprintf_s(name, L"WH8_CRYPTO_%u", target_pid);
        hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE,
                                  0, (DWORD)total, name);
    }
    if (!hMap) return nullptr;

    LPVOID view = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, total);
    if (!view) { CloseHandle(hMap); return nullptr; }
    memcpy(view, buf.data(), total);
    UnmapViewOfFile(view);
    return hMap;
}

static HANDLE create_hook_ready_event(DWORD target_pid) {
    wchar_t name[128];
    swprintf_s(name, L"Global\\WH8_CRYPTO_READY_%u", target_pid);
    HANDLE h = CreateEventW(nullptr, TRUE, FALSE, name);
    if (!h) {
        swprintf_s(name, L"WH8_CRYPTO_READY_%u", target_pid);
        h = CreateEventW(nullptr, TRUE, FALSE, name);
    }
    return h;
}

static bool wait_for_hook_ready(HANDLE hEvent, DWORD timeout_ms) {
    if (!hEvent) return false;
    return WaitForSingleObject(hEvent, timeout_ms) == WAIT_OBJECT_0;
}

std::vector<uint8_t> launcher::extract_resource(UINT res_id, const wchar_t* res_type) {
    HRSRC hr = FindResourceW(nullptr, MAKEINTRESOURCEW(res_id), res_type);
    if (!hr) return {};
    HGLOBAL hg = LoadResource(nullptr, hr);
    if (!hg) return {};
    DWORD size = SizeofResource(nullptr, hr);
    const void* data = LockResource(hg);
    if (!data || !size) return {};
    return std::vector<uint8_t>((const uint8_t*)data, (const uint8_t*)data + size);
}

std::wstring launcher::extract_hookdll_to_t8(const std::wstring& t8_exe) {
    auto dll_data = extract_resource(IDR_WHPACK_HOOKDLL, WHPACKRES_TYPE);
    if (dll_data.empty() || t8_exe.empty()) return L"";

    size_t slash = t8_exe.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    std::wstring dll_path = t8_exe.substr(0, slash) + L"\\" + wh_hook::kHookDllFileName;
    DeleteFileW((t8_exe.substr(0, slash) + L"\\wh8crypto_hook.dll").c_str());

    HANDLE hFile = CreateFileW(dll_path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return L"";
    DWORD written = 0;
    BOOL ok = WriteFile(hFile, dll_data.data(), (DWORD)dll_data.size(), &written, nullptr);
    CloseHandle(hFile);
    return (ok && written == dll_data.size()) ? dll_path : L"";
}

std::wstring launcher::extract_hookdll_to_temp() {
    auto dll_data = extract_resource(IDR_WHPACK_HOOKDLL, WHPACKRES_TYPE);
    if (dll_data.empty()) return L"";

    wchar_t temp_path[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_path);
    wchar_t dll_path[MAX_PATH];
    swprintf_s(dll_path, L"%swh8crypto_%u.dll", temp_path, GetCurrentProcessId());

    HANDLE hFile = CreateFileW(dll_path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return L"";
    DWORD written;
    WriteFile(hFile, dll_data.data(), (DWORD)dll_data.size(), &written, nullptr);
    CloseHandle(hFile);
    return dll_path;
}

static void show_msg_utf8(const char* title, const char* msg, UINT icon) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, msg, -1, nullptr, 0);
    std::wstring wmsg(wlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, &wmsg[0], wlen);
    int tlen = MultiByteToWideChar(CP_UTF8, 0, title, -1, nullptr, 0);
    std::wstring wtitle(tlen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, title, -1, &wtitle[0], tlen);
    MessageBoxW(nullptr, wmsg.c_str(), wtitle.c_str(), MB_OK | icon | MB_TOPMOST);
}

int launcher::run() {
    if (is_debugger_present()) ExitProcess(3);
    if (is_time_rollback_detected()) {
        show_msg_utf8("授权错误", "检测到系统时间异常，程序无法运行。\n请联系开发者。", MB_ICONERROR);
        return 3;
    }

    auto bundle = extract_resource(IDR_WHPACK_PACKAGE, WHPACKRES_TYPE);
    if (bundle.empty()) {
        show_msg_utf8("错误", "程序数据包缺失。请重新从开发者处获取完整程序。", MB_ICONERROR);
        return 3;
    }

    std::wstring software_name;
    std::vector<std::pair<std::wstring, std::vector<uint8_t>>> items;
    std::string err;
    if (!parse_bundle(bundle, software_name, items, &err)) {
        show_msg_utf8("错误", "数据包格式错误。", MB_ICONERROR);
        return 3;
    }
    if (items.empty()) {
        show_msg_utf8("错误", "数据包中不包含任何指标。", MB_ICONERROR);
        return 3;
    }

    // 用第一个 WHPKG 的元数据做授权检查（所有包共享同一套授权信息）
    wh::PackageHeader hdr{};
    if (!wh::package_parse_header(items[0].second, hdr, &err)) {
        show_msg_utf8("错误", "指标包格式错误。", MB_ICONERROR);
        return 3;
    }

    bool expired = false;
    if (!check_authorization(hdr.expire_unix, hdr.user, hdr.contact,
                             hdr.indicator_version.empty() ? WH_INDICATOR_VERSION : hdr.indicator_version,
                             &expired))
        return expired ? 1 : 3;

    auto master_key = hex_to_vec(WH_MASTER_KEY_HEX);
    if (master_key.size() != 32) {
        show_msg_utf8("错误", "程序完整性校验失败。", MB_ICONERROR);
        return 3;
    }

    // 一机一码校验（默认关闭：未嵌入机器码/注册码时直接通过）
    if (!check_machine_license(master_key.data(), master_key.size(),
                               WH_MACHINE_CODE, WH_LICENSE_KEY)) {
        return 3;
    }

    DWORD t8_pid = find_t8_process();
    if (!t8_pid) {
        t8_pid = launch_t8_process();
        if (!t8_pid) {
            show_msg_utf8("启动失败",
                "未找到文华 T8/WH8/WT8 程序，且无法自动启动。\n"
                "请先安装文华并重新运行本程序。", MB_ICONERROR);
            return 2;
        }
        for (int i = 0; i < 30; ++i) {
            Sleep(500);
            DWORD p = find_t8_process();
            if (p) { t8_pid = p; break; }
        }
    }

    std::wstring t8_path = resolve_t8_exe_path(t8_pid);
    if (t8_path.empty()) {
        show_msg_utf8("路径错误", "无法解析 WT8 安装路径，请重新选择 wh8.exe。", MB_ICONERROR);
        return 2;
    }
    std::wstring types_dir = types_dir_from_t8_exe(t8_path);
    if (software_name.empty())
        software_name = std::wstring(wh_hook::kDefaultVirtualFolder);
    std::wstring software_dir = types_dir + L"\\" + software_name;
    std::wstring order_ini = software_dir + L"\\Order.ini";
    std::wstring virtual_dir = software_dir;

    std::wstring dll_path = extract_hookdll_to_t8(t8_path);
    if (dll_path.empty())
        dll_path = extract_hookdll_to_temp();
    if (dll_path.empty()) {
        show_msg_utf8("注入失败", "无法释放 Hook DLL。", MB_ICONERROR);
        return 2;
    }

    const bool hook_loaded = wh8_has_hook_module(t8_pid);
    if (hook_loaded) {
        std::string loaded_ver = get_remote_hook_version(t8_pid, dll_path);
        if (loaded_ver.empty())
            loaded_ver = "(未知)";
        if (loaded_ver != WH_HOOK_VERSION) {
            std::string msg =
                "检测到文华8正在运行，且已加载旧版本指标组件。\n\n"
                "请按以下步骤操作：\n"
                "1. 完全退出文华8（任务管理器确认无 wh8.exe）\n"
                "2. 重新打开文华8\n"
                "3. 再运行本程序";
            show_msg_utf8("请先重启文华8", msg.c_str(), MB_ICONERROR);
            return 2;
        }
    }

    // 必须先注入 Hook，再写指标文件，避免 wh8 监控到文件变化后抢先读取 WHPKG 乱码
    HANDLE hShm = create_shared_memory(t8_pid, master_key.data(), master_key.size(),
                                       bundle, virtual_dir);
    if (!hShm) {
        show_msg_utf8("注入失败", "创建共享数据失败。", MB_ICONERROR);
        return 2;
    }

    HANDLE hReady = create_hook_ready_event(t8_pid);

    if (!hook_loaded) {
        if (!inject_dll(t8_pid, dll_path)) {
            if (hReady) CloseHandle(hReady);
            CloseHandle(hShm);
            show_msg_utf8("注入失败",
                "注入失败。\n"
                "可能原因：杀毒软件拦截（请加白名单后重试）或 T8 版本不兼容。\n\n"
                "详见随附《用户加白名单说明》。", MB_ICONERROR);
            return 2;
        }
    }

    if (!trigger_hook_reload(t8_pid, dll_path)) {
        if (hReady) CloseHandle(hReady);
        CloseHandle(hShm);
        show_msg_utf8("注入失败",
            "Hook 初始化失败。\n"
            "请确认 wh8 未被杀毒拦截，并重新启动 wh8 后再试。", MB_ICONERROR);
        return 2;
    }

    if (!wait_for_hook_ready(hReady, 15000)) {
        if (hReady) CloseHandle(hReady);
        CloseHandle(hShm);
        show_msg_utf8("注入失败",
            "Hook 初始化失败或超时，文华可能已退出。\n"
            "请确认 wh8 未被杀毒拦截，并重新启动 wh8 后再试。", MB_ICONERROR);
        return 2;
    }
    if (hReady) CloseHandle(hReady);
    CloseHandle(hShm);

    if (!write_indicator_stub_files(software_dir, items)) {
        show_msg_utf8("写入失败",
            "无法写入指标占位文件到软件目录。\n"
            "请确认 WT8 安装路径正确，并以管理员身份重试。", MB_ICONERROR);
        return 2;
    }

    std::vector<std::wstring> names;
    for (const auto& item : items) names.push_back(item.first);
    if (!register_in_order_ini(order_ini, names)) {
        show_msg_utf8("写入失败",
            "无法更新软件目录\\Order.ini。\n"
            "请关闭麦语言窗口后重试。", MB_ICONERROR);
        return 2;
    }

    std::string ver = hdr.indicator_version.empty() ? WH_INDICATOR_VERSION : hdr.indicator_version;
    std::string msg = "指标加载成功！\n\n用户：" + hdr.user + "\n版本：" + ver + "\n";
    int64_t remain = hdr.expire_unix - get_current_unix_utc();
    if (hdr.expire_unix > 0 && remain > 0)
        msg += "剩余授权：" + std::to_string((int)(remain / 86400)) + " 天\n";
    else if (hdr.expire_unix == 0)
        msg += "授权：永久\n";
    msg += "指标数量：" + std::to_string(items.size()) + "\n";
    msg += "\nHook 版本：" WH_HOOK_VERSION "\n"
           "加载步骤：K 线 → 右键 → 技术指标 → " + std::string(software_name.begin(), software_name.end()) + "。\n"
           "每次重启 wh8 后必须先运行本程序，否则加载会失败（无提示）。\n"
           "更换 Hook 版本后必须先完全退出 wh8 再运行。\n"
           "本程序运行后可关闭。";
    show_msg_utf8("文华指标加密工具", msg.c_str(), MB_ICONINFORMATION);
    return 0;
}
