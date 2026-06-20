#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>

#include "wh_hook.h"
#include "../crypto/wh_crypto.h"
#include "../crypto/wh_packet.h"
#include "../crypto/wh_xtrd.h"
#include <MinHook.h>

namespace {

struct HandleCtx {
    std::wstring filename;
    size_t offset = 0;
};

struct EnumState {
    HANDLE real_handle = INVALID_HANDLE_VALUE;
    bool virtual_sent = false;
    bool inject_subdir = false;
    std::vector<std::wstring> inject_files;
    size_t current_file_index = 0;
};

struct VirtualHandleInfo {
    size_t read_offset = 0;
    std::wstring filename;
};

struct HookState {
    bool initialized = false;
    std::unordered_map<std::wstring, std::vector<uint8_t>> file_plains;
    std::wstring types_root;
    std::wstring virtual_subdir_name;
    bool inject_subdir_at_types_root = false;
    std::wstring virtual_dir;
    std::wstring software_name;
    int64_t expire_unix = 0;
    std::string user;
    std::string contact;
    std::string indicator_version;

    volatile uint32_t next_handle_id = 1;
    std::mutex handle_mutex;
    std::unordered_map<uint32_t, VirtualHandleInfo> virtual_handles;
    std::unordered_map<uint64_t, EnumState> enum_states;
    std::unordered_map<uint64_t, HandleCtx> tracked_handles;

    decltype(&FindFirstFileW)  orig_FindFirstFileW  = nullptr;
    decltype(&FindNextFileW)   orig_FindNextFileW   = nullptr;
    decltype(&CreateFileW)     orig_CreateFileW     = nullptr;
    decltype(&CreateFileA)     orig_CreateFileA     = nullptr;
    decltype(&CreateFileMappingW) orig_CreateFileMappingW = nullptr;
    decltype(&CreateFileMappingA) orig_CreateFileMappingA = nullptr;
    decltype(&MapViewOfFile)   orig_MapViewOfFile   = nullptr;
    decltype(&UnmapViewOfFile) orig_UnmapViewOfFile = nullptr;
    decltype(&SetFilePointer)  orig_SetFilePointer  = nullptr;
    decltype(&SetFilePointerEx) orig_SetFilePointerEx = nullptr;
    decltype(&ReadFile)        orig_ReadFile        = nullptr;
    decltype(&GetFileSize)     orig_GetFileSize     = nullptr;
    decltype(&GetFileSizeEx)   orig_GetFileSizeEx   = nullptr;
    decltype(&GetFileInformationByHandle) orig_GetFileInformationByHandle = nullptr;
    decltype(&GetFileInformationByHandleEx) orig_GetFileInformationByHandleEx = nullptr;
    decltype(&FlushFileBuffers) orig_FlushFileBuffers = nullptr;
    decltype(&DuplicateHandle) orig_DuplicateHandle = nullptr;
    decltype(&CloseHandle) orig_CloseHandle = nullptr;
};

static HookState g;
static std::recursive_mutex g_track_mutex;
static std::unordered_map<std::wstring, HANDLE> g_file_plain_map_cache;
static std::atomic<bool> g_has_tracked_handles{false};

struct WStringIHash {
    size_t operator()(const std::wstring& s) const noexcept {
        std::wstring lower = s;
        for (auto& c : lower) c = (wchar_t)towlower(c);
        return std::hash<std::wstring>{}(lower);
    }
};

struct WStringIEq {
    bool operator()(const std::wstring& a, const std::wstring& b) const noexcept {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i)
            if (towlower(a[i]) != towlower(b[i])) return false;
        return true;
    }
};

static const std::vector<uint8_t>* get_plain(const std::wstring& filename) {
    auto it = g.file_plains.find(filename);
    return it == g.file_plains.end() ? nullptr : &it->second;
}

static size_t get_plain_size(const std::wstring& filename) {
    auto p = get_plain(filename);
    return p ? p->size() : 0;
}

static bool is_our_filename(const std::wstring& fname) {
    return get_plain(fname) != nullptr;
}

static std::wstring filename_from_path(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? path : path.substr(slash + 1);
}

static void sync_tracked_flag_locked() {
    g_has_tracked_handles.store(!g.tracked_handles.empty(), std::memory_order_relaxed);
}

static inline bool wh8crypto_hooks_active() {
    return g_has_tracked_handles.load(std::memory_order_relaxed);
}

static void invalidate_plain_map_cache() {
    for (auto& kv : g_file_plain_map_cache) {
        if (kv.second) {
            if (g.orig_CloseHandle)
                g.orig_CloseHandle(kv.second);
            else
                CloseHandle(kv.second);
        }
    }
    g_file_plain_map_cache.clear();
}

static void hook_log(const char* msg) {
    char path[MAX_PATH]{};
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "wh8crypto_hook.log");
    HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    char line[512];
    sprintf_s(line, "[%02d:%02d:%02d] %s\r\n", st.wHour, st.wMinute, st.wSecond, msg);
    DWORD w = 0;
    WriteFile(h, line, (DWORD)strlen(line), &w, nullptr);
    CloseHandle(h);
}

static void untrack_handle(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return;
    if (!wh8crypto_hooks_active()) return;
    uint64_t id = (uint64_t)(uintptr_t)h;
    std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
    g.tracked_handles.erase(id);
    sync_tracked_flag_locked();
}

static std::wstring normalize_path(const std::wstring& p) {
    if (p.empty()) return p;
    std::wstring out = p;
    if (out.rfind(L"\\\\?\\", 0) == 0) {
        out = out.substr(4);
        if (out.rfind(L"UNC\\", 0) == 0) out = L"\\" + out.substr(3);
    }
    for (auto& c : out) if (c == L'/') c = L'\\';
    while (out.size() > 1 && out.back() == L'\\') out.pop_back();
    return out;
}

static std::wstring resolve_long_path(const wchar_t* path) {
    if (!path || !path[0]) return L"";
    std::wstring norm = normalize_path(path);
    wchar_t long_path[MAX_PATH * 4]{};
    DWORD n = GetLongPathNameW(norm.c_str(), long_path, (DWORD)(sizeof(long_path) / sizeof(wchar_t)));
    if (n > 0 && n < sizeof(long_path) / sizeof(wchar_t))
        return normalize_path(long_path);
    return norm;
}

static std::wstring resolve_long_path_ansi(LPCSTR path) {
    if (!path || !path[0]) return L"";
    wchar_t wpath[MAX_PATH * 4]{};
    MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, (int)(sizeof(wpath) / sizeof(wchar_t)));
    return resolve_long_path(wpath);
}

static bool path_is_our_indicator(const std::wstring& path) {
    if (path.empty() || g.virtual_dir.empty()) return false;
    std::wstring norm = resolve_long_path(path.c_str());
    size_t slash = norm.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    std::wstring dir = norm.substr(0, slash);
    std::wstring fname = norm.substr(slash + 1);
    return _wcsicmp(dir.c_str(), g.virtual_dir.c_str()) == 0 && is_our_filename(fname);
}

static bool path_matches_virtual(const std::wstring& path) {
    return path_is_our_indicator(path);
}

static bool path_matches_virtual(LPCWSTR path) {
    return path && path_is_our_indicator(path);
}

static bool handle_is_wh8crypto(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE) return false;
    if (wh_hook::is_virtual_handle(h)) return true;
    std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
    return g.tracked_handles.find((uint64_t)(uintptr_t)h) != g.tracked_handles.end();
}

static void track_real_handle(HANDLE h, const std::wstring& path_hint) {
    if (!h || h == INVALID_HANDLE_VALUE) return;
    std::wstring filename;
    if (!path_hint.empty() && path_is_our_indicator(path_hint)) {
        filename = filename_from_path(path_hint);
    } else {
        wchar_t path_buf[MAX_PATH * 4]{};
        DWORD n = GetFinalPathNameByHandleW(h, path_buf,
            (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
        if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t)) {
            std::wstring resolved = resolve_long_path(path_buf);
            if (path_is_our_indicator(resolved))
                filename = filename_from_path(resolved);
        }
    }
    if (filename.empty()) return;
    std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
    g.tracked_handles[(uint64_t)(uintptr_t)h] = {filename, 0};
    sync_tracked_flag_locked();
}

static std::wstring get_tracked_filename(HANDLE h) {
    std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
    auto it = g.tracked_handles.find((uint64_t)(uintptr_t)h);
    return it == g.tracked_handles.end() ? L"" : it->second.filename;
}

static size_t* tracked_handle_offset_locked(HANDLE hFile) {
    if (!hFile || hFile == INVALID_HANDLE_VALUE || wh_hook::is_virtual_handle(hFile))
        return nullptr;
    auto it = g.tracked_handles.find((uint64_t)(uintptr_t)hFile);
    return it == g.tracked_handles.end() ? nullptr : &it->second.offset;
}

static bool is_wildcard_search(const std::wstring& path) {
    return path.find(L'*') != std::wstring::npos || path.find(L'?') != std::wstring::npos;
}

static bool search_targets_virtual_dir(const std::wstring& search_path) {
    if (g.virtual_dir.empty()) return false;
    std::wstring norm = normalize_path(search_path);
    std::wstring dir = norm;
    size_t slash = norm.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir = norm.substr(0, slash);
    else dir.clear();
    if (dir.empty()) return false;
    return _wcsicmp(dir.c_str(), g.virtual_dir.c_str()) == 0;
}

static bool is_types_root_wildcard(const std::wstring& search_path) {
    if (g.types_root.empty() || !is_wildcard_search(search_path)) return false;
    std::wstring norm = normalize_path(search_path);
    size_t slash = norm.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return false;
    std::wstring parent = norm.substr(0, slash);
    return _wcsicmp(parent.c_str(), g.types_root.c_str()) == 0;
}

static void make_virtual_subdir_find_data(WIN32_FIND_DATAW* fd) {
    ZeroMemory(fd, sizeof(*fd));
    wcscpy_s(fd->cFileName, g.virtual_subdir_name.c_str());
    fd->dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    fd->ftCreationTime = ft;
    fd->ftLastWriteTime = ft;
    fd->ftLastAccessTime = ft;
}

static bool pattern_matches_filename(const std::wstring& pattern, const std::wstring& name) {
    return PathMatchSpecW(name.c_str(), pattern.c_str()) != FALSE;
}

static HANDLE alloc_virtual_handle(const std::wstring& filename = L"") {
    std::lock_guard<std::mutex> lk(g.handle_mutex);
    uint32_t id = g.next_handle_id++;
    VirtualHandleInfo vi{};
    vi.filename = filename;
    g.virtual_handles[id] = vi;
    return (HANDLE)(uintptr_t)(wh_hook::kVirtualHandleMagic | id);
}

static void free_virtual_handle(HANDLE h) {
    if (!wh_hook::is_virtual_handle(h)) return;
    uint32_t id = (uint32_t)(uintptr_t)h;
    std::lock_guard<std::mutex> lk(g.handle_mutex);
    g.virtual_handles.erase(id);
}

static VirtualHandleInfo* get_virtual_info(HANDLE h) {
    if (!wh_hook::is_virtual_handle(h)) return nullptr;
    uint32_t id = (uint32_t)(uintptr_t)h;
    std::lock_guard<std::mutex> lk(g.handle_mutex);
    auto it = g.virtual_handles.find(id);
    return it == g.virtual_handles.end() ? nullptr : &it->second;
}

static void make_virtual_find_data(const std::wstring& filename, WIN32_FIND_DATAW* fd) {
    ZeroMemory(fd, sizeof(*fd));
    wcscpy_s(fd->cFileName, filename.c_str());
    fd->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    fd->nFileSizeLow = (DWORD)get_plain_size(filename);
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    fd->ftCreationTime = ft;
    fd->ftLastWriteTime = ft;
    fd->ftLastAccessTime = ft;
}

static bool parse_shared_mem(const uint8_t* mem, size_t mem_size,
                             const uint8_t** master_key, size_t* key_len,
                             const uint8_t** bundle_data, size_t* bundle_len,
                             std::wstring* vdir) {
    if (mem_size < 46) return false;
    if (memcmp(mem, wh_hook::SharedMemLayout::kMagic, 6) != 0) return false;
    uint32_t version = *(const uint32_t*)(mem + 6);
    if (version != wh_hook::SharedMemLayout::kVersion) return false;

    *master_key = mem + 14;
    *key_len = 32;
    size_t off = 46;

    if (off + 2 > mem_size) return false;
    uint16_t vdir_bytes = *(const uint16_t*)(mem + off); off += 2;
    if (off + vdir_bytes > mem_size) return false;
    vdir->assign((const wchar_t*)(mem + off), vdir_bytes / sizeof(wchar_t));
    off += vdir_bytes;

    if (off + 4 > mem_size) return false;
    *bundle_len = *(const uint32_t*)(mem + off); off += 4;
    if (off + *bundle_len > mem_size) return false;
    *bundle_data = mem + off;
    return true;
}

static bool parse_bundle(const std::vector<uint8_t>& bundle,
                         std::wstring& out_software_name,
                         std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& out_items,
                         std::string* err = nullptr) {
    auto fail = [&](const char* msg) -> bool {
        if (err) *err = msg;
        return false;
    };
    static const uint8_t kMagic[11] = {'W','H','B','U','N','D','L','E',0x00,0x01,0x00};
    if (bundle.size() < sizeof(kMagic)) return fail("bundle too small");
    if (memcmp(bundle.data(), kMagic, sizeof(kMagic)) != 0) return fail("bad bundle magic");
    size_t off = sizeof(kMagic);
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

static HANDLE WINAPI hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) {
    std::wstring norm = lpFileName ? normalize_path(lpFileName) : L"";

    // 直接访问某个我们的文件
    if (!norm.empty() && path_is_our_indicator(norm)) {
        std::wstring fname = filename_from_path(norm);
        make_virtual_find_data(fname, lpFindFileData);
        return alloc_virtual_handle(fname);
    }

    // TYPES 根目录枚举：注入虚拟子文件夹 software_name
    if (!norm.empty() && is_types_root_wildcard(norm) && g.inject_subdir_at_types_root) {
        HANDLE real = g.orig_FindFirstFileW(lpFileName, lpFindFileData);
        EnumState st{};
        st.inject_subdir = true;
        if (real != INVALID_HANDLE_VALUE) {
            st.real_handle = real;
            g.enum_states[(uint64_t)(uintptr_t)real] = st;
            return real;
        }
        make_virtual_subdir_find_data(lpFindFileData);
        HANDLE vh = alloc_virtual_handle();
        EnumState vst;
        vst.virtual_sent = true;
        g.enum_states[(uint64_t)(uintptr_t)vh] = vst;
        return vh;
    }

    if (lpFileName && is_wildcard_search(norm) && search_targets_virtual_dir(norm)) {
        size_t slash = norm.find_last_of(L"\\/");
        std::wstring pattern = (slash != std::wstring::npos) ? norm.substr(slash + 1) : norm;

        HANDLE real = g.orig_FindFirstFileW(lpFileName, lpFindFileData);
        EnumState st{};
        for (const auto& kv : g.file_plains) {
            if (pattern_matches_filename(pattern, kv.first))
                st.inject_files.push_back(kv.first);
        }

        if (real != INVALID_HANDLE_VALUE) {
            st.real_handle = real;
            g.enum_states[(uint64_t)(uintptr_t)real] = st;
            return real;
        }
        if (!st.inject_files.empty()) {
            make_virtual_find_data(st.inject_files[0], lpFindFileData);
            st.current_file_index = 1;
            HANDLE vh = alloc_virtual_handle();
            g.enum_states[(uint64_t)(uintptr_t)vh] = st;
            return vh;
        }
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    return g.orig_FindFirstFileW(lpFileName, lpFindFileData);
}

static BOOL WINAPI hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    auto it = g.enum_states.find((uint64_t)(uintptr_t)hFindFile);
    if (it != g.enum_states.end()) {
        EnumState& st = it->second;
        if (st.real_handle != INVALID_HANDLE_VALUE) {
            if (g.orig_FindNextFileW(hFindFile, lpFindFileData)) return TRUE;
        }
        if (st.inject_subdir && !st.virtual_sent) {
            make_virtual_subdir_find_data(lpFindFileData);
            st.virtual_sent = true;
            return TRUE;
        }
        if (st.current_file_index < st.inject_files.size()) {
            make_virtual_find_data(st.inject_files[st.current_file_index], lpFindFileData);
            st.current_file_index++;
            return TRUE;
        }
        SetLastError(ERROR_NO_MORE_FILES);
        return FALSE;
    }

    if (wh_hook::is_virtual_handle(hFindFile)) {
        SetLastError(ERROR_NO_MORE_FILES);
        return FALSE;
    }

    return g.orig_FindNextFileW(hFindFile, lpFindFileData);
}

static DWORD sanitize_create_disposition(const std::wstring& path, DWORD disp) {
    if (!path_is_our_indicator(path)) return disp;
    // 更新主图/保存时会 CREATE_ALWAYS 或 TRUNCATE，会把磁盘 WHPKG 占位清掉并导致崩溃
    if (disp == CREATE_ALWAYS || disp == TRUNCATE_EXISTING)
        return OPEN_EXISTING;
    return disp;
}

static HANDLE create_plain_section_mapping(const std::wstring& filename) {
    auto p = get_plain(filename);
    if (!p || p->empty()) return nullptr;
    DWORD size = (DWORD)p->size();
    HANDLE hMap = g.orig_CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                            PAGE_READWRITE, 0, size, nullptr);
    if (!hMap) return nullptr;
    if (!g.orig_MapViewOfFile || !g.orig_UnmapViewOfFile) {
        if (g.orig_CloseHandle) g.orig_CloseHandle(hMap);
        else CloseHandle(hMap);
        return nullptr;
    }
    LPVOID view = g.orig_MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, size);
    if (!view) {
        if (g.orig_CloseHandle) g.orig_CloseHandle(hMap);
        else CloseHandle(hMap);
        return nullptr;
    }
    memcpy(view, p->data(), size);
    g.orig_UnmapViewOfFile(view);
    g_file_plain_map_cache[filename] = hMap;
    return hMap;
}

static HANDLE get_plain_section_mapping(const std::wstring& filename) {
    auto it = g_file_plain_map_cache.find(filename);
    if (it != g_file_plain_map_cache.end() && it->second) return it->second;
    return create_plain_section_mapping(filename);
}

static bool path_might_be_our_indicator_ansi(LPCSTR path) {
    if (!path || !path[0] || g.virtual_dir.empty()) return false;
    std::wstring norm = resolve_long_path_ansi(path);
    return _wcsnicmp(norm.c_str(), g.virtual_dir.c_str(), g.virtual_dir.size()) == 0;
}

static bool path_might_be_our_indicator_w(LPCWSTR path) {
    if (!path || !path[0] || g.virtual_dir.empty()) return false;
    std::wstring norm = normalize_path(path);
    return _wcsnicmp(norm.c_str(), g.virtual_dir.c_str(), g.virtual_dir.size()) == 0;
}

static HANDLE WINAPI hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    const bool might = path_might_be_our_indicator_w(lpFileName);
    std::wstring path;
    DWORD disp = dwCreationDisposition;
    if (might) {
        path = lpFileName ? resolve_long_path(lpFileName) : L"";
        disp = sanitize_create_disposition(path, dwCreationDisposition);
    }
    HANDLE h = g.orig_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, disp, dwFlagsAndAttributes, hTemplateFile);
    if (h != INVALID_HANDLE_VALUE && might && path_is_our_indicator(path)) {
        hook_log("CreateFileW tracked indicator");
        track_real_handle(h, path);
    }
    return h;
}

static HANDLE WINAPI hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
    DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    const bool might = path_might_be_our_indicator_ansi(lpFileName);
    std::wstring path_hint;
    DWORD disp = dwCreationDisposition;
    if (might) {
        path_hint = lpFileName ? resolve_long_path_ansi(lpFileName) : L"";
        disp = sanitize_create_disposition(path_hint, dwCreationDisposition);
    }
    HANDLE h = g.orig_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, disp, dwFlagsAndAttributes, hTemplateFile);
    if (h != INVALID_HANDLE_VALUE && might && path_is_our_indicator(path_hint)) {
        hook_log("CreateFileA tracked indicator");
        track_real_handle(h, path_hint);
    }
    return h;
}

static bool handle_path_is_wh8crypto(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE || wh_hook::is_virtual_handle(h)) return false;
    wchar_t path_buf[MAX_PATH * 4]{};
    DWORD n = GetFinalPathNameByHandleW(h, path_buf,
        (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
    if (n == 0 || n >= sizeof(path_buf) / sizeof(wchar_t)) return false;
    return path_is_our_indicator(resolve_long_path(path_buf));
}

static bool handle_map_entry_stale(HANDLE h) {
    wchar_t path_buf[MAX_PATH * 4]{};
    DWORD n = GetFinalPathNameByHandleW(h, path_buf,
        (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
    if (n == 0 || n >= sizeof(path_buf) / sizeof(wchar_t)) return false;
    return !path_is_our_indicator(resolve_long_path(path_buf));
}

static bool handle_is_tracked_wh8crypto(HANDLE h) {
    if (!wh8crypto_hooks_active()) return false;
    if (!h || h == INVALID_HANDLE_VALUE || wh_hook::is_virtual_handle(h)) return false;
    std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
    auto it = g.tracked_handles.find((uint64_t)(uintptr_t)h);
    if (it == g.tracked_handles.end()) return false;
    if (handle_map_entry_stale(h)) {
        g.tracked_handles.erase(it);
        sync_tracked_flag_locked();
        return false;
    }
    return true;
}

static BOOL WINAPI hook_CloseHandle(HANDLE hObject) {
    if (wh_hook::is_virtual_handle(hObject)) {
        free_virtual_handle(hObject);
        return TRUE;
    }
    if (wh8crypto_hooks_active())
        untrack_handle(hObject);
    return g.orig_CloseHandle(hObject);
}

static HANDLE WINAPI hook_CreateFileMappingW(HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
    DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName) {
    if (!wh8crypto_hooks_active())
        return g.orig_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect,
            dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    std::wstring filename;
    if (handle_is_tracked_wh8crypto(hFile))
        filename = get_tracked_filename(hFile);
    if (filename.empty() && handle_path_is_wh8crypto(hFile)) {
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        wchar_t path_buf[MAX_PATH * 4]{};
        DWORD n = GetFinalPathNameByHandleW(hFile, path_buf,
            (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
        if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t)) {
            std::wstring resolved = resolve_long_path(path_buf);
            filename = filename_from_path(resolved);
            g.tracked_handles[(uint64_t)(uintptr_t)hFile] = {filename, 0};
            sync_tracked_flag_locked();
        }
    }
    if (!filename.empty())
        return get_plain_section_mapping(filename);
    return g.orig_CreateFileMappingW(hFile, lpFileMappingAttributes, flProtect,
        dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

static HANDLE WINAPI hook_CreateFileMappingA(HANDLE hFile,
    LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
    DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName) {
    if (!wh8crypto_hooks_active())
        return g.orig_CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect,
            dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
    std::wstring filename;
    if (handle_is_tracked_wh8crypto(hFile))
        filename = get_tracked_filename(hFile);
    if (filename.empty() && handle_path_is_wh8crypto(hFile)) {
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        wchar_t path_buf[MAX_PATH * 4]{};
        DWORD n = GetFinalPathNameByHandleW(hFile, path_buf,
            (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
        if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t)) {
            std::wstring resolved = resolve_long_path(path_buf);
            filename = filename_from_path(resolved);
            g.tracked_handles[(uint64_t)(uintptr_t)hFile] = {filename, 0};
            sync_tracked_flag_locked();
        }
    }
    if (!filename.empty())
        return get_plain_section_mapping(filename);
    return g.orig_CreateFileMappingA(hFile, lpFileMappingAttributes, flProtect,
        dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
}

static bool apply_file_pointer(DWORD dwMoveMethod, LONGLONG distance,
                               PLARGE_INTEGER lpNewFilePointer, size_t* inout_off, size_t file_size) {
    LONGLONG pos = 0;
    switch (dwMoveMethod) {
    case FILE_BEGIN: pos = distance; break;
    case FILE_CURRENT: pos = (LONGLONG)*inout_off + distance; break;
    case FILE_END: pos = (LONGLONG)file_size + distance; break;
    default: SetLastError(ERROR_INVALID_PARAMETER); return false;
    }
    if (pos < 0) pos = 0;
    *inout_off = (size_t)pos;
    if (lpNewFilePointer) lpNewFilePointer->QuadPart = pos;
    return true;
}

static DWORD WINAPI hook_SetFilePointer(HANDLE hFile, LONG lDistanceToMove,
    PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod) {
    if (wh_hook::is_virtual_handle(hFile)) {
        VirtualHandleInfo* vi = get_virtual_info(hFile);
        if (!vi || vi->filename.empty()) { SetLastError(ERROR_INVALID_HANDLE); return INVALID_SET_FILE_POINTER; }
        LARGE_INTEGER li{};
        if (!apply_file_pointer(dwMoveMethod, lDistanceToMove, &li, &vi->read_offset, get_plain_size(vi->filename)))
            return INVALID_SET_FILE_POINTER;
        if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = (LONG)(li.QuadPart >> 32);
        return (DWORD)(li.QuadPart & 0xFFFFFFFF);
    }
    if (!wh8crypto_hooks_active())
        return g.orig_SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
    {
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        size_t* poff = tracked_handle_offset_locked(hFile);
        if (!poff && handle_path_is_wh8crypto(hFile)) {
            wchar_t path_buf[MAX_PATH * 4]{};
            DWORD n = GetFinalPathNameByHandleW(hFile, path_buf,
                (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
            if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t)) {
                std::wstring resolved = resolve_long_path(path_buf);
                g.tracked_handles[(uint64_t)(uintptr_t)hFile] = {filename_from_path(resolved), 0};
                sync_tracked_flag_locked();
                poff = &g.tracked_handles[(uint64_t)(uintptr_t)hFile].offset;
            }
        }
        if (poff) {
            if (handle_map_entry_stale(hFile)) {
                g.tracked_handles.erase((uint64_t)(uintptr_t)hFile);
                sync_tracked_flag_locked();
            } else {
                std::wstring fname = g.tracked_handles[(uint64_t)(uintptr_t)hFile].filename;
                size_t file_size = get_plain_size(fname);
                size_t base = *poff;
                switch (dwMoveMethod) {
                case FILE_BEGIN: base = (size_t)lDistanceToMove; break;
                case FILE_CURRENT: base = *poff + (size_t)lDistanceToMove; break;
                case FILE_END: base = file_size + (size_t)lDistanceToMove; break;
                default: SetLastError(ERROR_INVALID_PARAMETER); return INVALID_SET_FILE_POINTER;
                }
                *poff = base;
                if (lpDistanceToMoveHigh) *lpDistanceToMoveHigh = (LONG)(base >> 32);
                return (DWORD)(base & 0xFFFFFFFF);
            }
        }
    }
    return g.orig_SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}

static BOOL WINAPI hook_SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove,
    PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod) {
    if (wh_hook::is_virtual_handle(hFile)) {
        VirtualHandleInfo* vi = get_virtual_info(hFile);
        if (!vi || vi->filename.empty()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
        return apply_file_pointer(dwMoveMethod, liDistanceToMove.QuadPart,
                                  lpNewFilePointer, &vi->read_offset, get_plain_size(vi->filename));
    }
    if (!wh8crypto_hooks_active())
        return g.orig_SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
    {
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        size_t* poff = tracked_handle_offset_locked(hFile);
        if (!poff && handle_path_is_wh8crypto(hFile)) {
            wchar_t path_buf[MAX_PATH * 4]{};
            DWORD n = GetFinalPathNameByHandleW(hFile, path_buf,
                (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
            if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t)) {
                std::wstring resolved = resolve_long_path(path_buf);
                g.tracked_handles[(uint64_t)(uintptr_t)hFile] = {filename_from_path(resolved), 0};
                sync_tracked_flag_locked();
                poff = &g.tracked_handles[(uint64_t)(uintptr_t)hFile].offset;
            }
        }
        if (poff) {
            if (handle_map_entry_stale(hFile)) {
                g.tracked_handles.erase((uint64_t)(uintptr_t)hFile);
                sync_tracked_flag_locked();
            } else {
                std::wstring fname = g.tracked_handles[(uint64_t)(uintptr_t)hFile].filename;
                size_t file_size = get_plain_size(fname);
                LONGLONG pos = 0;
                switch (dwMoveMethod) {
                case FILE_BEGIN: pos = liDistanceToMove.QuadPart; break;
                case FILE_CURRENT: pos = (LONGLONG)*poff + liDistanceToMove.QuadPart; break;
                case FILE_END: pos = (LONGLONG)file_size + liDistanceToMove.QuadPart; break;
                default: SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
                }
                if (pos < 0) pos = 0;
                *poff = (size_t)pos;
                if (lpNewFilePointer) lpNewFilePointer->QuadPart = pos;
                return TRUE;
            }
        }
    }
    return g.orig_SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
}

static BOOL read_plain_data(const std::wstring& filename, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
                            LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped,
                            size_t* inout_offset) {
    auto p = get_plain(filename);
    if (!p) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    const auto& data = *p;
    size_t offset = *inout_offset;
    if (lpOverlapped)
        offset = (size_t)lpOverlapped->Offset + ((size_t)lpOverlapped->OffsetHigh << 32);
    if (offset >= data.size()) {
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
        return TRUE;
    }
    size_t avail = data.size() - offset;
    DWORD to_read = (DWORD)(avail < nNumberOfBytesToRead ? avail : nNumberOfBytesToRead);
    memcpy(lpBuffer, data.data() + offset, to_read);
    if (lpNumberOfBytesRead) *lpNumberOfBytesRead = to_read;
    if (!lpOverlapped) *inout_offset = offset + to_read;
    return TRUE;
}

static void fill_synthetic_file_times(FILETIME* ft) {
    if (!ft) return;
    SYSTEMTIME st{};
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, ft);
}

static BOOL synthetic_file_information(const std::wstring& filename, HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpInfo) {
    if (!lpInfo) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    ZeroMemory(lpInfo, sizeof(*lpInfo));
    ULONGLONG sz = get_plain_size(filename);
    lpInfo->dwFileAttributes = FILE_ATTRIBUTE_NORMAL;
    lpInfo->ftCreationTime.dwLowDateTime = 0;
    lpInfo->ftCreationTime.dwHighDateTime = 0;
    fill_synthetic_file_times(&lpInfo->ftLastAccessTime);
    fill_synthetic_file_times(&lpInfo->ftLastWriteTime);
    lpInfo->nFileSizeHigh = (DWORD)(sz >> 32);
    lpInfo->nFileSizeLow = (DWORD)(sz & 0xFFFFFFFF);
    lpInfo->nNumberOfLinks = 1;
    (void)hFile;
    return TRUE;
}

static BOOL synthetic_file_standard_info(const std::wstring& filename, HANDLE hFile, LPVOID lpBuffer, DWORD dwBufferSize) {
    if (!lpBuffer || dwBufferSize < sizeof(FILE_STANDARD_INFO)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    auto* info = (FILE_STANDARD_INFO*)lpBuffer;
    ZeroMemory(info, sizeof(*info));
    ULONGLONG sz = get_plain_size(filename);
    info->AllocationSize.QuadPart = (LONGLONG)sz;
    info->EndOfFile.QuadPart = (LONGLONG)sz;
    info->NumberOfLinks = 1;
    info->DeletePending = FALSE;
    info->Directory = FALSE;
    (void)hFile;
    return TRUE;
}

static BOOL WINAPI hook_ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    if (wh_hook::is_virtual_handle(hFile)) {
        VirtualHandleInfo* vi = get_virtual_info(hFile);
        if (!vi || vi->filename.empty()) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
        return read_plain_data(vi->filename, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
                               lpOverlapped, &vi->read_offset);
    }
    if (!wh8crypto_hooks_active())
        return g.orig_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    {
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        uint64_t id = (uint64_t)(uintptr_t)hFile;
        auto it = g.tracked_handles.find(id);
        if (it != g.tracked_handles.end()) {
            if (handle_map_entry_stale(hFile)) {
                g.tracked_handles.erase(it);
                sync_tracked_flag_locked();
            } else
                return read_plain_data(it->second.filename, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
                                       lpOverlapped, &it->second.offset);
        }
        if (handle_path_is_wh8crypto(hFile)) {
            wchar_t path_buf[MAX_PATH * 4]{};
            DWORD n = GetFinalPathNameByHandleW(hFile, path_buf,
                (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
            std::wstring fname;
            if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t))
                fname = filename_from_path(resolve_long_path(path_buf));
            if (!fname.empty()) {
                g.tracked_handles[id] = {fname, 0};
                sync_tracked_flag_locked();
                return read_plain_data(fname, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
                                       lpOverlapped, &g.tracked_handles[id].offset);
            }
        }
    }
    BOOL ok = g.orig_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (ok && lpNumberOfBytesRead && *lpNumberOfBytesRead >= 5 &&
        memcmp(lpBuffer, "WHPKG", 5) == 0 && handle_path_is_wh8crypto(hFile)) {
        hook_log("ReadFile WHPKG replaced");
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        uint64_t id = (uint64_t)(uintptr_t)hFile;
        wchar_t path_buf[MAX_PATH * 4]{};
        DWORD n = GetFinalPathNameByHandleW(hFile, path_buf,
            (DWORD)(sizeof(path_buf) / sizeof(wchar_t)), FILE_NAME_NORMALIZED);
        std::wstring fname;
        if (n > 0 && n < sizeof(path_buf) / sizeof(wchar_t))
            fname = filename_from_path(resolve_long_path(path_buf));
        if (!fname.empty()) {
            g.tracked_handles[id] = {fname, 0};
            sync_tracked_flag_locked();
            return read_plain_data(fname, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
                                   lpOverlapped, &g.tracked_handles[id].offset);
        }
    }
    return ok;
}

static DWORD WINAPI hook_GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh) {
    if (wh_hook::is_virtual_handle(hFile)) {
        VirtualHandleInfo* vi = get_virtual_info(hFile);
        if (lpFileSizeHigh) *lpFileSizeHigh = 0;
        return (DWORD)get_plain_size(vi ? vi->filename : L"");
    }
    if (!wh8crypto_hooks_active())
        return g.orig_GetFileSize(hFile, lpFileSizeHigh);
    if (handle_is_tracked_wh8crypto(hFile)) {
        if (lpFileSizeHigh) *lpFileSizeHigh = 0;
        return (DWORD)get_plain_size(get_tracked_filename(hFile));
    }
    return g.orig_GetFileSize(hFile, lpFileSizeHigh);
}

static BOOL WINAPI hook_GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize) {
    if (wh_hook::is_virtual_handle(hFile)) {
        VirtualHandleInfo* vi = get_virtual_info(hFile);
        lpFileSize->QuadPart = (LONGLONG)get_plain_size(vi ? vi->filename : L"");
        return TRUE;
    }
    if (!wh8crypto_hooks_active())
        return g.orig_GetFileSizeEx(hFile, lpFileSize);
    if (handle_is_tracked_wh8crypto(hFile)) {
        lpFileSize->QuadPart = (LONGLONG)get_plain_size(get_tracked_filename(hFile));
        return TRUE;
    }
    return g.orig_GetFileSizeEx(hFile, lpFileSize);
}

static BOOL WINAPI hook_GetFileInformationByHandle(HANDLE hFile,
    LPBY_HANDLE_FILE_INFORMATION lpInfo) {
    if (!wh8crypto_hooks_active())
        return g.orig_GetFileInformationByHandle(hFile, lpInfo);
    if (!handle_is_tracked_wh8crypto(hFile))
        return g.orig_GetFileInformationByHandle(hFile, lpInfo);
    return synthetic_file_information(get_tracked_filename(hFile), hFile, lpInfo);
}

static BOOL WINAPI hook_GetFileInformationByHandleEx(HANDLE hFile,
    FILE_INFO_BY_HANDLE_CLASS infoClass, LPVOID lpBuffer, DWORD dwBufferSize) {
    if (!wh8crypto_hooks_active())
        return g.orig_GetFileInformationByHandleEx(hFile, infoClass, lpBuffer, dwBufferSize);
    if (!handle_is_tracked_wh8crypto(hFile) || infoClass != FileStandardInfo)
        return g.orig_GetFileInformationByHandleEx(hFile, infoClass, lpBuffer, dwBufferSize);
    return synthetic_file_standard_info(get_tracked_filename(hFile), hFile, lpBuffer, dwBufferSize);
}

static BOOL WINAPI hook_FlushFileBuffers(HANDLE hFile) {
    if (wh_hook::is_virtual_handle(hFile))
        return TRUE;
    if (!wh8crypto_hooks_active())
        return g.orig_FlushFileBuffers(hFile);
    if (handle_is_tracked_wh8crypto(hFile))
        return TRUE;
    return g.orig_FlushFileBuffers(hFile);
}

static bool load_payload_from_shared(const uint8_t* shared_mem, size_t mem_size) {
    const uint8_t* master_key = nullptr;
    size_t key_len = 0;
    const uint8_t* bundle_data = nullptr;
    size_t bundle_len = 0;
    std::wstring vdir;

    if (!parse_shared_mem(shared_mem, mem_size, &master_key, &key_len,
                          &bundle_data, &bundle_len, &vdir))
        return false;

    std::vector<uint8_t> bundle(bundle_data, bundle_data + bundle_len);
    std::wstring software_name;
    std::vector<std::pair<std::wstring, std::vector<uint8_t>>> items;
    std::string err;
    if (!parse_bundle(bundle, software_name, items, &err))
        return false;

    int64_t now = 0;
    bool have_now = false;
    auto get_now = [&]() {
        if (!have_now) {
            SYSTEMTIME st;
            GetSystemTime(&st);
            FILETIME ft;
            SystemTimeToFileTime(&st, &ft);
            now = ((int64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            now = (now - 116444736000000000LL) / 10000000LL;
            have_now = true;
        }
        return now;
    };

    g.file_plains.clear();
    invalidate_plain_map_cache();

    for (auto& item : items) {
        wh::PackageHeader hdr{};
        wh::PayloadPlain payload{};
        if (!wh::package_parse(item.second, master_key, hdr, payload, &err))
            return false;
        if (hdr.expire_unix > 0 && get_now() > hdr.expire_unix)
            return false;

        std::vector<uint8_t> plain;
        if (!payload.xtrd_raw.empty()) {
            if (!wh::xtrd_is_password_protected(payload.xtrd_raw)) return false;
            plain = payload.xtrd_raw;
        } else {
            plain = wh::xtrd_wrap_source(payload.source);
        }
        g.file_plains[item.first] = std::move(plain);
        g.expire_unix = hdr.expire_unix;
        g.user = hdr.user;
        g.contact = hdr.contact;
        g.indicator_version = hdr.indicator_version;
        g.software_name.assign(hdr.software_name.begin(), hdr.software_name.end());
    }

    if (!software_name.empty())
        g.software_name = software_name;

    g.virtual_dir = normalize_path(vdir.empty() ? L"D:\\WT8模拟版\\Formula\\TYPES\\自编" : vdir);

    size_t slash = g.virtual_dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        g.types_root = g.virtual_dir.substr(0, slash);
        g.virtual_subdir_name = g.virtual_dir.substr(slash + 1);
        g.inject_subdir_at_types_root =
            (_wcsicmp(g.virtual_subdir_name.c_str(), wh_hook::kUserTypesSubdir) != 0);
    } else {
        g.types_root = g.virtual_dir;
        g.virtual_subdir_name = g.software_name.empty() ? wh_hook::kDefaultVirtualFolder : g.software_name.c_str();
        g.inject_subdir_at_types_root = true;
    }
    return true;
}

static bool install_api_hooks_once() {
    if (g.initialized) return true;

    // STABLE v5.0.17: 未打开 WH8CRYPTO 时全 API 零锁 fast-path；不 Hook CloseHandle
    if (MH_Initialize() != MH_OK) return false;

    struct HookEntry { void** orig; void* hook_fn; const char* name; } hooks[] = {
        {(void**)&g.orig_CreateFileW,    (void*)hook_CreateFileW,    "CreateFileW"},
        {(void**)&g.orig_CreateFileA,    (void*)hook_CreateFileA,    "CreateFileA"},
        {(void**)&g.orig_CreateFileMappingW, (void*)hook_CreateFileMappingW, "CreateFileMappingW"},
        {(void**)&g.orig_CreateFileMappingA, (void*)hook_CreateFileMappingA, "CreateFileMappingA"},
        {(void**)&g.orig_SetFilePointer, (void*)hook_SetFilePointer, "SetFilePointer"},
        {(void**)&g.orig_SetFilePointerEx, (void*)hook_SetFilePointerEx, "SetFilePointerEx"},
        {(void**)&g.orig_ReadFile,       (void*)hook_ReadFile,       "ReadFile"},
        {(void**)&g.orig_GetFileSize,    (void*)hook_GetFileSize,    "GetFileSize"},
        {(void**)&g.orig_GetFileSizeEx,  (void*)hook_GetFileSizeEx,  "GetFileSizeEx"},
        {(void**)&g.orig_GetFileInformationByHandle, (void*)hook_GetFileInformationByHandle, "GetFileInformationByHandle"},
        {(void**)&g.orig_GetFileInformationByHandleEx, (void*)hook_GetFileInformationByHandleEx, "GetFileInformationByHandleEx"},
        {(void**)&g.orig_FlushFileBuffers, (void*)hook_FlushFileBuffers, "FlushFileBuffers"},
    };

    HMODULE modules[2] = {
        GetModuleHandleW(L"kernelbase.dll"),
        GetModuleHandleW(L"kernel32.dll"),
    };

    for (auto& h : hooks) {
        void* addr = nullptr;
        for (HMODULE mod : modules) {
            if (!mod) continue;
            void* p = (void*)GetProcAddress(mod, h.name);
            if (p) { addr = p; break; }
        }
        if (!addr || MH_CreateHook(addr, h.hook_fn, h.orig) != MH_OK) {
            MH_Uninitialize();
            return false;
        }
    }
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        MH_Uninitialize();
        return false;
    }
    g.initialized = true;
    return true;
}

} // namespace

bool wh_hook::hook_refresh_payload(const uint8_t* shared_mem, size_t mem_size) {
    return load_payload_from_shared(shared_mem, mem_size);
}

bool wh_hook::hook_install(const uint8_t* shared_mem, size_t mem_size) {
    if (g.initialized) {
        if (!hook_refresh_payload(shared_mem, mem_size)) return false;
        return true;
    }

    g.enum_states.clear();
    {
        std::lock_guard<std::mutex> lock(g.handle_mutex);
        g.virtual_handles.clear();
    }
    if (!load_payload_from_shared(shared_mem, mem_size)) return false;
    return install_api_hooks_once();
}

void wh_hook::hook_uninstall() {
    if (!g.initialized) return;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    auto wipe = [](std::vector<uint8_t>& v) {
        if (!v.empty()) { SecureZeroMemory(v.data(), v.size()); v.clear(); }
    };
    for (auto& kv : g.file_plains) wipe(kv.second);
    g.file_plains.clear();
    invalidate_plain_map_cache();
    g.enum_states.clear();
    {
        std::lock_guard<std::mutex> lock(g.handle_mutex);
        g.virtual_handles.clear();
    }
    {
        std::lock_guard<std::recursive_mutex> lk(g_track_mutex);
        g.tracked_handles.clear();
    }
    g_has_tracked_handles.store(false, std::memory_order_relaxed);
    g.initialized = false;
}
