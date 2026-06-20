#define WIN32_LEAN_AND_MEAN

#include <windows.h>

#include <stdio.h>

#include <string.h>

#include "wh_hook.h"



namespace {



HANDLE find_our_shared_memory() {

    DWORD pid = GetCurrentProcessId();

    wchar_t name[128];

    swprintf_s(name, L"Global\\WH8_CRYPTO_%u", pid);

    HANDLE h = OpenFileMappingW(FILE_MAP_READ, FALSE, name);

    if (h) return h;

    swprintf_s(name, L"WH8_CRYPTO_%u", pid);

    return OpenFileMappingW(FILE_MAP_READ, FALSE, name);

}



void signal_hook_ready() {

    DWORD pid = GetCurrentProcessId();

    wchar_t name[128];

    swprintf_s(name, L"Global\\WH8_CRYPTO_READY_%u", pid);

    HANDLE h = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);

    if (!h) {

        swprintf_s(name, L"WH8_CRYPTO_READY_%u", pid);

        h = OpenEventW(EVENT_MODIFY_STATE, FALSE, name);

    }

    if (h) {

        SetEvent(h);

        CloseHandle(h);

    }

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



static DWORD hook_reload_impl() {

    hook_log("reload start");

    HANDLE hMap = find_our_shared_memory();

    if (!hMap) { hook_log("shared memory not found"); return 1; }



    const uint8_t* data = (const uint8_t*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    if (!data) {

        CloseHandle(hMap);

        return 2;

    }



    MEMORY_BASIC_INFORMATION mbi{};

    SIZE_T q = VirtualQuery(data, &mbi, sizeof(mbi));

    size_t mem_size = q ? (size_t)mbi.RegionSize : 0;



    bool ok = wh_hook::hook_install(data, mem_size);

    UnmapViewOfFile(data);

    CloseHandle(hMap);

    hook_log("hook_install ok v5.0.17");

    if (ok) signal_hook_ready();

    return ok ? 0 : 3;

}



} // namespace



extern "C" __declspec(dllexport) DWORD WINAPI Wh8CryptoReload(LPVOID) {

    return hook_reload_impl();

}

extern "C" __declspec(dllexport) char Wh8CryptoHookVersion[] = "5.0.17";



BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {

    switch (reason) {

    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);

        return TRUE;

    case DLL_PROCESS_DETACH:

        wh_hook::hook_uninstall();

        return TRUE;

    default:

        return TRUE;

    }

}

