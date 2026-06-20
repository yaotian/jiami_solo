#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键生成客户端 Launcher.exe"""
import argparse
import glob
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK_VERSION = "5.0.17"
sys.path.insert(0, str(ROOT / "tools"))
from wh_pack import package_build, PRODUCT_T8_WH8
from wh_license import license_generate

CRYPTO_DIR = ROOT / "src" / "cpp" / "crypto"
HOOK_DIR = ROOT / "src" / "cpp" / "hook"
LAUNCHER_DIR = ROOT / "src" / "cpp" / "launcher"
MINHOOK_DIR = ROOT / "third_party" / "minhook"
BUILD_DIR = ROOT / "build"

CL_LAUNCHER = "/nologo /EHsc /std:c++14 /O2 /W3 /utf-8 /DWIN32 /D_WINDOWS /D_WIN32_WINNT=0x0A00 /DWH_HAVE_BCRYPT"
CL_DLL = "/nologo /EHsc /std:c++14 /O2 /W3 /utf-8 /MT /DWIN32 /DWH_BUILD_HOOKDLL /D_WIN32_WINNT=0x0A00 /DWH_HAVE_BCRYPT /LD"

BUNDLE_MAGIC = b"WHBUNDLE\x00\x01\x00"
BUNDLE_VERSION = 1


def build_bundle(software_name: str, items):
    """items: list of (filename, whpkg_bytes)"""
    out = bytearray()
    out += BUNDLE_MAGIC
    out += struct.pack("<I", BUNDLE_VERSION)
    sn = software_name.encode("utf-8")
    out += struct.pack("<H", len(sn))
    out += sn
    out += struct.pack("<I", len(items))
    for name, pkg in items:
        nb = name.encode("utf-8")
        out += struct.pack("<H", len(nb))
        out += nb
        out += struct.pack("<I", len(pkg))
        out += pkg
    return bytes(out)


def parse_bundle(data: bytes):
    if data[:len(BUNDLE_MAGIC)] != BUNDLE_MAGIC:
        raise ValueError("bad bundle magic")
    off = len(BUNDLE_MAGIC)
    version = struct.unpack_from("<I", data, off)[0]
    off += 4
    if version != BUNDLE_VERSION:
        raise ValueError(f"unsupported bundle version {version}")
    snlen = struct.unpack_from("<H", data, off)[0]
    off += 2
    software_name = data[off : off + snlen].decode("utf-8")
    off += snlen
    count = struct.unpack_from("<I", data, off)[0]
    off += 4
    items = []
    for _ in range(count):
        nlen = struct.unpack_from("<H", data, off)[0]
        off += 2
        name = data[off : off + nlen].decode("utf-8")
        off += nlen
        plen = struct.unpack_from("<I", data, off)[0]
        off += 4
        pkg = data[off : off + plen]
        off += plen
        items.append((name, pkg))
    return software_name, items


def has_windows_sdk():
    sdk = Path(r"C:\Program Files (x86)\Windows Kits\10\Include")
    if not sdk.exists():
        return False
    versions = sorted(sdk.iterdir(), reverse=True)
    return any(v.is_dir() for v in versions)


def find_vcvars():
    patterns = [
        r"C:\Program Files\Microsoft Visual Studio\2022\*\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\*\VC\Auxiliary\Build\vcvars64.bat",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    ]
    for pat in patterns:
        hits = glob.glob(pat)
        if hits:
            return hits[0]
    return None


def gen_config_h(path: Path, master_key: bytes, user, contact, expire, product, version, software_name, hook_version,
                 machine_code: str = "", license_key: str = ""):
    def esc(s):
        return s.replace("\\", "\\\\").replace('"', '\\"')

    path.write_text(
        f"""// auto-generated {time.strftime('%Y-%m-%d %H:%M:%S')}
#ifndef WH_LAUNCHER_CONFIG_H
#define WH_LAUNCHER_CONFIG_H
#define WH_MASTER_KEY_HEX "{master_key.hex()}"
#define WH_EXPIRE_UNIX {expire}LL
#define WH_USER "{esc(user)}"
#define WH_CONTACT "{esc(contact)}"
#define WH_INDICATOR_VERSION "{esc(version)}"
#define WH_SOFTWARE_NAME "{esc(software_name)}"
#define WH_PRODUCT_ID {product}
#define WH_HOOK_VERSION "{hook_version}"
#define WH_ENABLE_ANTI_DEBUG 0
#define WH_MACHINE_CODE "{esc(machine_code)}"
#define WH_LICENSE_KEY "{esc(license_key)}"
#endif
""",
        encoding="utf-8",
    )


def gen_rc(path: Path, pkg_path: Path, dll_path: Path, app_name: str):
    safe_name = app_name.encode("ascii", "ignore").decode() or "WH8Crypto"
    path.write_text(
        f"""#include <windows.h>
#define WHPACKRES 256
101 WHPACKRES "{pkg_path.as_posix()}"
102 WHPACKRES "{dll_path.as_posix()}"
1 VERSIONINFO
FILEVERSION 1,0,0,0
PRODUCTVERSION 1,0,0,0
FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
FILEFLAGS 0
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE VFT2_UNKNOWN
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "080404B0"
    BEGIN
      VALUE "CompanyName", "WH8Crypto"
      VALUE "FileDescription", "{safe_name}"
      VALUE "FileVersion", "1.0.0.0"
      VALUE "ProductName", "{safe_name}"
      VALUE "ProductVersion", "1.0.0.0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x804, 1200
  END
END
""",
        encoding="utf-8",
    )


def run_cmd(cmd: str, cwd=None):
    r = subprocess.run(f'cmd /c "{cmd}"', shell=True, capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        print(r.stdout[-2000:] if r.stdout else "")
        print(r.stderr[-2000:] if r.stderr else "")
        raise RuntimeError(f"command failed: {cmd}")
    return r


def compile_hook_dll(out_dir: Path, vcvars: str) -> Path:
    out = out_dir / "wh_hook.dll"
    mh = list((MINHOOK_DIR / "src").glob("*.c"))
    mh += list((MINHOOK_DIR / "src" / "hde").glob("hde64.c"))
    src = [
        CRYPTO_DIR / "wh_crypto.cpp",
        CRYPTO_DIR / "wh_packet.cpp",
        CRYPTO_DIR / "wh_xtrd.cpp",
        HOOK_DIR / "wh_hook.cpp",
        HOOK_DIR / "wh_hook_main.cpp",
    ] + mh
    inc = [
        f"/I{MINHOOK_DIR / 'include'}",
        f"/I{MINHOOK_DIR / 'src'}",
        f"/I{MINHOOK_DIR / 'src' / 'hde'}",
        f"/I{CRYPTO_DIR}",
        f"/I{HOOK_DIR}",
    ]
    cmd = (
        f'"{vcvars}" && cl {CL_DLL} {" ".join(inc)} '
        f'{" ".join(str(s) for s in src)} /Fe:"{out}" shlwapi.lib bcrypt.lib'
    )
    print("  compile hook dll...")
    run_cmd(cmd)
    return out


def compile_launcher(out_dir: Path, vcvars: str, rc_path: Path) -> Path:
    out = out_dir / "wh_launcher.exe"
    res = out_dir / "wh_launcher.res"
    run_cmd(f'"{vcvars}" && rc /nologo /fo "{res}" "{rc_path}"')
    src = [
        LAUNCHER_DIR / "wh_launcher_main.cpp",
        LAUNCHER_DIR / "wh_launcher.cpp",
        LAUNCHER_DIR / "wh_hwid.cpp",
        LAUNCHER_DIR / "wh_license.cpp",
        CRYPTO_DIR / "wh_crypto.cpp",
        CRYPTO_DIR / "wh_packet.cpp",
    ]
    inc = [f"/I{LAUNCHER_DIR}", f"/I{HOOK_DIR}", f"/I{CRYPTO_DIR}"]
    cmd = (
        f'"{vcvars}" && cl {CL_LAUNCHER} {" ".join(inc)} '
        f'{" ".join(str(s) for s in src)} "{res}" /Fe:"{out}" '
        f'/link /SUBSYSTEM:WINDOWS /MACHINE:X64 '
        f'shlwapi.lib shell32.lib advapi32.lib user32.lib comdlg32.lib bcrypt.lib'
    )
    print("  compile launcher...")
    run_cmd(cmd)
    return out


def build_client(args):
    from wh_pack import xtrd_is_password_protected

    if not args.xtrd and not args.src:
        print("ERROR: 请指定 --src（.myl）或 --xtrd（WH8 带查看密码的指标文件），可多次指定")
        return 1

    master_key = bytes.fromhex(args.master) if args.master else secrets.token_bytes(32)
    software_name = args.software_name or "WH8Crypto"

    items = []  # (filename, whpkg_bytes)
    seen_names = set()

    for xtrd in (args.xtrd or []):
        xtrd_path = Path(xtrd)
        xtrd_raw = xtrd_path.read_bytes()
        if not xtrd_is_password_protected(xtrd_raw):
            print(f"ERROR: {xtrd} 须含 <HEAD> 与密文 <CODE>，请先在 WH8 指标管理器里设置查看密码后保存。")
            return 1
        name = xtrd_path.name
        if name in seen_names:
            print(f"ERROR: 指标文件名重复: {name}")
            return 1
        seen_names.add(name)
        pkg = package_build(
            master_key, args.product, args.expire, args.user, args.contact,
            args.indicator_version, software_name, "", name, xtrd_raw=xtrd_raw,
        )
        items.append((name, pkg))

    for src_spec in (args.src or []):
        # 支持 "名称=路径" 或仅路径（取 stem）
        if "=" in src_spec:
            name, src_path = src_spec.split("=", 1)
        else:
            src_path = src_spec
            name = Path(src_path).stem + ".XTRD"
        name = name.strip()
        source = Path(src_path).read_text(encoding="utf-8")
        if name in seen_names:
            print(f"ERROR: 指标文件名重复: {name}")
            return 1
        seen_names.add(name)
        pkg = package_build(
            master_key, args.product, args.expire, args.user, args.contact,
            args.indicator_version, software_name, source, name,
        )
        items.append((name, pkg))

    if not items:
        print("ERROR: 没有有效的指标输入")
        return 1

    bundle = build_bundle(software_name, items)

    license_key = args.license_key or ""
    machine_code = args.machine_code or ""
    if machine_code and not license_key:
        # 根据机器码自动生成注册码（方便管理端一键绑定机器）
        license_key = license_generate(master_key, machine_code, args.expire)
        print(f"  auto license for machine {machine_code}: {license_key}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # rc.exe 不支持 Unicode 路径，临时目录必须用 ASCII 路径
    tmp = Path(tempfile.mkdtemp(prefix="wh8build_", dir=os.environ.get("TEMP", None)))

    bundle_path = tmp / "bundle.bin"
    bundle_path.write_bytes(bundle)
    gen_config_h(LAUNCHER_DIR / "wh_launcher_config.h", master_key,
                 args.user, args.contact, args.expire, args.product, args.indicator_version,
                 software_name, HOOK_VERSION, machine_code, license_key)

    vcvars = find_vcvars()
    if not vcvars:
        print("未找到 MSVC (vcvars64.bat)。请安装 Visual Studio Build Tools。")
        print(f"已生成数据包: {bundle_path}")
        return 1
    if not has_windows_sdk():
        print("未找到 Windows 10 SDK（缺少 windows.h / stddef.h）。")
        print("请打开 Visual Studio Installer → 修改 Build Tools → 勾选「Windows 10/11 SDK」。")
        print(f"已生成数据包: {bundle_path}")
        return 1

    dll_path = compile_hook_dll(tmp, vcvars)
    rc_path = tmp / "wh_launcher.rc"
    gen_rc(rc_path, bundle_path, dll_path, args.app_name or software_name)
    exe_path = compile_launcher(tmp, vcvars, rc_path)
    shutil.copy2(exe_path, out_path)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"OK: {out_path} ({out_path.stat().st_size} bytes)")
    print(f"master_key={master_key.hex()}")
    return 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", action="append", help="plain .myl source (legacy); 可多次，支持 名称=路径")
    p.add_argument("--xtrd", action="append", help="password-protected .XTRD exported from WH8; 可多次")
    p.add_argument("--user", required=True)
    p.add_argument("--contact", required=True)
    p.add_argument("--indicator-version", default="1.0.0")
    p.add_argument("--software-name", default="WH8Crypto")
    p.add_argument("--expire", type=int, default=0)
    p.add_argument("--product", type=int, default=PRODUCT_T8_WH8)
    p.add_argument("--master", help="64 hex chars; omit to auto-generate")
    p.add_argument("--machine-code", help="绑定机器码（可选），如同时提供 --license-key 则直接嵌入注册码")
    p.add_argument("--license-key", help="嵌入的离线注册码（可选）")
    p.add_argument("--app-name", default="文华指标客户端")
    p.add_argument("-o", "--output", required=True)
    sys.exit(build_client(p.parse_args()))


if __name__ == "__main__":
    main()
